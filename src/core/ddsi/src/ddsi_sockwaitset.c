// Copyright(c) 2006 to 2022 ZettaScale Technology and others
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License v. 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
// v. 1.0 which is available at
// http://www.eclipse.org/org/documents/edl-v10.php.
//
// SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

#include <assert.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "dds/ddsrt/heap.h"
#include "dds/ddsrt/sockets.h"
#include "dds/ddsrt/sync.h"

#include "dds/ddsi/ddsi_log.h"
#include "ddsi__sockwaitset.h"
#include "ddsi__tran.h"

#define WAITSET_DELTA 8

#define MODE_KQUEUE 1
#define MODE_SELECT 2
#define MODE_EPOLL  4

#if LWIP_SOCKET
#define MODE_SEL MODE_SELECT
#elif defined __APPLE__
#define MODE_SEL MODE_KQUEUE
#elif defined __linux
#define MODE_SEL MODE_EPOLL
#else
#define MODE_SEL MODE_SELECT
#endif

#if MODE_SEL == MODE_KQUEUE || MODE_SEL == MODE_EPOLL || (MODE_SEL == MODE_SELECT && !LWIP_SOCKET)
static void consume_trigger (struct ddsi_sock_waitset *ws);
#ifndef _WIN32
#include <errno.h>
#endif
#endif

static dds_duration_t wait_duration (ddsrt_mtime_t deadline)
{
  if (deadline.v == DDS_NEVER)
    return DDS_INFINITY;
  const ddsrt_mtime_t now = ddsrt_time_monotonic ();
  return deadline.v <= now.v ? 0 : deadline.v - now.v;
}

#if MODE_SEL == MODE_KQUEUE || MODE_SEL == MODE_EPOLL

#include <unistd.h>
#include <fcntl.h>
#if MODE_SEL == MODE_KQUEUE
#include <sys/event.h>
typedef struct kevent wait_event_t;
#else
#include <sys/epoll.h>
typedef struct epoll_event wait_event_t;
#endif

struct entry {
  struct ddsi_tran_conn *conn;
  uint32_t next;
  bool read_enabled;
};

struct ddsi_sock_waitset_ctx
{
  wait_event_t evs[64];
  int n, index;
  struct ddsi_sock_waitset *ws;
};

struct ddsi_sock_waitset
{
  int pollfd;
  int pipe[2];
  bool trigger_pending;
  ddsrt_mutex_t lock;
  struct entry *entries;
  uint32_t nslots;
  uint32_t available, retired_first, retired_last;
  struct ddsi_sock_waitset_ctx ctx;
};

static int update_interest (int pollfd, int fd, uint32_t slot, bool add)
{
  int ret;
#if MODE_SEL == MODE_KQUEUE
  struct kevent ev;
  EV_SET (&ev, (unsigned) fd, EVFILT_READ, add ? EV_ADD : EV_DELETE, 0, 0, (void *) (uintptr_t) slot);
  do { ret = kevent (pollfd, &ev, 1, NULL, 0, NULL); } while (ret == -1 && errno == EINTR);
#else
  struct epoll_event ev = { .events = EPOLLIN, .data.u32 = slot };
  do { ret = epoll_ctl (pollfd, add ? EPOLL_CTL_ADD : EPOLL_CTL_DEL, fd, &ev); } while (ret == -1 && errno == EINTR);
#endif
  return ret;
}

struct ddsi_sock_waitset *ddsi_sock_waitset_new (void)
{
  struct ddsi_sock_waitset *ws = ddsrt_calloc_s (1, sizeof (*ws));
  if (!ws)
    return NULL;
#if MODE_SEL == MODE_KQUEUE
  ws->pollfd = kqueue ();
#else
  ws->pollfd = epoll_create (1);
#endif
  if (ws->pollfd == -1)
    goto fail;
  if (pipe (ws->pipe) == -1)
    goto fail_pipe;
  if (fcntl (ws->pollfd, F_SETFD, FD_CLOEXEC) == -1 ||
      fcntl (ws->pipe[0], F_SETFD, FD_CLOEXEC) == -1 ||
      fcntl (ws->pipe[1], F_SETFD, FD_CLOEXEC) == -1 ||
      update_interest (ws->pollfd, ws->pipe[0], 0, true) == -1)
    goto fail_setup;
  ws->ctx.ws = ws;
  ddsrt_mutex_init (&ws->lock);
  return ws;

fail_setup:
  close (ws->pipe[0]);
  close (ws->pipe[1]);
fail_pipe:
  close (ws->pollfd);
fail:
  ddsrt_free (ws);
  return NULL;
}

void ddsi_sock_waitset_free (struct ddsi_sock_waitset *ws)
{
  ddsrt_mutex_destroy (&ws->lock);
  close (ws->pipe[0]);
  close (ws->pipe[1]);
  close (ws->pollfd);
  ddsrt_free (ws->entries);
  ddsrt_free (ws);
}

int ddsi_sock_waitset_add (struct ddsi_sock_waitset *ws, struct ddsi_tran_conn *conn)
{
  const int fd = ddsi_conn_handle (conn);
  if (fd < 0)
    return -1;
  int ret = 0;
  ddsrt_mutex_lock (&ws->lock);
  if (!conn->m_waitset_slot || conn->m_waitset_slot >= ws->nslots || ws->entries[conn->m_waitset_slot].conn != conn)
  {
    if (!ws->available)
    {
      /* Slot zero identifies the trigger and terminates the free lists. */
      const uint32_t first = ws->nslots ? ws->nslots : 1;
      if (first > INT_MAX / (2 * sizeof (*ws->entries)))
        goto fail;
      const uint32_t size = ws->nslots ? ws->nslots * 2 : WAITSET_DELTA;
      struct entry *entries = ddsrt_realloc_s (ws->entries, size * sizeof (*entries));
      if (entries == NULL)
        goto fail;
      for (uint32_t i = first; i < size; i++)
        entries[i] = (struct entry) { .next = (i + 1 == size) ? 0 : i + 1 };
      ws->entries = entries;
      ws->nslots = size;
      ws->available = first;
    }
    const uint32_t slot = ws->available;
    if (update_interest (ws->pollfd, fd, slot, true) == -1)
      goto fail;
    ws->available = ws->entries[slot].next;
    ws->entries[slot].conn = conn;
    ws->entries[slot].read_enabled = true;
    conn->m_waitset_slot = slot;
    ret = 1;
  }
  ddsrt_mutex_unlock (&ws->lock);
  return ret;
fail:
  ddsrt_mutex_unlock (&ws->lock);
  return -1;
}

bool ddsi_sock_waitset_set_read_enabled (struct ddsi_sock_waitset *ws, struct ddsi_tran_conn *conn, bool enabled)
{
  ddsrt_mutex_lock (&ws->lock);
  const uint32_t slot = conn->m_waitset_slot;
  bool ok = slot && slot < ws->nslots && ws->entries[slot].conn == conn;
  if (ok && ws->entries[slot].read_enabled != enabled)
  {
    ok = update_interest (ws->pollfd, ddsi_conn_handle (conn), slot, enabled) == 0;
    if (ok)
      ws->entries[slot].read_enabled = enabled;
  }
  ddsrt_mutex_unlock (&ws->lock);
  return ok;
}

void ddsi_sock_waitset_remove (struct ddsi_sock_waitset *ws, struct ddsi_tran_conn *conn)
{
  ddsrt_mutex_lock (&ws->lock);
  const uint32_t slot = conn->m_waitset_slot;
  if (slot && slot < ws->nslots && ws->entries[slot].conn == conn)
  {
    if (!ws->entries[slot].read_enabled || update_interest (ws->pollfd, ddsi_conn_handle (conn), slot, false) == 0 || errno == ENOENT || errno == EBADF)
    {
      /* Already returned events can still name this slot until the next wait. */
      ws->entries[slot].next = ws->retired_first;
      ws->retired_first = slot;
      if (!ws->retired_last)
        ws->retired_last = slot;
    }
    else
    {
      /* Keep the slot empty if the kernel may still report events for it. */
      DDS_WARNING ("ddsi_sock_waitset_remove: failed to unregister socket, errno = %d\n", errno);
    }
    ws->entries[slot].conn = NULL;
    conn->m_waitset_slot = 0;
  }
  ddsrt_mutex_unlock (&ws->lock);
}

struct ddsi_sock_waitset_ctx *ddsi_sock_waitset_wait_until (struct ddsi_sock_waitset *ws, ddsrt_mtime_t deadline)
{
  ddsrt_mutex_lock (&ws->lock);
  if (ws->retired_last)
  {
    ws->entries[ws->retired_last].next = ws->available;
    ws->available = ws->retired_first;
    ws->retired_first = ws->retired_last = 0;
  }
  ddsrt_mutex_unlock (&ws->lock);
  const dds_duration_t remaining = wait_duration (deadline);
  const int maxevents = (int) (sizeof (ws->ctx.evs) / sizeof (ws->ctx.evs[0]));
#if MODE_SEL == MODE_KQUEUE
  const struct timespec timeout = { .tv_sec = (time_t) (remaining / DDS_NSECS_IN_SEC), .tv_nsec = (long) (remaining % DDS_NSECS_IN_SEC) };
  const int n = kevent (ws->pollfd, NULL, 0, ws->ctx.evs, maxevents, remaining == DDS_INFINITY ? NULL : &timeout);
#else
  const int timeout = remaining == DDS_INFINITY ? -1 : remaining >= DDS_MSECS (INT_MAX) ? INT_MAX :
                      (int) ((remaining + DDS_NSECS_IN_MSEC - 1) / DDS_NSECS_IN_MSEC);
  const int n = epoll_wait (ws->pollfd, ws->ctx.evs, maxevents, timeout);
#endif
  if (n < 0)
  {
    if (errno != EINTR)
      DDS_WARNING ("ddsi_sock_waitset_wait: failed, errno = %d\n", errno);
    return NULL;
  }
  ws->ctx.n = n;
  ws->ctx.index = 0;
  return &ws->ctx;
}

int ddsi_sock_waitset_next_event (struct ddsi_sock_waitset_ctx *ctx, struct ddsi_tran_conn **conn)
{
  while (ctx->index < ctx->n)
  {
#if MODE_SEL == MODE_KQUEUE
    const uint32_t slot = (uint32_t) (uintptr_t) ctx->evs[ctx->index++].udata;
#else
    const uint32_t slot = ctx->evs[ctx->index++].data.u32;
#endif
    if (!slot)
      consume_trigger (ctx->ws);
    else
    {
      ddsrt_mutex_lock (&ctx->ws->lock);
      *conn = ctx->ws->entries[slot].read_enabled ? ctx->ws->entries[slot].conn : NULL;
      if (*conn)
        ddsi_conn_add_ref (*conn);
      ddsrt_mutex_unlock (&ctx->ws->lock);
      if (*conn)
        return (int) (slot - 1);
    }
  }
  return -1;
}

#elif MODE_SEL == MODE_SELECT

#ifdef __VXWORKS__
#include <pipeDrv.h>
#include <ioLib.h>
#include <string.h>
#include <selectLib.h>
#define OSPL_PIPENAMESIZE 26
#endif

#if !_WIN32 && !LWIP_SOCKET && !__ZEPHYR__

#if ! __VXWORKS__&& !__QNXNTO__
#include <sys/fcntl.h>
#endif /* __VXWORKS__ __QNXNTO__ */

#ifndef _WRS_KERNEL
#include <sys/select.h>
#endif
#ifdef __sun
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#endif

#endif /* !_WIN32 && !LWIP_SOCKET && !__ZEPHYR__ */

struct select_entry
{
  struct ddsi_tran_conn *conn;
  ddsrt_socket_t fd;
  bool disabled; /* paused registration or invalidated snapshot entry */
};

struct select_set
{
  struct select_entry *entries;
  unsigned sz;
  unsigned n;
};

struct ddsi_sock_waitset_ctx
{
  struct ddsi_sock_waitset *ws;
  struct select_set set;
  unsigned index;
  fd_set rdset;
};

struct ddsi_sock_waitset
{
  bool trigger_pending; /* protected by lock */
#if LWIP_SOCKET
  ddsrt_cond_mtime_t wake;
#else
  ddsrt_socket_t pipe[2];
#endif
  ddsrt_mutex_t lock;
  struct select_set set;
  struct ddsi_sock_waitset_ctx ctx;
};

#if defined (_WIN32)
static int make_pipe (ddsrt_socket_t fd[2])
{
  struct sockaddr_in addr = { 0 };
  socklen_t asize = sizeof (addr);
  ddsrt_socket_t listener = socket (AF_INET, SOCK_STREAM, 0);
  ddsrt_socket_t s1 = socket (AF_INET, SOCK_STREAM, 0);
  ddsrt_socket_t s2 = DDSRT_INVALID_SOCKET;

  if (listener == DDSRT_INVALID_SOCKET || s1 == DDSRT_INVALID_SOCKET)
    goto fail;
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  addr.sin_port = 0;
  if (bind (listener, (struct sockaddr *)&addr, sizeof (addr)) == -1)
    goto fail;
  // NOTE: Although the common practice is to call getsockname() immediately
  //       after bind(), some WIN32-like platforms like RTX64 require that
  //       listen() be called before getsockname() when using ephemeral port.
  if (listen (listener, 1) == -1)
    goto fail;
  if (getsockname (listener, (struct sockaddr *)&addr, &asize) == -1)
    goto fail;
  if (connect (s1, (struct sockaddr *)&addr, sizeof (addr)) == -1)
    goto fail;
  if ((s2 = accept (listener, 0, 0)) == INVALID_SOCKET)
    goto fail;
#ifndef WINCE
  if (!SetHandleInformation ((HANDLE) s1, HANDLE_FLAG_INHERIT, 0) ||
      !SetHandleInformation ((HANDLE) s2, HANDLE_FLAG_INHERIT, 0))
    goto fail;
#endif
  closesocket (listener);
  fd[0] = s1;
  fd[1] = s2;
  return 0;

fail:
  if (listener != DDSRT_INVALID_SOCKET)
    closesocket (listener);
  if (s1 != DDSRT_INVALID_SOCKET)
    closesocket (s1);
  if (s2 != DDSRT_INVALID_SOCKET)
    closesocket (s2);
  return -1;
}
#elif defined(__VXWORKS__)
#include <errnoLib.h>
static int make_pipe (int pfd[2])
{
  char pipename[OSPL_PIPENAMESIZE];
  int pipecount = 0, result;
  do {
    snprintf ((char*)&pipename, sizeof (pipename), "/pipe/ospl%d", pipecount++);
  } while ((result = pipeDevCreate ((char*)&pipename, 1, 1)) == -1 && errnoGet() == EINVAL);
  if (result == -1)
    goto fail_pipedev;
  if ((pfd[0] = open ((char*)&pipename, O_RDWR, 0644)) == -1)
    goto fail_open0;
  if ((pfd[1] = open ((char*)&pipename, O_RDWR, 0644)) == -1)
    goto fail_open1;
  return 0;

fail_open1:
  close (pfd[0]);
fail_open0:
  pipeDevDelete (pipename, 0);
fail_pipedev:
  return -1;
}
#elif defined(__ZEPHYR__)
static int make_pipe (int pfd[2])
{
  /* needs CONFIG_NET_SOCKETPAIR */
  int res;
  res = socketpair(AF_UNIX, SOCK_STREAM, 0, pfd);
  if (res < 0) {
    return -1;
  }
  return res;
}
#elif !LWIP_SOCKET
static int make_pipe (int pfd[2])
{
  return pipe (pfd);
}
#endif

#ifndef _WIN32
static bool selectable_fd (ddsrt_socket_t fd)
{
#if LWIP_SOCKET && defined(LWIP_SOCKET_OFFSET)
  return fd >= LWIP_SOCKET_OFFSET && fd - LWIP_SOCKET_OFFSET < FD_SETSIZE;
#else
  return fd >= 0 && fd < FD_SETSIZE;
#endif
}
#endif

#if !LWIP_SOCKET
static void close_pipe (ddsrt_socket_t pfd[2])
{
#if defined(__VXWORKS__) && defined(__RTP__)
  char name[OSPL_PIPENAMESIZE];
  ioctl (pfd[0], FIOGETNAME, &name);
#endif
#ifdef _WIN32
  closesocket (pfd[0]);
  closesocket (pfd[1]);
#else
  (void) close (pfd[0]);
  (void) close (pfd[1]);
#endif
#if defined(__VXWORKS__) && defined(__RTP__)
  pipeDevDelete (name, 0);
#endif
}
#endif

struct ddsi_sock_waitset *ddsi_sock_waitset_new (void)
{
  struct ddsi_sock_waitset *ws = ddsrt_calloc_s (1, sizeof (*ws));
  if (ws == NULL)
    return NULL;
#if LWIP_SOCKET
  ddsrt_cond_mtime_init (&ws->wake);
#else
  if (make_pipe (ws->pipe) < 0)
    goto fail;
#ifndef _WIN32
  if (!selectable_fd (ws->pipe[0]))
    goto fail_pipe;
#endif
#if !defined(__VXWORKS__) && !defined(_WIN32) && !defined(__QNXNTO__) && !defined(__ZEPHYR__)
  if (fcntl (ws->pipe[0], F_SETFD, FD_CLOEXEC) == -1 || fcntl (ws->pipe[1], F_SETFD, FD_CLOEXEC) == -1)
    goto fail_pipe;
#endif
#endif
  ws->ctx.ws = ws;
  ddsrt_mutex_init (&ws->lock);
  return ws;
#if !LWIP_SOCKET
#ifndef _WIN32
fail_pipe:
  close_pipe (ws->pipe);
#endif
fail:
  ddsrt_free (ws);
  return NULL;
#endif
}

void ddsi_sock_waitset_free (struct ddsi_sock_waitset *ws)
{
  assert (ws->ctx.index == ws->ctx.set.n);
#if LWIP_SOCKET
  ddsrt_cond_mtime_destroy (&ws->wake);
#else
  close_pipe (ws->pipe);
#endif
  ddsrt_free (ws->set.entries);
  ddsrt_free (ws->ctx.set.entries);
  ddsrt_mutex_destroy (&ws->lock);
  ddsrt_free (ws);
}

int ddsi_sock_waitset_add (struct ddsi_sock_waitset *ws, struct ddsi_tran_conn *conn)
{
  const ddsrt_socket_t fd = ddsi_conn_handle (conn);
#ifdef _WIN32
  if (fd == DDSRT_INVALID_SOCKET)
#else
  if (!selectable_fd (fd))
#endif
    return -1;
  ddsrt_mutex_lock (&ws->lock);
  for (unsigned i = 0; i < ws->set.n; i++)
  {
    if (ws->set.entries[i].conn == conn)
    {
      ddsrt_mutex_unlock (&ws->lock);
      return 0;
    }
  }
#ifdef _WIN32
  if (ws->set.n + 1 >= FD_SETSIZE) /* Winsock counts sockets, including the wake socket */
  {
    ddsrt_mutex_unlock (&ws->lock);
    return -1;
  }
#endif
  if (ws->set.n == ws->set.sz)
  {
    const unsigned sz = ws->set.sz ? 2 * ws->set.sz : WAITSET_DELTA;
    struct select_entry *entries = ddsrt_realloc_s (ws->set.entries, sz * sizeof (*entries));
    if (entries == NULL)
    {
      ddsrt_mutex_unlock (&ws->lock);
      return -1;
    }
    ws->set.entries = entries;
    entries = ddsrt_realloc_s (ws->ctx.set.entries, sz * sizeof (*entries));
    if (entries == NULL)
    {
      ddsrt_mutex_unlock (&ws->lock);
      return -1;
    }
    ws->ctx.set.entries = entries;
    ws->set.sz = sz;
  }
  ws->set.entries[ws->set.n++] = (struct select_entry) { .conn = conn, .fd = fd };
  ddsrt_mutex_unlock (&ws->lock);
  return 1;
}

bool ddsi_sock_waitset_set_read_enabled (struct ddsi_sock_waitset *ws, struct ddsi_tran_conn *conn, bool enabled)
{
  bool found = false;
  ddsrt_mutex_lock (&ws->lock);
  for (unsigned i = 0; i < ws->set.n; i++)
  {
    if (ws->set.entries[i].conn == conn)
    {
      ws->set.entries[i].disabled = !enabled;
      found = true;
      break;
    }
  }
  ddsrt_mutex_unlock (&ws->lock);
  return found;
}

void ddsi_sock_waitset_remove (struct ddsi_sock_waitset *ws, struct ddsi_tran_conn *conn)
{
  bool wake = false;
  ddsrt_mutex_lock (&ws->lock);
  for (unsigned i = 0; i < ws->set.n; i++)
  {
    if (ws->set.entries[i].conn == conn)
    {
      ws->set.entries[i] = ws->set.entries[--ws->set.n];
      for (unsigned j = ws->ctx.index; j < ws->ctx.set.n; j++)
      {
        if (ws->ctx.set.entries[j].conn == conn)
        {
          ws->ctx.set.entries[j].disabled = true;
          wake = true;
          break;
        }
      }
      break;
    }
  }
  ddsrt_mutex_unlock (&ws->lock);
  if (wake)
    ddsi_sock_waitset_trigger (ws);
}

#if LWIP_SOCKET
DDSRT_WARNING_GNUC_OFF(sign-conversion)
#endif
struct ddsi_sock_waitset_ctx *ddsi_sock_waitset_wait_until (struct ddsi_sock_waitset *ws, ddsrt_mtime_t deadline)
{
  struct ddsi_sock_waitset_ctx *ctx = &ws->ctx;
  int fdmax = 0;
  ddsrt_mutex_lock (&ws->lock);
  assert (ctx->index == ctx->set.n);
  FD_ZERO (&ctx->rdset);
#if !LWIP_SOCKET
  FD_SET (ws->pipe[0], &ctx->rdset);
#ifndef _WIN32
  fdmax = ws->pipe[0] + 1;
#endif
#endif
  ctx->index = 0;
  ctx->set.n = 0;
  for (unsigned i = 0; i < ws->set.n; i++)
  {
    if (ws->set.entries[i].disabled)
      continue;
    ctx->set.entries[ctx->set.n++] = ws->set.entries[i];
    ddsi_conn_add_ref (ws->set.entries[i].conn);
    const ddsrt_socket_t fd = ws->set.entries[i].fd;
    FD_SET (fd, &ctx->rdset);
#ifndef _WIN32
    if (fd >= fdmax)
      fdmax = fd + 1;
#endif
  }
#if LWIP_SOCKET
  /* Without a selectable descriptor, only the wake signal or a deadline
     (including the next retry of a suspended TLS read) needs to wake us. */
  if (ctx->set.n == 0)
  {
    while (!ws->trigger_pending)
      if (!ddsrt_cond_mtime_waituntil (&ws->wake, &ws->lock, deadline))
        break;
    ws->trigger_pending = false;
    ddsrt_mutex_unlock (&ws->lock);
    return ctx;
  }
  if (ws->trigger_pending)
  {
    deadline.v = 0;
    ws->trigger_pending = false;
  }
#endif
  ddsrt_mutex_unlock (&ws->lock);
  dds_return_t rc;
#if LWIP_SOCKET
  /* There is no selectable wake pipe. Keep the snapshot pinned across short
     polls, checking the explicit wake and the caller's deadline between them. */
  fd_set fds = ctx->rdset;
  for (;;)
  {
    const dds_duration_t timeout = wait_duration (deadline);
    ctx->rdset = fds;
    rc = ddsrt_select (fdmax, &ctx->rdset, NULL, NULL, timeout < DDS_MSECS (25) ? timeout : DDS_MSECS (25));
    if (rc != DDS_RETCODE_TIMEOUT || timeout <= DDS_MSECS (25))
      break;
    ddsrt_mutex_lock (&ws->lock);
    const bool wake = ws->trigger_pending;
    ws->trigger_pending = false;
    ddsrt_mutex_unlock (&ws->lock);
    if (wake)
      break;
  }
#else
  rc = ddsrt_select (fdmax, &ctx->rdset, NULL, NULL, wait_duration (deadline));
#endif
  if (rc <= 0)
  {
    if (rc != DDS_RETCODE_TIMEOUT && rc != DDS_RETCODE_INTERRUPTED && rc != DDS_RETCODE_TRY_AGAIN)
      DDS_WARNING ("ddsi_sock_waitset_wait: select failed, retcode = %"PRId32"\n", rc);
    FD_ZERO (&ctx->rdset);
  }
#if !LWIP_SOCKET
  else if (FD_ISSET (ws->pipe[0], &ctx->rdset))
    consume_trigger (ws);
#endif
  return ctx;
}

int ddsi_sock_waitset_next_event (struct ddsi_sock_waitset_ctx *ctx, struct ddsi_tran_conn **conn)
{
  for (;;)
  {
    ddsrt_mutex_lock (&ctx->ws->lock);
    if (ctx->index == ctx->set.n)
    {
      ddsrt_mutex_unlock (&ctx->ws->lock);
      return -1;
    }
    const unsigned idx = ctx->index++;
    const struct select_entry entry = ctx->set.entries[idx];
    ddsrt_mutex_unlock (&ctx->ws->lock);
    if (!entry.disabled && FD_ISSET (entry.fd, &ctx->rdset))
    {
      *conn = entry.conn;
      return (int) idx;
    }
    ddsi_conn_unref (entry.conn);
  }
}
#if LWIP_SOCKET
DDSRT_WARNING_GNUC_ON(sign-conversion)
#endif

#else
#error "no mode selected"
#endif

#if MODE_SEL == MODE_KQUEUE || MODE_SEL == MODE_EPOLL || (MODE_SEL == MODE_SELECT && !LWIP_SOCKET)
/* Only one wake byte may be outstanding. Holding the same lock across each
   one-byte transfer and the state change also lets a trigger racing the read
   write a fresh byte as soon as the previous wake has been consumed. */
void ddsi_sock_waitset_trigger (struct ddsi_sock_waitset *ws)
{
  ddsrt_mutex_lock (&ws->lock);
  if (!ws->trigger_pending)
  {
    const char byte = 0;
    int n;
#ifdef _WIN32
    do { n = send (ws->pipe[1], &byte, 1, 0); } while (n < 0 && WSAGetLastError () == WSAEINTR);
#else
    do { n = (int) write (ws->pipe[1], &byte, 1); } while (n < 0 && errno == EINTR);
#endif
    if (n == 1)
      ws->trigger_pending = true;
    else
      DDS_WARNING ("ddsi_sock_waitset_trigger: write failed on trigger pipe\n");
  }
  ddsrt_mutex_unlock (&ws->lock);
}

static void consume_trigger (struct ddsi_sock_waitset *ws)
{
  char byte;
  int n;
  ddsrt_mutex_lock (&ws->lock);
  assert (ws->trigger_pending);
#ifdef _WIN32
  do { n = recv (ws->pipe[0], &byte, 1, 0); } while (n < 0 && WSAGetLastError () == WSAEINTR);
#else
  do { n = (int) read (ws->pipe[0], &byte, 1); } while (n < 0 && errno == EINTR);
#endif
  if (n != 1)
    DDS_WARNING ("ddsi_sock_waitset_wait: read failed on trigger pipe\n");
  ws->trigger_pending = false;
  ddsrt_mutex_unlock (&ws->lock);
}
#elif MODE_SEL == MODE_SELECT
void ddsi_sock_waitset_trigger (struct ddsi_sock_waitset *ws)
{
  ddsrt_mutex_lock (&ws->lock);
  ws->trigger_pending = true;
  ddsrt_cond_mtime_signal (&ws->wake);
  ddsrt_mutex_unlock (&ws->lock);
}
#endif

struct ddsi_sock_waitset_ctx *ddsi_sock_waitset_wait (struct ddsi_sock_waitset *ws)
{
  return ddsi_sock_waitset_wait_until (ws, DDSRT_MTIME_NEVER);
}
