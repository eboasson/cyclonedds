// Copyright(c) 2026 ZettaScale Technology and others
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License v. 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
// v. 1.0 which is available at
// http://www.eclipse.org/org/documents/edl-v10.php.
//
// SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

#include "dds/features.h"
#include "dds/ddsrt/heap.h"
#include "dds/ddsrt/sync.h"
#include "dds/ddsrt/time.h"
#include "dds/ddsi/ddsi_domaingv.h"
#include "ddsi__ssl.h"
#include "ddsi__tcp_connect.h"
#include "ddsi__thread.h"

#if (defined __APPLE__ || defined __linux) && !DDSRT_WITH_LWIP
#include <errno.h>
#include <poll.h>
#define DDSI_CONNECT_POLL 1
#else
#define DDSI_CONNECT_POLL 0
#endif

/* Keep capacity for both directions even if an entire batch of handshakes
   waits for its timeout. Winsock must fit both batches in one fd_set. */
#if defined (_WIN32) && FD_SETSIZE < 128
#define MAX_PER_DIRECTION (FD_SETSIZE / 2)
#else
#define MAX_PER_DIRECTION 64
#endif
#define MAX_ACTIVE (2 * MAX_PER_DIRECTION)
DDSRT_STATIC_ASSERT (MAX_PER_DIRECTION > 0);

enum connect_direction { OUTGOING, INCOMING };

struct connect_request {
  struct ddsi_tcp_conn *conn;
  struct connect_request *next;
  ddsrt_mtime_t deadline;
  ddsrt_socket_t sock;
  struct ssl_st *ssl;
  enum connect_direction direction;
  bool ready;
  bool want_read;
};

struct connect_queue {
  struct connect_request *head;
  struct connect_request **tail;
  size_t count;
};

struct ddsi_tcp_connector {
  struct ddsi_domaingv *gv;
  struct ddsi_ssl_ctx *tls;
  struct ddsi_thread_state *thread;
  ddsrt_mutex_t lock;
  ddsrt_cond_t cond;
  bool stopping;
  struct connect_queue queue[2];
};

static dds_return_t advance_connect (const struct ddsi_tcp_connector *connector, struct connect_request *req)
{
  if (req->sock == DDSRT_INVALID_SOCKET)
  {
    dds_return_t rc = ddsi_tcp_connect_begin (req->conn, &req->sock);
    /* A retryable socket creation error leaves nothing to wait on. */
    if (req->sock == DDSRT_INVALID_SOCKET)
      return (rc == DDS_RETCODE_OK || rc == DDS_RETCODE_TRY_AGAIN) ? DDS_RETCODE_ERROR : rc;
    if (rc == DDS_RETCODE_IN_PROGRESS || rc == DDS_RETCODE_TRY_AGAIN || rc == DDS_RETCODE_INTERRUPTED)
      return DDS_RETCODE_TRY_AGAIN; /* wait for writability, then read SO_ERROR */
    if (rc != DDS_RETCODE_OK)
      return rc;
  }
  else if (req->direction == OUTGOING && !req->ssl)
  {
    int error;
    socklen_t len = sizeof (error);
    dds_return_t rc = ddsrt_getsockopt (req->sock, SOL_SOCKET, SO_ERROR, &error, &len);
    if (rc != DDS_RETCODE_OK)
      return rc;
    if (error)
      return DDS_RETCODE_NO_CONNECTION;
  }
#ifdef DDS_HAS_TCP_TLS
  if (connector->tls)
  {
    if (!req->ssl && (req->ssl = ddsi_ssl_new (connector->gv, connector->tls, req->sock, req->direction == INCOMING)) == NULL)
      return DDS_RETCODE_ERROR;
    return ddsi_ssl_handshake (connector->gv, req->ssl, &req->want_read);
  }
#else
  (void) connector;
#endif
  return DDS_RETCODE_OK;
}

static void complete_connect (struct connect_request *req, dds_return_t rc)
{
#ifdef DDS_HAS_TCP_TLS
  if (req->direction == INCOMING)
    ddsi_tcp_accept_done (req->conn, rc, req->sock, req->ssl);
  else
#endif
    ddsi_tcp_connect_done (req->conn, rc, req->sock, req->ssl);
  ddsrt_free (req);
}

/* Wait for the next connect/handshake step on any active peer. An active
   worker checks for submissions and shutdown at least every 25 ms. An idle
   worker sleeps on the condition variable until signalled. */
static dds_return_t wait_for_ready (struct connect_request * const *active, size_t n, dds_duration_t timeout)
{
#if DDSI_CONNECT_POLL
  struct pollfd fds[MAX_ACTIVE];
  for (size_t i = 0; i < n; i++)
    fds[i] = (struct pollfd) { .fd = active[i]->sock, .events = active[i]->want_read ? POLLIN : POLLOUT };
  const int ms = (int) ((timeout + DDS_NSECS_IN_MSEC - 1) / DDS_NSECS_IN_MSEC);
  const int ret = poll (fds, (nfds_t) n, ms);
  if (ret < 0)
    return errno == EINTR ? DDS_RETCODE_OK : DDS_RETCODE_ERROR;
  for (size_t i = 0; i < n; i++)
    active[i]->ready = fds[i].revents != 0;
#else
  fd_set rfds, wfds, efds;
  FD_ZERO (&rfds);
  FD_ZERO (&wfds);
  FD_ZERO (&efds);
  int nfds = 0; /* ignored by Winsock */
#if LWIP_SOCKET == 1
  DDSRT_WARNING_GNUC_OFF(sign-conversion)
#endif
  for (size_t i = 0; i < n; i++)
  {
    const ddsrt_socket_t sock = active[i]->sock;
#ifndef _WIN32
    /* The TCP transport checks the select fd limit when opening a socket. */
    assert (sock >= 0 && sock < FD_SETSIZE);
    if (nfds <= sock)
      nfds = sock + 1;
#endif
    if (active[i]->want_read)
      FD_SET (sock, &rfds);
    else
    {
      FD_SET (sock, &wfds);
      /* Winsock signals unsuccessful connects via the exception set. */
      FD_SET (sock, &efds);
    }
  }
  dds_return_t rc = ddsrt_select (nfds, &rfds, &wfds, &efds, timeout);
  if (rc == DDS_RETCODE_TIMEOUT || rc == DDS_RETCODE_INTERRUPTED)
    return DDS_RETCODE_OK;
  if (rc < 0)
    return rc;
  for (size_t i = 0; i < n; i++)
  {
    const ddsrt_socket_t sock = active[i]->sock;
    active[i]->ready = FD_ISSET (sock, &rfds) || FD_ISSET (sock, &wfds) || FD_ISSET (sock, &efds);
  }
#if LWIP_SOCKET == 1
  DDSRT_WARNING_GNUC_ON(sign-conversion)
#endif
#endif
  return DDS_RETCODE_OK;
}

static uint32_t tcp_connect_thread (void *arg)
{
  struct ddsi_tcp_connector *connector = arg;
  struct ddsi_thread_state *thrst = ddsi_lookup_thread_state ();
  struct connect_request *active[MAX_ACTIVE];
  size_t nactive[2] = { 0, 0 };
  size_t n = 0;
  for (;;)
  {
    ddsrt_mutex_lock (&connector->lock);
    while (!n && !connector->queue[OUTGOING].head && !connector->queue[INCOMING].head && !connector->stopping)
      ddsrt_cond_wait (&connector->cond, &connector->lock);
    const bool stop = connector->stopping;
    const ddsrt_mtime_t now = ddsrt_time_monotonic ();
    for (size_t dir = 0; dir < 2; dir++)
    {
      struct connect_queue *q = &connector->queue[dir];
      while (q->head && nactive[dir] < MAX_PER_DIRECTION)
      {
        struct connect_request *req = q->head;
        q->head = req->next;
        q->count--;
        nactive[dir]++;
        active[n++] = req;
      }
      if (!q->head)
        q->tail = &q->head;
    }
    ddsrt_mutex_unlock (&connector->lock);
    if (!n && stop)
      break;

    const size_t started = n;
    ddsrt_mtime_t earliest = ddsrt_mtime_add_duration (now, DDS_MSECS (25));
    ddsi_thread_state_awake_fixed_domain (thrst);
    for (size_t i = 0; i < n; )
    {
      struct connect_request *req = active[i];
      dds_return_t rc;
      if (stop)
        rc = DDS_RETCODE_ALREADY_DELETED;
      else if (req->deadline.v <= ddsrt_time_monotonic ().v)
        rc = DDS_RETCODE_TIMEOUT;
      else if (req->ready)
        rc = advance_connect (connector, req);
      else
        rc = DDS_RETCODE_TRY_AGAIN;
      if (rc != DDS_RETCODE_TRY_AGAIN)
      {
        nactive[req->direction]--;
        complete_connect (req, rc);
        active[i] = active[--n];
      }
      else
      {
        req->ready = false;
        if (req->deadline.v < earliest.v)
          earliest = req->deadline;
        i++;
      }
    }
    ddsi_thread_state_asleep (thrst);
    if (n)
    {
      /* When a slot opens, admit queued peers on the next iteration. Still
         check readiness so a stream of failed dials can't starve handshakes. */
      const dds_duration_t remaining = earliest.v - ddsrt_time_monotonic ().v;
      const dds_duration_t timeout = (n < started || remaining < 0) ? 0 : remaining;
      const dds_return_t rc = wait_for_ready (active, n, timeout);
      if (rc != DDS_RETCODE_OK)
      {
        ddsi_thread_state_awake_fixed_domain (thrst);
        while (n)
          complete_connect (active[--n], rc);
        nactive[OUTGOING] = nactive[INCOMING] = 0;
        ddsi_thread_state_asleep (thrst);
      }
    }
  }
  return 0;
}

struct ddsi_tcp_connector *ddsi_tcp_connector_new (struct ddsi_domaingv *gv, struct ddsi_ssl_ctx *tls)
{
  struct ddsi_tcp_connector *connector = ddsrt_calloc_s (1, sizeof (*connector));
  if (connector == NULL)
    return NULL;
  connector->gv = gv;
  connector->tls = tls;
  for (size_t dir = 0; dir < 2; dir++)
    connector->queue[dir].tail = &connector->queue[dir].head;
  ddsrt_mutex_init (&connector->lock);
  ddsrt_cond_init (&connector->cond);
  if (ddsi_create_thread (&connector->thread, gv, "tcp.connect", tcp_connect_thread, connector) != DDS_RETCODE_OK)
  {
    ddsi_tcp_connector_free (connector);
    return NULL;
  }
  return connector;
}

static bool submit (struct ddsi_tcp_connector *connector, struct ddsi_tcp_conn *conn, ddsrt_socket_t sock, enum connect_direction dir)
{
  struct connect_request *req = ddsrt_calloc_s (1, sizeof (*req));
  if (req == NULL)
    return false;
  req->conn = conn;
  req->sock = sock;
  req->direction = dir;
  /* FIXME: This deadline includes waiting for a MAX_PER_DIRECTION slot.
     If outgoing attempts occupy all slots until timeout, later queued
     destinations can expire without ever opening a socket. SPDP retries
     in locator order, so the same reachable peers can repeatedly lose
     their chance to connect. Increasing the limit only moves the
     saturation threshold; it does not guarantee progress. */
  req->deadline = ddsrt_mtime_add_duration (ddsrt_time_monotonic (), connector->gv->config.tcp_connect_timeout);
  req->ready = true;
  ddsrt_mutex_lock (&connector->lock);
  struct connect_queue *q = &connector->queue[dir];
  /* Incoming requests already own sockets. Outgoing requests need only a
     cache entry while waiting. Discovery will retry destinations refused here. */
  const size_t limit = dir == INCOMING ? MAX_PER_DIRECTION : 4 * MAX_PER_DIRECTION;
  if (connector->stopping || q->count == limit)
  {
    ddsrt_mutex_unlock (&connector->lock);
    ddsrt_free (req);
    return false;
  }
  *q->tail = req;
  q->tail = &req->next;
  q->count++;
  ddsrt_cond_signal (&connector->cond);
  ddsrt_mutex_unlock (&connector->lock);
  return true;
}

bool ddsi_tcp_connector_submit (struct ddsi_tcp_connector *connector, struct ddsi_tcp_conn *conn)
{
  return submit (connector, conn, DDSRT_INVALID_SOCKET, OUTGOING);
}

#ifdef DDS_HAS_TCP_TLS
bool ddsi_tcp_connector_accept (struct ddsi_tcp_connector *connector, struct ddsi_tcp_conn *conn, ddsrt_socket_t sock)
{
  return submit (connector, conn, sock, INCOMING);
}
#endif

void ddsi_tcp_connector_stop (struct ddsi_tcp_connector *connector)
{
  if (connector && connector->thread)
  {
    ddsrt_mutex_lock (&connector->lock);
    connector->stopping = true;
    ddsrt_cond_signal (&connector->cond);
    ddsrt_mutex_unlock (&connector->lock);
    (void) ddsi_join_thread (connector->thread);
    connector->thread = NULL;
  }
}

void ddsi_tcp_connector_free (struct ddsi_tcp_connector *connector)
{
  if (connector)
  {
    ddsi_tcp_connector_stop (connector);
    ddsrt_cond_destroy (&connector->cond);
    ddsrt_mutex_destroy (&connector->lock);
    ddsrt_free (connector);
  }
}
