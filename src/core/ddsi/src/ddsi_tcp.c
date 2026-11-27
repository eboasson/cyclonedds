// Copyright(c) 2006 to 2022 ZettaScale Technology and others
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License v. 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
// v. 1.0 which is available at
// http://www.eclipse.org/org/documents/edl-v10.php.
//
// SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

#include <stddef.h>
#include <assert.h>
#include <string.h>

#include "dds/features.h"
#include "dds/ddsrt/heap.h"
#include "dds/ddsrt/log.h"
#include "dds/ddsrt/sockets.h"
#include "dds/ddsrt/time.h"
#include "dds/ddsrt/avl.h"
#include "dds/ddsrt/circlist.h"
#include "dds/ddsi/ddsi_log.h"
#include "dds/ddsi/ddsi_iid.h"
#include "ddsi__radmin.h"
#include "dds/ddsi/ddsi_endpoint.h"
#include "dds/ddsi/ddsi_domaingv.h"
#include "ddsi__eth.h"
#include "ddsi__tran.h"
#include "ddsi__tcp.h"
#include "ddsi__ipaddr.h"
#include "ddsi__entity.h"
#include "ddsi__ssl.h"
#include "ddsi__proxy_participant.h"
#include "ddsi__sockwaitset.h"

#if (defined __APPLE__ || defined __linux) && !DDSRT_WITH_LWIP
#define DDSI_TCP_USE_POLL 1
#include <poll.h>
#include <errno.h>
#else
#define DDSI_TCP_USE_POLL 0
#endif

#define INVALID_PORT (~0u)

/* Cache entries and writers each own a reference. Once a socket is published,
   the receive thread owns another reference until it unregisters the socket.
   Only that thread closes the connection, or the factory after threads stop. */

union addr {
  struct sockaddr a;
  struct sockaddr_in a4;
#if DDSRT_HAVE_IPV6
  struct sockaddr_in6 a6;
#endif
};

typedef struct ddsi_tcp_conn {
  struct ddsi_tran_conn m_base;
  union addr m_peer_addr;
  uint32_t m_peer_port;
  struct ddsrt_circlist_elem m_recv_link;
  bool m_retired; /* protected by m_mutex */
  ddsrt_mutex_t m_mutex;
  ddsrt_socket_t m_sock;
#ifdef DDS_HAS_TCP_TLS
  SSL *m_ssl;
  ddsrt_mutex_t m_ssl_mutex;
  bool m_ssl_failed;
#endif
} *ddsi_tcp_conn_t;

typedef struct ddsi_tcp_listener {
  struct ddsi_tran_listener m_base;
  ddsrt_socket_t m_sock;
} *ddsi_tcp_listener_t;

struct ddsi_tran_factory_tcp {
  struct ddsi_tran_factory fact;
  int32_t m_kind;
  ddsrt_mutex_t ddsi_tcp_cache_lock_g;
  ddsrt_avl_tree_t ddsi_tcp_cache_g;
  struct ddsrt_circlist recv_conns; /* protected by the cache lock */
  struct ddsi_tcp_conn ddsi_tcp_conn_client;
#ifdef DDS_HAS_TCP_TLS
  struct ddsi_ssl_ctx *ssl_ctx;
#endif
};

static int ddsi_tcp_cmp_conn (const struct ddsi_tcp_conn *c1, const struct ddsi_tcp_conn *c2)
{
  const struct sockaddr *a1s = &c1->m_peer_addr.a;
  const struct sockaddr *a2s = &c2->m_peer_addr.a;
  if (a1s->sa_family != a2s->sa_family)
   return (a1s->sa_family < a2s->sa_family) ? -1 : 1;
  else if (c1->m_peer_port != c2->m_peer_port)
    return (c1->m_peer_port < c2->m_peer_port) ? -1 : 1;
  return ddsi_ipaddr_compare (a1s, a2s);
}

static int ddsi_tcp_cmp_conn_wrap (const void *a, const void *b)
{
  return ddsi_tcp_cmp_conn (a, b);
}

typedef struct ddsi_tcp_node {
  ddsrt_avl_node_t m_avlnode;
  ddsi_tcp_conn_t m_conn;
} * ddsi_tcp_node_t;

static const ddsrt_avl_treedef_t ddsi_tcp_treedef = DDSRT_AVL_TREEDEF_INITIALIZER_INDKEY
(
  offsetof (struct ddsi_tcp_node, m_avlnode),
  offsetof (struct ddsi_tcp_node, m_conn),
  ddsi_tcp_cmp_conn_wrap,
  0
);

static dds_return_t ddsi_tcp_wait_once (ddsrt_socket_t sock, bool want_read, dds_duration_t timeout)
{
#if DDSI_TCP_USE_POLL
  struct pollfd pfd = { .fd = sock, .events = want_read ? POLLIN : POLLOUT };
  const int ms = (int) ((timeout + DDS_NSECS_IN_MSEC - 1) / DDS_NSECS_IN_MSEC);
  const int n = poll (&pfd, 1, ms);
  if (n == 0)
    return DDS_RETCODE_TIMEOUT;
  if (n < 0)
    return errno == EINTR ? DDS_RETCODE_INTERRUPTED : DDS_RETCODE_ERROR;
  return (pfd.revents & POLLNVAL) ? DDS_RETCODE_BAD_PARAMETER : DDS_RETCODE_OK;
#else
#ifdef _WIN32
  const int nfds = 0; /* ignored by Winsock */
#else
  if (sock < 0 || sock >= FD_SETSIZE)
    return DDS_RETCODE_OUT_OF_RESOURCES;
  const int nfds = sock + 1;
#endif
  fd_set fds;
  FD_ZERO (&fds);
#if LWIP_SOCKET == 1
  DDSRT_WARNING_GNUC_OFF(sign-conversion)
#endif
  FD_SET (sock, &fds);
#if LWIP_SOCKET == 1
  DDSRT_WARNING_GNUC_ON(sign-conversion)
#endif
#ifdef _WIN32
  /* Winsock reports an unsuccessful nonblocking connect as an exception. */
  fd_set exceptions = fds;
  fd_set *exceptfds = want_read ? NULL : &exceptions;
#else
  fd_set *exceptfds = NULL;
#endif
  const dds_return_t rc = ddsrt_select (nfds, want_read ? &fds : NULL, want_read ? NULL : &fds, exceptfds, timeout);
  return rc > 0 ? DDS_RETCODE_OK : rc;
#endif
}

/* Wait for socket I/O without delaying domain shutdown past the polling interval. */
static dds_return_t ddsi_tcp_wait (const struct ddsi_domaingv *gv, ddsrt_socket_t sock, bool want_read, ddsrt_mtime_t deadline)
{
  while (ddsrt_atomic_ld32 (&gv->rtps_keepgoing))
  {
    const dds_duration_t remaining = deadline.v - ddsrt_time_monotonic ().v;
    if (remaining <= 0)
      return DDS_RETCODE_TIMEOUT;
    const dds_duration_t slice = DDS_MSECS (100);
    const dds_return_t rc = ddsi_tcp_wait_once (sock, want_read, remaining < slice ? remaining : slice);
    if (rc != DDS_RETCODE_INTERRUPTED && rc != DDS_RETCODE_TIMEOUT)
      return rc;
  }
  return DDS_RETCODE_ALREADY_DELETED;
}

static ddsi_tcp_conn_t ddsi_tcp_new_conn (struct ddsi_tran_factory_tcp *fact, const struct ddsi_network_interface *interf, ddsrt_socket_t, bool, struct sockaddr *);

static char *sockaddr_to_string_with_port (char *dst, size_t sizeof_dst, const struct sockaddr *src)
{
  ddsi_locator_t loc;
  ddsi_ipaddr_to_loc(&loc, src, src->sa_family == AF_INET ? DDSI_LOCATOR_KIND_TCPv4 : DDSI_LOCATOR_KIND_TCPv6);
  ddsi_locator_to_string(dst, sizeof_dst, &loc);
  return dst;
}

/* Connection cache dump routine for debugging

static void ddsi_tcp_cache_dump (void)
{
  char buff[64];
  ddsrt_avl_iter_t iter;
  ddsi_tcp_node_t n;
  unsigned i = 0;

  n = ddsrt_avl_iter_first (&ddsi_tcp_treedef, &ddsi_tcp_cache_g, &iter);
  while (n)
  {
    os_sockaddrAddressPortToString ((const os_sockaddr *) &n->m_conn->m_peer_addr, buff, sizeof (buff));
    DDS_TRACE
    (
      DDS_LC_TCP,
      "%s cache #%d: %s sock %d port %u peer %s\n",
      ddsi_name, i++, n->m_conn->m_base.m_server ? "server" : "client",
      n->m_conn->m_sock, n->m_conn->m_base.m_base.m_port, buff
    );
    n = ddsrt_avl_iter_next (&iter);
  }
}
*/

static uint16_t get_socket_port (struct ddsi_domaingv const * const gv, ddsrt_socket_t socket)
{
  union addr addr;
  socklen_t addrlen = sizeof (addr);
  dds_return_t ret;

  ret = ddsrt_getsockname(socket, &addr.a, &addrlen);
  if (ret != DDS_RETCODE_OK) {
    GVERROR ("ddsi_tcp_get_socket_port: ddsrt_getsockname retcode %"PRId32"\n", ret);
    return 0;
  }
  return ddsrt_sockaddr_get_port (&addr.a);
}

static void ddsi_tcp_conn_set_socket (ddsi_tcp_conn_t conn, ddsrt_socket_t sock)
{
  struct ddsi_domaingv const * const gv = conn->m_base.m_base.gv;
  conn->m_sock = sock;
  conn->m_base.m_base.m_port = (sock == DDSRT_INVALID_SOCKET) ? INVALID_PORT : get_socket_port (gv, sock);
}

static void ddsi_tcp_sock_free (struct ddsi_domaingv const * const gv, ddsrt_socket_t sock, const char *msg)
{
  if (sock != DDSRT_INVALID_SOCKET)
  {
    if (msg)
      GVLOG (DDS_LC_TCP, "tcp %s free socket %"PRIdSOCK"\n", msg, sock);
    ddsrt_close (sock);
  }
}

/* All TCP waits, including connection setup, use ddsi_tcp_wait. */
static dds_return_t ddsi_tcp_prepare_socket (ddsrt_socket_t sock)
{
#if !defined (_WIN32) && !DDSI_TCP_USE_POLL
  if (sock >= FD_SETSIZE)
    return DDS_RETCODE_OUT_OF_RESOURCES;
#endif
#ifdef SO_NOSIGPIPE
  const int one = 1;
  const dds_return_t rc = ddsrt_setsockopt (sock, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof (one));
  if (rc != DDS_RETCODE_OK)
    return rc;
#endif
  return ddsrt_setsocknonblocking (sock, true);
}

static dds_return_t ddsi_tcp_sock_new (struct ddsi_tran_factory_tcp * const fact, ddsrt_socket_t *sock, uint16_t port)
{
  struct ddsi_domaingv const * const gv = fact->fact.gv;
  union addr socketname;
  dds_return_t rc;
#ifdef TCP_NODELAY
  const int one = 1;
#endif

  memset (&socketname, 0, sizeof (socketname));
  switch (fact->m_kind)
  {
    case DDSI_LOCATOR_KIND_TCPv4:
      socketname.a4.sin_family = AF_INET;
      socketname.a4.sin_addr.s_addr = htonl (INADDR_ANY);
      socketname.a4.sin_port = htons (port);
      break;
#if DDSRT_HAVE_IPV6
    case DDSI_LOCATOR_KIND_TCPv6:
      socketname.a6.sin6_family = AF_INET6;
      socketname.a6.sin6_addr = ddsrt_in6addr_any;
      socketname.a6.sin6_port = htons (port);
      break;
#endif
    default:
      DDS_FATAL ("ddsi_tcp_sock_new: unsupported kind %"PRId32"\n", fact->m_kind);
  }
  if ((rc = ddsrt_socket (sock, socketname.a.sa_family, SOCK_STREAM, 0)) != DDS_RETCODE_OK)
  {
    GVERROR ("ddsi_tcp_sock_new: failed to create socket: %s\n", dds_strretcode (rc));
    goto fail;
  }

  /* If we're binding to a port number, allow others to bind to the same port */
  if (port && (rc = ddsrt_setsockreuse (*sock, true)) != DDS_RETCODE_OK) {
    if (rc != DDS_RETCODE_UNSUPPORTED) {
      GVERROR ("ddsi_tcp_sock_new: failed to enable port reuse: %s\n", dds_strretcode(rc));
      goto fail_w_socket;
    } else {
      // If the network stack doesn't support it, do make it fairly easy to find out,
      // but don't always print it to stderr because it would likely be more annoying
      // than helpful.
      GVLOG (DDS_LC_CONFIG, "ddsi_tcp_sock_new: port reuse not supported by network stack\n");
    }
  }

  if ((rc = ddsrt_bind (*sock, &socketname.a, ddsrt_sockaddr_get_size (&socketname.a))) != DDS_RETCODE_OK)
  {
    GVERROR ("ddsi_tcp_sock_new: failed to bind to ANY:%"PRIu16": %s\n", port,
             (rc == DDS_RETCODE_PRECONDITION_NOT_MET) ? "address in use" : dds_strretcode (rc));
    goto fail_w_socket;
  }

  if ((rc = ddsi_tcp_prepare_socket (*sock)) != DDS_RETCODE_OK)
    goto fail_w_socket;
#ifdef TCP_NODELAY
  if (gv->config.tcp_nodelay && (rc = ddsrt_setsockopt (*sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof (one))) != DDS_RETCODE_OK)
  {
    GVERROR ("ddsi_tcp_sock_new: failed to set NODELAY: %s\n", dds_strretcode (rc));
    goto fail_w_socket;
  }
#endif
  return DDS_RETCODE_OK;

fail_w_socket:
  ddsrt_close (*sock);
fail:
  *sock = DDSRT_INVALID_SOCKET;
  return rc;
}

static void ddsi_tcp_node_free (void *vnode)
{
  ddsi_tcp_node_t node = vnode;
  ddsi_conn_unref (&node->m_conn->m_base);
  ddsrt_free (node);
}

#ifdef DDS_HAS_TCP_TLS
static dds_return_t ddsi_tcp_handshake (const struct ddsi_tran_factory_tcp *fact, ddsrt_socket_t sock, bool server, ddsrt_mtime_t deadline, SSL **result)
{
  const struct ddsi_domaingv *gv = fact->fact.gv;
  SSL *ssl = ddsi_ssl_new (gv, fact->ssl_ctx, sock, server);
  if (ssl == NULL)
    return DDS_RETCODE_ERROR;

  bool want_read;
  dds_return_t ret;
  while ((ret = ddsi_ssl_handshake (gv, ssl, &want_read)) == DDS_RETCODE_TRY_AGAIN)
    if ((ret = ddsi_tcp_wait (gv, sock, want_read, deadline)) != DDS_RETCODE_OK)
      break;
  if (ret == DDS_RETCODE_OK)
    *result = ssl;
  else
    SSL_free (ssl);
  return ret;
}
#endif

ddsrt_attribute_warn_unused_result
static dds_return_t ddsi_tcp_conn_connect (ddsi_tcp_conn_t conn, const struct sockaddr *msg_name, size_t msg_namelen)
{
  struct ddsi_tran_factory_tcp * const fact = (struct ddsi_tran_factory_tcp *) conn->m_base.m_factory;
  struct ddsi_domaingv const * const gv = fact->fact.gv;
  char buff[DDSI_LOCSTRLEN];
  ddsrt_socket_t sock;
  dds_return_t ret;

  if ((ret = ddsi_tcp_sock_new (fact, &sock, 0)) != DDS_RETCODE_OK)
    return ret;

  const ddsrt_mtime_t deadline = DDSRT_MTIME_NEVER;
  ret = ddsrt_connect (sock, msg_name, (socklen_t) msg_namelen);
  if (ret == DDS_RETCODE_IN_PROGRESS || ret == DDS_RETCODE_TRY_AGAIN || ret == DDS_RETCODE_INTERRUPTED)
  {
    /* A writable socket can also mean the connection attempt failed. */
    int error;
    socklen_t len = sizeof (error);
    if ((ret = ddsi_tcp_wait (gv, sock, false, deadline)) != DDS_RETCODE_OK)
      goto fail_w_socket;
    if ((ret = ddsrt_getsockopt (sock, SOL_SOCKET, SO_ERROR, &error, &len)) != DDS_RETCODE_OK)
      goto fail_w_socket;
    if (error != 0)
      ret = DDS_RETCODE_NO_CONNECTION;
  }
  if (ret != DDS_RETCODE_OK)
    goto fail_w_socket;
#ifdef DDS_HAS_TCP_TLS
  if (fact->ssl_ctx && (ret = ddsi_tcp_handshake (fact, sock, false, deadline, &conn->m_ssl)) != DDS_RETCODE_OK)
    goto fail_w_socket;
#endif

  ddsi_tcp_conn_set_socket (conn, sock);
  sockaddr_to_string_with_port (buff, sizeof (buff), msg_name);
  GVLOG (DDS_LC_TCP, "tcp connect socket %"PRIdSOCK" port %u to %s\n", sock, conn->m_base.m_base.m_port, buff);

  assert (conn->m_base.m_base.gv->n_recv_threads > 0);
  assert (conn->m_base.m_base.gv->recv_threads[0].arg.mode == DDSI_RTM_MANY);
  struct ddsi_sock_waitset * const ws = gv->recv_threads[0].arg.u.many.ws;
  ddsi_conn_add_ref (&conn->m_base);
  ddsrt_mutex_lock (&fact->ddsi_tcp_cache_lock_g);
  if (ddsi_sock_waitset_add (ws, &conn->m_base) < 0)
  {
    ddsrt_mutex_unlock (&fact->ddsi_tcp_cache_lock_g);
    ddsi_conn_unref (&conn->m_base);
#ifdef DDS_HAS_TCP_TLS
    SSL_free (conn->m_ssl);
    conn->m_ssl = NULL;
#endif
    ddsi_tcp_conn_set_socket (conn, DDSRT_INVALID_SOCKET);
    ret = DDS_RETCODE_OUT_OF_RESOURCES;
    goto fail_w_socket;
  }
  ddsrt_circlist_append (&fact->recv_conns, &conn->m_recv_link);
  ddsrt_mutex_unlock (&fact->ddsi_tcp_cache_lock_g);
  ddsi_sock_waitset_trigger (ws);
  return DDS_RETCODE_OK;

fail_w_socket:
  ddsi_tcp_sock_free (gv, sock, NULL);
  return ret;
}

/* Returns the displaced cache reference, if any. The caller retires it after
   releasing the cache lock, so an in-flight writer can finish first. */
static ddsi_tcp_conn_t ddsi_tcp_cache_add (struct ddsi_tran_factory_tcp *fact, ddsi_tcp_conn_t conn, ddsrt_avl_ipath_t *path)
{
  struct ddsi_domaingv * const gv = fact->fact.gv;
  ddsrt_avl_ipath_t local_path;
  ddsi_tcp_node_t node = path ? NULL : ddsrt_avl_lookup_ipath (&ddsi_tcp_treedef, &fact->ddsi_tcp_cache_g, conn, &local_path);
  ddsi_tcp_conn_t old = node ? node->m_conn : NULL;
  ddsi_conn_add_ref (&conn->m_base);
  if (node)
    node->m_conn = conn;
  else
  {
    node = ddsrt_malloc (sizeof (*node));
    node->m_conn = conn;
    ddsrt_avl_insert_ipath (&ddsi_tcp_treedef, &fact->ddsi_tcp_cache_g, node, path ? path : &local_path);
  }
  char buff[DDSI_LOCSTRLEN];
  sockaddr_to_string_with_port (buff, sizeof (buff), &conn->m_peer_addr.a);
  GVLOG (DDS_LC_TCP, "tcp cache %s %s connection to %s (%p)\n", old ? "updated" : "added", conn->m_base.m_server ? "server" : "client", buff, (void *) conn);
  return old;
}

static void ddsi_tcp_cache_remove (ddsi_tcp_conn_t conn)
{
  struct ddsi_tran_factory_tcp * const fact = (struct ddsi_tran_factory_tcp *) conn->m_base.m_factory;
  ddsrt_avl_dpath_t path;
  ddsrt_mutex_lock (&fact->ddsi_tcp_cache_lock_g);
  ddsi_tcp_node_t node = ddsrt_avl_lookup_dpath (&ddsi_tcp_treedef, &fact->ddsi_tcp_cache_g, conn, &path);
  if (node && node->m_conn == conn)
    ddsrt_avl_delete_dpath (&ddsi_tcp_treedef, &fact->ddsi_tcp_cache_g, node, &path);
  else
    node = NULL;
  ddsrt_mutex_unlock (&fact->ddsi_tcp_cache_lock_g);
  if (node)
    ddsi_tcp_node_free (node);
}

/* Interrupt the receiver. Its reference keeps queued waitset events valid
   until it observes the shutdown and removes the socket itself. */
static void ddsi_tcp_retire_locked (ddsi_tcp_conn_t conn, bool orderly)
{
  if (!conn->m_retired && conn->m_sock != DDSRT_INVALID_SOCKET)
  {
#ifdef DDS_HAS_TCP_TLS
    if (orderly && conn->m_ssl)
    {
      ddsrt_mutex_lock (&conn->m_ssl_mutex);
      if (!conn->m_ssl_failed)
        ddsi_ssl_shutdown (conn->m_ssl);
      ddsrt_mutex_unlock (&conn->m_ssl_mutex);
    }
#else
    (void) orderly;
#endif
    (void) ddsrt_shutdown (conn->m_sock, DDSRT_SHUTDOWN_READ_WRITE);
  }
  conn->m_retired = true;
}

/* The losing/closed stream may have a writer blocked in a readiness wait.
   Its caller owns a reference, so the socket can be interrupted before taking
   the writer mutex. This keeps discovery, accept and receive progressing. */
static void ddsi_tcp_retire (ddsi_tcp_conn_t conn)
{
  const bool orderly = ddsrt_mutex_trylock (&conn->m_mutex);
  if (!orderly)
  {
    if (conn->m_sock != DDSRT_INVALID_SOCKET)
      (void) ddsrt_shutdown (conn->m_sock, DDSRT_SHUTDOWN_READ_WRITE);
    ddsrt_mutex_lock (&conn->m_mutex);
  }
  ddsi_tcp_retire_locked (conn, orderly);
  ddsrt_mutex_unlock (&conn->m_mutex);
}

static ddsi_tcp_conn_t ddsi_tcp_cache_find (struct ddsi_tran_factory_tcp *fact, const struct sockaddr *msg_name, size_t msg_namelen)
{
  ddsrt_avl_ipath_t path;
  struct ddsi_tcp_conn key = { .m_peer_port = ddsrt_sockaddr_get_port (msg_name) };
  memcpy (&key.m_peer_addr, msg_name, msg_namelen);

  ddsrt_mutex_lock (&fact->ddsi_tcp_cache_lock_g);
  ddsi_tcp_node_t node = ddsrt_avl_lookup_ipath (&ddsi_tcp_treedef, &fact->ddsi_tcp_cache_g, &key, &path);
  ddsi_tcp_conn_t conn;
  if (node)
  {
    conn = node->m_conn;
    ddsi_conn_add_ref (&conn->m_base);
  }
  else
  {
    conn = ddsi_tcp_new_conn (fact, NULL, DDSRT_INVALID_SOCKET, false, &key.m_peer_addr.a);
    (void) ddsi_tcp_cache_add (fact, conn, &path);
  }
  ddsrt_mutex_unlock (&fact->ddsi_tcp_cache_lock_g);
  return conn;
}

static int32_t addrfam_to_locator_kind (int af)
{
  assert (af == AF_INET || af == AF_INET6);
  return (af == AF_INET) ? DDSI_LOCATOR_KIND_TCPv4 : DDSI_LOCATOR_KIND_TCPv6;
}

#ifdef DDS_HAS_TCP_TLS
static dds_return_t ddsi_tcp_tls_read (ddsi_tcp_conn_t conn, void *buf, size_t size, size_t *bytes_read, ddsrt_mtime_t deadline)
{
  const struct ddsi_domaingv *gv = conn->m_base.m_base.gv;
  bool want_read;
  dds_return_t rc = DDS_RETCODE_NO_CONNECTION;
  ddsrt_mutex_lock (&conn->m_ssl_mutex);
  if (!conn->m_ssl_failed)
  {
    for (;;)
    {
      rc = ddsi_ssl_read (gv, conn->m_ssl, buf, size, bytes_read, &want_read);
      if (rc != DDS_RETCODE_TRY_AGAIN || want_read)
        break;
      /* A TLS read can need to send protocol data before it can continue. */
      if ((rc = ddsi_tcp_wait (gv, conn->m_sock, false, deadline)) != DDS_RETCODE_OK)
        break;
    }
    if (rc != DDS_RETCODE_OK && rc != DDS_RETCODE_TRY_AGAIN)
      conn->m_ssl_failed = true;
  }
  ddsrt_mutex_unlock (&conn->m_ssl_mutex);
  return rc;
}

/* Return to the level-triggered waitset when the socket itself is readable:
   other connections then get their turn before the next buffered frame. */
static bool ddsi_tcp_tls_read_pending (struct ddsi_tran_conn *base)
{
  ddsi_tcp_conn_t conn = (ddsi_tcp_conn_t) base;
  ddsrt_mutex_lock (&conn->m_ssl_mutex);
  const bool pending = conn->m_ssl && !conn->m_ssl_failed && SSL_pending (conn->m_ssl) > 0;
  ddsrt_mutex_unlock (&conn->m_ssl_mutex);
  return pending && ddsi_tcp_wait_once (conn->m_sock, true, 0) != DDS_RETCODE_OK;
}
#endif

/** @brief Read bytes from an connection that may have SSL enabled
 * @param[in,out] conn connection to read data from
 * @param[out] buf buffer of at least len bytes to store received bytes
 * @param[in] len size of buffer pointed to by buf
 * @param[in] allow_spurious if true, return TRY_AGAIN if no bytes available
 * @param[in] pktinfo (optional) source & destination IP address information
 * @param[out] bytes_read number of bytes read on successful completion, set to 0 in all other cases
 * @return return code indicating success or failure
 * @retval `DDS_RETCODE_OK` bytes read or EOF, `bytes_read` is 0 on EOF else in [1,len]
 * @retval `DDS_RETCODE_TRY_AGAIN` no bytes available but not EOF either (only if `allow_spurious`)
 * @retval `DDS_RETCODE_ERROR` unspecified error */
ddsrt_nonnull((1, 2, 6)) ddsrt_attribute_warn_unused_result
static dds_return_t ddsi_tcp_conn_read (struct ddsi_tran_conn * conn, unsigned char *buf, size_t len, bool allow_spurious, struct ddsi_network_packet_info *pktinfo, size_t *bytes_read)
{
  struct ddsi_domaingv const * const gv = conn->m_base.gv;
  ddsi_tcp_conn_t tcp = (ddsi_tcp_conn_t) conn;
  size_t pos = 0;
  dds_return_t rc = DDS_RETCODE_OK;
  const ddsrt_mtime_t deadline = ddsrt_mtime_add_duration (ddsrt_time_monotonic (), gv->config.tcp_read_timeout);
  *bytes_read = 0;

  while (pos < len)
  {
    size_t n;
#ifdef DDS_HAS_TCP_TLS
    if (tcp->m_ssl)
      rc = ddsi_tcp_tls_read (tcp, buf + pos, len - pos, &n, deadline);
    else
#endif
      rc = ddsrt_recv (tcp->m_sock, buf + pos, len - pos, 0, &n);
    if (rc == DDS_RETCODE_OK)
    {
      if (n == 0)
      {
        GVLOG (DDS_LC_TCP, "tcp read: sock %"PRIdSOCK" closed-by-peer\n", tcp->m_sock);
        return pos == 0 ? DDS_RETCODE_OK : DDS_RETCODE_ERROR;
      }
      pos += n;
    }
    else
    {
      if (rc == DDS_RETCODE_TRY_AGAIN && allow_spurious && pos == 0)
        return rc;
      if (rc == DDS_RETCODE_TRY_AGAIN || rc == DDS_RETCODE_INTERRUPTED)
        rc = ddsi_tcp_wait (gv, tcp->m_sock, true, deadline);
      if (rc != DDS_RETCODE_OK)
      {
        GVLOG (DDS_LC_TCP, "tcp read: sock %"PRIdSOCK" error %"PRId32"\n", tcp->m_sock, rc);
        return rc;
      }
    }
  }
  if (pktinfo)
  {
    const int32_t kind = addrfam_to_locator_kind (tcp->m_peer_addr.a.sa_family);
    ddsi_ipaddr_to_loc (&pktinfo->src, &tcp->m_peer_addr.a, kind);
    pktinfo->if_index = 0;
    pktinfo->dst.kind = DDSI_LOCATOR_KIND_INVALID;
  }
  *bytes_read = pos;
  return DDS_RETCODE_OK;
}

/* Finish a block in the original buffer. SSL_write retries require the same
   address and length until OpenSSL reports progress. */
static dds_return_t ddsi_tcp_write_block (ddsi_tcp_conn_t conn, const char *buf, size_t size, size_t *cursor, ddsrt_mtime_t deadline)
{
  const struct ddsi_domaingv *gv = conn->m_base.m_base.gv;
  dds_return_t rc = DDS_RETCODE_OK;
  size_t pos = 0;
  int sendflags = 0;
#ifdef MSG_NOSIGNAL
  sendflags |= MSG_NOSIGNAL;
#endif
#ifdef DDS_HAS_TCP_TLS
  if (conn->m_ssl)
  {
    ddsrt_mutex_lock (&conn->m_ssl_mutex);
    if (conn->m_ssl_failed)
      rc = DDS_RETCODE_NO_CONNECTION;
  }
#endif
  while (rc == DDS_RETCODE_OK && pos < size)
  {
    size_t n;
    bool want_read = false;
#ifdef DDS_HAS_TCP_TLS
    if (conn->m_ssl)
      rc = ddsi_ssl_write (gv, conn->m_ssl, buf + pos, size - pos, &n, &want_read);
    else
#endif
      rc = ddsrt_send (conn->m_sock, buf + pos, size - pos, sendflags, &n);
    if (rc == DDS_RETCODE_OK)
    {
      if (n == 0)
        rc = DDS_RETCODE_NO_CONNECTION;
      else
        pos += n;
    }
    else if (rc == DDS_RETCODE_TRY_AGAIN || rc == DDS_RETCODE_INTERRUPTED)
      rc = ddsi_tcp_wait (gv, conn->m_sock, want_read, deadline);
  }
#ifdef DDS_HAS_TCP_TLS
  if (conn->m_ssl)
  {
    if (rc != DDS_RETCODE_OK)
      conn->m_ssl_failed = true;
    ddsrt_mutex_unlock (&conn->m_ssl_mutex);
  }
#endif
  *cursor += pos;
  return rc;
}

static dds_return_t iovlen_sum (size_t niov, const ddsrt_iovec_t *iov, size_t *size)
{
  size_t total = 0;
  for (size_t i = 0; i < niov; i++)
  {
    if (iov[i].iov_len > SIZE_MAX - total)
      return DDS_RETCODE_BAD_PARAMETER;
    total += iov[i].iov_len;
  }
  *size = total;
  return DDS_RETCODE_OK;
}

static void set_msghdr_iov (ddsrt_msghdr_t *mhdr, ddsrt_iovec_t *iov, size_t iovlen)
{
  mhdr->msg_iov = iov;
  mhdr->msg_iovlen = (ddsrt_msg_iovlen_t)iovlen;
}

struct ddsi_tcp_concat_msg {
#ifdef DDS_HAS_TCP_TLS
  char msgbuf[4096];
  ddsrt_iovec_t iovec;
#else
  char dummy;
#endif
};

ddsrt_nonnull_all
static void ddsi_tcp_conn_concat_msg_init (struct ddsi_tcp_concat_msg *concat_msg)
{
#ifdef DDS_HAS_TCP_TLS
  concat_msg->iovec.iov_base = NULL;
#else
  (void) concat_msg;
#endif
}

#ifdef DDS_HAS_TCP_TLS
ddsrt_nonnull_all ddsrt_attribute_warn_unused_result
static dds_return_t ddsi_tcp_conn_concat_msg (ddsrt_msghdr_t *msg, struct ddsi_tcp_concat_msg *concat_msg, const ddsi_tran_write_msgfrags_t *msgfrags, size_t size)
{
  if (msgfrags->niov == 1)
    return DDS_RETCODE_OK;

  char *ptr;
  if ((ddsrt_iov_len_t) size != size)
    return DDS_RETCODE_BAD_PARAMETER;
  concat_msg->iovec.iov_len = (ddsrt_iov_len_t) size;
  concat_msg->iovec.iov_base = (size <= sizeof (concat_msg->msgbuf)) ? concat_msg->msgbuf : ddsrt_malloc (size);
  if (concat_msg->iovec.iov_base == NULL)
    return DDS_RETCODE_OUT_OF_RESOURCES;
  ptr = concat_msg->iovec.iov_base;
  for (size_t i = 0; i < msgfrags->niov; i++)
  {
    if (msgfrags->iov[i].iov_len)
      memcpy (ptr, msgfrags->iov[i].iov_base, msgfrags->iov[i].iov_len);
    ptr += msgfrags->iov[i].iov_len;
  }
  msg->msg_iov = &concat_msg->iovec;
  msg->msg_iovlen = 1;
  return DDS_RETCODE_OK;
}
#endif

ddsrt_nonnull_all
static void ddsi_tcp_conn_concat_msg_fini (struct ddsi_tcp_concat_msg *concat_msg)
{
#ifdef DDS_HAS_TCP_TLS
  DDSRT_WARNING_MSVC_OFF(28199)
  if (concat_msg->iovec.iov_base && concat_msg->iovec.iov_base != concat_msg->msgbuf)
    ddsrt_free (concat_msg->iovec.iov_base);
  DDSRT_WARNING_MSVC_ON(28199)
#else
  (void) concat_msg;
#endif
}

ddsrt_nonnull_all ddsrt_attribute_warn_unused_result
static dds_return_t ddsi_tcp_conn_write_msg (ddsi_tcp_conn_t conn, ddsrt_msghdr_t *msg, size_t *nbytes_written)
{
  int sendflags = 0;
#ifdef MSG_NOSIGNAL
  sendflags |= MSG_NOSIGNAL;
#endif
  dds_return_t rc = ddsrt_sendmsg (conn->m_sock, msg, sendflags, nbytes_written);
  switch (rc)
  {
    case DDS_RETCODE_OK:
      // possibly partial write
      break;
    case DDS_RETCODE_INTERRUPTED:
    case DDS_RETCODE_TRY_AGAIN:
      // No bytes were sent. Resume in piecewise mode.
      *nbytes_written = 0;
      rc = DDS_RETCODE_OK;
      break;
    case DDS_RETCODE_NO_CONNECTION:
    case DDS_RETCODE_ILLEGAL_OPERATION: {
      struct ddsi_domaingv * const gv = conn->m_base.m_factory->gv;
      GVLOG (DDS_LC_TCP, "tcp write: sock %"PRIdSOCK" DDS_RETCODE_NO_CONNECTION\n", conn->m_sock);
      break;
    }
    default:
      if (!ddsrt_atomic_ld32 (&conn->m_base.m_closed)) {
        struct ddsi_domaingv * const gv = conn->m_base.m_factory->gv;
        GVWARNING ("tcp write failed on socket %"PRIdSOCK" with errno %"PRId32"\n", conn->m_sock, rc);
      }
      break;
  }
  return rc;
}

ddsrt_nonnull_all ddsrt_attribute_warn_unused_result
static dds_return_t ddsi_tcp_conn_write_msg_piecewise (ddsi_tcp_conn_t conn, const ddsrt_msghdr_t *msg, size_t *cursor)
{
  const struct ddsi_domaingv *gv = conn->m_base.m_base.gv;
  const ddsrt_mtime_t deadline = ddsrt_mtime_add_duration (ddsrt_time_monotonic (), gv->config.tcp_write_timeout);
  size_t skip = *cursor;
  for (size_t i = 0; i < (size_t) msg->msg_iovlen; i++)
  {
    const ddsrt_iovec_t *iov = &msg->msg_iov[i];
    if (skip >= iov->iov_len)
      skip -= iov->iov_len;
    else
    {
      const dds_return_t rc = ddsi_tcp_write_block (conn, (const char *) iov->iov_base + skip, iov->iov_len - skip, cursor, deadline);
      if (rc != DDS_RETCODE_OK)
        return rc;
      skip = 0;
    }
  }
  return DDS_RETCODE_OK;
}

/** @brief Write a message to a destination address
 * @param[in,out] base a placeholder for a connection to write data to (actual connection comes from cache after address lookup)
 * @param[in] dst destination address
 * @param[in] msgfrags message contents
 * @param[in] flags write flags -- FIXME: do we actually have any?
 * @param[out] bytes_written optional, number of bytes written on successful completion, undefined in all other cases
 * @return return code indicating success or failure
 * @retval `DDS_RETCODE_OK` bytes written or EOF, `bytes_written` not equal to len implies EOF
 * @retval `DDS_RETCODE_TIMEOUT` not all data written because of a timeout
 * @retval `DDS_RETCODE_ERROR` unspecified error
 * @retval other error codes possible as well (from ddsrt) */
ddsrt_nonnull ((1, 2, 3))
static dds_return_t ddsi_tcp_conn_write (struct ddsi_tran_conn * base, const ddsi_locator_t *dst, const ddsi_tran_write_msgfrags_t *msgfrags, uint32_t flags, size_t *bytes_written)
{
  if (bytes_written)
    *bytes_written = 0;
  if (msgfrags->niov > INT_MAX)
    return DDS_RETCODE_BAD_PARAMETER;

  struct ddsi_tran_factory_tcp * const fact = (struct ddsi_tran_factory_tcp *) base->m_factory;
  union {
    struct sockaddr_storage x;
    union addr a;
  } dstaddr;
  ddsi_ipaddr_from_loc (&dstaddr.x, dst);
  size_t size;
  dds_return_t rc = iovlen_sum (msgfrags->niov, msgfrags->iov, &size);
  if (rc != DDS_RETCODE_OK || size == 0)
    return rc;
  struct ddsi_tcp_concat_msg concat_msg;
  ddsi_tcp_conn_concat_msg_init (&concat_msg);

  size_t cursor = 0;
  ddsrt_msghdr_t msg;
  memset (&msg, 0, sizeof(msg));
  set_msghdr_iov (&msg, (ddsrt_iovec_t *) msgfrags->iov, msgfrags->niov);
#if DDSRT_MSGHDR_FLAGS
  msg.msg_flags = (int) flags;
#endif

#ifdef DDS_HAS_TCP_TLS
  struct ddsi_domaingv const * const gv = fact->fact.gv;
  if (gv->config.ssl_enable && (rc = ddsi_tcp_conn_concat_msg (&msg, &concat_msg, msgfrags, size)) != DDS_RETCODE_OK)
    return rc;
#endif

  ddsi_tcp_conn_t const conn = ddsi_tcp_cache_find (fact, &dstaddr.a.a, (size_t) ddsrt_sockaddr_get_size (&dstaddr.a.a));
  if (conn == NULL)
  {
    ddsi_tcp_conn_concat_msg_fini (&concat_msg);
    return DDS_RETCODE_ERROR;
  }
  ddsrt_mutex_lock (&conn->m_mutex);
  if (conn->m_retired || ddsrt_atomic_ld32 (&conn->m_base.m_closed))
  {
    rc = DDS_RETCODE_NO_CONNECTION;
    goto done_no_remove;
  }
  if (conn->m_sock == DDSRT_INVALID_SOCKET)
  {
    assert (!conn->m_base.m_server);
    if ((rc = ddsi_tcp_conn_connect (conn, &dstaddr.a.a, (size_t) ddsrt_sockaddr_get_size (&dstaddr.a.a))) != DDS_RETCODE_OK)
    {
      /* Other writers waiting on this attempt must see the same failure.
         A subsequent lookup may start a fresh connection. */
      ddsi_tcp_retire_locked (conn, false);
      ddsi_tcp_cache_remove (conn);
      goto done_no_remove;
    }
  }

  assert (conn->m_sock != DDSRT_INVALID_SOCKET);
#ifdef DDS_HAS_TCP_TLS
  if (gv->config.ssl_enable)
  {
    assert (msg.msg_iovlen == 1);
    if (conn->m_ssl == NULL)
      rc = DDS_RETCODE_NO_CONNECTION;
  }
  else
#endif
    rc = ddsi_tcp_conn_write_msg (conn, &msg, &cursor);
  if (rc == DDS_RETCODE_OK && cursor < size)
    rc = ddsi_tcp_conn_write_msg_piecewise (conn, &msg, &cursor);

  if (rc != DDS_RETCODE_OK || cursor < size)
  {
    ddsi_tcp_retire_locked (conn, false);
    ddsi_tcp_cache_remove (conn);
  }
done_no_remove:
  ddsrt_mutex_unlock (&conn->m_mutex);
  ddsi_conn_unref (&conn->m_base);
  ddsi_tcp_conn_concat_msg_fini (&concat_msg);
  if (bytes_written)
    *bytes_written = cursor;
  return rc;
}

static ddsrt_socket_t ddsi_tcp_conn_handle (struct ddsi_tran_base * base)
{
  return ((ddsi_tcp_conn_t) base)->m_sock;
}

ddsrt_attribute_no_sanitize (("thread"))
static bool ddsi_tcp_supports (const struct ddsi_tran_factory *fact_cmn, int32_t kind)
{
  struct ddsi_tran_factory_tcp * const fact = (struct ddsi_tran_factory_tcp *) fact_cmn;
  return kind == fact->m_kind;
}

static int ddsi_tcp_locator (struct ddsi_tran_factory *fact_cmn, struct ddsi_tran_base * base, ddsi_locator_t *loc)
{
  struct ddsi_tran_factory_tcp * const fact = (struct ddsi_tran_factory_tcp *) fact_cmn;
  loc->kind = fact->m_kind;
  memcpy(loc->address, base->gv->interfaces[0].loc.address, sizeof(loc->address));
  loc->port = base->m_port;
  return 0;
}

static dds_return_t ddsi_tcp_create_conn (struct ddsi_tran_conn **conn_out, struct ddsi_tran_factory *fact_cmn, uint32_t port, const struct ddsi_tran_qos *qos)
{
  struct ddsi_tran_factory_tcp * const fact = (struct ddsi_tran_factory_tcp *) fact_cmn;
  (void) qos;
  (void) port;
  struct ddsi_domaingv const * const gv = fact->fact.gv;
  struct ddsi_network_interface const * const intf = qos->m_interface ? qos->m_interface : &gv->interfaces[0];

  fact->ddsi_tcp_conn_client.m_base.m_interf = intf;
  *conn_out = &fact->ddsi_tcp_conn_client.m_base;
  return DDS_RETCODE_OK;
}

#if defined __GNUC__ && __GNUC__ >= 13
DDSRT_WARNING_GNUC_OFF (analyzer-fd-leak)
#endif
static int ddsi_tcp_listen (struct ddsi_tran_listener * listener)
{
  ddsi_tcp_listener_t tl = (ddsi_tcp_listener_t) listener;
  return listen (tl->m_sock, 4);
}
#if defined __GNUC__ && __GNUC__ >= 13
DDSRT_WARNING_GNUC_ON (analyzer-fd-leak)
#endif

static struct ddsi_tran_conn * ddsi_tcp_accept (struct ddsi_tran_listener * listener)
{
  struct ddsi_tran_factory_tcp * const fact = (struct ddsi_tran_factory_tcp *) listener->m_factory;
  struct ddsi_domaingv const * const gv = fact->fact.gv;
  ddsi_tcp_listener_t tl = (ddsi_tcp_listener_t) listener;
  ddsrt_socket_t sock = DDSRT_INVALID_SOCKET;
  union addr addr;
  socklen_t addrlen = sizeof (addr);
  char buff[DDSI_LOCSTRLEN];
  dds_return_t rc;
#ifdef DDS_HAS_TCP_TLS
  SSL * ssl = NULL;
#endif

  if (ddsi_tcp_wait (gv, tl->m_sock, true, DDSRT_MTIME_NEVER) != DDS_RETCODE_OK)
    return NULL;
  rc = ddsrt_accept (tl->m_sock, &addr.a, &addrlen, &sock);
  if (rc != DDS_RETCODE_OK)
  {
    if (rc != DDS_RETCODE_TRY_AGAIN && rc != DDS_RETCODE_INTERRUPTED && ddsrt_atomic_ld32 (&gv->rtps_keepgoing))
    {
      GVWARNING ("tcp accept failed on socket %"PRIdSOCK": %s\n", tl->m_sock, dds_strretcode (rc));
      dds_sleepfor (DDS_MSECS (100));
    }
    return NULL;
  }

  rc = ddsi_tcp_prepare_socket (sock);
#ifdef DDS_HAS_TCP_TLS
  if (rc == DDS_RETCODE_OK && fact->ssl_ctx)
  {
    const ddsrt_mtime_t deadline = DDSRT_MTIME_NEVER;
    rc = ddsi_tcp_handshake (fact, sock, true, deadline, &ssl);
  }
#endif
  if (rc != DDS_RETCODE_OK)
  {
    ddsi_tcp_sock_free (gv, sock, NULL);
    return NULL;
  }

  sockaddr_to_string_with_port (buff, sizeof (buff), &addr.a);
  GVLOG (DDS_LC_TCP, "tcp accept new socket %"PRIdSOCK" on socket %"PRIdSOCK" from %s\n", sock, tl->m_sock, buff);
  ddsi_tcp_conn_t tcp = ddsi_tcp_new_conn (fact, NULL, sock, true, &addr.a);
#ifdef DDS_HAS_TCP_TLS
  tcp->m_ssl = ssl;
#endif
  /* The accept caller owns the initial reference. Track it for shutdown
     and publish a separate cache reference for bidirectional writes. */
  ddsrt_mutex_lock (&fact->ddsi_tcp_cache_lock_g);
  ddsrt_circlist_append (&fact->recv_conns, &tcp->m_recv_link);
  ddsi_tcp_conn_t old = ddsi_tcp_cache_add (fact, tcp, NULL);
  ddsrt_mutex_unlock (&fact->ddsi_tcp_cache_lock_g);
  if (old)
  {
    ddsi_tcp_retire (old);
    ddsi_conn_unref (&old->m_base);
  }
  return &tcp->m_base;
}

static ddsrt_socket_t ddsi_tcp_listener_handle (struct ddsi_tran_base * base)
{
  return ((ddsi_tcp_listener_t) base)->m_sock;
}

/*
  ddsi_tcp_conn_address: This function is called when an entity had been discovered
  with an empty locator list and the locator is being set to the address of the
  caller (supporting call back over NAT).
*/

static void addr_to_loc (ddsi_locator_t *loc, const union addr *addr)
{
  ddsi_ipaddr_to_loc (loc, &addr->a, addrfam_to_locator_kind (addr->a.sa_family));
}

static void ddsi_tcp_conn_peer_locator (struct ddsi_tran_conn * conn, ddsi_locator_t * loc)
{
  struct ddsi_domaingv const * const gv = conn->m_base.gv;
  char buff[DDSI_LOCSTRLEN];
  ddsi_tcp_conn_t tc = (ddsi_tcp_conn_t) conn;
  assert (tc->m_sock != DDSRT_INVALID_SOCKET);
  addr_to_loc (loc, &tc->m_peer_addr);
  ddsi_locator_to_string(buff, sizeof(buff), loc);
  GVLOG (DDS_LC_TCP, "(tcp EP:%s)", buff);
}

static void ddsi_tcp_base_init (const struct ddsi_tran_factory_tcp *fact, const struct ddsi_network_interface *interf, struct ddsi_tran_conn *base)
{
  ddsi_factory_conn_init (&fact->fact, interf, base);
  base->m_base.m_trantype = DDSI_TRAN_CONN;
  base->m_base.m_handle_fn = ddsi_tcp_conn_handle;
  base->m_read_fn = ddsi_tcp_conn_read;
#ifdef DDS_HAS_TCP_TLS
  if (fact->fact.gv->config.ssl_enable)
    base->m_read_pending_fn = ddsi_tcp_tls_read_pending;
#endif
  base->m_write_fn = ddsi_tcp_conn_write;
  base->m_peer_locator_fn = ddsi_tcp_conn_peer_locator;
  base->m_disable_multiplexing_fn = 0;
  base->m_locator_fn = ddsi_tcp_locator;
}

static ddsi_tcp_conn_t ddsi_tcp_new_conn (struct ddsi_tran_factory_tcp *fact, const struct ddsi_network_interface *interf, ddsrt_socket_t sock, bool server, struct sockaddr * peer)
{
  ddsi_tcp_conn_t conn = ddsrt_malloc (sizeof (*conn));

  memset (conn, 0, sizeof (*conn));
  ddsi_tcp_base_init (fact, interf, &conn->m_base);
  ddsrt_mutex_init (&conn->m_mutex);
#ifdef DDS_HAS_TCP_TLS
  ddsrt_mutex_init (&conn->m_ssl_mutex);
#endif
  conn->m_sock = DDSRT_INVALID_SOCKET;
  (void)memcpy(&conn->m_peer_addr, peer, (size_t)ddsrt_sockaddr_get_size(peer));
  conn->m_peer_port = ddsrt_sockaddr_get_port (peer);
  conn->m_base.m_server = server;
  conn->m_base.m_conn_id = ddsi_iid_gen ();
  conn->m_base.m_base.m_port = INVALID_PORT;
  ddsi_tcp_conn_set_socket (conn, sock);

  char buff[DDSI_LOCSTRLEN];
  struct ddsi_domaingv * const gv = fact->fact.gv;
  sockaddr_to_string_with_port(buff, sizeof(buff), &conn->m_peer_addr.a);
  GVLOG (DDS_LC_TCP, "tcp new %s connection on socket %"PRIdSOCK" to %s (%p)\n", conn->m_base.m_server ? "server" : "client", conn->m_sock, buff, (void *) conn);
  return conn;
}

static dds_return_t ddsi_tcp_create_listener (struct ddsi_tran_listener **listener_out, struct ddsi_tran_factory * fact, uint32_t port, const struct ddsi_tran_qos *qos)
{
  struct ddsi_tran_factory_tcp * const fact_tcp = (struct ddsi_tran_factory_tcp *) fact;
  struct ddsi_domaingv const * const gv = fact_tcp->fact.gv;
  ddsrt_socket_t sock;
  (void) qos;

  if (ddsi_tcp_sock_new (fact_tcp, &sock, (uint16_t) port) != DDS_RETCODE_OK)
    return DDS_RETCODE_ERROR;

  char buff[DDSI_LOCSTRLEN];
  union addr addr;
  socklen_t addrlen = sizeof (addr);
  dds_return_t ret;
  if ((ret = ddsrt_getsockname (sock, &addr.a, &addrlen)) != DDS_RETCODE_OK)
  {
    GVERROR ("ddsi_tcp_create_listener: ddsrt_getsockname returned %"PRId32"\n", ret);
    ddsi_tcp_sock_free (gv, sock, NULL);
    return DDS_RETCODE_ERROR;
  }
  sockaddr_to_string_with_port (buff, sizeof (buff), &addr.a);
  GVLOG (DDS_LC_TCP, "tcp create listener socket %"PRIdSOCK" on %s\n", sock, buff);

  ddsi_tcp_listener_t tl = ddsrt_malloc (sizeof (*tl));
  memset (tl, 0, sizeof (*tl));

  tl->m_sock = sock;

  tl->m_base.m_base.gv = fact->gv;
  tl->m_base.m_listen_fn = ddsi_tcp_listen;
  tl->m_base.m_accept_fn = ddsi_tcp_accept;
  tl->m_base.m_factory = fact;

  tl->m_base.m_base.m_port = get_socket_port (gv, sock);
  tl->m_base.m_base.m_trantype = DDSI_TRAN_LISTENER;
  tl->m_base.m_base.m_handle_fn = ddsi_tcp_listener_handle;
  tl->m_base.m_locator_fn = ddsi_tcp_locator;
  *listener_out = &tl->m_base;
  return DDS_RETCODE_OK;
}

static void ddsi_tcp_conn_delete (ddsi_tcp_conn_t conn)
{
  struct ddsi_tran_factory_tcp * const fact = (struct ddsi_tran_factory_tcp *) conn->m_base.m_factory;
  struct ddsi_domaingv const * const gv = fact->fact.gv;
  char buff[DDSI_LOCSTRLEN];
  sockaddr_to_string_with_port(buff, sizeof(buff), &conn->m_peer_addr.a);
  GVLOG (DDS_LC_TCP, "tcp free %s connection on socket %"PRIdSOCK" to %s (%p)\n", conn->m_base.m_server ? "server" : "client", conn->m_sock, buff, (void *) conn);

#ifdef DDS_HAS_TCP_TLS
  SSL_free (conn->m_ssl);
  ddsrt_mutex_destroy (&conn->m_ssl_mutex);
#endif
  ddsi_tcp_sock_free (gv, conn->m_sock, "connection");
  ddsrt_mutex_destroy (&conn->m_mutex);
  ddsrt_free (conn);
}

struct closed_stream {
  struct ddsi_domaingv *gv;
  uint64_t id;
};

static void ddsi_tcp_prune_closed (void *arg)
{
  struct closed_stream *closed = arg;
  ddsi_purge_proxy_participants (closed->gv, closed->id);
  ddsrt_free (closed);
}

static void ddsi_tcp_close_conn (struct ddsi_tran_conn *tc)
{
  struct ddsi_tran_factory_tcp * const fact = (struct ddsi_tran_factory_tcp *) tc->m_factory;
  if (tc == &fact->ddsi_tcp_conn_client.m_base)
    return;
  ddsi_tcp_conn_t conn = (ddsi_tcp_conn_t) tc;
  ddsi_tcp_retire (conn);
  ddsi_tcp_cache_remove (conn);

  ddsrt_mutex_lock (&fact->ddsi_tcp_cache_lock_g);
  ddsrt_circlist_remove (&fact->recv_conns, &conn->m_recv_link);
  ddsrt_mutex_unlock (&fact->ddsi_tcp_cache_lock_g);

  /* Serialize with SPDP already queued by the receiver. The shutdown path
     joins receive threads and drains discovery before deleting all proxies. */
  if (ddsrt_atomic_ld32 (&fact->fact.gv->rtps_keepgoing))
  {
    struct closed_stream *closed = ddsrt_malloc (sizeof (*closed));
    closed->gv = fact->fact.gv;
    closed->id = tc->m_conn_id;
    ddsi_dqueue_enqueue_callback (closed->gv->builtins_dqueue, ddsi_tcp_prune_closed, closed);
  }
}

static void ddsi_tcp_release_conn (struct ddsi_tran_conn * conn)
{
  struct ddsi_tran_factory_tcp * const fact_tcp = (struct ddsi_tran_factory_tcp *) conn->m_factory;
  if (conn != &fact_tcp->ddsi_tcp_conn_client.m_base)
  {
    ddsi_tcp_conn_delete ((ddsi_tcp_conn_t) conn);
  }
}

static void ddsi_tcp_unblock_listener (struct ddsi_tran_listener * listener)
{
  ddsi_tcp_listener_t tl = (ddsi_tcp_listener_t) listener;
  /* Wake the listener where supported. The socket wait also observes shutdown
     on platforms where shutdown() cannot interrupt a listening socket. */
  (void) ddsrt_shutdown (tl->m_sock, DDSRT_SHUTDOWN_READ_WRITE);
}

static void ddsi_tcp_release_listener (struct ddsi_tran_listener * listener)
{
  ddsi_tcp_listener_t tl = (ddsi_tcp_listener_t) listener;
  struct ddsi_domaingv const * const gv = tl->m_base.m_base.gv;
  ddsi_tcp_sock_free (gv, tl->m_sock, "listener");
  ddsrt_free (tl);
}

static void ddsi_tcp_release_factory (struct ddsi_tran_factory *fact_cmn)
{
  struct ddsi_tran_factory_tcp * const fact = (struct ddsi_tran_factory_tcp *) fact_cmn;
  struct ddsi_domaingv const * const gv = fact->fact.gv;
  /* The receiver has stopped. Release its remaining socket references,
     including connections displaced from the cache before shutdown. */
  while (!ddsrt_circlist_isempty (&fact->recv_conns))
  {
    struct ddsrt_circlist_elem *link = ddsrt_circlist_oldest (&fact->recv_conns);
    ddsi_tcp_conn_t conn = (ddsi_tcp_conn_t) ((char *) link - offsetof (struct ddsi_tcp_conn, m_recv_link));
    ddsi_conn_free (&conn->m_base);
  }
  ddsrt_avl_free (&ddsi_tcp_treedef, &fact->ddsi_tcp_cache_g, ddsi_tcp_node_free);
  ddsrt_mutex_destroy (&fact->ddsi_tcp_cache_lock_g);
#ifdef DDS_HAS_TCP_TLS
  ddsi_ssl_ctx_free (fact->ssl_ctx);
#endif
  GVLOG (DDS_LC_CONFIG, "tcp de-initialized\n");
  ddsrt_free (fact);
}

static enum ddsi_locator_from_string_result ddsi_tcp_address_from_string (const struct ddsi_tran_factory *fact_cmn, ddsi_locator_t *loc, const char *str)
{
  struct ddsi_tran_factory_tcp * const fact = (struct ddsi_tran_factory_tcp *) fact_cmn;
  return ddsi_ipaddr_from_string(loc, str, fact->m_kind);
}

static int ddsi_tcp_is_loopbackaddr (const struct ddsi_tran_factory *tran, const ddsi_locator_t *loc)
{
  (void) tran;
  switch (loc->kind)
  {
    case DDSI_LOCATOR_KIND_UDPv4: {
      return loc->address[12] == 127;
    }
#if DDSRT_HAVE_IPV6
    case DDSI_LOCATOR_KIND_UDPv6: {
      const struct in6_addr *ipv6 = (const struct in6_addr *) loc->address;
      return IN6_IS_ADDR_LOOPBACK (ipv6);
    }
#endif
    default: {
      return 0;
    }
  }
}

static int ddsi_tcp_is_mcaddr (const struct ddsi_tran_factory *tran, const ddsi_locator_t *loc)
{
  (void) tran;
  (void) loc;
  return 0;
}

static int ddsi_tcp_is_ssm_mcaddr (const struct ddsi_tran_factory *tran, const ddsi_locator_t *loc)
{
  (void) tran;
  (void) loc;
  return 0;
}

static enum ddsi_nearby_address_result ddsi_tcp_is_nearby_address (const ddsi_locator_t *loc, size_t ninterf, const struct ddsi_network_interface interf[], size_t *interf_idx)
{
  return ddsi_ipaddr_is_nearby_address(loc, ninterf, interf, interf_idx);
}

static int ddsi_tcp_is_valid_port (const struct ddsi_tran_factory *fact, uint32_t port)
{
  (void) fact;
  return (0 < port && port <= 65535);
}

static uint32_t ddsi_tcp_receive_buffer_size (const struct ddsi_tran_factory *fact)
{
  (void) fact;
  return 0;
}

static char *ddsi_tcp_locator_to_string (char *dst, size_t sizeof_dst, const ddsi_locator_t *loc, struct ddsi_tran_conn * conn, int with_port)
{
  (void) conn;
  return ddsi_ipaddr_to_string(dst, sizeof_dst, loc, with_port, NULL);
}

static int ddsi_tcp_locator_from_sockaddr (const struct ddsi_tran_factory *tran_cmn, ddsi_locator_t *loc, const struct sockaddr *sockaddr)
{
  struct ddsi_tran_factory_tcp * const tran = (struct ddsi_tran_factory_tcp *) tran_cmn;
  switch (sockaddr->sa_family)
  {
    case AF_INET:
      if (tran->m_kind != DDSI_LOCATOR_KIND_TCPv4)
        return -1;
      break;
    case AF_INET6:
      if (tran->m_kind != DDSI_LOCATOR_KIND_TCPv6)
        return -1;
      break;
  }
  ddsi_ipaddr_to_loc (loc, sockaddr, tran->m_kind);
  return 0;
}

int ddsi_tcp_init (struct ddsi_domaingv *gv)
{
  struct ddsi_tran_factory_tcp *fact = ddsrt_malloc (sizeof (*fact));

  memset (fact, 0, sizeof (*fact));
  fact->m_kind = DDSI_LOCATOR_KIND_TCPv4;
  fact->fact.gv = gv;
  fact->fact.m_typename = "tcp";
  fact->fact.m_default_spdp_address = NULL;
  fact->fact.m_stream = true;
  fact->fact.m_connless = false;
  fact->fact.m_enable_spdp = true;
  fact->fact.m_supports_fn = ddsi_tcp_supports;
  fact->fact.m_create_listener_fn = ddsi_tcp_create_listener;
  fact->fact.m_create_conn_fn = ddsi_tcp_create_conn;
  fact->fact.m_release_conn_fn = ddsi_tcp_release_conn;
  fact->fact.m_close_conn_fn = ddsi_tcp_close_conn;
  fact->fact.m_unblock_listener_fn = ddsi_tcp_unblock_listener;
  fact->fact.m_release_listener_fn = ddsi_tcp_release_listener;
  fact->fact.m_free_fn = ddsi_tcp_release_factory;
  fact->fact.m_locator_from_string_fn = ddsi_tcp_address_from_string;
  fact->fact.m_locator_to_string_fn = ddsi_tcp_locator_to_string;
  fact->fact.m_enumerate_interfaces_fn = ddsi_eth_enumerate_interfaces;
  fact->fact.m_is_loopbackaddr_fn = ddsi_tcp_is_loopbackaddr;
  fact->fact.m_is_mcaddr_fn = ddsi_tcp_is_mcaddr;
  fact->fact.m_is_ssm_mcaddr_fn = ddsi_tcp_is_ssm_mcaddr;
  fact->fact.m_is_nearby_address_fn = ddsi_tcp_is_nearby_address;
  fact->fact.m_is_valid_port_fn = ddsi_tcp_is_valid_port;
  fact->fact.m_receive_buffer_size_fn = ddsi_tcp_receive_buffer_size;
  fact->fact.m_locator_from_sockaddr_fn = ddsi_tcp_locator_from_sockaddr;

#if DDSRT_HAVE_IPV6
  if (gv->config.transport_selector == DDSI_TRANS_TCP6)
  {
    fact->m_kind = DDSI_LOCATOR_KIND_TCPv6;
    fact->fact.m_typename = "tcp6";
  }
#endif

  memset (&fact->ddsi_tcp_conn_client, 0, sizeof (fact->ddsi_tcp_conn_client));
  ddsi_tcp_base_init (fact, NULL, &fact->ddsi_tcp_conn_client.m_base);
  fact->ddsi_tcp_conn_client.m_sock = DDSRT_INVALID_SOCKET;

#ifdef DDS_HAS_TCP_TLS
  if (gv->config.ssl_enable && (fact->ssl_ctx = ddsi_ssl_ctx_new (gv)) == NULL)
  {
    ddsrt_free (fact);
    return -1;
  }
#endif

  ddsrt_circlist_init (&fact->recv_conns);
  ddsrt_avl_init (&ddsi_tcp_treedef, &fact->ddsi_tcp_cache_g);
  ddsrt_mutex_init (&fact->ddsi_tcp_cache_lock_g);

  ddsi_factory_add (gv, &fact->fact);
  GVLOG (DDS_LC_CONFIG, "tcp initialized\n");
  return 0;
}
