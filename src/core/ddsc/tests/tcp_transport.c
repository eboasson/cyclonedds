// Copyright(c) 2025 ZettaScale Technology and others
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License v. 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
// v. 1.0 which is available at
// http://www.eclipse.org/org/documents/edl-v10.php.
//
// SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

#include <stdio.h>
#include <string.h>

#include "dds/ddsrt/io.h"
#include "dds/ddsi/ddsi_domaingv.h"
#include "dds/ddsi/ddsi_protocol.h"
#include "ddsi__tran.h"
#include "test_common.h"
#include "tcp_test.h"

void tcp_test_bind_loopback_socket (ddsrt_socket_t *listener, uint32_t *port)
{
  struct sockaddr_in addr = { .sin_family = AF_INET, .sin_addr.s_addr = htonl (INADDR_LOOPBACK) };
  socklen_t len = sizeof (addr);
  CU_ASSERT_EQ_FATAL (ddsrt_socket (listener, AF_INET, SOCK_STREAM, 0), DDS_RETCODE_OK);
  CU_ASSERT_EQ_FATAL (ddsrt_bind (*listener, (struct sockaddr *) &addr, len), DDS_RETCODE_OK);
  CU_ASSERT_EQ_FATAL (ddsrt_getsockname (*listener, (struct sockaddr *) &addr, &len), DDS_RETCODE_OK);
  *port = ntohs (addr.sin_port);
}

dds_entity_t tcp_test_create_isolated_domain (dds_domainid_t id, int port, const char *timeout, const char *extra_config)
{
  char *config;
  (void) ddsrt_asprintf (&config,
    "<General><Transport>tcp</Transport><Interfaces><NetworkInterface address=\"127.0.0.1\"/>"
    "</Interfaces></General><Discovery><ExternalDomainId>0</ExternalDomainId>"
    "<Tag>${CYCLONEDDS_PID}</Tag><Peers AddLocalhost=\"false\"/></Discovery>"
    "<TCP><Port>%d</Port><ConnectTimeout>%s</ConnectTimeout></TCP>%s", port, timeout, extra_config);
  const dds_entity_t domain = dds_create_domain (id, config);
  ddsrt_free (config);
  return domain;
}

dds_return_t tcp_test_write_byte (struct ddsi_domaingv *gv, const ddsi_locator_t *dst, char byte, uint32_t flags, size_t *written)
{
  DDSI_DECL_TRAN_WRITE_MSGFRAGS_PTR (mf, 1);
  mf->niov = 1;
  mf->iov[0] = (ddsrt_iovec_t) { .iov_len = 1, .iov_base = &byte };
  return ddsi_conn_write (gv->xmit_conns_meta[0], dst, mf, flags, written);
}

CU_Test (ddsc_tcp, connect_unavailable_then_retry, .timeout = 10)
{
  ddsrt_socket_t listener, stream;
  uint32_t port;
  tcp_test_bind_loopback_socket (&listener, &port);
  const dds_entity_t domain = tcp_test_create_isolated_domain (0, -1, "200 ms", "");
  CU_ASSERT_GT_FATAL (domain, 0);
  struct ddsi_domaingv * const gv = get_domaingv (domain);
  ddsi_locator_t peer = gv->interfaces[0].loc;
  peer.port = port;
  size_t written = SIZE_MAX;
  CU_ASSERT_EQ_FATAL (tcp_test_write_byte (gv, &peer, 'A', 0, &written), DDS_RETCODE_TRY_AGAIN);
  CU_ASSERT_EQ (written, 0);

  /* Wait until the failed attempt leaves the cache before opening the port. */
  const ddsrt_mtime_t deadline = ddsrt_mtime_add_duration (ddsrt_time_monotonic (), DDS_SECS (5));
  dds_return_t rc;
  do {
    rc = tcp_test_write_byte (gv, &peer, 'P', DDSI_TRAN_NO_CONNECT, &written);
    CU_ASSERT_EQ (written, 0);
    if (rc == DDS_RETCODE_NO_CONNECTION)
      break;
    CU_ASSERT_EQ_FATAL (rc, DDS_RETCODE_TRY_AGAIN);
    dds_sleepfor (DDS_MSECS (10));
  } while (ddsrt_time_monotonic ().v < deadline.v);
  CU_ASSERT_EQ_FATAL (rc, DDS_RETCODE_NO_CONNECTION);
  CU_ASSERT_EQ_FATAL (ddsrt_listen (listener, 1), DDS_RETCODE_OK);
  CU_ASSERT_EQ_FATAL (tcp_test_write_byte (gv, &peer, 'P', DDSI_TRAN_NO_CONNECT, &written), DDS_RETCODE_NO_CONNECTION);
  CU_ASSERT_EQ (written, 0);

  CU_ASSERT_EQ_FATAL (tcp_test_write_byte (gv, &peer, 'B', 0, &written), DDS_RETCODE_TRY_AGAIN);
  CU_ASSERT_EQ (written, 0);
  do {
    rc = tcp_test_write_byte (gv, &peer, 'C', 0, &written);
    if (rc == DDS_RETCODE_OK)
      break;
    CU_ASSERT_EQ_FATAL (rc, DDS_RETCODE_TRY_AGAIN);
    CU_ASSERT_EQ (written, 0);
    dds_sleepfor (DDS_MSECS (10));
  } while (ddsrt_time_monotonic ().v < deadline.v);
  CU_ASSERT_EQ_FATAL (rc, DDS_RETCODE_OK);
  CU_ASSERT_EQ (written, 1);
  CU_ASSERT_EQ_FATAL (ddsrt_accept (listener, NULL, NULL, &stream), DDS_RETCODE_OK);
  char byte;
  size_t n;
  CU_ASSERT_EQ_FATAL (ddsrt_recv (stream, &byte, 1, 0, &n), DDS_RETCODE_OK);
  CU_ASSERT_EQ_FATAL (n, 1);
  CU_ASSERT_EQ (byte, 'C');
  CU_ASSERT_EQ (dds_delete (domain), DDS_RETCODE_OK);
  CU_ASSERT_EQ_FATAL (ddsrt_recv (stream, &byte, 1, 0, &n), DDS_RETCODE_OK);
  CU_ASSERT_EQ (n, 0);
  CU_ASSERT_EQ (ddsrt_close (stream), DDS_RETCODE_OK);
  CU_ASSERT_EQ (ddsrt_close (listener), DDS_RETCODE_OK);
}

void tcp_test_connect_to_listener (ddsrt_socket_t *sock, const ddsi_locator_t *loc)
{
  struct sockaddr_in addr = { .sin_family = AF_INET, .sin_addr.s_addr = htonl (INADDR_LOOPBACK), .sin_port = htons ((uint16_t) loc->port) };
  CU_ASSERT_EQ_FATAL (ddsrt_socket (sock, AF_INET, SOCK_STREAM, 0), DDS_RETCODE_OK);
  CU_ASSERT_EQ_FATAL (ddsrt_connect (*sock, (struct sockaddr *) &addr, sizeof (addr)), DDS_RETCODE_OK);
}

static void trace_test_frames (void *arg, const dds_log_data_t *data)
{
  if (strstr (data->message, "HDR(aaaaaaaa:aaaaaaaa:aaaaaaaa ") != NULL)
    ddsrt_atomic_or32 (arg, 1);
  if (strstr (data->message, "HDR(bbbbbbbb:bbbbbbbb:bbbbbbbb ") != NULL)
    ddsrt_atomic_or32 (arg, 2);
}

static void send_frame_part (ddsrt_socket_t sock, const unsigned char *buf, size_t size)
{
  while (size)
  {
    size_t n;
    CU_ASSERT_EQ_FATAL (ddsrt_send (sock, buf, size, 0, &n), DDS_RETCODE_OK);
    CU_ASSERT_GT_FATAL (n, 0);
    buf += n;
    size -= n;
  }
}

static bool wait_for_frames (const ddsrt_atomic_uint32_t *flags, uint32_t mask)
{
  const ddsrt_mtime_t deadline = ddsrt_mtime_add_duration (ddsrt_time_monotonic (), DDS_SECS (3));
  while ((ddsrt_atomic_ld32 (flags) & mask) != mask && ddsrt_time_monotonic ().v < deadline.v)
    dds_sleepfor (DDS_MSECS (5));
  return (ddsrt_atomic_ld32 (flags) & mask) == mask;
}

CU_Test (ddsc_tcp, interleaved_frame_reads, .timeout = 20)
{
  const dds_entity_t server = dds_create_domain (0,
    "<General><Transport>tcp</Transport><Interfaces><NetworkInterface address=\"127.0.0.1\"/>"
    "</Interfaces></General><Discovery><Peers AddLocalhost=\"false\"/></Discovery>"
    "<TCP><Port>0</Port><ReadTimeout>10 s</ReadTimeout></TCP>"
    "<Tracing><Category>trace</Category><OutputFile>stdout</OutputFile></Tracing>");
  CU_ASSERT_GT_FATAL (server, 0);
  struct ddsi_domaingv *gv = get_domaingv (server);
  ddsrt_atomic_uint32_t flags = DDSRT_ATOMIC_UINT32_INIT (0);
  dds_set_trace_sink (trace_test_frames, &flags);
  ddsrt_socket_t slow, fast;
  tcp_test_connect_to_listener (&slow, &gv->loc_meta_uc);
  tcp_test_connect_to_listener (&fast, &gv->loc_meta_uc);
  unsigned char frame[32] = {
    'R','T','P','S', 2,3, 1,16, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    DDSI_RTPS_SMID_ADLINK_MSG_LEN, 0,0,4, 0,0,0,32, DDSI_RTPS_SMID_PAD, 0,0,0
  };
  memset (frame + 8, 0xaa, 12);
  send_frame_part (slow, frame, 3);
  /* Send a whole frame on another stream before finishing the first header. */
  memset (frame + 8, 0xbb, 12);
  send_frame_part (fast, frame, sizeof (frame));
  bool first = wait_for_frames (&flags, 2);
  memset (frame + 8, 0xaa, 12);
  send_frame_part (slow, frame + 3, 27);
  /* At this point the length is known, with two bytes of body outstanding. */
  ddsrt_atomic_st32 (&flags, 0);
  memset (frame + 8, 0xbb, 12);
  send_frame_part (fast, frame, sizeof (frame));
  bool second = wait_for_frames (&flags, 2);
  send_frame_part (slow, frame + 30, 2);
  bool resumed = wait_for_frames (&flags, 1);
  dds_set_trace_sink (NULL, NULL);
  CU_ASSERT (first);
  CU_ASSERT (second);
  CU_ASSERT (resumed);
  CU_ASSERT_EQ (ddsrt_close (slow), DDS_RETCODE_OK);
  CU_ASSERT_EQ (ddsrt_close (fast), DDS_RETCODE_OK);
  CU_ASSERT_EQ (dds_delete (server), DDS_RETCODE_OK);
}

CU_Test (ddsc_tcp, incomplete_frame_timeout, .timeout = 5)
{
  const dds_entity_t server = dds_create_domain (0,
    "<General><Transport>tcp</Transport><Interfaces><NetworkInterface address=\"127.0.0.1\"/>"
    "</Interfaces></General><Discovery><Peers AddLocalhost=\"false\"/></Discovery>"
    "<TCP><Port>0</Port><ReadTimeout>100 ms</ReadTimeout></TCP>");
  CU_ASSERT_GT_FATAL (server, 0);
  ddsrt_socket_t sock;
  tcp_test_connect_to_listener (&sock, &get_domaingv (server)->loc_meta_uc);
  const ddsrt_mtime_t start = ddsrt_time_monotonic ();
  send_frame_part (sock, (const unsigned char *) "RTPS", 4);
  unsigned char byte;
  size_t n;
  CU_ASSERT_EQ_FATAL (ddsrt_recv (sock, &byte, 1, 0, &n), DDS_RETCODE_OK);
  CU_ASSERT_EQ (n, 0);
  CU_ASSERT_GEQ (ddsrt_time_monotonic ().v - start.v, DDS_MSECS (100));
  CU_ASSERT_EQ (ddsrt_close (sock), DDS_RETCODE_OK);
  CU_ASSERT_EQ (dds_delete (server), DDS_RETCODE_OK);
}
