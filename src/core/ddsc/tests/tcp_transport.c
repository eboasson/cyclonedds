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

#include "dds/ddsrt/bswap.h"
#include "dds/ddsrt/io.h"
#include "dds/ddsi/ddsi_entity_index.h"
#include "dds/ddsi/ddsi_plist.h"
#include "dds/ddsi/ddsi_protocol.h"
#include "dds/ddsi/ddsi_proxy_endpoint.h"
#include "dds/ddsi/ddsi_thread.h"
#include "dds__guid.h"
#include "ddsi__addrset.h"
#include "ddsi__proxy_participant.h"
#include "ddsi__radmin.h"
#include "ddsi__spdp_schedule.h"
#include "ddsi__tcp.h"
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

struct stream_counts {
  ddsrt_atomic_uint32_t opened, closed, participants_deleted;
};

static void count_streams (void *arg, const dds_log_data_t *data)
{
  struct stream_counts *counts = arg;
  if (strstr (data->message, "tcp accept new socket") || (strstr (data->message, "tcp connect ") && strstr (data->message, ": ready")))
    ddsrt_atomic_inc32 (&counts->opened);
  if (strstr (data->message, "tcp free client connection") || strstr (data->message, "tcp free server connection"))
    ddsrt_atomic_inc32 (&counts->closed);
  if (strstr (data->message, "delete_proxy_participant(") && strstr (data->message, "deleting endpoints"))
    ddsrt_atomic_inc32 (&counts->participants_deleted);
}

static bool wait_count (const ddsrt_atomic_uint32_t *count, uint32_t target)
{
  const dds_time_t deadline = dds_time () + DDS_SECS (5);
  while (ddsrt_atomic_ld32 (count) < target && dds_time () < deadline)
    dds_sleepfor (DDS_MSECS (10));
  return ddsrt_atomic_ld32 (count) == target;
}

void tcp_test_two_listeners (bool simultaneous, uint32_t nparticipants, const char *options)
{
  struct stream_counts counts = {
    .opened = DDSRT_ATOMIC_UINT32_INIT (0), .closed = DDSRT_ATOMIC_UINT32_INIT (0),
    .participants_deleted = DDSRT_ATOMIC_UINT32_INIT (0)
  };
  dds_set_trace_sink (count_streams, &counts);
  dds_entity_t domain[2], pp[2][3], tp[2][3];
  CU_ASSERT_LEQ_FATAL (nparticipants, 3);
  struct ddsi_domaingv *gv[2];
  for (dds_domainid_t i = 0; i < 2; i++)
  {
    domain[i] = tcp_test_create_isolated_domain (i, 0, "2 s", options);
    CU_ASSERT_GT_FATAL (domain[i], 0);
    gv[i] = get_domaingv (domain[i]);
  }
  /* Establish the requested streams before creating any participants so
     a cross-connect is deterministic, independent of discovery timing. */
  const uint32_t initial = simultaneous ? 2 : 1;
  for (uint32_t i = 0; i < initial; i++)
  {
    size_t written;
    CU_ASSERT_EQ_FATAL (tcp_test_write_byte (gv[i], &gv[1-i]->loc_meta_uc, 0, 0, &written), DDS_RETCODE_TRY_AGAIN);
  }
  CU_ASSERT_FATAL (wait_count (&counts.opened, 2 * initial));
  for (dds_domainid_t i = 0; i < 2; i++)
  {
    for (uint32_t p = 0; p < nparticipants; p++)
    {
      pp[i][p] = dds_create_participant (i, NULL, NULL);
      CU_ASSERT_GT_FATAL (pp[i][p], 0);
      char topic[40];
      (void) snprintf (topic, sizeof (topic), "tcp_two_listeners_%"PRIu32, p);
      tp[i][p] = dds_create_topic (pp[i][p], &Space_Type1_desc, topic, NULL, NULL);
      CU_ASSERT_GT_FATAL (tp[i][p], 0);
    }
  }
  for (uint32_t i = 0; i < initial; i++)
  {
    ddsi_xlocator_t loc = { .c = gv[1-i]->loc_meta_uc, .conn = gv[i]->xmit_conns_meta[0] };
    struct ddsi_thread_state *thrst = ddsi_lookup_thread_state ();
    ddsi_thread_state_awake (thrst, gv[i]);
    ddsi_spdp_republish_to_locator (gv[i]->spdp_schedule, &loc);
    ddsi_thread_state_asleep (thrst);
  }
  dds_entity_t rd[3], wr[3];
  for (uint32_t p = 0; p < nparticipants; p++)
  {
    rd[p] = dds_create_reader (pp[0][p], tp[0][p], NULL, NULL);
    wr[p] = dds_create_writer (pp[1][p], tp[1][p], NULL, NULL);
    CU_ASSERT_GT_FATAL (rd[p], 0);
    CU_ASSERT_GT_FATAL (wr[p], 0);
    sync_reader_writer (pp[0][p], rd[p], pp[1][p], wr[p]);
  }
  CU_ASSERT (wait_count (&counts.closed, 2 * (initial - 1)));
  for (uint32_t p = 0; p < nparticipants; p++)
    tcp_test_basic_write (rd[p], wr[p], NULL);
  CU_ASSERT_EQ (ddsrt_atomic_ld32 (&counts.opened), 2 * initial);
  CU_ASSERT_EQ (ddsrt_atomic_ld32 (&counts.closed), 2 * (initial - 1));
  CU_ASSERT_EQ (ddsrt_atomic_ld32 (&counts.participants_deleted), 0);
  CU_ASSERT_EQ (dds_delete (domain[1]), DDS_RETCODE_OK);
  CU_ASSERT_EQ (dds_delete (domain[0]), DDS_RETCODE_OK);
  dds_set_trace_sink (NULL, NULL);
}

struct shared_stream_arg {
  struct ddsi_domaingv *gv;
  ddsi_guid_t remote, extra, local[2];
  ddsi_locator_t old_src, keep_src;
  uint64_t old_id, keep_id, extra_iid;
  uint32_t checks;
  ddsrt_atomic_uint32_t done;
};

static void add_shared_stream_participant (void *varg)
{
  struct shared_stream_arg *arg = varg;
  struct ddsi_proxy_participant *pp = ddsi_entidx_lookup_proxy_participant_guid (arg->gv->entity_index, &arg->remote);
  if (pp && pp->source_route_conn_id)
  {
    arg->old_src = pp->source_route;
    arg->old_id = pp->source_route_conn_id;
    ddsi_plist_t plist = *pp->plist;
    plist.participant_guid = arg->extra;
    struct ddsi_addrset *as_default = ddsi_new_addrset (), *as_meta = ddsi_new_addrset ();
    ddsi_copy_addrset_into_addrset (arg->gv, as_default, pp->as_default);
    ddsi_copy_addrset_into_addrset (arg->gv, as_meta, pp->as_meta);
    struct ddsi_proxy_participant *extra;
    if (ddsi_new_proxy_participant (&extra, arg->gv, &arg->extra, 0,
        as_default, as_meta, &plist,
        DDS_INFINITY, pp->vendor, ddsrt_time_wallclock (), 1))
    {
      extra->source_route = arg->old_src;
      extra->source_route_conn_id = arg->old_id;
      ddsi_proxy_participant_note_connection (extra, arg->old_id);
      arg->extra_iid = extra->e.iid;
      arg->checks = 1;
    }
  }
  ddsrt_atomic_st32 (&arg->done, 1);
}

static void find_shared_stream_survivor (void *varg)
{
  struct shared_stream_arg *arg = varg;
  struct ddsi_proxy_participant *pp = ddsi_entidx_lookup_proxy_participant_guid (arg->gv->entity_index, &arg->remote);
  if (pp && pp->source_route_conn_id != arg->old_id)
  {
    arg->keep_src = pp->source_route;
    arg->keep_id = pp->source_route_conn_id;
  }
  ddsrt_atomic_st32 (&arg->done, 1);
}

static bool shared_stream_is_cached (const struct shared_stream_arg *arg, const struct ddsi_proxy_participant *pp)
{
  ddsi_locator_t src = arg->old_src;
  uint64_t id = arg->old_id;
  bool announce, confirm;
  /* With no listener, selection only validates the original stream identity. */
  (void) ddsi_tcp_select_peer_stream (arg->gv, pp, NULL, &src, &id, NULL, &announce, &confirm);
  return id == arg->old_id;
}

static void check_shared_stream_retirement (void *varg)
{
  struct shared_stream_arg *arg = varg;
  struct ddsi_proxy_participant *pp = ddsi_entidx_lookup_proxy_participant_guid (arg->gv->entity_index, &arg->remote);
  struct ddsi_proxy_participant *extra = ddsi_entidx_lookup_proxy_participant_guid (arg->gv->entity_index, &arg->extra);
  arg->checks = 0;
  if (pp && extra)
  {
    const ddsi_locator_t *listener = &pp->plist->metatraffic_unicast_locators.first->loc;
    ddsi_locator_t src = arg->keep_src;
    uint64_t id = arg->keep_id;
    bool announce, confirm;
    (void) ddsi_tcp_select_peer_stream (arg->gv, pp, listener, &src, &id, &arg->local[0].prefix, &announce, &confirm);
    ddsi_tcp_prune_peer_stream (arg->gv, &src, id);
    if (shared_stream_is_cached (arg, extra))
      arg->checks |= 1;

    /* Merely observing the other stream does not move the selected route. */
    ddsi_proxy_participant_note_connection (extra, id);
    ddsi_tcp_prune_peer_stream (arg->gv, &src, id);
    if (shared_stream_is_cached (arg, extra))
      arg->checks |= 2;

    const ddsi_xlocator_t old = { .c = arg->old_src, .conn = arg->gv->xmit_conns_meta[0]->m_return_conn };
    const ddsi_xlocator_t replacement = { .c = src, .conn = old.conn };
    (void) ddsi_addrset_replace_uc (extra->as_default, &old, &replacement);
    (void) ddsi_addrset_replace_uc (extra->as_meta, &old, &replacement);
    if (ddsi_spdp_ref_locator (arg->gv->spdp_schedule, &replacement, true) != DDS_RETCODE_OK)
    {
      ddsrt_atomic_st32 (&arg->done, 1);
      return;
    }
    ddsi_spdp_unref_locator (arg->gv->spdp_schedule, &old, false);
    extra->source_route = src;
    extra->source_route_conn_id = id;
    ddsi_tcp_prune_peer_stream (arg->gv, &src, id);
    /* The second local participant still needs its own return-path proof. */
    if (shared_stream_is_cached (arg, extra))
      arg->checks |= 4;

    (void) ddsi_tcp_select_peer_stream (arg->gv, pp, listener, &src, &id, &arg->local[1].prefix, &announce, &confirm);
    ddsi_tcp_prune_peer_stream (arg->gv, &src, id);
    if (!shared_stream_is_cached (arg, extra))
      arg->checks |= 8;
  }
  ddsrt_atomic_st32 (&arg->done, 1);
}

static void check_shared_stream_participant_alive (void *varg)
{
  struct shared_stream_arg *arg = varg;
  struct ddsi_proxy_participant *extra = ddsi_entidx_lookup_proxy_participant_guid (arg->gv->entity_index, &arg->extra);
  arg->checks = extra && extra->e.iid == arg->extra_iid;
  ddsrt_atomic_st32 (&arg->done, 1);
}

static void run_shared_stream_callback (struct shared_stream_arg *arg, ddsi_dqueue_callback_t callback)
{
  ddsrt_atomic_st32 (&arg->done, 0);
  ddsi_dqueue_enqueue_callback (arg->gv->builtins_dqueue, callback, arg);
  while (!ddsrt_atomic_ld32 (&arg->done))
    dds_sleepfor (DDS_MSECS (1));
}

static void shared_stream_participants (void)
{
  struct stream_counts counts = { 0 };
  dds_set_trace_sink (count_streams, &counts);
  dds_entity_t domain[2], pp[2];
  struct ddsi_domaingv *gv[2];
  ddsi_guid_t guid[2];
  for (dds_domainid_t i = 0; i < 2; i++)
  {
    domain[i] = tcp_test_create_isolated_domain (i, 0, "2 s", TCP_TEST_TRACE_STREAMS);
    CU_ASSERT_GT_FATAL (domain[i], 0);
    gv[i] = get_domaingv (domain[i]);
    pp[i] = dds_create_participant (i, NULL, NULL);
    CU_ASSERT_GT_FATAL (pp[i], 0);
    dds_guid_t g;
    CU_ASSERT_EQ_FATAL (dds_get_guid (pp[i], &g), DDS_RETCODE_OK);
    guid[i] = dds_guid_to_ddsi_guid (g);
  }
  const uint32_t high = gv[0]->loc_meta_uc.port > gv[1]->loc_meta_uc.port ? 0 : 1;
  const uint32_t low = 1 - high;
  size_t written;
  CU_ASSERT_EQ_FATAL (tcp_test_write_byte (gv[high], &gv[low]->loc_meta_uc, 0, 0, &written), DDS_RETCODE_TRY_AGAIN);
  CU_ASSERT_FATAL (tcp_test_wait_for_proxy (gv[high], &guid[low], true));
  CU_ASSERT_FATAL (tcp_test_wait_for_proxy (gv[low], &guid[high], true));

  struct shared_stream_arg arg = {
    .gv = gv[high], .remote = guid[low], .local = { guid[high] },
    .extra = { .prefix = { .u = { 0, 0, 1 } }, .entityid = { .u = DDSI_ENTITYID_PARTICIPANT } }
  };
  /* A second remote participant is known only on the first stream. Keeping it
     in the discovery queue makes this ordering independent of packet timing. */
  run_shared_stream_callback (&arg, add_shared_stream_participant);
  CU_ASSERT_EQ_FATAL (arg.checks, 1);
  CU_ASSERT_EQ_FATAL (tcp_test_write_byte (gv[low], &gv[high]->loc_meta_uc, 0, 0, &written), DDS_RETCODE_TRY_AGAIN);
  CU_ASSERT_FATAL (wait_count (&counts.opened, 4));
  const dds_time_t deadline = dds_time () + DDS_SECS (5);
  while (!arg.keep_id && dds_time () < deadline)
  {
    run_shared_stream_callback (&arg, find_shared_stream_survivor);
    if (!arg.keep_id)
      dds_sleepfor (DDS_MSECS (10));
  }
  CU_ASSERT_NEQ_FATAL (arg.keep_id, 0);

  /* Hold back the second local participant's SPDP so its confirmation cannot
     race the staged retirement checks below. */
  CU_ASSERT_EQ_FATAL (dds_domain_set_deafmute (domain[high], false, true, DDS_INFINITY), DDS_RETCODE_OK);
  const dds_entity_t local2 = dds_create_participant (high, NULL, NULL);
  CU_ASSERT_GT_FATAL (local2, 0);
  dds_guid_t g;
  CU_ASSERT_EQ_FATAL (dds_get_guid (local2, &g), DDS_RETCODE_OK);
  arg.local[1] = dds_guid_to_ddsi_guid (g);
  run_shared_stream_callback (&arg, check_shared_stream_retirement);
  CU_ASSERT_EQ (arg.checks, 15);
  CU_ASSERT_FATAL (wait_count (&counts.closed, 2));
  run_shared_stream_callback (&arg, check_shared_stream_participant_alive);
  CU_ASSERT_EQ (arg.checks, 1);
  CU_ASSERT_EQ (ddsrt_atomic_ld32 (&counts.participants_deleted), 0);
  CU_ASSERT_EQ (dds_delete (domain[high]), DDS_RETCODE_OK);
  CU_ASSERT_EQ (dds_delete (domain[low]), DDS_RETCODE_OK);
  dds_set_trace_sink (NULL, NULL);
}

static void read_frame_part (ddsrt_socket_t sock, unsigned char *buf, size_t size)
{
  while (size)
  {
    size_t n;
    CU_ASSERT_EQ_FATAL (ddsrt_recv (sock, buf, size, 0, &n), DDS_RETCODE_OK);
    CU_ASSERT_GT_FATAL (n, 0);
    size -= n;
    buf += n;
  }
}

static bool wait_return_port (struct ddsi_domaingv *gv, const ddsi_guid_t *guid, uint16_t port)
{
  struct ddsi_thread_state *thrst = ddsi_lookup_thread_state ();
  const dds_time_t deadline = dds_time () + DDS_SECS (5);
  const ddsi_guid_t builtin = { .prefix = guid->prefix, .entityid = { .u = DDSI_ENTITYID_SEDP_BUILTIN_PUBLICATIONS_READER } };
  do
  {
    ddsi_thread_state_awake (thrst, gv);
    struct ddsi_proxy_participant *pp = ddsi_entidx_lookup_proxy_participant_guid (gv->entity_index, guid);
    struct ddsi_proxy_reader *prd = ddsi_entidx_lookup_proxy_reader_guid (gv->entity_index, &builtin);
    ddsi_xlocator_t meta = { 0 }, data = { 0 };
    uint32_t preferred_port = 0;
    if (pp && prd)
    {
      ddsrt_mutex_lock (&pp->source_route_lock);
      preferred_port = prd->c.loc_uc.c.port;
      ddsrt_mutex_unlock (&pp->source_route_lock);
    }
    if (pp)
    {
      ddsi_addrset_any_uc (pp->as_meta, &meta);
      ddsi_addrset_any_uc (pp->as_default, &data);
    }
    ddsi_thread_state_asleep (thrst);
    if (meta.c.port == port && data.c.port == port && preferred_port == port)
      return true;
    dds_sleepfor (DDS_MSECS (10));
  } while (dds_time () < deadline);
  return false;
}

CU_Test (ddsc_tcp, reuse_accepted_stream, .timeout = 20)
{
  tcp_test_two_listeners (false, 1, TCP_TEST_TRACE_STREAMS);
}

CU_Test (ddsc_tcp, simultaneous_connections, .timeout = 20)
{
  tcp_test_two_listeners (true, 1, TCP_TEST_TRACE_STREAMS);
}

CU_Test (ddsc_tcp, simultaneous_connections_multiple_participants, .timeout = 30)
{
  tcp_test_two_listeners (true, 3, TCP_TEST_TRACE_STREAMS);
}

CU_Test (ddsc_tcp, shared_stream_participants, .timeout = 20)
{
  shared_stream_participants ();
}

CU_Test (ddsc_tcp, migrate_source_route, .timeout = 20)
{
  /* Forward a client-only participant's real announcement over two streams
     to the server. The second source port must take over while the first
     connection is still open, even though the sequence number is unchanged. */
  ddsrt_socket_t listener, client, streams[2];
  uint32_t port;
  tcp_test_bind_loopback_socket (&listener, &port);
  CU_ASSERT_EQ_FATAL (ddsrt_listen (listener, 1), DDS_RETCODE_OK);
  const dds_entity_t dc = tcp_test_create_isolated_domain (0, -1, "2 s", "");
  const dds_entity_t ds = tcp_test_create_isolated_domain (1, 0, "2 s", "");
  CU_ASSERT_GT_FATAL (dc, 0);
  CU_ASSERT_GT_FATAL (ds, 0);
  const dds_entity_t pp = dds_create_participant (0, NULL, NULL);
  CU_ASSERT_GT_FATAL (pp, 0);
  dds_guid_t guid;
  CU_ASSERT_EQ_FATAL (dds_get_guid (pp, &guid), DDS_RETCODE_OK);
  const ddsi_guid_t remote = dds_guid_to_ddsi_guid (guid);
  const dds_entity_t serverpp = dds_create_participant (1, NULL, NULL);
  CU_ASSERT_GT_FATAL (serverpp, 0);
  struct ddsi_domaingv *gc = get_domaingv (dc), *gs = get_domaingv (ds);
  ddsi_locator_t relay = gc->interfaces[0].loc;
  relay.port = port;
  size_t n;
  CU_ASSERT_EQ_FATAL (tcp_test_write_byte (gc, &relay, 0, 0, &n), DDS_RETCODE_TRY_AGAIN);
  CU_ASSERT_EQ_FATAL (ddsrt_accept (listener, NULL, NULL, &client), DDS_RETCODE_OK);
  unsigned char frame[65536];
  const size_t hdrsz = DDSI_RTPS_MESSAGE_HEADER_SIZE + sizeof (ddsi_rtps_msg_len_t);
  read_frame_part (client, frame, hdrsz);
  ddsi_rtps_msg_len_t ml;
  memcpy (&ml, frame + DDSI_RTPS_MESSAGE_HEADER_SIZE, sizeof (ml));
  const uint32_t len = (ml.smhdr.flags & DDSI_RTPS_SUBMESSAGE_FLAG_ENDIANNESS) ? ddsrt_toLE4u (ml.length) : ddsrt_fromBE4u (ml.length);
  CU_ASSERT_GEQ_FATAL (len, hdrsz);
  CU_ASSERT_LEQ_FATAL (len, sizeof (frame));
  read_frame_part (client, frame + hdrsz, len - hdrsz);
  uint16_t last_port = 0;
  for (size_t i = 0; i < 2; i++)
  {
    tcp_test_connect_to_listener (&streams[i], &gs->loc_meta_uc);
    struct sockaddr_in addr;
    socklen_t alen = sizeof (addr);
    CU_ASSERT_EQ_FATAL (ddsrt_getsockname (streams[i], (struct sockaddr *) &addr, &alen), DDS_RETCODE_OK);
    last_port = ntohs (addr.sin_port);
    send_frame_part (streams[i], frame, len);
    CU_ASSERT_FATAL (wait_return_port (gs, &remote, last_port));
  }
  CU_ASSERT_EQ (ddsrt_close (streams[0]), DDS_RETCODE_OK);
  /* The immediate SPDP reply on the selected stream also exercises its
     actual return path. Old-stream traffic must not redirect later replies. */
  read_frame_part (streams[1], frame, hdrsz);
  CU_ASSERT_EQ (memcmp (frame, "RTPS", 4), 0);
  CU_ASSERT_FATAL (wait_return_port (gs, &remote, last_port));
  CU_ASSERT_EQ (ddsrt_close (streams[1]), DDS_RETCODE_OK);
  CU_ASSERT_FATAL (tcp_test_wait_for_proxy (gs, &remote, false));
  CU_ASSERT_EQ (ddsrt_close (client), DDS_RETCODE_OK);
  CU_ASSERT_EQ (ddsrt_close (listener), DDS_RETCODE_OK);
  CU_ASSERT_EQ (dds_delete (ds), DDS_RETCODE_OK);
  CU_ASSERT_EQ (dds_delete (dc), DDS_RETCODE_OK);
}
