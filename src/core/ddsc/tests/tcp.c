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
#include "dds/ddsi/ddsi_entity_index.h"
#include "dds/ddsi/ddsi_iid.h"
#include "dds/ddsi/ddsi_plist.h"
#include "dds/ddsi/ddsi_proxy_participant.h"
#include "dds/ddsi/ddsi_thread.h"
#include "dds__guid.h"
#include "ddsi__addrset.h"
#include "ddsi__discovery_addrset.h"
#include "ddsi__proxy_participant.h"
#include "ddsi__radmin.h"
#include "ddsi__tran.h"
#include "test_common.h"
#include "tcp_test.h"

static ddsrt_atomic_uint32_t framing_errors;

static void scan_for_framing_error (void *ptr, const dds_log_data_t *data)
{
  (void) ptr;
  //tprintf ("[%"PRIu32"] %s", data->domid, data->message);
  if (strstr (data->message, "framing error, dropping connection") != NULL)
    ddsrt_atomic_or32 (&framing_errors, 1u << data->domid);
}

void tcp_test_run_config (const char *extra, const dds_topic_descriptor_t *desc, dds_duration_t latency_budget,
                          void (*action) (dds_entity_t rd, dds_entity_t wr, void *arg), void *arg)
{
  const char *config_fmt =
    "<General>"
    "  <Interfaces>"
    "    <NetworkInterface address=\"127.0.0.1\"/>"
    "  </Interfaces>"
    "  <Transport>tcp</Transport>"
    "</General>"
    "<Discovery>"
    "  <ExternalDomainId>0</ExternalDomainId>"
    "  <Tag>${CYCLONEDDS_PID}</Tag>"
    "  <Peers>"
    "    %s"
    "  </Peers>"
    "</Discovery>"
    "<TCP>"
    "  <Port>%d</Port>"
    "</TCP>%s"
    "<Tracing><Category>trace,tcp</Category><OutputFile>stdout</OutputFile></Tracing>";

  ddsrt_atomic_st32 (&framing_errors, 0);
  dds_set_log_sink (scan_for_framing_error, NULL);
  dds_set_trace_sink (scan_for_framing_error, NULL);

  // Start up a new domain listening to an ephemeral TCP port
  char *configs = NULL;
  (void) ddsrt_asprintf (&configs, config_fmt, "", 0, extra);
  const dds_entity_t doms = dds_create_domain (0, configs);
  ddsrt_free (configs);

#ifdef DDS_HAS_TCP
  CU_ASSERT_GT_FATAL (doms, 0);
  struct ddsi_domaingv * const gvs = get_domaingv (doms);
  CU_ASSERT_NEQ_FATAL (gvs, NULL);

  // Create a second domain instance without a server socket and with the
  // first domain's ephemeral port as the peer
  char peerlocbuf[DDSI_LOCSTRLEN];
  char *peerstr = NULL;
  (void) ddsrt_asprintf (&peerstr, "<Peer address=\"%s\"/>", ddsi_locator_to_string (peerlocbuf, sizeof (peerlocbuf), &gvs->loc_meta_uc));
  char *configc = NULL;
  (void) ddsrt_asprintf (&configc, config_fmt, peerstr, -1, extra);
  const dds_entity_t domc = dds_create_domain (1, configc);
  CU_ASSERT_GT_FATAL (domc, 0);
  ddsrt_free (configc);
  ddsrt_free (peerstr);

  const dds_entity_t pp_pub = dds_create_participant (0, NULL, NULL);
  CU_ASSERT_GT_FATAL (pp_pub, 0);
  const dds_entity_t pp_sub = dds_create_participant (1, NULL, NULL);
  CU_ASSERT_GT_FATAL (pp_sub, 0);
  char topicname[100];
  create_unique_topic_name ("tcp_basic", topicname, sizeof (topicname));
  dds_qos_t *qos = dds_create_qos ();
  dds_qset_reliability (qos, DDS_RELIABILITY_RELIABLE, DDS_INFINITY);
  dds_qset_latency_budget (qos, latency_budget);
  const dds_entity_t tp_pub = dds_create_topic (pp_pub, desc, topicname, qos, NULL);
  const dds_entity_t tp_sub = dds_create_topic (pp_sub, desc, topicname, qos, NULL);
  dds_delete_qos (qos);

  const dds_entity_t wr = dds_create_writer (pp_pub, tp_pub, NULL, NULL);
  const dds_entity_t rd = dds_create_reader (pp_sub, tp_sub, NULL, NULL);
  sync_reader_writer (pp_sub, rd, pp_pub, wr);

  action (rd, wr, arg);

  dds_return_t rc;
  rc = dds_delete (domc);
  CU_ASSERT_EQ_FATAL (rc, 0);
  rc = dds_delete (doms);
  CU_ASSERT_EQ_FATAL (rc, 0);
#else // DDS_HAS_TCP
  (void) desc;
  (void) latency_budget;
  (void) action;
  (void) arg;
  CU_ASSERT_LT_FATAL (doms, 0);
#endif // DDS_HAS_TCP

  dds_set_log_sink (scan_for_framing_error, NULL);
  dds_set_trace_sink (scan_for_framing_error, NULL);
}

static void do_tcp (void (*action) (dds_entity_t rd, dds_entity_t wr, void *arg), void *arg)
{
  tcp_test_run_config ("", &Space_Type1_desc, 0, action, arg);
}

void tcp_test_basic_write (dds_entity_t rd, dds_entity_t wr, void *varg)
{
  (void) varg;

  dds_return_t rc;
  rc = dds_write (wr, &(Space_Type1){345,678,101});
  CU_ASSERT_EQ_FATAL (rc, 0);

  const dds_entity_t ws = dds_create_waitset (dds_get_participant (rd));
  CU_ASSERT_GT_FATAL (ws, 0);
  rc = dds_set_status_mask (rd, DDS_DATA_AVAILABLE_STATUS);
  CU_ASSERT_EQ_FATAL (rc, 0);
  rc = dds_waitset_attach (ws, rd, 0);
  CU_ASSERT_EQ_FATAL (rc, 0);
  rc = dds_waitset_wait (ws, NULL, 0, DDS_MSECS (5000));
  CU_ASSERT_EQ (rc, 1);

  Space_Type1 sample;
  void *rawsample = &sample;
  dds_sample_info_t si;
  rc = dds_take (rd, &rawsample, &si, 1, 1);
  CU_ASSERT_EQ_FATAL (rc, 1);
  CU_ASSERT_FATAL(si.valid_data);
  CU_ASSERT_EQ_FATAL (sample.long_1, 345);
  CU_ASSERT_EQ_FATAL (sample.long_2, 678);
  CU_ASSERT_EQ_FATAL (sample.long_3, 101);
}

CU_Test (ddsc_tcp, basic)
{
  do_tcp (tcp_test_basic_write, NULL);
}

static void do_async_reliable_write (dds_entity_t rd, dds_entity_t wr, void *arg)
{
  (void) arg;
  const Space_simpletypes samples[] = {
    { .l = 1, .s = "a" },
    { .l = 2, .s = "a longer string key for the second frame" }
  };
  const dds_entity_t ws = dds_create_waitset (dds_get_participant (rd));
  const dds_entity_t condition = dds_create_readcondition (rd, DDS_ANY_STATE);
  CU_ASSERT_GT_FATAL (ws, 0);
  CU_ASSERT_GT_FATAL (condition, 0);
  CU_ASSERT_EQ_FATAL (dds_waitset_attach (ws, condition, 0), DDS_RETCODE_OK);

  for (size_t i = 0; i < 2; i++)
    CU_ASSERT_EQ_FATAL (dds_write (wr, &samples[i]), DDS_RETCODE_OK);

  bool seen[2] = { false, false };
  const dds_time_t deadline = dds_time () + DDS_SECS (5);
  for (size_t i = 0; i < 2; i++)
  {
    void *loan = NULL;
    dds_sample_info_t si;
    const dds_return_t ready = dds_waitset_wait_until (ws, NULL, 0, deadline);
    CU_ASSERT_EQ (ready, 1);
    if (ready != 1)
      return;
    CU_ASSERT_EQ_FATAL (dds_take (rd, &loan, &si, 1, 1), 1);
    const Space_simpletypes *sample = loan;
    for (size_t j = 0; j < 2; j++)
      if (si.valid_data && sample->l == samples[j].l && sample->s && strcmp (sample->s, samples[j].s) == 0)
        seen[j] = true;
    CU_ASSERT_EQ_FATAL (dds_return_loan (rd, &loan, 1), DDS_RETCODE_OK);
  }
  CU_ASSERT (seen[0] && seen[1]);
  CU_ASSERT_EQ (dds_wait_for_acks (wr, DDS_SECS (5)), DDS_RETCODE_OK);
  CU_ASSERT_EQ (ddsrt_atomic_ld32 (&framing_errors), 0);
}

CU_Test (ddsc_tcp, async_reliable_write, .timeout = 20)
{
  tcp_test_run_config ("", &Space_simpletypes_desc, DDS_MSECS (10), do_async_reliable_write, NULL);
}

struct inject_arg {
  ddsrt_iovec_t data;
};

static void do_inject (dds_entity_t rd, dds_entity_t wr, void *varg)
{
  const struct inject_arg *arg = varg;
  struct ddsi_domaingv * const gvwr = get_domaingv (wr);

  // Find reader's proxy participant in writer's domain
  dds_guid_t rdguid;
  dds_get_guid (rd, &rdguid);
  ddsi_guid_t rdpp_guid = dds_guid_to_ddsi_guid (rdguid);
  rdpp_guid.entityid.u = DDSI_ENTITYID_PARTICIPANT;
  ddsi_thread_state_awake (ddsi_lookup_thread_state (), gvwr);
  struct ddsi_proxy_participant *rdproxypp = ddsi_entidx_lookup_proxy_participant_guid (gvwr->entity_index, &rdpp_guid);
  CU_ASSERT_NEQ_FATAL (rdproxypp, NULL);
  ddsi_thread_state_asleep (ddsi_lookup_thread_state ());
  // ... because we need the address
  ddsi_xlocator_t xloc;
  ddsi_addrset_any_uc (rdproxypp->as_default, &xloc);

  // Make writer's domain mute so we can inject garbage in the TCP connection without
  // interfering with RTPS messages being sent in the background
  dds_domain_set_deafmute (wr, false, true, DDS_INFINITY);

  DDSI_DECL_TRAN_WRITE_MSGFRAGS_PTR(mf, 1);
  mf->niov = 1;
  mf->iov[0] = arg->data;
  ddsi_conn_write (xloc.conn, &xloc.c, mf, 0, NULL);

  // logger should
  dds_domainid_t rd_domain_id;
  dds_return_t rc;
  rc = dds_get_domainid (rd, &rd_domain_id);
  CU_ASSERT_EQ_FATAL (rc, 0);
  while (ddsrt_atomic_ld32 (&framing_errors) == 0)
    dds_sleepfor (DDS_MSECS (10));
  CU_ASSERT_EQ_FATAL (ddsrt_atomic_ld32 (&framing_errors), (1u << rd_domain_id));
}

CU_Test (ddsc_tcp, inject_wrong_smid)
{
  unsigned char msg[] = {
    'R', 'T', 'P', 'S', /* version (don't care): */ 2,5,
    /* vendor id (don't care, 1.16 = Cyclone */ 1,16,
    /* GUID prefix (don't care) */ 1,16,3,4, 5,6,7,8, 9,10,11,12,
    /* SMID_ADLINK_MSG_LEN, big-endian, 4 octets-to-next-header */ 130,0,0,4,
    /* fake length */ 0x0,0x0,0x0,0x20
  };
  struct inject_arg arg = {
    .data = {
      .iov_len = 28,
      .iov_base = msg
    }
  };
  do_tcp (do_inject, &arg);
}

CU_Test (ddsc_tcp, inject_short_length)
{
  unsigned char msg[] = {
    'R', 'T', 'P', 'S', /* version (don't care): */ 2,5,
    /* vendor id (don't care, 1.16 = Cyclone */ 1,16,
    /* GUID prefix (don't care) */ 1,16,3,4, 5,6,7,8, 9,10,11,12,
    /* SMID_ADLINK_MSG_LEN, big-endian, 4 octets-to-next-header */ 129,0,0,4,
    /* fake length */ 0x0,0x0,0x0,0x3
  };
  struct inject_arg arg = {
    .data = {
      .iov_len = 28,
      .iov_base = msg
    }
  };
  do_tcp (do_inject, &arg);
}

CU_Test (ddsc_tcp, inject_oversize_length)
{
  unsigned char msg[] = {
    'R', 'T', 'P', 'S', /* version (don't care): */ 2,5,
    /* vendor id (don't care, 1.16 = Cyclone */ 1,16,
    /* GUID prefix (don't care) */ 1,16,3,4, 5,6,7,8, 9,10,11,12,
    /* SMID_ADLINK_MSG_LEN, big-endian, 4 octets-to-next-header */ 129,0,0,4,
    /* fake length */ 0x33,0x44,0x55,0x66
  };
  struct inject_arg arg = {
    .data = {
      .iov_len = 28,
      .iov_base = msg
    }
  };
  do_tcp (do_inject, &arg);
}

bool tcp_test_wait_for_proxy (struct ddsi_domaingv *gv, const ddsi_guid_t *guid, bool present)
{
  struct ddsi_thread_state * const thrst = ddsi_lookup_thread_state ();
  const dds_time_t deadline = dds_time () + DDS_SECS (5);
  do {
    ddsi_thread_state_awake (thrst, gv);
    const bool found = ddsi_entidx_lookup_proxy_participant_guid (gv->entity_index, guid) != NULL;
    ddsi_thread_state_asleep (thrst);
    if (found == present)
      return true;
    dds_sleepfor (DDS_MSECS (10));
  } while (dds_time () < deadline);
  return false;
}

struct extra_stream_arg {
  struct ddsi_domaingv *gv;
  ddsi_guid_t guid;
  ddsrt_atomic_uint32_t result;
};

static void check_extra_stream (void *arg)
{
  struct extra_stream_arg * const a = arg;
  struct ddsi_proxy_participant *pp = ddsi_entidx_lookup_proxy_participant_guid (a->gv->entity_index, &a->guid);
  bool retained = false;
  if (pp)
  {
    /* Record duplicate announcements on a second stream, then close that stream.
       The original stream must still own the discovery association. */
    const uint64_t id = ddsi_iid_gen ();
    ddsi_proxy_participant_note_connection (pp, id);
    ddsi_proxy_participant_note_connection (pp, id);
    ddsi_purge_proxy_participants (a->gv, id);
    retained = ddsi_entidx_lookup_proxy_participant_guid (a->gv->entity_index, &a->guid) == pp;
  }
  ddsrt_atomic_st32 (&a->result, retained ? 1 : 2);
}

static void check_disconnect (dds_entity_t rd, dds_entity_t wr, void *arg)
{
  (void) arg;
  struct ddsi_domaingv * const gv = get_domaingv (wr);
  char peer[DDSI_LOCSTRLEN];
  char *config;
  (void) ddsrt_asprintf (&config,
    "<General><Transport>tcp</Transport><Interfaces><NetworkInterface address=\"127.0.0.1\"/>"
    "</Interfaces></General><Discovery><ExternalDomainId>0</ExternalDomainId><Tag>${CYCLONEDDS_PID}</Tag>"
    "<LeaseDuration>120 s</LeaseDuration><Peers><Peer address=\"%s\"/></Peers></Discovery><TCP><Port>-1</Port></TCP>",
    ddsi_locator_to_string (peer, sizeof (peer), &gv->loc_meta_uc));
  const dds_entity_t domain = dds_create_domain (2, config);
  ddsrt_free (config);
  CU_ASSERT_GT_FATAL (domain, 0);
  const dds_entity_t pp = dds_create_participant (2, NULL, NULL);
  CU_ASSERT_GT_FATAL (pp, 0);
  dds_guid_t guid;
  CU_ASSERT_EQ_FATAL (dds_get_guid (pp, &guid), DDS_RETCODE_OK);
  const ddsi_guid_t ddsi_guid = dds_guid_to_ddsi_guid (guid);
  CU_ASSERT_FATAL (tcp_test_wait_for_proxy (gv, &ddsi_guid, true));
  struct extra_stream_arg extra = { .gv = gv, .guid = ddsi_guid };
  ddsi_dqueue_enqueue_callback (gv->builtins_dqueue, check_extra_stream, &extra);
  while (ddsrt_atomic_ld32 (&extra.result) == 0)
    dds_sleepfor (DDS_MSECS (1));
  CU_ASSERT_EQ_FATAL (ddsrt_atomic_ld32 (&extra.result), 1);

  /* Suppress the SPDP dispose. Closing the stream must remove this participant
     before its lease expires, while the other client's stream remains usable. */
  CU_ASSERT_EQ_FATAL (dds_domain_set_deafmute (domain, false, true, DDS_INFINITY), DDS_RETCODE_OK);
  CU_ASSERT_EQ_FATAL (dds_delete (domain), DDS_RETCODE_OK);
  CU_ASSERT (tcp_test_wait_for_proxy (gv, &ddsi_guid, false));
  tcp_test_basic_write (rd, wr, NULL);
}

CU_Test (ddsc_tcp, prune_disconnected_peer, .timeout = 30)
{
  do_tcp (check_disconnect, NULL);
}

CU_Test (ddsc_tcp, preserve_endpoint_listener)
{
  const ddsi_locator_t src = { .kind = DDSI_LOCATOR_KIND_TCPv4, .port = 49152, .address = { [12] = 127, [15] = 1 } };
  struct ddsi_locators_one meta = { .loc = src }, ep = { .loc = src };
  const ddsi_locators_t listeners = { .n = 1, .first = &meta, .last = &meta };
  const ddsi_locators_t destinations = { .n = 1, .first = &ep, .last = &ep };
  meta.loc.port = 7400;
  ep.loc.port = 7500;
  CU_ASSERT (!ddsi_use_tcp_return_path (&src, &destinations, &listeners));
  ep.loc.port = meta.loc.port;
  CU_ASSERT (ddsi_use_tcp_return_path (&src, &destinations, &listeners));
  ep.loc.address[15] = 2;
  CU_ASSERT (!ddsi_use_tcp_return_path (&src, &destinations, &listeners));
  ep.loc = src;
  CU_ASSERT (ddsi_use_tcp_return_path (&src, &destinations, NULL));
}
