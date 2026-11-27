// Copyright(c) 2025 ZettaScale Technology and others
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License v. 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
// v. 1.0 which is available at
// http://www.eclipse.org/org/documents/edl-v10.php.
//
// SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "dds/ddsrt/heap.h"
#include "dds/ddsrt/io.h"
#include "dds/ddsi/ddsi_proxy_participant.h"
#include "dds__guid.h"
#include "ddsi__tran.h"
#include "test_common.h"
#include "tcp_test.h"

#define TLS_TEST_OPTIONS "<SSL><Enable>true</Enable><KeystoreFile>" TCP_TEST_KEYSTORE "</KeystoreFile></SSL>"

CU_Test (ddsc_tcp, tls_mutual_auth, .timeout = 20)
{
  tcp_test_run_config (TLS_TEST_OPTIONS, tcp_test_basic_write, NULL);
}

static dds_entity_t create_tls_domain (dds_domainid_t id, const char *peers, const char *suite)
{
  char *config;
  (void) ddsrt_asprintf (&config,
    "<General><Transport>tcp</Transport><Interfaces><NetworkInterface address=\"127.0.0.1\"/>"
    "</Interfaces></General><Discovery><ExternalDomainId>0</ExternalDomainId>"
    "<Tag>${CYCLONEDDS_PID}</Tag><Peers AddLocalhost=\"false\">%s</Peers></Discovery>"
    "<TCP><Port>%d</Port></TCP><SSL><Enable>true</Enable><KeystoreFile>" TCP_TEST_KEYSTORE
    "</KeystoreFile><MinimumTLSVersion>1.3</MinimumTLSVersion><CipherSuites>%s</CipherSuites></SSL>",
    peers, id == 0 ? 0 : -1, suite);
  const dds_entity_t dom = dds_create_domain (id, config);
  ddsrt_free (config);
  return dom;
}

static void record_tls_rejection (void *arg, const dds_log_data_t *data)
{
  if (data->domid == 0 && strstr (data->message, "no shared cipher") != NULL)
    ddsrt_atomic_st32 (arg, 1);
}

CU_Test (ddsc_tcp, tls_domain_policies, .timeout = 25)
{
  const char * const suite = "TLS_AES_128_GCM_SHA256";
  const dds_entity_t server = create_tls_domain (0, "", suite);
  CU_ASSERT_GT_FATAL (server, 0);
  const dds_entity_t pub = dds_create_participant (0, NULL, NULL);
  CU_ASSERT_GT_FATAL (pub, 0);
  char loc[DDSI_LOCSTRLEN], peer[DDSI_LOCSTRLEN + 20];
  (void) snprintf (peer, sizeof (peer), "<Peer Address=\"%s\"/>",
                   ddsi_locator_to_string (loc, sizeof (loc), &get_domaingv (server)->loc_meta_uc));

  /* Wait for an actual rejection on the server before starting the compatible peer. */
  ddsrt_atomic_uint32_t rejected = DDSRT_ATOMIC_UINT32_INIT (0);
  dds_set_log_sink (record_tls_rejection, &rejected);
  const dds_entity_t incompatible = create_tls_domain (1, peer, "TLS_AES_256_GCM_SHA384");
  const dds_entity_t badpp = incompatible > 0 ? dds_create_participant (1, NULL, NULL) : incompatible;
  const ddsrt_mtime_t deadline = ddsrt_mtime_add_duration (ddsrt_time_monotonic (), DDS_SECS (5));
  while (badpp > 0 && !ddsrt_atomic_ld32 (&rejected) && ddsrt_time_monotonic ().v < deadline.v)
    dds_sleepfor (DDS_MSECS (10));
  dds_set_log_sink (NULL, NULL);
  CU_ASSERT_GT_FATAL (badpp, 0);
  CU_ASSERT_EQ (ddsrt_atomic_ld32 (&rejected), 1);

  const dds_entity_t compatible = create_tls_domain (2, peer, suite);
  CU_ASSERT_GT_FATAL (compatible, 0);
  const dds_entity_t sub = dds_create_participant (2, NULL, NULL);
  CU_ASSERT_GT_FATAL (sub, 0);
  const char * const name = "tcp_tls_domain_policies";
  const dds_entity_t tp_pub = dds_create_topic (pub, &Space_Type1_desc, name, NULL, NULL);
  CU_ASSERT_GT_FATAL (tp_pub, 0);
  const dds_entity_t tp_sub = dds_create_topic (sub, &Space_Type1_desc, name, NULL, NULL);
  CU_ASSERT_GT_FATAL (tp_sub, 0);
  const dds_entity_t wr = dds_create_writer (pub, tp_pub, NULL, NULL);
  CU_ASSERT_GT_FATAL (wr, 0);
  const dds_entity_t rd = dds_create_reader (sub, tp_sub, NULL, NULL);
  CU_ASSERT_GT_FATAL (rd, 0);
  sync_reader_writer (sub, rd, pub, wr);
  tcp_test_basic_write (rd, wr, NULL);

  CU_ASSERT_EQ (dds_delete (compatible), DDS_RETCODE_OK);
  CU_ASSERT_EQ (dds_delete (incompatible), DDS_RETCODE_OK);
  CU_ASSERT_EQ (dds_delete (server), DDS_RETCODE_OK);
}

CU_Test (ddsc_tcp, tls_connect_timeout, .timeout = 10)
{
  ddsrt_socket_t listener;
  uint32_t port;
  tcp_test_bind_loopback_socket (&listener, &port);
  CU_ASSERT_EQ_FATAL (ddsrt_listen (listener, 1), DDS_RETCODE_OK);
  CU_ASSERT_EQ_FATAL (ddsrt_setsocknonblocking (listener, true), DDS_RETCODE_OK);
  const dds_entity_t domain = tcp_test_create_isolated_domain (0, -1, "500 ms", TLS_TEST_OPTIONS);
  CU_ASSERT_GT_FATAL (domain, 0);
  struct ddsi_domaingv * const gv = get_domaingv (domain);
  ddsi_locator_t peer = gv->interfaces[0].loc;
  peer.port = port;

  /* Withhold the TLS response and observe expiry on the peer socket. Repeat
     on the same locator to check that a timed out attempt can be retried. */
  for (int i = 0; i < 2; i++)
  {
    const ddsrt_mtime_t start = ddsrt_time_monotonic ();
    size_t n = SIZE_MAX;
    ddsrt_socket_t stream;
    for (;;)
    {
      const dds_return_t wr = tcp_test_write_byte (gv, &peer, 'A', 0, &n);
      CU_ASSERT_FATAL (wr == DDS_RETCODE_TRY_AGAIN || wr == DDS_RETCODE_NO_CONNECTION);
      CU_ASSERT_EQ (n, 0);
      const dds_return_t rc = ddsrt_accept (listener, NULL, NULL, &stream);
      if (rc == DDS_RETCODE_OK)
        break;
      CU_ASSERT_EQ_FATAL (rc, DDS_RETCODE_TRY_AGAIN);
      dds_sleepfor (DDS_MSECS (10));
    }
    CU_ASSERT_EQ_FATAL (ddsrt_setsocknonblocking (stream, false), DDS_RETCODE_OK);
    char buf[1024];
    size_t received = 0;
    do {
      CU_ASSERT_EQ_FATAL (ddsrt_recv (stream, buf, sizeof (buf), 0, &n), DDS_RETCODE_OK);
      received += n;
    } while (n != 0);
    CU_ASSERT_GT (received, 0);
    CU_ASSERT_GEQ (ddsrt_time_monotonic ().v - start.v, DDS_MSECS (500));
    CU_ASSERT_EQ (ddsrt_close (stream), DDS_RETCODE_OK);
  }
  CU_ASSERT_EQ (dds_delete (domain), DDS_RETCODE_OK);
  CU_ASSERT_EQ (ddsrt_close (listener), DDS_RETCODE_OK);
}

CU_Test (ddsc_tcp, tls_parallel_connect_spdp, .timeout = 20)
{
  ddsrt_socket_t listener, stream;
  uint32_t port;
  tcp_test_bind_loopback_socket (&listener, &port);
  CU_ASSERT_EQ_FATAL (ddsrt_listen (listener, 1), DDS_RETCODE_OK);
  const dds_entity_t server = tcp_test_create_isolated_domain (0, 0, "30 s", TLS_TEST_OPTIONS);
  CU_ASSERT_GT_FATAL (server, 0);
  const dds_entity_t client = tcp_test_create_isolated_domain (1, -1, "30 s", TLS_TEST_OPTIONS);
  CU_ASSERT_GT_FATAL (client, 0);
  CU_ASSERT_GT_FATAL (dds_create_participant (0, NULL, NULL), 0);
  dds_guid_t guid[2];
  for (size_t i = 0; i < 2; i++)
  {
    const dds_entity_t pp = dds_create_participant (1, NULL, NULL);
    CU_ASSERT_GT_FATAL (pp, 0);
    CU_ASSERT_EQ_FATAL (dds_get_guid (pp, &guid[i]), DDS_RETCODE_OK);
  }

  struct ddsi_domaingv * const gvc = get_domaingv (client);
  struct ddsi_domaingv * const gvs = get_domaingv (server);
  /* Both directions have an unrelated handshake outstanding during discovery. */
  ddsrt_socket_t stalled_in;
  tcp_test_connect_to_listener (&stalled_in, &gvs->loc_meta_uc);
  ddsi_locator_t stalled = gvc->interfaces[0].loc;
  stalled.port = port;
  size_t written = SIZE_MAX;
  CU_ASSERT_EQ_FATAL (tcp_test_write_byte (gvc, &stalled, 'A', 0, &written), DDS_RETCODE_TRY_AGAIN);
  CU_ASSERT_EQ (written, 0);
  CU_ASSERT_EQ_FATAL (ddsrt_accept (listener, NULL, NULL, &stream), DDS_RETCODE_OK);
  /* Withhold the TLS response to keep this peer pending throughout the test. */
  CU_ASSERT_EQ_FATAL (tcp_test_write_byte (gvc, &stalled, 'B', 0, &written), DDS_RETCODE_TRY_AGAIN);
  CU_ASSERT_EQ (written, 0);

  /* Neither domain has configured discovery peers. The first write to the
     real server starts setup; readiness must then announce both participants. */
  CU_ASSERT_EQ_FATAL (tcp_test_write_byte (gvc, &gvs->loc_meta_uc, 'C', 0, &written), DDS_RETCODE_TRY_AGAIN);
  CU_ASSERT_EQ (written, 0);
  for (size_t i = 0; i < 2; i++)
  {
    const ddsi_guid_t pp_guid = dds_guid_to_ddsi_guid (guid[i]);
    CU_ASSERT_FATAL (tcp_test_wait_for_proxy (gvs, &pp_guid, true));
  }
  /* Shutdown must interrupt both pending handshakes before their 30 s timeouts. */
  CU_ASSERT_EQ (dds_delete (client), DDS_RETCODE_OK);
  CU_ASSERT_EQ (dds_delete (server), DDS_RETCODE_OK);
  CU_ASSERT_EQ (ddsrt_close (stalled_in), DDS_RETCODE_OK);
  CU_ASSERT_EQ (ddsrt_close (stream), DDS_RETCODE_OK);
  CU_ASSERT_EQ (ddsrt_close (listener), DDS_RETCODE_OK);
}
