// Copyright(c) 2022 ZettaScale Technology and others
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License v. 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
// v. 1.0 which is available at
// http://www.eclipse.org/org/documents/edl-v10.php.
//
// SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

#include <assert.h>
#include <string.h>

#include "CUnit/Theory.h"

#include "dds/dds.h"
#include "dds/ddsrt/environ.h"
#include "dds/ddsrt/heap.h"
#include "dds/ddsrt/io.h"
#include "dds/ddsrt/string.h"
#include "dds/ddsi/ddsi_domaingv.h"
#include "ddsi__nwpart.h"
#include "ddsi__tran.h"
#include "nwpart_test.h"
#include "test_util.h"

static bool check_address_list (const char *expected, struct ddsi_networkpartition_address *as)
{
  char *copy = ddsrt_strdup (expected), *cursor = copy, *tok;
  while ((tok = ddsrt_strsep (&cursor, ",")) != NULL)
  {
    if (as == NULL) {
      tprintf ("check_address_list: too few addresses\n");
      goto err;
    }
    char buf[DDSI_LOCSTRLEN];
    ddsi_locator_to_string (buf, sizeof (buf), &as->loc);
    if (strcmp (tok, buf) != 0) {
      tprintf ("check_address_list: expected %s, got %s\n", tok, buf);
      goto err;
    }
    as = as->next;
  }
  if (as != NULL) {
    tprintf ("check_address_list: too many addresses\n");
    goto err;
  }
  ddsrt_free (copy);
  return true;
err:
  ddsrt_free (copy);
  return false;
}

CU_TheoryDataPoints(ddsc_nwpart, definition) = {
  CU_DataPoints(struct ddsi_config_networkpartition_listelem,
    { .name = "p0", .address_string = "192.168.1.1", .interface_names = "eth1" },  // both unicast & interface
    { .name = "p1", .address_string = "", .interface_names = "not_an_interface" }, // non-existent interface
    { .name = "p2", .address_string = "239.255.0.8", .interface_names = "nomc" },  // multicast address on non-mc intf
    { .name = "p3", .address_string = "239.255.0.8,193.168.0.1", .interface_names = "" }, // multicast address on non-mc intf
    { .name = "p4", .address_string = "239.255.0.8", .interface_names = "" },      // multicast address, no mc-capable intf
    { .name = "p5", .address_string = "7.7.7.7", .interface_names = "" },          // no matching interface
    { .name = "p6", .address_string = "192.168.1.7", .interface_names = "" },      // network part of address, but host part non-zero
    //
    { .name = "p7", .address_string = "192.168.1.1", .interface_names = "" },
    { .name = "p8", .address_string = "", .interface_names = "lo,eth0" },
    { .name = "p9", .address_string = "239.255.0.8", .interface_names = "eth1,lo,eth0" },
    { .name = "pA", .address_string = "192.169.1.1", .interface_names = "" },     // matching should also work on external address
    { .name = "pB", .address_string = "192.168.1.0", .interface_names = "" },     // only network part of address
    { .name = "pC", .address_string = "239.255.0.4,239.255.0.5", .interface_names = "" }),
  CU_DataPoints(bool, // allow_mc
    true, true, true, true, false, true, true,
    true, true, true, true, true, true),
  CU_DataPoints(const char *, // uc addresses
    // expecting an error
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    // note: output is expected to be "external" address
    // input order is maintained in lists of addresses in network partition
    "udp/192.169.1.1:31415",
    "udp/127.0.0.1:31415,udp/192.169.0.1:31415",
    "udp/192.169.1.1:31415,udp/127.0.0.1:31415,udp/192.169.0.1:31415",
    "udp/192.169.1.1:31415",
    "udp/192.169.1.1:31415",
    ""),
  CU_DataPoints(const char *, // mc addresses
    // expecting an error
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    // note: output is expected to be "external" address
    "",
    "",
    "udp/239.255.0.8:7401",
    "",
    "",
    "udp/239.255.0.4:7401,udp/239.255.0.5:7401")
};
CU_Theory ((struct ddsi_config_networkpartition_listelem ps, bool allow_mc, const char *uc, const char *mc), ddsc_nwpart, definition)
{
  // Low-level trickery so we can control the addresses/network interfaces without
  // having any system dependency
  assert ((uc == NULL) == (mc == NULL));
  tprintf ("test: %s\n", ps.name);
  struct ddsi_domaingv gv;
  struct ddsi_config config;
  ddsi_config_init_default (&config);
  config.networkPartitions = &ps;
  nwpart_test_setup (&gv, &config, allow_mc, true);
  int rc = ddsi_convert_nwpart_config (&gv, 31415);
  if (uc == NULL) {
    CU_ASSERT_LT_FATAL (rc, 0);
    CU_ASSERT_GT_FATAL (nwpart_test_log_count (), 0);
  } else {
    CU_ASSERT_EQ_FATAL (rc, 0);
    CU_ASSERT_EQ_FATAL (nwpart_test_log_count (), 0);
    CU_ASSERT_FATAL (check_address_list (uc, ps.uc_addresses));
    CU_ASSERT_FATAL (check_address_list (mc, ps.asm_addresses));
  }
  ddsi_free_config_nwpart_addresses (&gv);
  nwpart_test_teardown (&gv);
}

CU_Test (ddsc_nwpart, duplicate)
{
  // network partition names are case-insensitive, it appears,
  // so make the duplicate name use a different case
  const char *config =
    "<Partitioning>"
    "  <NetworkPartitions>"
    "    <NetworkPartition name=\"p2\" address=\"239.255.0.13\"/>"
    "    <NetworkPartition name=\"p1\" address=\"239.255.0.12\"/>"
    "    <NetworkPartition name=\"P2\" address=\"239.255.0.11\"/>"
    "  </NetworkPartitions>"
    "</Partitioning>";
  dds_entity_t eh = dds_create_domain (0, config);
  CU_ASSERT_LT_FATAL (eh, 0);
}

CU_Test (ddsc_nwpart, mapping_undefined)
{
  // Network partition names are case-insensitive, it appears,
  // so make the duplicate name use a different case.
  //
  // Test depends on multicast support, but most regular machines
  // and the CI all support it, so that is not an issue in practice.
  const char *config =
    "${CYCLONEDDS_URI},<Partitioning>"
    "  <NetworkPartitions>"
    "    <NetworkPartition name=\"p2\" address=\"239.255.0.13\"/>"
    "    <NetworkPartition name=\"p1\" address=\"239.255.0.12\"/>"
    "    <NetworkPartition name=\"p0\" address=\"239.255.0.11\"/>"
    "  </NetworkPartitions>"
    "  <PartitionMappings>"
    "    <PartitionMapping DCPSPartitionTopic=\"a.b\" networkpartition=\"pX\"/>"
    "  </PartitionMappings>"
    "</Partitioning>";
  char *config1 = ddsrt_expand_envvars (config, 0);
  dds_entity_t eh = dds_create_domain (0, config1);
  ddsrt_free (config1);
  CU_ASSERT_LT_FATAL (eh, 0);
}

CU_Test (ddsc_nwpart, mapping_multiple)
{
  // Network partition names are case-insensitive, it appears,
  // so make the mapping use a different case.
  //
  // Test depends on multicast support, but most regular machines
  // and the CI all support it, so that is not an issue in practice.
  const char *config =
    "${CYCLONEDDS_URI},<Partitioning>"
    "  <NetworkPartitions>"
    "    <NetworkPartition name=\"p2\" address=\"239.255.0.13\"/>"
    "    <NetworkPartition name=\"p1\" address=\"239.255.0.12\"/>"
    "    <NetworkPartition name=\"p0\" address=\"239.255.0.11\"/>"
    "  </NetworkPartitions>"
    "  <PartitionMappings>"
    "    <PartitionMapping DCPSPartitionTopic=\"a.b\" networkpartition=\"P0\"/>"
    "    <PartitionMapping DCPSPartitionTopic=\"c.d\" networkpartition=\"p2\"/>"
    "  </PartitionMappings>"
    "</Partitioning>";
  char *config1 = ddsrt_expand_envvars (config, 0);
  dds_entity_t eh = dds_create_domain (0, config1);
  ddsrt_free (config1);
  CU_ASSERT_GT_FATAL (eh, 0);
  struct ddsi_domaingv * const gv = get_domaingv (eh);
  // all of this is order preserving; check that the entries meet that expectation
  struct ddsi_config_partitionmapping_listelem *m0, *m1;
  m0 = gv->config.partitionMappings;
  m1 = m0->next;
  CU_ASSERT_STREQ_FATAL (m0->networkPartition, "P0");
  CU_ASSERT_STREQ_FATAL (m1->networkPartition, "p2");
  CU_ASSERT_EQ_FATAL (m1->next, NULL);
  struct ddsi_config_networkpartition_listelem *p0, *p1, *p2;
  p2 = gv->config.networkPartitions; // this order matches the names
  p1 = p2->next;
  p0 = p1->next;
  CU_ASSERT_STREQ_FATAL (p2->name, "p2");
  CU_ASSERT_STREQ_FATAL (p1->name, "p1");
  CU_ASSERT_STREQ_FATAL (p0->name, "p0");
  CU_ASSERT_EQ_FATAL (p0->next, NULL);
  // given that:
  CU_ASSERT_EQ_FATAL (m0->partition, p0);
  CU_ASSERT_EQ_FATAL (m1->partition, p2);
  dds_delete (eh);
}

// ParticipantIndex none/auto and ManySocketsMode none/single take very different paths
// when making sockets and selecting port numbers.  I have been bitten by that difference,
// so better run through the set of combinations (MSM = none requires PI = none).
CU_TheoryDataPoints(ddsc_nwpart, full_stack_init) = {
  CU_DataPoints(const char *, "none", "auto", "none"),    // participant index
  CU_DataPoints(const char *, "single", "single", "none") // many sockets mode
};
CU_Theory ((const char *pistr, const char *msmstr), ddsc_nwpart, full_stack_init)
{
  dds_return_t rc;
  const char *transport = test_config_inherits_fakeudp () ? "<Transport>fakeudp</Transport>" : "";
  char *config = NULL;

  // Start up a domain to discover the interface name.  Do not inherit the
  // full CYCLONEDDS_URI here: the test constructs an explicit interface
  // selection below, and inheriting one from the environment as well can select
  // the same interface twice.  Preserve the fakeudp transport choice because
  // the test suite may be running with fake network topologies.
  (void) ddsrt_asprintf (&config, "<General>%s</General>", transport);
  dds_entity_t eh = dds_create_domain (0, config);
  ddsrt_free (config);
  CU_ASSERT_GT_FATAL (eh, 0);
  const struct ddsi_domaingv *gv = get_domaingv (eh);
  CU_ASSERT_NEQ_FATAL (gv, NULL);
  // Construct a configuration using this interface.  Use a high value for
  // "max auto participant index" to avoid spurious failures caused by running
  // several tests in parallel (using a unique domain id would help, too, but
  // where to find a unique id?)
  config = NULL;
  (void) ddsrt_asprintf (&config,
    "<General>"
    "  %s"
    "  <Interfaces>"
    "    <NetworkInterface name=\"%s\"/>"
    "  </Interfaces>"
    "</General>"
    "<Discovery>"
    "  <MaxAutoParticipantIndex>100</MaxAutoParticipantIndex>"
    "  <ParticipantIndex>%s</ParticipantIndex>"
    "</Discovery>"
    "<Compatibility>"
    "  <ManySocketsMode>%s</ManySocketsMode>"
    "</Compatibility>"
    "<Partitioning>"
    "  <NetworkPartitions>"
    "    <NetworkPartition name=\"part\" address=\"239.255.0.13\" interface=\"%s\"/>"
    "  </NetworkPartitions>"
    "</Partitioning>",
    transport,
    gv->interfaces[0].name,
    pistr,
    msmstr,
    gv->interfaces[0].name);
  rc = dds_delete (eh);
  CU_ASSERT_EQ_FATAL (rc, 0);
  // start up a new domain with this new configuration
  eh = dds_create_domain (0, config);
  ddsrt_free (config);
  CU_ASSERT_GT_FATAL (eh, 0);
  gv = get_domaingv (eh);
  CU_ASSERT_NEQ_FATAL (gv, NULL);
  // verify that the unicast address and port number in the network partition
  // are correct (this is slightly different from the other tests: those mock
  // most of the code, this uses the actual code)
  struct ddsi_config_networkpartition_listelem const * const np = gv->config.networkPartitions;
  struct ddsi_locator const * const nploc = &np->uc_addresses->loc;
  CU_ASSERT_MEMEQ (gv->interfaces[0].loc.address, sizeof (gv->interfaces[0].loc.address), nploc->address, sizeof (nploc->address));
  CU_ASSERT_MEMEQ (gv->loc_default_uc.address, sizeof (gv->loc_default_uc.address), nploc->address, sizeof (nploc->address));
  CU_ASSERT_EQ_FATAL (gv->loc_default_uc.port, nploc->port);
  rc = dds_delete (eh);
  CU_ASSERT_EQ_FATAL (rc, 0);
}
