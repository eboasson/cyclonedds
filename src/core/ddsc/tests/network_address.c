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
#include <stdio.h>
#include <string.h>

#include "CUnit/Theory.h"

#include "dds/dds.h"
#include "dds/ddsrt/heap.h"
#include "dds/ddsrt/io.h"
#include "dds/ddsi/ddsi_domaingv.h"
#include "dds/ddsi/ddsi_iid.h"
#include "dds/ddsi/ddsi_init.h"
#include "ddsi__addrset.h"
#include "ddsi__discovery_endpoint.h"
#include "ddsi__misc.h"
#include "ddsi__plist.h"
#include "ddsi__thread.h"
#include "ddsi__tran.h"
#include "ddsi__udp.h"
#include "nwpart_test.h"
#include "test_util.h"

static int errcount;

int nwpart_test_log_count (void)
{
  return errcount;
}

static void null_log_sink (void *vcount, const dds_log_data_t *msg)
{
  int *count = vcount;
  tprintf ("%s", msg->message);
  (*count)++;
}

static void intf_init (struct ddsi_network_interface *intf, int index, bool allow_mc, bool weird_extloc)
{
  memset (intf, 0, sizeof (*intf));
  intf->loc.kind = DDSI_LOCATOR_KIND_UDPv4;
  intf->loc.port = 0;
  // IPv4 locator address format: 12 leading 0s
  // - index 0 is loopback, indices > 0 are regular networks
  // - internal address: 127.0.0.1 / 192.168.(index-1).1
  // - configured external address if weird_extloc: 127.0.0.1 / 192.169.(index-1).1
  // netmask is 255.0.0.0 / 255.255.255.0
  // loopback and index > 1 are multicast-capable (if allow_mc)
  // index 1 is never multicast-capable
  if (index <= 0)
  {
    intf->loc.address[12] = 127;
    intf->loc.address[13] = 0;
    intf->loc.address[14] = 0;
    intf->loc.address[15] = 1;
    intf->netmask.address[12] = 255;
    intf->netmask.address[13] = 0;
    intf->netmask.address[14] = 0;
    intf->netmask.address[15] = 0;
    intf->extloc = intf->loc;
  }
  else
  {
    intf->loc.address[12] = (index == 1) ? 193 : 192;
    intf->loc.address[13] = 168;
    intf->loc.address[14] = (index >= 2) ? (unsigned char) (index - 2) : 0;
    intf->loc.address[15] = 1;
    intf->netmask.address[12] = 255;
    intf->netmask.address[13] = 255;
    intf->netmask.address[14] = 255;
    intf->netmask.address[15] = 0;
    intf->extloc = intf->loc;
    if (weird_extloc)
      intf->extloc.address[13]++;
  }
  intf->netmask.kind = DDSI_LOCATOR_KIND_UDPv4;
  // if_index is whatever index the operating system assigned to it, we just put
  // something in that would (probably) lead to disaster if used as an index in
  // gv->interfaces
  intf->if_index = 1000u + (uint32_t) index;
  intf->mc_capable = (!allow_mc || index == 1) ? 0 : 1;
  intf->mc_flaky = 0;
  intf->allow_multicast = (allow_mc && intf->mc_capable) ? DDSI_AMC_TRUE : DDSI_AMC_FALSE;
  intf->point_to_point = 0;
  intf->loopback = (index == 0) ? 1 : 0;
  intf->prefer_multicast = 0;
  intf->priority = 0;
  intf->addrset_costs.uc = 2;
  intf->addrset_costs.mc = 3;
  intf->addrset_costs.ssm = 2;
  intf->addrset_costs.delivered = -1;
  intf->addrset_costs.discarded = 1;
  intf->addrset_costs.redundant_psmx = 0;
  // naming them as lo, nomc, eth0, eth1, ... in an attempt at reducing headaches
  // in remembering what's what when writing test definitions
  switch (index)
  {
    case 0:  (void) ddsrt_asprintf (&intf->name, "lo"); break;
    case 1:  (void) ddsrt_asprintf (&intf->name, "nomc"); break;
    default: (void) ddsrt_asprintf (&intf->name, "eth%d", index - 2); break;
  }
}

void nwpart_test_setup (struct ddsi_domaingv *gv, const struct ddsi_config *config, bool allow_mc, bool weird_extloc)
{
  errcount = 0;
  ddsi_iid_init ();
  ddsi_thread_states_init ();

  // register the main thread, then claim it as spawned by Cyclone because the
  // internal processing has various asserts that it isn't an application thread
  // doing the dirty work
  struct ddsi_thread_state * const thrst = ddsi_lookup_thread_state ();
  // coverity[missing_lock:FALSE]
  assert (thrst->state == DDSI_THREAD_STATE_LAZILY_CREATED);
  thrst->state = DDSI_THREAD_STATE_ALIVE;
  ddsrt_atomic_stvoidp (&thrst->gv, &gv);

  memset (gv, 0, sizeof (*gv));
  gv->config = *config;

  // UDP means:
  gv->config.publish_uc_locators = 1;
  gv->config.enable_uc_locators = 1;
  (void) ddsi_udp_init (gv);
  gv->m_factory = ddsi_factory_find (gv, "udp");
  assert (gv->m_factory != NULL);

  DDSRT_STATIC_ASSERT (4 <= MAX_XMIT_CONNS);
  gv->extmask.kind = DDSI_LOCATOR_KIND_INVALID;
  gv->n_interfaces = 4;
  for (int i = 0; i < gv->n_interfaces; i++)
  {
    intf_init (&gv->interfaces[i], i, allow_mc, weird_extloc);
    // minimalistic inialisation of xmit conns just so we can use xlocators and addrsets
    struct ddsi_tran_conn *fakeconn = ddsrt_malloc (sizeof (*fakeconn));
    fakeconn->m_factory = gv->m_factory;
    fakeconn->m_base.gv = gv;
    fakeconn->m_interf = &gv->interfaces[i];
    gv->xmit_conns_meta[i] = fakeconn;
    gv->xmit_conns_data[i] = fakeconn;
  }

  ddsi_config_domain_init (gv, NULL);
  dds_set_log_sink (null_log_sink, &errcount);
  dds_set_trace_sink (null_log_sink, &errcount);
  gv->logconfig.c.tracemask = gv->logconfig.c.mask = UINT32_MAX;
}

void nwpart_test_teardown (struct ddsi_domaingv *gv)
{
  ddsi_config_domain_fini (gv, NULL);
  // for some reason, GCC 12's analyzer thinks some of this is uninitialised
#if __GNUC__ >= 12
  DDSRT_WARNING_GNUC_OFF(analyzer-use-of-uninitialized-value)
#endif
  for (int i = 0; i < gv->n_interfaces; i++)
  {
    ddsrt_free (gv->xmit_conns_data[i]);
    ddsrt_free (gv->interfaces[i].name);
  }
  while (gv->ddsi_tran_factories)
  {
    struct ddsi_tran_factory *f = gv->ddsi_tran_factories;
    gv->ddsi_tran_factories = f->m_factory;
    ddsi_factory_free (f);
  }
#if __GNUC__ >= 12
  DDSRT_WARNING_GNUC_ON(analyzer-use-of-uninitialized-value)
#endif

  // On shutdown, there is an expectation that the thread was discovered dynamically.
  // We overrode it in the setup code, we undo it now.
  // coverity[missing_lock:FALSE]
  struct ddsi_thread_state * const thrst = ddsi_lookup_thread_state ();
  thrst->state = DDSI_THREAD_STATE_LAZILY_CREATED;
  ddsi_thread_states_fini ();
  ddsi_iid_fini ();
}

struct check_address_present_arg {
  const char **expected;
  bool ok;
};

static void check_address_present (const ddsi_xlocator_t *loc, void *varg)
{
  struct check_address_present_arg *arg = varg;
  char buf[DDSI_LOCSTRLEN];
  ddsi_xlocator_to_string (buf, sizeof (buf), loc);
  printf (" %s", buf);
  fflush (stdout);
  int i = 0;
  while (arg->expected[i] && strcmp (arg->expected[i], buf) != 0)
    i++;
  if (arg->expected[i] == NULL)
    arg->ok = false;
}

CU_TheoryDataPoints(ddsc_nwpart, selected_addrs) = {
  CU_DataPoints(bool, // same machine = loopback applies
    true,  true,  false, false,
    true,  true,  false, false,
    true,  true,  false, false,
    true,  true,  false, false,
    true,  true,  false, false),
  CU_DataPoints(bool, // as_default has multicast address (see also # mc addrs)
    true,  false, true,  false,
    true,  false, true,  false,
    true,  false, true,  false,
    true,  false, true,  false,
    true,  false, true,  false),
  CU_DataPoints(int, // # uc addrs in SEDP: if 0, use as_default UC addrs for interfaces
    0,     0,     0,     0,
    2,     2,     2,     2,
    3,     3,     3,     3,
    3,     3,     3,     3,
    3,     3,     3,     3),
  CU_DataPoints(int, // # mc addrs in SEDP: if mc ok, then if 0 use as_default MC addr else use 239.255.0.2 (+.3)
    0,     1,     0,     1,
    1,     0,     1,     0,
    0,     0,     0,     0,
    1,     1,     1,     1,
    2,     2,     2,     2),
  CU_DataPoints(const char **, // expected result
    (const char *[]){ // same host,  mc in as_default: yes, SEDP 0 uc, 0 mc
      "udp/127.0.0.1:31416@1000", "udp/193.168.0.1:31416@1001", "udp/192.168.0.1:31416@1002", "udp/192.168.1.1:31416@1003",
      "udp/239.255.0.1:7401@1000", "udp/239.255.0.1:7401@1002", "udp/239.255.0.1:7401@1003", NULL },
    (const char *[]){ // same host,  mc in as_default: no,  SEDP 0 uc, 1 mc
      "udp/127.0.0.1:31416@1000", "udp/193.168.0.1:31416@1001", "udp/192.168.0.1:31416@1002", "udp/192.168.1.1:31416@1003",
      "udp/239.255.0.2:7401@1000", "udp/239.255.0.2:7401@1002", "udp/239.255.0.2:7401@1003", NULL },
    (const char *[]){ // other host, mc in as_default: yes, SEDP 0 uc, 0 mc
      "udp/193.168.0.2:31416@1001", "udp/192.168.0.2:31416@1002", "udp/192.168.1.2:31416@1003",
      "udp/239.255.0.1:7401@1002", "udp/239.255.0.1:7401@1003", NULL },
    (const char *[]){ // other host, mc in as_default: no,  SEDP 0 uc, 1 mc
      "udp/193.168.0.2:31416@1001", "udp/192.168.0.2:31416@1002", "udp/192.168.1.2:31416@1003",
      "udp/239.255.0.2:7401@1002", "udp/239.255.0.2:7401@1003", NULL },
    //
    (const char *[]){ // same host,  mc in as_default: yes, SEDP 2 uc, 1 mc
      "udp/127.0.0.1:31416@1000", "udp/193.168.0.1:31416@1001",
      "udp/239.255.0.2:7401@1000", NULL },
    (const char *[]){ // same host,  mc in as_default: no,  SEDP 2 uc, 0 mc
      "udp/127.0.0.1:31416@1000", "udp/193.168.0.1:31416@1001", NULL },
    (const char *[]){ // other host, mc in as_default: yes, SEDP 2 uc, 1 mc
      "udp/193.168.0.2:31416@1001", NULL },
    (const char *[]){ // other host, mc in as_default: no,  SEDP 2 uc, 0 mc
      "udp/193.168.0.2:31416@1001", NULL },
    //
    // Expected behaviour: if SEDP gives:
    // - no addresses, use ppant uni- and multicast addresses
    // - only multicast, use those for multicast and use ppant address for unicast
    // - only unicast, use only those (i.e., disable multicast for this reader, cos
    //   that's a useful feature but it cannot be configured otherwise given the
    //   information available in the protocol)
    // - both, use only those
    // So here we're not expecting multicast in the resulting addrset even though the
    // the proxy participant does allow it and one could be forgiven for thinking that
    // it would be inherited.
    (const char *[]){ // same host,  mc in as_default: yes, SEDP 3 uc, 0 mc
      "udp/127.0.0.1:31416@1000", "udp/193.168.0.1:31416@1001", "udp/192.168.0.1:31416@1002", NULL },
    (const char *[]){ // same host,  mc in as_default: no,  SEDP 3 uc, 0 mc
      "udp/127.0.0.1:31416@1000", "udp/193.168.0.1:31416@1001", "udp/192.168.0.1:31416@1002", NULL },
    (const char *[]){ // other host, mc in as_default: yes, SEDP 3 uc, 0 mc
      "udp/193.168.0.2:31416@1001", "udp/192.168.0.2:31416@1002", NULL },
    (const char *[]){ // other host, mc in as_default: no,  SEDP 3 uc, 0 mc
      "udp/193.168.0.2:31416@1001", "udp/192.168.0.2:31416@1002", NULL },
    //
    (const char *[]){ // same host,  mc in as_default: yes, SEDP 3 uc, 1 mc
      "udp/127.0.0.1:31416@1000", "udp/193.168.0.1:31416@1001", "udp/192.168.0.1:31416@1002",
      "udp/239.255.0.2:7401@1000", "udp/239.255.0.2:7401@1002", NULL },
    (const char *[]){ // same host,  mc in as_default: no,  SEDP 3 uc, 1 mc
      "udp/127.0.0.1:31416@1000", "udp/193.168.0.1:31416@1001", "udp/192.168.0.1:31416@1002",
      "udp/239.255.0.2:7401@1000", "udp/239.255.0.2:7401@1002", NULL },
    (const char *[]){ // other host, mc in as_default: yes, SEDP 3 uc, 1 mc
      "udp/193.168.0.2:31416@1001", "udp/192.168.0.2:31416@1002",
      "udp/239.255.0.2:7401@1002", NULL },
    (const char *[]){ // other host, mc in as_default: no,  SEDP 3 uc, 1 mc
      "udp/193.168.0.2:31416@1001", "udp/192.168.0.2:31416@1002",
      "udp/239.255.0.2:7401@1002", NULL },
    //
    (const char *[]){ // same host,  mc in as_default: yes, SEDP 3 uc, 2 mc
      "udp/127.0.0.1:31416@1000", "udp/193.168.0.1:31416@1001", "udp/192.168.0.1:31416@1002",
      "udp/239.255.0.2:7401@1000", "udp/239.255.0.2:7401@1002",
      "udp/239.255.0.3:7401@1000", "udp/239.255.0.3:7401@1002", NULL },
    (const char *[]){ // same host,  mc in as_default: no,  SEDP 3 uc, 2 mc
      "udp/127.0.0.1:31416@1000", "udp/193.168.0.1:31416@1001", "udp/192.168.0.1:31416@1002",
      "udp/239.255.0.2:7401@1000", "udp/239.255.0.2:7401@1002",
      "udp/239.255.0.3:7401@1000", "udp/239.255.0.3:7401@1002", NULL },
    (const char *[]){ // other host, mc in as_default: yes, SEDP 3 uc, 2 mc
      "udp/193.168.0.2:31416@1001", "udp/192.168.0.2:31416@1002",
      "udp/239.255.0.2:7401@1002",
      "udp/239.255.0.3:7401@1002", NULL },
    (const char *[]){ // other host, mc in as_default: no,  SEDP 3 uc, 2 mc
      "udp/193.168.0.2:31416@1001", "udp/192.168.0.2:31416@1002",
      "udp/239.255.0.2:7401@1002",
      "udp/239.255.0.3:7401@1002", NULL })
};

CU_Theory ((bool same_machine, bool proxypp_has_defmc, int n_ep_uc, int n_ep_mc, const char **expected), ddsc_nwpart, selected_addrs)
{
  tprintf ("---------------\n");
  tprintf ("same_machine %d proxypp_has_defmc %d n_ep_uc %d n_ep_mc %d\n", same_machine, proxypp_has_defmc, n_ep_uc, n_ep_mc);
  struct ddsi_domaingv gv;
  struct ddsi_config config;
  ddsi_config_init_default (&config);
  config.transport_selector = DDSI_TRANS_UDP;
  config.allowMulticast = DDSI_AMC_DEFAULT;
  memset (&gv, 0, sizeof (gv)); // solves a spurious gcc-12 "uninitialized" warning
  nwpart_test_setup (&gv, &config, true, false);
  tprintf ("interfaces =\n");
  for (int i = 0; i < gv.n_interfaces; i++)
  {
    char buf[DDSI_LOCSTRLEN];
    tprintf ("  %s", ddsi_locator_to_string_no_port (buf, sizeof (buf), &gv.interfaces[i].loc));
    printf (" extern: %s", ddsi_locator_to_string_no_port (buf, sizeof (buf), &gv.interfaces[i].extloc));
    printf (" (%smc)\n", gv.interfaces[i].mc_capable ? "" : "no-");
    fflush (stdout);
  }

  // pretend the remote one is on another machine but on the same networks
  tprintf ("as_default =\n");
  struct ddsi_addrset *as_default = ddsi_new_addrset ();
  for (int i = (same_machine ? 0 : 1); i < gv.n_interfaces; i++)
  {
    ddsi_xlocator_t xloc = {
      .conn = gv.xmit_conns_data[i],
      .c = gv.interfaces[i].extloc
    };
    xloc.c.port = 31416;
    if (!same_machine && i > 0) // i = 0 => loopback => no change
      xloc.c.address[15]++;
    char buf[DDSI_LOCSTRLEN];
    tprintf ("  %s\n", ddsi_xlocator_to_string (buf, sizeof (buf), &xloc));
    ddsi_add_xlocator_to_addrset (&gv, as_default, &xloc);
  }

  const ddsi_locator_t defmcloc = {
    .kind = DDSI_LOCATOR_KIND_UDPv4,
    .port = 7401,
    .address = { 0,0,0,0, 0,0,0,0, 0,0,0,0, 239,255,0,1 }
  };
  if (proxypp_has_defmc)
  {
    for (int i = (same_machine ? 0 : 1); i < gv.n_interfaces; i++)
    {
      if (gv.interfaces[i].mc_capable)
      {
        ddsi_xlocator_t xloc = { .conn = gv.xmit_conns_data[i], .c = defmcloc };
        char buf[DDSI_LOCSTRLEN];
        tprintf ("  %s\n", ddsi_xlocator_to_string (buf, sizeof (buf), &xloc));
        ddsi_add_xlocator_to_addrset (&gv, as_default, &xloc);
      }
    }
  }

  // remote endpoint: advertise the first few interfaces in unicast addresses
  // (interfaces are: lo, nomc, eth0, eth1)
  ddsi_plist_t plist;
  ddsi_plist_init_empty (&plist);
  struct ddsi_locators_one uc[MAX_XMIT_CONNS];
  assert (n_ep_uc <= gv.n_interfaces);
  for (int i = 0; i < n_ep_uc; i++)
  {
    uc[i].next = &uc[i+1];
    uc[i].loc = gv.interfaces[i].extloc;
    uc[i].loc.port = 31416;
    if (!same_machine && i > 0) // i = 0 => loopback => no change
      uc[i].loc.address[15]++; // see as_default above
  }
  if (n_ep_uc > 0)
  {
    uc[n_ep_uc-1].next = NULL;
    plist.unicast_locators = (ddsi_locators_t){ .n = (uint32_t)n_ep_uc, .first = &uc[0], .last = &uc[n_ep_uc-1] };
    plist.present |= PP_UNICAST_LOCATOR;
  }

  struct ddsi_locators_one mc[2] = {
    { .next = &mc[1],
      .loc = {
        .kind = DDSI_LOCATOR_KIND_UDPv4,
        .port = 7401,
        .address = { 0,0,0,0, 0,0,0,0, 0,0,0,0, 239,255,0,2 }
      }
    },
    { .next = NULL,
      .loc = {
        .kind = DDSI_LOCATOR_KIND_UDPv4,
        .port = 7401,
        .address = { 0,0,0,0, 0,0,0,0, 0,0,0,0, 239,255,0,3 }
      }
    }
  };
  assert (n_ep_mc <= (int) (sizeof (mc) / sizeof (mc[0])));
  if (n_ep_mc > 0)
  {
    mc[n_ep_mc-1].next = NULL;
    plist.multicast_locators = (ddsi_locators_t){ .n = (uint32_t)n_ep_mc, .first = &mc[0], .last = &mc[n_ep_mc-1] };
    plist.present |= PP_MULTICAST_LOCATOR;
  }

  {
    char buf[1024];
    ddsi_plist_print (buf, sizeof (buf), &plist);
    tprintf ("advertised plist: %s\n", buf);
  }

  struct ddsi_network_packet_info pktinfo;
  ddsi_set_unspec_locator (&pktinfo.src);
  pktinfo.if_index = 0;
  pktinfo.dst.kind = DDSI_LOCATOR_KIND_INVALID;
  struct ddsi_addrset *as = ddsi_get_endpoint_addrset (&gv, gv.xmit_conns_data, &plist, as_default, &pktinfo, false, false);

  int n = 0;
  while (expected[n])
    n++;
  struct check_address_present_arg arg = {
    .expected = expected,
    .ok = (ddsi_addrset_count (as) == (size_t) n)
  };
  tprintf ("addrset =");
  ddsi_addrset_forall (as, check_address_present, &arg);
  printf ("\n");
  if (arg.ok)
    tprintf ("OK\n");
  else
  {
    tprintf ("expected =");
    for (int i = 0; expected[i]; i++)
      printf (" %s", expected[i]);
    printf ("\n");
    tprintf ("(in any order)\n");
  }
  CU_ASSERT_NEQ (arg.ok, 0);
  ddsi_unref_addrset (as);
  // not calling plist_fini: we didn't allocate anything
  ddsi_unref_addrset (as_default);
  nwpart_test_teardown (&gv);
}
