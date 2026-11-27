// Copyright(c) 2025 ZettaScale Technology and others
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License v. 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
// v. 1.0 which is available at
// http://www.eclipse.org/org/documents/edl-v10.php.
//
// SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

#include "CUnit/Test.h"
#include "tcp_test.h"

CU_Test (ddsc_tcp, release_listener_on_init_failure)
{
  ddsrt_socket_t socket;
  uint32_t port;
  tcp_test_bind_loopback_socket (&socket, &port);
  CU_ASSERT_EQ_FATAL (ddsrt_close (socket), DDS_RETCODE_OK);
  /* Partition addresses are validated after the listener is bound. A port is invalid here. */
  const char *bad_partition =
    "<Partitioning><NetworkPartitions><NetworkPartition name='bad' address='127.0.0.1:42'/>"
    "</NetworkPartitions></Partitioning>";
  CU_ASSERT_LT_FATAL (tcp_test_create_isolated_domain (0, (int) port, "2 s", bad_partition), 0);
  dds_entity_t domain = tcp_test_create_isolated_domain (0, (int) port, "2 s", "");
  CU_ASSERT_GT_FATAL (domain, 0);
  CU_ASSERT_EQ (dds_delete (domain), DDS_RETCODE_OK);
}
