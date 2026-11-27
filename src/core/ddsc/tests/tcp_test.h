// Copyright(c) 2025 ZettaScale Technology and others
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License v. 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
// v. 1.0 which is available at
// http://www.eclipse.org/org/documents/edl-v10.php.
//
// SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

#ifndef TCP_TEST_H
#define TCP_TEST_H

#include "dds/dds.h"
#include "dds/ddsi/ddsi_guid.h"
#include "dds/ddsi/ddsi_locator.h"
#include "dds/ddsrt/sockets.h"

struct ddsi_domaingv;

void tcp_test_run_config (const char *extra, void (*action) (dds_entity_t rd, dds_entity_t wr, void *arg), void *arg);
void tcp_test_basic_write (dds_entity_t rd, dds_entity_t wr, void *arg);
bool tcp_test_wait_for_proxy (struct ddsi_domaingv *gv, const ddsi_guid_t *guid, bool present);

void tcp_test_bind_loopback_socket (ddsrt_socket_t *listener, uint32_t *port);
dds_entity_t tcp_test_create_isolated_domain (dds_domainid_t id, int port, const char *timeout, const char *extra_config);
dds_return_t tcp_test_write_byte (struct ddsi_domaingv *gv, const ddsi_locator_t *dst, char byte, uint32_t flags, size_t *written);
void tcp_test_connect_to_listener (ddsrt_socket_t *sock, const ddsi_locator_t *loc);

#endif /* TCP_TEST_H */
