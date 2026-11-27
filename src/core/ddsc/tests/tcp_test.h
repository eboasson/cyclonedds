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

void tcp_test_run_config (const char *extra, void (*action) (dds_entity_t rd, dds_entity_t wr, void *arg), void *arg);
void tcp_test_basic_write (dds_entity_t rd, dds_entity_t wr, void *arg);

#endif /* TCP_TEST_H */
