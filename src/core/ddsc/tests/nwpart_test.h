// Copyright(c) 2022 ZettaScale Technology and others
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License v. 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
// v. 1.0 which is available at
// http://www.eclipse.org/org/documents/edl-v10.php.
//
// SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

#ifndef NWPART_TEST_H
#define NWPART_TEST_H

#include <stdbool.h>

struct ddsi_config;
struct ddsi_domaingv;

void nwpart_test_setup (struct ddsi_domaingv *gv, const struct ddsi_config *config, bool allow_mc, bool weird_extloc);
void nwpart_test_teardown (struct ddsi_domaingv *gv);
int nwpart_test_log_count (void);

#endif /* NWPART_TEST_H */
