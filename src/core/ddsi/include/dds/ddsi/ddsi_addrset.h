// Copyright(c) 2006 to 2022 ZettaScale Technology and others
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License v. 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
// v. 1.0 which is available at
// http://www.eclipse.org/org/documents/edl-v10.php.
//
// SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

#ifndef DDSI_ADDRSET_H
#define DDSI_ADDRSET_H

#include "dds/ddsrt/sync.h"
#include "dds/ddsrt/atomics.h"
#include "dds/ddsrt/avl.h"
#include "dds/ddsi/ddsi_locator.h"

#if defined (__cplusplus)
extern "C" {
#endif

struct ddsi_addrset;

typedef void (*ddsi_addrset_forall_fun_t) (const ddsi_xlocator_t *loc, void *arg);

/** @component locators */
bool ddsi_addrset_empty (const struct ddsi_addrset *as)
  ddsrt_nonnull_all;

/** @component locators */
void ddsi_addrset_forall (struct ddsi_addrset *as, ddsi_addrset_forall_fun_t f, void *arg)
  ddsrt_nonnull ((1,2));

/** @component locators */
struct ddsi_domaingv;
DDS_EXPORT void ddsi_add_locator_to_addrset (const struct ddsi_domaingv *gv, struct ddsi_addrset *as, const ddsi_locator_t *loc)
  ddsrt_nonnull_all;

/** @component locators */
DDS_EXPORT void ddsi_remove_from_addrset (const struct ddsi_domaingv *gv, struct ddsi_addrset *as, const ddsi_xlocator_t *loc)
  ddsrt_nonnull_all;

#if defined (__cplusplus)
}
#endif
#endif /* DDSI_ADDRSET_H */
