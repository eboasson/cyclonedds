/*
 * Copyright(c) 2023 ZettaScale Technology and others
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v. 1.0 which is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 */
#ifndef DDSI_VIRTUAL_INTERFACE_H
#define DDSI_VIRTUAL_INTERFACE_H

#include "dds/ddsi/ddsi_locator.h"

#if defined (__cplusplus)
extern "C" {
#endif

struct ddsi_virtual_interface_locators {
  uint32_t length;
  struct {
      char *virtual_interface_name;
      ddsi_locator_t locator;
  } *items;
};

#if defined (__cplusplus)
}
#endif

#endif // DDSI_VIRTUAL_INTERFACE_H
