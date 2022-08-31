/*
 * Copyright(c) 2022 ZettaScale Technology and others
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v. 1.0 which is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 */
#ifndef DDSI_VIRTUAL_INTERFACE_LOADER_H
#define DDSI_VIRTUAL_INTERFACE_LOADER_H

#include "dds/ddsc/dds_virtual_interface.h"
#include "dds/ddsi/ddsi_config_impl.h"
#include "dds/ddsrt/dynlib.h"

bool ddsi_virtual_interface_load(struct ddsi_domaingv *gv, struct ddsi_config_virtual_interface *config, ddsi_virtual_interface_t **out);

#endif // DDSI_VIRTUAL_INTERFACE_LOADER_H
