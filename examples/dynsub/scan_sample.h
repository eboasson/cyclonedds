// Copyright(c) 2022 to 2023 ZettaScale Technology and others
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License v. 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
// v. 1.0 which is available at
// http://www.eclipse.org/org/documents/edl-v10.php.
//
// SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

#ifndef SCAN_SAMPLE_H
#define SCAN_SAMPLE_H

#include "dds/dds.h"
#include "dds/ddsi/ddsi_xt_typeinfo.h"

#include "domtree.h"

void *scan_sample (const struct elem *input, const DDS_XTypes_CompleteTypeObject *typeobj);

#endif /* PRINT_SAMPLE_H */
