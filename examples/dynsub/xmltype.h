// Copyright(c) 2026 ZettaScale Technology and others
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License v. 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
// v. 1.0 which is available at
// http://www.eclipse.org/org/documents/edl-v10.php.
//
// SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

#ifndef XMLTYPE_H
#define XMLTYPE_H

#include "dds/ddsrt/attributes.h"

#include "xmltype.h"
#include "domtree.h"

ddsrt_nonnull_all
ddsrt_attribute_noreturn
ddsrt_attribute_format_printf (1, 2)
void exitfmt (const char *fmt, ...);

ddsrt_nonnull_all
ddsrt_attribute_noreturn
ddsrt_attribute_format_printf (2, 3)
void exitelem (const struct elem *elem, const char *fmt, ...);

#endif
