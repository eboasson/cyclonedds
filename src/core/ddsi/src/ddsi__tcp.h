// Copyright(c) 2006 to 2020 ZettaScale Technology and others
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License v. 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
// v. 1.0 which is available at
// http://www.eclipse.org/org/documents/edl-v10.php.
//
// SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

#ifndef DDSI__TCP_H
#define DDSI__TCP_H

#include "dds/ddsi/ddsi_tran.h"

#if defined (__cplusplus)
extern "C" {
#endif

struct ddsi_domaingv;

/** @component tcp_transport */
int ddsi_tcp_init (struct ddsi_domaingv *gv);

/** @component tcp_transport */
struct ddsi_tran_factory *ddsi_tcp_new_factory (struct ddsi_domaingv *gv);

/** @component tcp_transport */
bool ddsi_tcp_start_connector (struct ddsi_tran_factory *factory);

/** @component tcp_transport */
void ddsi_tcp_stop_connector (struct ddsi_tran_factory *factory);

/** @component tcp_transport
    Accept a private stream without publishing it to RTPS. The caller owns
    the stream until ddsi_tcp_close_stream and must keep the listener alive. */
struct ddsi_tran_conn *ddsi_tcp_accept_stream (struct ddsi_tran_listener *listener);

/** @component tcp_transport */
dds_return_t ddsi_tcp_write_stream (struct ddsi_tran_listener *listener, struct ddsi_tran_conn *conn, const void *data, size_t size);

/** @component tcp_transport */
void ddsi_tcp_close_stream (struct ddsi_tran_listener *listener, struct ddsi_tran_conn *conn);

#if defined (__cplusplus)
}
#endif

#endif /* DDSI__TCP_H */
