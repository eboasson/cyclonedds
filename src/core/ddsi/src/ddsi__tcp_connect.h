// Copyright(c) 2026 ZettaScale Technology and others
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License v. 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
// v. 1.0 which is available at
// http://www.eclipse.org/org/documents/edl-v10.php.
//
// SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

#ifndef DDSI__TCP_CONNECT_H
#define DDSI__TCP_CONNECT_H

#include "dds/features.h"
#include "dds/ddsrt/sockets.h"

#if defined (__cplusplus)
extern "C" {
#endif

struct ddsi_domaingv;
struct ddsi_ssl_ctx;
struct ddsi_tcp_conn;
struct ddsi_tcp_connector;
struct ssl_st;

/* Open a nonblocking socket and initiate connect. The connector owns any
   socket returned, including on error. */
dds_return_t ddsi_tcp_connect_begin (struct ddsi_tcp_conn *conn, ddsrt_socket_t *sock);

/* Runs on the domain-awake connector thread without the connector lock.
   Takes the submitted reference and any socket and TLS session allocated. */
void ddsi_tcp_connect_done (struct ddsi_tcp_conn *conn, dds_return_t result, ddsrt_socket_t sock, struct ssl_st *ssl);

#ifdef DDS_HAS_TCP_TLS
/* The same ownership transfer for a completed incoming TLS handshake. */
void ddsi_tcp_accept_done (struct ddsi_tcp_conn *conn, dds_return_t result, ddsrt_socket_t sock, struct ssl_st *ssl);

/* Transfers the connection reference and accepted socket only on success. */
bool ddsi_tcp_connector_accept (struct ddsi_tcp_connector *connector, struct ddsi_tcp_conn *conn, ddsrt_socket_t sock);
#endif

struct ddsi_tcp_connector *ddsi_tcp_connector_new (struct ddsi_domaingv *gv, struct ddsi_ssl_ctx *tls);

/* Transfers one connection reference if accepted. The caller is responsible
   for submitting at most one request for a given cache entry. */
bool ddsi_tcp_connector_submit (struct ddsi_tcp_connector *connector, struct ddsi_tcp_conn *conn);

/* Stop submissions, complete all outstanding requests, and join the worker.
   Stop/free are serialized by the domain startup and shutdown paths. */
void ddsi_tcp_connector_stop (struct ddsi_tcp_connector *connector);
void ddsi_tcp_connector_free (struct ddsi_tcp_connector *connector);

#if defined (__cplusplus)
}
#endif

#endif /* DDSI__TCP_CONNECT_H */
