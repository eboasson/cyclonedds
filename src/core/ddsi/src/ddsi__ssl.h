// Copyright(c) 2006 to 2020 ZettaScale Technology and others
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License v. 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
// v. 1.0 which is available at
// http://www.eclipse.org/org/documents/edl-v10.php.
//
// SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

#ifndef DDSI__SSL_H
#define DDSI__SSL_H

#include "dds/features.h"

#ifdef DDS_HAS_TCP_TLS

#include "dds/ddsrt/sockets.h"
#include <openssl/ssl.h>

#if defined (__cplusplus)
extern "C" {
#endif

struct ddsi_domaingv;
struct ddsi_ssl_ctx;

/** @component legacy_ssl */
struct ddsi_ssl_ctx *ddsi_ssl_ctx_new (const struct ddsi_domaingv *gv);

/** @brief Release the factory context after freeing its TLS sessions.
 * @component legacy_ssl */
void ddsi_ssl_ctx_free (struct ddsi_ssl_ctx *ctx);

/** @brief Create a TLS session over a nonblocking socket owned by the caller.
 * @component legacy_ssl */
SSL *ddsi_ssl_new (const struct ddsi_domaingv *gv, struct ddsi_ssl_ctx *ctx, ddsrt_socket_t sock, bool server);

/* TCP serializes access to a session. After TRY_AGAIN, want_read selects the
   socket readiness needed to retry the same operation. */

/** @brief Advance the handshake on the connected socket.
 * @component legacy_ssl */
dds_return_t ddsi_ssl_handshake (const struct ddsi_domaingv *gv, SSL *ssl, bool *want_read);

/** @brief Make at least one plaintext byte available. Retry with the same probe.
 * @component legacy_ssl */
dds_return_t ddsi_ssl_peek (const struct ddsi_domaingv *gv, SSL *ssl, unsigned char *probe, bool *want_read);

/** @brief Read application data. A successful zero-length result for a nonempty request is EOF.
 * @component legacy_ssl */
dds_return_t ddsi_ssl_read (const struct ddsi_domaingv *gv, SSL *ssl, void *buf, size_t len, size_t *n, bool *want_read);

/** @brief Encrypt one application record. Flush its ciphertext before the next record.
 * On TRY_AGAIN retry with the same buffer and length.
 * @component legacy_ssl */
dds_return_t ddsi_ssl_write (const struct ddsi_domaingv *gv, SSL *ssl, const void *buf, size_t len, size_t *n, bool *want_read);

/** @brief Drain buffered ciphertext to the nonblocking socket. TRY_AGAIN requests writability.
 * @component legacy_ssl */
dds_return_t ddsi_ssl_flush (const struct ddsi_domaingv *gv, SSL *ssl);

/** @brief Attempt close_notify once on an orderly, nonblocking connection before closing its socket.
 * @component legacy_ssl */
void ddsi_ssl_shutdown (SSL *ssl);

#if defined (__cplusplus)
}
#endif

#endif /* DDS_HAS_TCP_TLS */
#endif /* DDSI__SSL_H */
