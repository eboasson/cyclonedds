// Copyright(c) 2006 to 2022 ZettaScale Technology and others
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License v. 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
// v. 1.0 which is available at
// http://www.eclipse.org/org/documents/edl-v10.php.
//
// SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

#include "ddsi__ssl.h"

#ifdef DDS_HAS_TCP_TLS

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "dds/ddsi/ddsi_domaingv.h"
#include "dds/ddsi/ddsi_log.h"
#include "dds/ddsrt/heap.h"

/* A plain OpenSSL socket BIO can raise SIGPIPE. On systems with SO_NOSIGPIPE,
   TCP sets it on the socket. Where only MSG_NOSIGNAL is available it must be
   supplied to each send, including control traffic generated during reads. */
#if defined MSG_NOSIGNAL && !defined SO_NOSIGPIPE && !defined _WIN32 && !LWIP_SOCKET
#define DDSI_SSL_SEND_NOSIGNAL 1
#else
#define DDSI_SSL_SEND_NOSIGNAL 0
#endif

struct ddsi_ssl_ctx {
  SSL_CTX *ctx;
#if DDSI_SSL_SEND_NOSIGNAL
  BIO_METHOD *socket_write_method;
#endif
};

#if DDSI_SSL_SEND_NOSIGNAL
static int socket_bio_write (BIO *bio, const char *buf, int len)
{
  const int fd = (int) (intptr_t) BIO_get_data (bio);
  BIO_clear_retry_flags (bio);
  const int n = (int) send (fd, buf, (size_t) len, MSG_NOSIGNAL);
  if (n < 0 && BIO_sock_should_retry (n))
    BIO_set_retry_write (bio);
  return n;
}

static long socket_bio_ctrl (BIO *bio, int cmd, long arg, void *ptr)
{
  (void) arg;
  switch (cmd)
  {
    case BIO_CTRL_FLUSH:
      return 1;
    case BIO_C_GET_FD: {
      const int fd = (int) (intptr_t) BIO_get_data (bio);
      if (ptr)
        *(int *) ptr = fd;
      return fd;
    }
    default:
      return 0;
  }
}
#endif

static void log_ssl_errors (const struct ddsi_domaingv *gv)
{
  unsigned long code;
  while ((code = ERR_get_error ()) != 0)
  {
    char msg[256];
    ERR_error_string_n (code, msg, sizeof (msg));
    GVERROR ("tcp/ssl: %s\n", msg);
  }
}

static const char *format_name (const X509_NAME *name, char *buf, int size)
{
  if (name == NULL || X509_NAME_oneline (name, buf, size) == NULL)
    return "<unavailable>";
  return buf;
}

static int verify_cert (int ok, X509_STORE_CTX *store)
{
  if (!ok)
  {
    char issuer[256];
    X509 *cert = X509_STORE_CTX_get_current_cert (store);
    const char *name = cert ? format_name (X509_get_issuer_name (cert), issuer, sizeof (issuer)) : "<unavailable>";
    DDS_ERROR ("tcp/ssl failed to verify certificate from %s: %s\n", name, X509_verify_cert_error_string (X509_STORE_CTX_get_error (store)));
  }
  return ok;
}

static int verify_allow_self_signed (int ok, X509_STORE_CTX *store)
{
  const int err = X509_STORE_CTX_get_error (store);
  if (err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT || err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN)
    return 1;
  return verify_cert (ok, store);
}

static int ddsi_ssl_password (char *buf, int size, int rwflag, void *arg)
{
  const char *password = arg;
  const size_t len = strlen (password);
  (void) rwflag;
  if (size < 0 || len > (size_t) size)
    return -1;
  memcpy (buf, password, len);
  return (int) len;
}

struct ddsi_ssl_ctx *ddsi_ssl_ctx_new (const struct ddsi_domaingv *gv)
{
  ERR_clear_error ();
  struct ddsi_ssl_ctx *tls = ddsrt_calloc_s (1, sizeof (*tls));
  if (tls == NULL)
    return NULL;
  SSL_CTX *ctx = tls->ctx = SSL_CTX_new (TLS_method ());
  if (ctx == NULL)
  {
    GVERROR ("tcp/ssl failed to create TLS context\n");
    goto fail;
  }

  SSL_CTX_set_default_passwd_cb (ctx, ddsi_ssl_password);
  SSL_CTX_set_default_passwd_cb_userdata (ctx, gv->config.ssl_key_pass);
  if (!SSL_CTX_use_certificate_file (ctx, gv->config.ssl_keystore, SSL_FILETYPE_PEM))
  {
    GVERROR ("tcp/ssl failed to load certificate from file: %s\n", gv->config.ssl_keystore);
    goto fail;
  }
  if (!SSL_CTX_use_PrivateKey_file (ctx, gv->config.ssl_keystore, SSL_FILETYPE_PEM) || !SSL_CTX_check_private_key (ctx))
  {
    GVERROR ("tcp/ssl failed to load a matching private key from file: %s\n", gv->config.ssl_keystore);
    goto fail;
  }
  if (!SSL_CTX_load_verify_locations (ctx, gv->config.ssl_keystore, NULL))
  {
    GVERROR ("tcp/ssl failed to load CA from file: %s\n", gv->config.ssl_keystore);
    goto fail;
  }
  SSL_CTX_set_default_passwd_cb (ctx, NULL);
  SSL_CTX_set_default_passwd_cb_userdata (ctx, NULL);

  if (!SSL_CTX_set_cipher_list (ctx, gv->config.ssl_ciphers))
  {
    GVERROR ("tcp/ssl failed to set ciphers: %s\n", gv->config.ssl_ciphers);
    goto fail;
  }
  if (gv->config.ssl_ciphersuites != NULL && gv->config.ssl_ciphersuites[0] != '\0' &&
      !SSL_CTX_set_ciphersuites (ctx, gv->config.ssl_ciphersuites))
  {
    GVERROR ("tcp/ssl failed to set TLS 1.3 ciphersuites: %s\n", gv->config.ssl_ciphersuites);
    goto fail;
  }
  if (gv->config.ssl_rand_file[0] != '\0' && RAND_load_file (gv->config.ssl_rand_file, 4096) <= 0)
  {
    GVERROR ("tcp/ssl failed to load random seed from file: %s\n", gv->config.ssl_rand_file);
    goto fail;
  }

  if (gv->config.ssl_verify)
  {
    int mode = SSL_VERIFY_PEER;
    if (gv->config.ssl_verify_client)
      mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    SSL_CTX_set_verify (ctx, mode, gv->config.ssl_self_signed ? verify_allow_self_signed : verify_cert);
  }

  int min_version;
  if (gv->config.ssl_min_version.major == 1 && gv->config.ssl_min_version.minor == 2)
    min_version = TLS1_2_VERSION;
  else if (gv->config.ssl_min_version.major == 1 && gv->config.ssl_min_version.minor == 3)
    min_version = TLS1_3_VERSION;
  else
    min_version = 0;
  if (!min_version || !SSL_CTX_set_min_proto_version (ctx, min_version))
  {
    GVERROR ("tcp/ssl failed to set minimum TLS version to %d.%d\n", gv->config.ssl_min_version.major, gv->config.ssl_min_version.minor);
    goto fail;
  }
  SSL_CTX_set_options (ctx, SSL_OP_ALL);
  /* Let TCP advance its write cursor after each completed TLS record. */
  SSL_CTX_set_mode (ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
#if DDSI_SSL_SEND_NOSIGNAL
  tls->socket_write_method = BIO_meth_new (BIO_TYPE_SOURCE_SINK | BIO_TYPE_DESCRIPTOR, "TCP socket write with MSG_NOSIGNAL");
  if (tls->socket_write_method == NULL ||
      !BIO_meth_set_write (tls->socket_write_method, socket_bio_write) ||
      !BIO_meth_set_ctrl (tls->socket_write_method, socket_bio_ctrl))
  {
    GVERROR ("tcp/ssl failed to create socket BIO method\n");
    goto fail;
  }
#endif
  return tls;

fail:
  log_ssl_errors (gv);
  ddsi_ssl_ctx_free (tls);
  return NULL;
}

void ddsi_ssl_ctx_free (struct ddsi_ssl_ctx *ctx)
{
  if (ctx)
  {
    SSL_CTX_free (ctx->ctx);
#if DDSI_SSL_SEND_NOSIGNAL
    BIO_meth_free (ctx->socket_write_method);
#endif
    ddsrt_free (ctx);
  }
}

static void report_tls_peer (const struct ddsi_domaingv *gv, const SSL *ssl)
{
  if (!(gv->logconfig.c.mask & DDS_LC_TRACE))
    return;
  const char *oper = SSL_is_server (ssl) ? "accepted from" : "connected to";
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  X509 *cert = SSL_get0_peer_certificate (ssl);
#else
  X509 *cert = SSL_get_peer_certificate (ssl);
#endif
  if (cert == NULL)
    GVTRACE ("tcp/ssl %s peer without certificate [%s]\n", oper, SSL_get_version (ssl));
  else
  {
    char issuer[256], subject[256];
    const char *issuer_name = format_name (X509_get_issuer_name (cert), issuer, sizeof (issuer));
    const char *subject_name = format_name (X509_get_subject_name (cert), subject, sizeof (subject));
    GVTRACE ("tcp/ssl %s %s issued by %s [%s]\n", oper, subject_name, issuer_name, SSL_get_version (ssl));
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    X509_free (cert);
#endif
  }
}

SSL *ddsi_ssl_new (const struct ddsi_domaingv *gv, struct ddsi_ssl_ctx *ctx, ddsrt_socket_t sock, bool server)
{
  ERR_clear_error ();
  SSL *ssl = SSL_new (ctx->ctx);
  /* SSL_set_fd takes an int even on Windows, where SOCKET has pointer width.
     Its socket BIO never owns the socket. */
  if (ssl == NULL || !SSL_set_fd (ssl, (int) sock))
    goto fail;
#if DDSI_SSL_SEND_NOSIGNAL
  /* Keep the normal socket read BIO, replacing only its write side. */
  BIO *wbio = BIO_new (ctx->socket_write_method);
  if (wbio == NULL)
    goto fail;
  BIO_set_data (wbio, (void *) (intptr_t) sock);
  BIO_set_init (wbio, 1);
  SSL_set0_wbio (ssl, wbio);
#endif
  if (server)
    SSL_set_accept_state (ssl);
  else
    SSL_set_connect_state (ssl);
  return ssl;

fail:
  GVERROR ("tcp/ssl failed to attach TLS session to socket\n");
  log_ssl_errors (gv);
  SSL_free (ssl);
  return NULL;
}

static dds_return_t ssl_io_error (const struct ddsi_domaingv *gv, SSL *ssl, int result, bool *want_read, const char *op, dds_return_t eof)
{
  /* Called immediately after the failed operation in the same thread. */
#ifdef _WIN32
  const int sockerr = WSAGetLastError ();
#else
  const int sockerr = errno;
#endif
  const int err = SSL_get_error (ssl, result);
  switch (err)
  {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      *want_read = (err == SSL_ERROR_WANT_READ);
      return DDS_RETCODE_TRY_AGAIN;
    case SSL_ERROR_ZERO_RETURN:
      return eof;
    default:
      if (err == SSL_ERROR_SYSCALL)
        GVERROR ("tcp/ssl %s failed (SSL_ERROR_SYSCALL, socket error %d)\n", op, sockerr);
      else
        GVERROR ("tcp/ssl %s failed (SSL_get_error %d)\n", op, err);
      log_ssl_errors (gv);
      return DDS_RETCODE_ERROR;
  }
}

dds_return_t ddsi_ssl_handshake (const struct ddsi_domaingv *gv, SSL *ssl, bool *want_read)
{
  ERR_clear_error ();
  const int ret = SSL_do_handshake (ssl);
  if (ret != 1)
    return ssl_io_error (gv, ssl, ret, want_read, "handshake", DDS_RETCODE_ERROR);
  /* Separate a completed TLS write from draining its ciphertext to the socket.
     A writer flushing a full socket can then let SSL_read decrypt incoming
     records. Only one application record is submitted between flushes. */
  BIO *out = SSL_get_wbio (ssl);
  BIO *buf = BIO_new (BIO_f_buffer ());
  if (!buf || BIO_set_write_buffer_size (buf, 32768) <= 0 || !BIO_up_ref (out))
  {
    BIO_free (buf);
    log_ssl_errors (gv);
    return DDS_RETCODE_OUT_OF_RESOURCES;
  }
  BIO_push (buf, out);
  SSL_set0_wbio (ssl, buf);
  report_tls_peer (gv, ssl);
  return DDS_RETCODE_OK;
}

dds_return_t ddsi_ssl_peek (const struct ddsi_domaingv *gv, SSL *ssl, unsigned char *probe, bool *want_read)
{
  ERR_clear_error ();
  const int ret = SSL_peek (ssl, probe, 1);
  if (ret == 1)
    return DDS_RETCODE_OK;
  return ssl_io_error (gv, ssl, ret, want_read, "peek", DDS_RETCODE_NO_CONNECTION);
}

dds_return_t ddsi_ssl_read (const struct ddsi_domaingv *gv, SSL *ssl, void *buf, size_t len, size_t *n, bool *want_read)
{
  *n = 0;
  if (len == 0)
    return DDS_RETCODE_OK;
  ERR_clear_error ();
  size_t read_size;
  const int ret = SSL_read_ex (ssl, buf, len, &read_size);
  if (ret != 1)
    return ssl_io_error (gv, ssl, ret, want_read, "read", DDS_RETCODE_OK);
  *n = read_size;
  return DDS_RETCODE_OK;
}

dds_return_t ddsi_ssl_write (const struct ddsi_domaingv *gv, SSL *ssl, const void *buf, size_t len, size_t *n, bool *want_read)
{
  *n = 0;
  if (len == 0)
    return DDS_RETCODE_OK;
  ERR_clear_error ();
  size_t written;
  const int ret = SSL_write_ex (ssl, buf, len, &written);
  if (ret != 1)
    return ssl_io_error (gv, ssl, ret, want_read, "write", DDS_RETCODE_ERROR);
  *n = written;
  return DDS_RETCODE_OK;
}

dds_return_t ddsi_ssl_flush (const struct ddsi_domaingv *gv, SSL *ssl)
{
  BIO *out = SSL_get_wbio (ssl);
  if (BIO_ctrl_wpending (out) == 0)
    return DDS_RETCODE_OK;
  ERR_clear_error ();
  if (BIO_flush (out) > 0)
    return DDS_RETCODE_OK;
  if (BIO_should_retry (out))
    return DDS_RETCODE_TRY_AGAIN;
  log_ssl_errors (gv);
  return DDS_RETCODE_ERROR;
}

void ddsi_ssl_shutdown (SSL *ssl)
{
  ERR_clear_error ();
  /* The TCP owner closes the nonblocking socket immediately after this attempt. */
  (void) SSL_shutdown (ssl);
  (void) BIO_flush (SSL_get_wbio (ssl));
  ERR_clear_error ();
}

#endif /* DDS_HAS_TCP_TLS */
