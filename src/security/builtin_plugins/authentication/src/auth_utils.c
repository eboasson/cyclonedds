/*
 * Copyright(c) 2006 to 2019 ADLINK Technology Limited and others
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v. 1.0 which is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 */

#include <assert.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#if OPENSSL_VERSION_NUMBER >= 0x1000200fL
#define AUTH_INCLUDE_EC
#include <openssl/ec.h>
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#define AUTH_INCLUDE_DH_ACCESSORS
#endif
#else
#error "OpenSSL version is not supported"
#endif
#include "dds/ddsrt/time.h"
#include "dds/ddsrt/heap.h"
#include "dds/ddsrt/filesystem.h"
#include "dds/ddsrt/retcode.h"
#include "dds/ddsrt/heap.h"
#include "dds/ddsrt/atomics.h"
#include "dds/ddsrt/string.h"
#include "dds/ddsrt/io.h"
#include "dds/security/dds_security_api_defs.h"
#include "dds/security/core/dds_security_utils.h"
#include "auth_utils.h"

/* There is a problem when compiling on windows w.r.t. X509_NAME.
 * The windows api already defines the type X509_NAME which
 * conficts with some openssl versions. The workaround is to
 * undef the openssl X509_NAME
 */
#ifdef _WIN32
#undef X509_NAME
#endif

/* The DDS Security spec is unclear about how public keys are to be represented in the properties ("the big-endian CDR representation" it references is undefined and the OMG has an open issue for this matter) and from a bit of experimentation, it seems that ASN1 is not universally used even though it is a standard representation.  Instead, some implementations rely on OpenSSL's BN_bn2bin, but I think that is an OpenSSL specific one.  Setting this to false will use BN_bn2bin instead of ASN1 representation, just in case it ever turns out to be expected behaviour. */
#define USE_ASN1_FOR_PUBKEY 1

#define MAX_TRUSTED_CA 100

DDS_Security_ValidationResult_t authexc (DDS_Security_SecurityException *ex, const char *fmt, ...)
{
  va_list ap;
  va_start (ap, fmt);
  DDS_Security_Exception_vset (ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, 1, fmt, ap);
  va_end (ap);
  return DDS_SECURITY_VALIDATION_FAILED;
}

DDS_Security_ValidationResult_t auth_exc_code (DDS_Security_SecurityException *ex, int code, const char *fmt, ...)
{
  va_list ap;
  va_start (ap, fmt);
  DDS_Security_Exception_vset (ex, DDS_AUTH_PLUGIN_CONTEXT, code, 1, fmt, ap);
  va_end (ap);
  return DDS_SECURITY_VALIDATION_FAILED;
}

DDS_Security_ValidationResult_t authexc_ssl (DDS_Security_SecurityException *ex, const char *fmt, ...)
{
  va_list ap;
  va_start (ap, fmt);
  DDS_Security_Exception_vset_with_openssl_error (ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, 1, fmt, ap);
  va_end (ap);
  return DDS_SECURITY_VALIDATION_FAILED;
}

char *get_certificate_subject_name(X509 *cert, DDS_Security_SecurityException *ex)
{
  X509_NAME *name;
  assert(cert);
  if (!(name = X509_get_subject_name(cert)))
  {
    (void) authexc_ssl (ex, "X509_get_subject_name failed");
    return NULL;
  }
  char *subject_openssl = X509_NAME_oneline(name, NULL, 0);
  char *subject = ddsrt_strdup(subject_openssl);
  OPENSSL_free(subject_openssl);
  return subject;
}

dds_time_t get_certificate_expiry(const X509 *cert)
{
  assert(cert);
  ASN1_TIME *asn1 = X509_get_notAfter(cert);
  if (asn1 != NULL)
  {
    int days, seconds;
    if (ASN1_TIME_diff(&days, &seconds, NULL, asn1) == 1)
    {
      static const dds_duration_t secs_in_day = 86400;
      const dds_time_t now = dds_time();
      const int64_t max_valid_days_to_wait = (INT64_MAX - now) / DDS_NSECS_IN_SEC / secs_in_day;
      if (days < max_valid_days_to_wait)
      {
        dds_duration_t delta = ((dds_duration_t)seconds + ((dds_duration_t)days * secs_in_day)) * DDS_NSECS_IN_SEC;
        return now + delta;
      }
      return DDS_NEVER;
    }
  }
  return DDS_TIME_INVALID;
}

DDS_Security_ValidationResult_t get_subject_name_DER_encoded(const X509 *cert, unsigned char **buffer, size_t *size, DDS_Security_SecurityException *ex)
{
  unsigned char *tmp = NULL;
  int32_t sz;
  X509_NAME *name;

  assert(cert);
  assert(buffer);
  assert(size);

  *size = 0;
  if (!(name = X509_get_subject_name((X509 *)cert)))
    return authexc (ex, "X509_get_subject_name failed");
  if ((sz = i2d_X509_NAME(name, &tmp)) <= 0)
  {
    return authexc_ssl (ex, "i2d_X509_NAME failed");
  }

  *size = (size_t)sz;
  *buffer = ddsrt_malloc(*size);
  memcpy(*buffer, tmp, *size);
  OPENSSL_free(tmp);
  return DDS_SECURITY_VALIDATION_OK;
}

static DDS_Security_ValidationResult_t check_key_type_and_size(EVP_PKEY *key, int isPrivate, DDS_Security_SecurityException *ex)
{
  const char *sub = isPrivate ? "private key" : "certificate";
  assert(key);
  switch (EVP_PKEY_id(key))
  {
  case EVP_PKEY_RSA:
    if (EVP_PKEY_bits(key) != 2048)
      return authexc (ex, "RSA %s has unsupported key size (%d)", sub, EVP_PKEY_bits (key));
    if (isPrivate)
    {
      RSA *rsaKey = EVP_PKEY_get0_RSA(key);
      if (rsaKey && RSA_check_key(rsaKey) != 1)
        return authexc_ssl (ex, "RSA key not correct");
    }
    return DDS_SECURITY_VALIDATION_OK;

  case EVP_PKEY_EC:
    if (EVP_PKEY_bits(key) != 256)
      return authexc (ex, "EC %s has unsupported key size (%d)", sub, EVP_PKEY_bits (key));
    EC_KEY *ecKey = EVP_PKEY_get0_EC_KEY(key);
    if (ecKey && EC_KEY_check_key(ecKey) != 1)
      return authexc_ssl (ex, "EC key not correct");
    return DDS_SECURITY_VALIDATION_OK;

  default:
    return authexc (ex, "%s has not supported type", sub);
  }
}

static DDS_Security_ValidationResult_t check_certificate_type_and_size(X509 *cert, DDS_Security_SecurityException *ex)
{
  assert(cert);
  EVP_PKEY *pkey = X509_get_pubkey(cert);
  if (!pkey)
    return authexc (ex, "X509_get_pubkey failed");
  DDS_Security_ValidationResult_t result = check_key_type_and_size(pkey, false, ex);
  EVP_PKEY_free(pkey);
  return result;
}

DDS_Security_ValidationResult_t check_certificate_expiry(const X509 *cert, DDS_Security_SecurityException *ex)
{
  assert(cert);
  if (X509_cmp_current_time(X509_get_notBefore(cert)) == 0)
    return auth_exc_code (ex, DDS_SECURITY_ERR_CERT_STARTDATE_IN_FUTURE_CODE, DDS_SECURITY_ERR_CERT_STARTDATE_IN_FUTURE_MESSAGE);
  if (X509_cmp_current_time(X509_get_notAfter(cert)) == 0)
    return auth_exc_code (ex, DDS_SECURITY_ERR_CERT_EXPIRED_CODE, DDS_SECURITY_ERR_CERT_STARTDATE_IN_FUTURE_MESSAGE);
  return DDS_SECURITY_VALIDATION_OK;
}

DDS_Security_ValidationResult_t load_X509_certificate_from_data(const char *data, int len, X509 **x509Cert, DDS_Security_SecurityException *ex)
{
  BIO *bio;
  assert(data);
  assert(len >= 0);
  assert(x509Cert);

  if (!(bio = BIO_new_mem_buf((void *)data, len)))
    return authexc (ex, "BIO_new_mem_buf failed");
  if (!(*x509Cert = PEM_read_bio_X509(bio, NULL, NULL, NULL)))
  {
    BIO_free(bio);
    return authexc_ssl (ex, "Failed to parse certificate");
  }
  BIO_free(bio);

  if (get_authentication_algo_kind(*x509Cert) == AUTH_ALGO_KIND_UNKNOWN)
  {
    X509_free(*x509Cert);
    return auth_exc_code (ex, DDS_SECURITY_ERR_CERT_AUTH_ALGO_KIND_UNKNOWN_CODE, DDS_SECURITY_ERR_CERT_AUTH_ALGO_KIND_UNKNOWN_MESSAGE);
  }

  return DDS_SECURITY_VALIDATION_OK;
}

DDS_Security_ValidationResult_t load_X509_certificate_from_file(const char *filename, X509 **x509Cert, DDS_Security_SecurityException *ex)
{
  assert(filename);
  assert(x509Cert);

  DDSRT_WARNING_MSVC_OFF(4996);
  FILE *file_ptr = fopen(filename, "r");
  DDSRT_WARNING_MSVC_ON(4996);

  if (file_ptr == NULL)
    return auth_exc_code (ex, DDS_SECURITY_ERR_INVALID_FILE_PATH_CODE, DDS_SECURITY_ERR_INVALID_FILE_PATH_MESSAGE, filename);
  if (!(*x509Cert = PEM_read_X509(file_ptr, NULL, NULL, NULL)))
  {
    (void)fclose(file_ptr);
    return authexc_ssl (ex, "Failed to parse certificate");
  }
  (void)fclose(file_ptr);

  if (get_authentication_algo_kind(*x509Cert) == AUTH_ALGO_KIND_UNKNOWN)
  {
    X509_free(*x509Cert);
    return auth_exc_code (ex, DDS_SECURITY_ERR_CERT_AUTH_ALGO_KIND_UNKNOWN_CODE, DDS_SECURITY_ERR_CERT_AUTH_ALGO_KIND_UNKNOWN_MESSAGE);
  }

  return DDS_SECURITY_VALIDATION_OK;
}

static DDS_Security_ValidationResult_t load_private_key_from_data(const char *data, const char *password, EVP_PKEY **privateKey, DDS_Security_SecurityException *ex)
{
  BIO *bio;
  assert(data);
  assert(privateKey);

  if (!(bio = BIO_new_mem_buf((void *)data, -1)))
    return authexc (ex, "BIO_new_mem_buf failed");
  if (!(*privateKey = PEM_read_bio_PrivateKey(bio, NULL, NULL, (void *)(password ? password : ""))))
  {
    BIO_free(bio);
    return authexc_ssl(ex, "Failed to parse private key");
  }

  BIO_free(bio);
  return DDS_SECURITY_VALIDATION_OK;
}

static DDS_Security_ValidationResult_t load_private_key_from_file(const char *filepath, const char *password, EVP_PKEY **privateKey, DDS_Security_SecurityException *ex)
{
  FILE *file_ptr;
  assert(filepath);
  assert(privateKey);

  DDSRT_WARNING_MSVC_OFF(4996);
  file_ptr = fopen(filepath, "r");
  DDSRT_WARNING_MSVC_ON(4996);
  if (file_ptr == NULL)
    return auth_exc_code(ex, DDS_SECURITY_ERR_INVALID_FILE_PATH_CODE, DDS_SECURITY_ERR_INVALID_FILE_PATH_MESSAGE, filepath);
  if (!(*privateKey = PEM_read_PrivateKey(file_ptr, NULL, NULL, (void *)(password ? password : ""))))
  {
    (void)fclose(file_ptr);
    return authexc_ssl(ex, "Failed to parse certificate");
  }

  (void)fclose(file_ptr);
  return DDS_SECURITY_VALIDATION_OK;
}

/*
 * Gets the URI string (as referred in DDS Security spec) and returns the URI type
 * data: data part of the URI. Typically It contains different format according to URI type.
 */
AuthConfItemPrefix_t get_conf_item_type(const char *str, char **data)
{
  const char *f = "file:", *d = "data:,", *p = "pkcs11:";
  size_t sf = strlen(f), sd = strlen(d), sp = strlen(p);
  assert(str);
  assert(data);

  char *ptr = ddssec_strchrs(str, " \t", false);
  if (strncmp(ptr, f, sf) == 0)
  {
    size_t e = strncmp(ptr + sf, "//", 2) == 0 ? 2 : 0;
    *data = ddsrt_strdup(ptr + sf + e);
    return AUTH_CONF_ITEM_PREFIX_FILE;
  }
  if (strncmp(ptr, d, sd) == 0)
  {
    *data = ddsrt_strdup(ptr + sd);
    return AUTH_CONF_ITEM_PREFIX_DATA;
  }
  if (strncmp(ptr, p, sp) == 0)
  {
    *data = ddsrt_strdup(ptr + sp);
    return AUTH_CONF_ITEM_PREFIX_PKCS11;
  }

  return AUTH_CONF_ITEM_PREFIX_UNKNOWN;
}

DDS_Security_ValidationResult_t load_X509_certificate(const char *data, X509 **x509Cert, DDS_Security_SecurityException *ex)
{
  DDS_Security_ValidationResult_t result;
  char *contents = NULL;
  assert(data);
  assert(x509Cert);

  switch (get_conf_item_type(data, &contents))
  {
  case AUTH_CONF_ITEM_PREFIX_FILE:
    result = load_X509_certificate_from_file(contents, x509Cert, ex);
    break;
  case AUTH_CONF_ITEM_PREFIX_DATA:
    result = load_X509_certificate_from_data(contents, (int)strlen(contents), x509Cert, ex);
    break;
  case AUTH_CONF_ITEM_PREFIX_PKCS11:
    result = authexc (ex, "Certificate pkcs11 format currently not supported: %s", data);
    break;
  default:
    result = authexc (ex, "Specified certificate has wrong format: %s", data);
    break;
  }
  ddsrt_free(contents);

  if (result == DDS_SECURITY_VALIDATION_OK)
  {
    if (check_certificate_type_and_size(*x509Cert, ex) != DDS_SECURITY_VALIDATION_OK ||
        check_certificate_expiry(*x509Cert, ex) != DDS_SECURITY_VALIDATION_OK)
    {
      result = DDS_SECURITY_VALIDATION_FAILED;
      X509_free(*x509Cert);
    }
  }
  return result;
}

DDS_Security_ValidationResult_t load_X509_private_key(const char *data, const char *password, EVP_PKEY **privateKey, DDS_Security_SecurityException *ex)
{
  DDS_Security_ValidationResult_t result;
  char *contents = NULL;
  assert(data);
  assert(privateKey);

  switch (get_conf_item_type(data, &contents))
  {
  case AUTH_CONF_ITEM_PREFIX_FILE:
    result = load_private_key_from_file(contents, password, privateKey, ex);
    break;
  case AUTH_CONF_ITEM_PREFIX_DATA:
    result = load_private_key_from_data(contents, password, privateKey, ex);
    break;
  case AUTH_CONF_ITEM_PREFIX_PKCS11:
    result = authexc (ex, "PrivateKey pkcs11 format currently not supported: %s", data);
    break;
  default:
    result = authexc (ex, "Specified PrivateKey has wrong format: %s", data);
    break;
  }
  ddsrt_free(contents);

  if (result == DDS_SECURITY_VALIDATION_OK)
  {
    if (check_key_type_and_size(*privateKey, true, ex) != DDS_SECURITY_VALIDATION_OK)
    {
      result = DDS_SECURITY_VALIDATION_FAILED;
      EVP_PKEY_free(*privateKey);
    }
  }

  return result;
}

DDS_Security_ValidationResult_t verify_certificate(X509 *identityCert, X509 *identityCa, DDS_Security_SecurityException *ex)
{
  X509_STORE_CTX *ctx;
  X509_STORE *store;
  const char *errmsg = "?";
  assert(identityCert);
  assert(identityCa);

  /* Currently only a self signed indentiyCa is supported. Verification of against a certificate chain is not yet supported */
  /* Verification of the certificate expiry using a CRL is not yet supported */

  if (!(store = X509_STORE_new()))
  {
    errmsg = "X509_STORE_new failed";
    goto err_store_new;
  }
  if (X509_STORE_add_cert(store, identityCa) != 1)
  {
    errmsg = "X509_STORE_add_cert failed";
    goto err_add_cert;
  }
  if (!(ctx = X509_STORE_CTX_new()))
  {
    errmsg = "X509_STORE_CTX_new failed";
    goto err_ctx_new;
  }
  if (X509_STORE_CTX_init(ctx, store, identityCert, NULL) != 1)
  {
    errmsg = "X509_STORE_CTX_init failed";
    goto err_ctx_init;
  }
  if (X509_verify_cert(ctx) != 1)
  {
    const char *msg = X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx));
    char *subject = get_certificate_subject_name(identityCert, NULL);
    errmsg = NULL;
    (void) authexc (ex, "Certificate not valid: error: %s; subject: %s", msg, subject ? subject : "[not found]");
    ddsrt_free(subject);
    goto err_ctx_init;
  }
  X509_STORE_CTX_free(ctx);
  X509_STORE_free(store);
  return DDS_SECURITY_VALIDATION_OK;

err_ctx_init:
  X509_STORE_CTX_free(ctx);
err_ctx_new:
err_add_cert:
  X509_STORE_free(store);
err_store_new:
  return errmsg ? authexc_ssl (ex, "verify_certificate failed (%s)", errmsg) : DDS_SECURITY_VALIDATION_FAILED;
}

AuthenticationAlgoKind_t get_authentication_algo_kind(X509 *cert)
{
  AuthenticationAlgoKind_t kind = AUTH_ALGO_KIND_UNKNOWN;
  assert(cert);
  EVP_PKEY *pkey = X509_get_pubkey(cert);
  if (pkey)
  {
    switch (EVP_PKEY_id(pkey))
    {
    case EVP_PKEY_RSA:
      if (EVP_PKEY_bits(pkey) == 2048)
        kind = AUTH_ALGO_KIND_RSA_2048;
      break;
    case EVP_PKEY_EC:
      if (EVP_PKEY_bits(pkey) == 256)
        kind = AUTH_ALGO_KIND_EC_PRIME256V1;
      break;
    }
    EVP_PKEY_free(pkey);
  }
  return kind;
}

AuthenticationChallenge * generate_challenge(DDS_Security_SecurityException *ex)
{
  AuthenticationChallenge *result = ddsrt_malloc(sizeof(*result));
  if (RAND_bytes (result->value, sizeof(result->value)) < 0)
  {
    (void) authexc_ssl (ex, "Failed to generate a 256 bit random number");
    ddsrt_free (result);
    return NULL;
  }
  return result;
}

DDS_Security_ValidationResult_t get_certificate_contents(X509 *cert, unsigned char **data, uint32_t *size, DDS_Security_SecurityException *ex)
{
  BIO *bio = NULL;
  char *ptr;
  if ((bio = BIO_new(BIO_s_mem())) == NULL)
    return authexc (ex, "BIO_new_mem_buf failed");
  if (!PEM_write_bio_X509(bio, cert))
  {
    BIO_free (bio);
    return authexc_ssl (ex, "PEM_write_bio_X509 failed");
  }

  size_t sz = (size_t)BIO_get_mem_data(bio, &ptr);
  *data = ddsrt_malloc(sz + 1);
  memcpy(*data, ptr, sz);
  (*data)[sz] = '\0';
  *size = (uint32_t)sz;
  BIO_free(bio);
  return DDS_SECURITY_VALIDATION_OK;
}

static DDS_Security_ValidationResult_t get_rsa_dh_parameters(EVP_PKEY **params, DDS_Security_SecurityException *ex)
{
  DH *dh = NULL;
  *params = NULL;
  if ((*params = EVP_PKEY_new()) == NULL)
    return authexc_ssl (ex, "Failed to allocate DH generation parameters");
  if ((dh = DH_get_2048_256()) == NULL)
  {
    EVP_PKEY_free(*params);
    return authexc_ssl (ex, "Failed to allocate DH parameter using DH_get_2048_256");
  }
  if (EVP_PKEY_set1_DH(*params, dh) <= 0)
  {
    EVP_PKEY_free(*params);
    DH_free(dh);
    return authexc (ex, "Failed to set DH generation parameters using EVP_PKEY_set1_DH");
  }

  DH_free(dh);
  return DDS_SECURITY_VALIDATION_OK;
}

static DDS_Security_ValidationResult_t get_ec_dh_parameters(EVP_PKEY **params, DDS_Security_SecurityException *ex)
{
  EVP_PKEY_CTX *pctx = NULL;
  if ((pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)) == NULL)
    return authexc_ssl (ex, "Failed to allocate DH parameter context");
  if (EVP_PKEY_paramgen_init(pctx) <= 0)
  {
    EVP_PKEY_CTX_free(pctx);
    return authexc_ssl(ex, "Failed to initialize DH generation context");
  }
  if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0)
  {
    EVP_PKEY_CTX_free(pctx);
    return authexc_ssl (ex, "Failed to set DH generation parameter generation method");
  }
  if (EVP_PKEY_paramgen(pctx, params) <= 0)
  {
    EVP_PKEY_CTX_free(pctx);
    return authexc_ssl (ex, "Failed to generate DH parameters");
  }

  EVP_PKEY_CTX_free(pctx);
  return DDS_SECURITY_VALIDATION_OK;
}

DDS_Security_ValidationResult_t generate_dh_keys(EVP_PKEY **dhkey, AuthenticationAlgoKind_t authKind, DDS_Security_SecurityException *ex)
{
  EVP_PKEY *params = NULL;
  EVP_PKEY_CTX *kctx = NULL;
  *dhkey = NULL;
  switch (authKind)
  {
  case AUTH_ALGO_KIND_RSA_2048:
    if (get_rsa_dh_parameters(&params, ex) != DDS_SECURITY_VALIDATION_OK)
      goto failed;
    break;
  case AUTH_ALGO_KIND_EC_PRIME256V1:
    if (get_ec_dh_parameters(&params, ex) != DDS_SECURITY_VALIDATION_OK)
      goto failed;
    break;
  default:
    assert(0);
    goto failed;
  }

  if ((kctx = EVP_PKEY_CTX_new(params, NULL)) == NULL)
  {
    (void) authexc_ssl (ex, "Failed to allocate DH generation context");
    goto failed_params;
  }
  if (EVP_PKEY_keygen_init(kctx) <= 0)
  {
    (void) authexc_ssl (ex, "Failed to initialize DH generation context");
    goto failed_kctx;
  }
  if (EVP_PKEY_keygen(kctx, dhkey) <= 0)
  {
    (void) authexc_ssl (ex, "Failed to generate DH key pair");
    goto failed_kctx;
  }
  EVP_PKEY_CTX_free(kctx);
  EVP_PKEY_free(params);
  return DDS_SECURITY_VALIDATION_OK;

failed_kctx:
  EVP_PKEY_CTX_free(kctx);
failed_params:
  EVP_PKEY_free(params);
failed:
  return DDS_SECURITY_VALIDATION_FAILED;
}

static const BIGNUM *dh_get_public_key(DH *dhkey)
{
#ifdef AUTH_INCLUDE_DH_ACCESSORS
  const BIGNUM *pubkey, *privkey;
  DH_get0_key(dhkey, &pubkey, &privkey);
  return pubkey;
#else
  return dhkey->pub_key;
#endif
}

static int dh_set_public_key(DH *dhkey, BIGNUM *pubkey)
{
#ifdef AUTH_INCLUDE_DH_ACCESSORS
  return DH_set0_key(dhkey, pubkey, NULL);
#else
  dhkey->pub_key = pubkey;
#endif
  return 1;
}

static DDS_Security_ValidationResult_t dh_public_key_to_oct_modp(EVP_PKEY *pkey, unsigned char **buffer, uint32_t *length, DDS_Security_SecurityException *ex)
{
  DH *dhkey;
  *buffer = NULL;
  if (!(dhkey = EVP_PKEY_get1_DH(pkey)))
    return authexc (ex, "Failed to get DH key from PKEY");
#if USE_ASN1_FOR_PUBKEY
  ASN1_INTEGER *asn1int;
  if (!(asn1int = BN_to_ASN1_INTEGER(dh_get_public_key(dhkey), NULL)))
  {
    DH_free(dhkey);
    return authexc_ssl (ex, "Failed to convert DH key to ASN1 integer");
  }
  *length = (uint32_t)i2d_ASN1_INTEGER(asn1int, buffer);
  ASN1_INTEGER_free(asn1int);
#else
  const BIGNUM *pubkey = dh_get_public_key(dhkey);
  const int numbytes = BN_num_bytes (pubkey);
  assert (numbytes > 0);
  *buffer = ddsrt_malloc ((size_t) numbytes);
  const int x = BN_bn2bin (pubkey, *buffer);
  assert (x > 0 && x <= numbytes);
  *length = (uint32_t) x;
#endif
  DH_free(dhkey);
  return DDS_SECURITY_VALIDATION_OK;
}

static DDS_Security_ValidationResult_t dh_public_key_to_oct_ecdh(EVP_PKEY *pkey, unsigned char **buffer, uint32_t *length, DDS_Security_SecurityException *ex)
{
  EC_KEY *eckey;
  const EC_GROUP *group;
  const EC_POINT *point;
  size_t sz;

  if (!(eckey = EVP_PKEY_get1_EC_KEY(pkey)))
  {
    (void) authexc_ssl (ex, "Failed to get EC key from PKEY");
    goto failed_key;
  }
  if (!(point = EC_KEY_get0_public_key(eckey)))
  {
    (void) authexc_ssl (ex, "Failed to get public key from ECKEY");
    goto failed;
  }
  if (!(group = EC_KEY_get0_group(eckey)))
  {
    (void) authexc_ssl (ex, "Failed to get group from ECKEY");
    goto failed;
  }
  if ((sz = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL)) == 0)
  {
    (void) authexc_ssl (ex, "Failed to serialize public EC key");
    goto failed;
  }
  *buffer = ddsrt_malloc(sz);
  if ((*length = (uint32_t)EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, *buffer, sz, NULL)) == 0)
  {
    (void) authexc_ssl (ex, "Failed to serialize public EC key");
    ddsrt_free(*buffer);
    goto failed;
  }
  EC_KEY_free(eckey);
  return DDS_SECURITY_VALIDATION_OK;

failed:
  EC_KEY_free(eckey);
failed_key:
  return DDS_SECURITY_VALIDATION_FAILED;
}

DDS_Security_ValidationResult_t dh_public_key_to_oct(EVP_PKEY *pkey, AuthenticationAlgoKind_t algo, unsigned char **buffer, uint32_t *length, DDS_Security_SecurityException *ex)
{
  assert(pkey);
  assert(buffer);
  assert(length);
  switch (algo)
  {
  case AUTH_ALGO_KIND_RSA_2048:
    return dh_public_key_to_oct_modp(pkey, buffer, length, ex);
  case AUTH_ALGO_KIND_EC_PRIME256V1:
    return dh_public_key_to_oct_ecdh(pkey, buffer, length, ex);
  default:
    assert(0);
    return authexc (ex, "Invalid key algorithm specified");
  }
}

static DDS_Security_ValidationResult_t dh_oct_to_public_key_modp(EVP_PKEY **pkey, const unsigned char *keystr, uint32_t size, DDS_Security_SecurityException *ex)
{
  const char *msg = "?";
  DH *dhkey;
  BIGNUM *pubkey;

  if (!(*pkey = EVP_PKEY_new()))
  {
    msg = "alloc new pkey";
    goto fail_alloc_pkey;
  }
#if USE_ASN1_FOR_PUBKEY
  ASN1_INTEGER *asn1int;
  if ((asn1int = d2i_ASN1_INTEGER(NULL, (const unsigned char **)&keystr, size)) == NULL)
  {
    msg = "conv to ASN1";
    goto fail_get_pubkey;
  }
  pubkey = ASN1_INTEGER_to_BN(asn1int, NULL);
  ASN1_INTEGER_free(asn1int);
  if (pubkey == NULL)
  {
    msg = "conv ASN1 to BIGNUM";
    ASN1_INTEGER_free(asn1int);
    goto fail_get_pubkey;
  }
#else
  if (size > INT_MAX)
  {
    msg = "oversize input";
    goto fail_get_pubkey;
  }
  if ((pubkey = BN_bin2bn (keystr, (int) size, NULL)) == NULL)
  {
    msg = "conv to BIGNUM";
    goto fail_get_pubkey;
  }
#endif
  if ((dhkey = DH_get_2048_256()) == NULL)
  {
    msg = "alloc DH key";
    BN_free(pubkey);
    goto fail_get_pubkey;
  }
  if (dh_set_public_key(dhkey, pubkey) == 0)
  {
    msg = "set public key";
    BN_free(pubkey);
    goto fail_set_dhkey;
  }
  if (EVP_PKEY_set1_DH(*pkey, dhkey) == 0)
  {
    msg = "conv DH to PKEY";
    goto fail_set_dhkey;
  }
  DH_free(dhkey);
  return DDS_SECURITY_VALIDATION_OK;

fail_set_dhkey:
  DH_free(dhkey);
fail_get_pubkey:
  EVP_PKEY_free(*pkey);
fail_alloc_pkey:
  DDS_Security_Exception_set_with_openssl_error (ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, DDS_SECURITY_VALIDATION_FAILED, "Failed to convert octet sequence to public key (%s)", msg);
  return DDS_SECURITY_VALIDATION_FAILED;
}

static DDS_Security_ValidationResult_t dh_oct_to_public_key_ecdh(EVP_PKEY **pkey, const unsigned char *keystr, uint32_t size, DDS_Security_SecurityException *ex)
{
  EC_KEY *eckey;
  EC_GROUP *group;
  EC_POINT *point;
  if (!(group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)))
  {
    (void) authexc_ssl (ex, "Failed to allocate EC group");
    goto fail_alloc_group;
  }
  if (!(point = EC_POINT_new(group)))
  {
    (void) authexc_ssl (ex, "Failed to allocate EC point");
    goto fail_alloc_point;
  }
  if (EC_POINT_oct2point(group, point, keystr, size, NULL) != 1)
  {
    (void) authexc_ssl (ex, "Failed to deserialize EC public key to EC point");
    goto fail_oct2point;
  }
  if (!(eckey = EC_KEY_new()))
  {
    (void) authexc_ssl (ex, "Failed to allocate EC KEY");
    goto fail_alloc_eckey;
  }
  if (EC_KEY_set_group(eckey, group) != 1)
  {
    (void) authexc_ssl (ex, "Failed to set EC group");
    goto fail_eckey_set;
  }
  if (EC_KEY_set_public_key(eckey, point) != 1)
  {
    (void) authexc_ssl (ex, "Failed to set EC public key");
    goto fail_eckey_set;
  }
  if (!(*pkey = EVP_PKEY_new()))
  {
    (void) authexc_ssl (ex, "Failed to allocate EVP key");
    goto fail_alloc_pkey;
  }
  if (EVP_PKEY_set1_EC_KEY(*pkey, eckey) != 1)
  {
    (void) authexc_ssl (ex, "Failed to set EVP key to EC public key");
    goto fail_pkey_set_eckey;
  }
  EC_KEY_free(eckey);
  EC_POINT_free(point);
  EC_GROUP_free(group);
  return DDS_SECURITY_VALIDATION_OK;

fail_pkey_set_eckey:
  EVP_PKEY_free(*pkey);
fail_alloc_pkey:
fail_eckey_set:
  EC_KEY_free(eckey);
fail_alloc_eckey:
fail_oct2point:
  EC_POINT_free(point);
fail_alloc_point:
  EC_GROUP_free(group);
fail_alloc_group:
  return DDS_SECURITY_VALIDATION_FAILED;
}

DDS_Security_ValidationResult_t dh_oct_to_public_key(EVP_PKEY **data, AuthenticationAlgoKind_t algo, const unsigned char *str, uint32_t size, DDS_Security_SecurityException *ex)
{
  assert(data);
  assert(str);
  switch (algo)
  {
  case AUTH_ALGO_KIND_RSA_2048:
    return dh_oct_to_public_key_modp(data, str, size, ex);
  case AUTH_ALGO_KIND_EC_PRIME256V1:
    return dh_oct_to_public_key_ecdh(data, str, size, ex);
  default:
    assert(0);
    return authexc (ex, "Invalid key algorithm specified");
  }
}

char *string_from_data(const unsigned char *data, uint32_t size)
{
  char *str = NULL;
  if (size > 0 && data)
  {
    str = ddsrt_malloc(size + 1);
    memcpy(str, data, size);
    str[size] = '\0';
  }
  return str;
}

void free_ca_list_contents(X509Seq *ca_list)
{
  unsigned i;
  if (ca_list->buffer != NULL && ca_list->length > 0)
  {
    for (i = 0; i < ca_list->length; ++i)
      X509_free(ca_list->buffer[i]);
    ddsrt_free(ca_list->buffer);
  }
  ca_list->buffer = NULL;
  ca_list->length = 0;
}

DDS_Security_ValidationResult_t get_trusted_ca_list(const char *trusted_ca_dir, X509Seq *ca_list, DDS_Security_SecurityException *ex)
{
  ddsrt_dir_handle_t d_descr;
  struct ddsrt_dirent d_entry;
  struct ddsrt_stat status;
  X509 *ca_buf[MAX_TRUSTED_CA];
  unsigned ca_cnt = 0;
  char *tca_dir_norm = ddsrt_file_normalize(trusted_ca_dir);
  dds_return_t ret = ddsrt_opendir(tca_dir_norm, &d_descr);
  ddsrt_free(tca_dir_norm);
  if (ret != DDS_RETCODE_OK)
    return auth_exc_code (ex, DDS_SECURITY_ERR_INVALID_TRUSTED_CA_DIR_CODE, DDS_SECURITY_ERR_INVALID_TRUSTED_CA_DIR_MESSAGE);

  char *fpath, *fname;
  X509 *ca;
  bool failed = false;
  while (!failed && ddsrt_readdir(d_descr, &d_entry) == DDS_RETCODE_OK)
  {
    ddsrt_asprintf(&fpath, "%s%s%s", trusted_ca_dir, ddsrt_file_sep(), d_entry.d_name);
    if (ddsrt_stat(fpath, &status) == DDS_RETCODE_OK
      && strcmp(d_entry.d_name, ".") != 0 && strcmp(d_entry.d_name, "..") != 0
      && (fname = ddsrt_file_normalize(fpath)) != NULL)
    {
      if (ca_cnt >= MAX_TRUSTED_CA)
      {
        (void) auth_exc_code (ex, DDS_SECURITY_ERR_TRUSTED_CA_DIR_MAX_EXCEEDED_CODE, DDS_SECURITY_ERR_TRUSTED_CA_DIR_MAX_EXCEEDED_MESSAGE, MAX_TRUSTED_CA);
        failed = true;
      }
      else if (load_X509_certificate_from_file(fname, &ca, ex) == DDS_SECURITY_VALIDATION_OK)
        ca_buf[ca_cnt++] = ca;
      else
        DDS_Security_Exception_reset(ex);
      ddsrt_free(fname);
    }
    ddsrt_free(fpath);
  }
  ddsrt_closedir(d_descr);

  if (!failed)
  {
    free_ca_list_contents(ca_list);
    if (ca_cnt > 0)
    {
      ca_list->buffer = ddsrt_malloc(ca_cnt * sizeof(X509 *));
      for (unsigned i = 0; i < ca_cnt; ++i)
        ca_list->buffer[i] = ca_buf[i];
    }
    ca_list->length = ca_cnt;
  }
  return failed ? DDS_SECURITY_VALIDATION_FAILED : DDS_SECURITY_VALIDATION_OK;
}

DDS_Security_ValidationResult_t create_validate_asymmetrical_signature(bool create, EVP_PKEY *pkey, const unsigned char *data, const size_t dataLen,
    unsigned char **signature, size_t *signatureLen, DDS_Security_SecurityException *ex)
{
  EVP_MD_CTX *mdctx = NULL;
  EVP_PKEY_CTX *kctx = NULL;
  if (!(mdctx = EVP_MD_CTX_create()))
    return authexc_ssl (ex, "Failed to create digest context");
  if ((create ? EVP_DigestSignInit(mdctx, &kctx, EVP_sha256(), NULL, pkey) : EVP_DigestVerifyInit(mdctx, &kctx, EVP_sha256(), NULL, pkey)) != 1)
  {
    (void) authexc_ssl (ex, "Failed to initialize digest context");
    goto err;
  }
  if (EVP_PKEY_id(pkey) == EVP_PKEY_RSA)
  {
    if (EVP_PKEY_CTX_set_rsa_padding(kctx, RSA_PKCS1_PSS_PADDING) < 1)
    {
      (void) authexc_ssl (ex, "Failed to initialize digest context");
      goto err;
    }
  }
  if ((create ? EVP_DigestSignUpdate(mdctx, data, dataLen) : EVP_DigestVerifyUpdate(mdctx, data, dataLen)) != 1)
  {
    (void) authexc_ssl (ex, "Failed to update digest context");
    goto err;
  }
  if (create)
  {
    if (EVP_DigestSignFinal(mdctx, NULL, signatureLen) != 1)
    {
      (void) authexc_ssl (ex, "Failed to finalize digest context");
      goto err;
    }
    *signature = ddsrt_malloc(sizeof(unsigned char) * (*signatureLen));
  }
  if ((create ? EVP_DigestSignFinal(mdctx, *signature, signatureLen) : EVP_DigestVerifyFinal(mdctx, *signature, *signatureLen)) != 1)
  {
    (void) authexc_ssl (ex, "Failed to finalize digest context");
    if (create)
      ddsrt_free(*signature);
    goto err;
  }
  EVP_MD_CTX_destroy(mdctx);
  return DDS_SECURITY_VALIDATION_OK;

err:
  EVP_MD_CTX_destroy(mdctx);
  return DDS_SECURITY_VALIDATION_FAILED;
}
