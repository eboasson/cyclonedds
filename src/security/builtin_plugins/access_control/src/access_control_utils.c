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
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/x509.h>
#include <openssl/pkcs7.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include "dds/ddsrt/heap.h"
#include "dds/ddsrt/misc.h"
#include "dds/ddsrt/string.h"
#include "dds/ddsrt/time.h"
#include "dds/ddsrt/types.h"
#include "dds/security/dds_security_api.h"
#include "dds/security/core/dds_security_utils.h"
#include "access_control_utils.h"

#define SEQ_ERR -1
#define SEQ_NOMATCH 0
#define SEQ_MATCH 1

bool ac_exc_code (DDS_Security_SecurityException *ex, int code, const char *fmt, ...)
{
  va_list ap;
  va_start (ap, fmt);
  DDS_Security_Exception_vset (ex, DDS_ACCESS_CONTROL_PLUGIN_CONTEXT, code, 1, fmt, ap);
  va_end (ap);
  return false;
}

bool ac_exc_ssl (DDS_Security_SecurityException *ex, int code, const char *fmt, ...)
{
  va_list ap;
  va_start (ap, fmt);
  DDS_Security_Exception_vset_with_openssl_error (ex, DDS_ACCESS_CONTROL_PLUGIN_CONTEXT, code, 1, fmt, ap);
  va_end (ap);
  return false;
}

bool ac_X509_certificate_from_data (const char *data, size_t len, X509 **x509Cert, DDS_Security_SecurityException *ex)
{
  BIO *bio;

  if (len > INT_MAX)
    GOTO_ERR_MSG (err_oversize, UNDEFINED, "oversize X509 certificate");
  if ((bio = BIO_new_mem_buf ((void *) data, (int) len)) == NULL)
    GOTO_SSLERR (err_bio_new, ALLOCATION_FAILED);
  if ((*x509Cert = PEM_read_bio_X509 (bio, NULL, NULL, NULL)) == NULL)
    GOTO_SSLERR (err_read_x509, INVALID_CERTIFICATE);
  BIO_free (bio);
  return true;

err_read_x509:
  BIO_free (bio);
err_bio_new:
err_oversize:
  return false;
}

static bool X509_certificate_from_file (const char *filename, X509 **x509Cert, DDS_Security_SecurityException *ex)
{
  DDSRT_WARNING_MSVC_OFF(4996);
  FILE *fp;

  /* Check if this is a valid file by getting its size. FIXME: what problem does this solve? */
  if (ac_regular_file_size(filename) == 0)
    GOTO_ERR_MSG (err_fopen, INVALID_FILE_PATH, DDS_SECURITY_ERR_INVALID_FILE_PATH_MESSAGE, filename);
if ((fp = fopen (filename, "r")) == NULL)
    GOTO_ERR_MSG (err_fopen, INVALID_FILE_PATH, DDS_SECURITY_ERR_INVALID_FILE_PATH_MESSAGE, filename);
  if ((*x509Cert = PEM_read_X509 (fp, NULL, NULL, NULL)) == NULL)
    GOTO_SSLERR (err_read_x509, INVALID_CERTIFICATE); // FIXME: why no file name here?
  fclose (fp);
  return true;

err_read_x509:
  fclose (fp);
err_fopen:
  return false;
  DDSRT_WARNING_MSVC_ON(4996);
}

bool ac_X509_certificate_read(const char *data, X509 **x509Cert, DDS_Security_SecurityException *ex)
{
  DDS_Security_config_item_prefix_t type;
  char *contents = NULL;
  if ((type = DDS_Security_get_conf_item_type (data, &contents)) == DDS_SECURITY_CONFIG_ITEM_PREFIX_UNKNOWN)
    return ac_exc_code (ex, DDS_SECURITY_ERR_CERTIFICATE_TYPE_NOT_SUPPORTED_CODE, DDS_SECURITY_ERR_CERTIFICATE_TYPE_NOT_SUPPORTED_MESSAGE);
  else
  {
    bool result = false;
    switch (type)
    {
      case DDS_SECURITY_CONFIG_ITEM_PREFIX_FILE:
        result = X509_certificate_from_file (contents, x509Cert, ex);
        break;
      case DDS_SECURITY_CONFIG_ITEM_PREFIX_DATA:
        result = ac_X509_certificate_from_data (contents, strlen (contents), x509Cert, ex);
        break;
      case DDS_SECURITY_CONFIG_ITEM_PREFIX_PKCS11:
        result = ac_exc_code (ex, DDS_SECURITY_ERR_CERTIFICATE_TYPE_NOT_SUPPORTED_CODE, DDS_SECURITY_ERR_CERTIFICATE_TYPE_NOT_SUPPORTED_MESSAGE " (pkcs11)");
        break;
      case DDS_SECURITY_CONFIG_ITEM_PREFIX_UNKNOWN:
        assert (0);
        break;
    }
    ddsrt_free (contents);
    return result;
  }
}

char *ac_get_certificate_subject_name(X509 *cert, DDS_Security_SecurityException *ex)
{
  X509_NAME *name;
  BIO *bio;
  char *subject = NULL;
  char *pmem;
  long lsz;

  if ((bio = BIO_new (BIO_s_mem ())) == NULL)
    GOTO_SSLERR (err_bio_new, ALLOCATION_FAILED);
  if ((name = X509_get_subject_name (cert)) == NULL)
    GOTO_SSLERR (err_get_x509_subject, INVALID_SUBJECT_NAME);

  /* TODO: check if this is the correct format of the subject name: check spec */
  X509_NAME_print_ex (bio, name, 0, XN_FLAG_RFC2253);

  lsz = BIO_get_mem_data (bio, &pmem);
  if (lsz < 0 || (uintmax_t) lsz >= SIZE_MAX || lsz >= INT_MAX)
    GOTO_ERR_MSG (err_alloc_subject, UNDEFINED, "subject name has invalid size (%ld)", lsz);
  const size_t sz = (size_t) lsz;
  if ((subject = ddsrt_malloc (sz + 1)) == NULL)
    GOTO_ERR (err_alloc_subject, ALLOCATION_FAILED);
  if (BIO_gets (bio, subject, (int) sz + 1) <= 0)
    GOTO_SSLERR (err_read_subject, INVALID_SUBJECT_NAME);
  BIO_free (bio);
  return subject;

err_read_subject:
  ddsrt_free (subject);
err_alloc_subject:
err_get_x509_subject:
  BIO_free (bio);
err_bio_new:
  return NULL;
}

bool ac_PKCS7_document_check (const char *data, size_t len, X509 *cert, char **document, DDS_Security_SecurityException *ex)
{
  bool result = false;
  PKCS7 *p7;
  X509_STORE *store;
  BIO *bio, *bcont, *bdoc;
  char *pmem;
  long lsz;

  if (len >= INT_MAX)
    GOTO_ERR_MSG (err_bio_new0, UNDEFINED, "data length out of range (%zu)", len);
  if ((bio = BIO_new_mem_buf ((void *) data, (int) len)) == NULL)
    GOTO_SSLERR (err_bio_new0, ALLOCATION_FAILED);
  bcont = NULL;
  if ((p7 = SMIME_read_PKCS7 (bio, &bcont)) == NULL)
    GOTO_SSLERR (err_read_pkcs7, INVALID_SMIME_DOCUMENT);

  if ((bdoc = BIO_new (BIO_s_mem ())) == NULL)
    GOTO_SSLERR (err_bio_new1, ALLOCATION_FAILED);
  if ((store = X509_STORE_new ()) == NULL)
    GOTO_SSLERR (err_store_new, ALLOCATION_FAILED);
  if (!X509_STORE_add_cert (store, cert))
    GOTO_SSLERR_MSG (err_add_cert, UNDEFINED, "PKCS7_document_verify: failed to add cert to store");
  if (!PKCS7_verify (p7, NULL, store, bcont, bdoc, PKCS7_TEXT))
    GOTO_SSLERR (err_verify, INVALID_SMIME_DOCUMENT);

  lsz = BIO_get_mem_data (bdoc, &pmem);
  if (lsz < 0 || (uintmax_t) lsz >= SIZE_MAX || lsz >= INT_MAX)
    GOTO_ERR_MSG (err_alloc_doc, UNDEFINED, "document has invalid size (%ld)", lsz);
  const size_t sz = (size_t) lsz;
  if ((*document = ddsrt_malloc (sz + 1)) == NULL)
    GOTO_ERR (err_alloc_doc, ALLOCATION_FAILED);
  memcpy (*document, pmem, sz);
  (*document)[sz] = '\0';
  result = true;

err_alloc_doc:
err_verify:
err_add_cert:
  X509_STORE_free (store);
err_store_new:
  BIO_free (bdoc);
err_bio_new1:
  BIO_free (bcont);
  PKCS7_free (p7);
err_read_pkcs7:
  BIO_free (bio);
err_bio_new0:
  return result;
}

static bool string_to_properties (const char *str, DDS_Security_PropertySeq *properties)
{
  char *copy = ddsrt_strdup (str), *cursor = copy, *tok;
  while ((tok = ddsrt_strsep (&cursor, ",/|")) != NULL)
  {
    if (strlen (tok) == 0)
      continue;
    char *name = ddsrt_strsep (&tok, "=");
    if (name == NULL || tok == NULL || properties->_length >= properties->_maximum)
    {
      ddsrt_free (copy);
      return false;
    }
    properties->_buffer[properties->_length].name = ddsrt_strdup (name);
    properties->_buffer[properties->_length].value = ddsrt_strdup (tok);
    properties->_length++;
  }
  ddsrt_free (copy);
  return true;
}

bool ac_check_subjects_are_equal (const char *permissions_sn, const char *identity_sn)
{
  bool result = false;
  char *copy_idsn = ddsrt_strdup (identity_sn), *cursor_idsn = copy_idsn, *tok_idsn;
  DDS_Security_PropertySeq prop_pmsn;
  prop_pmsn._length = 0;
  prop_pmsn._maximum = 20;
  prop_pmsn._buffer = ddsrt_malloc (prop_pmsn._maximum * sizeof (*prop_pmsn._buffer));
  if (!string_to_properties (permissions_sn, &prop_pmsn))
    goto err;

  while ((tok_idsn = ddsrt_strsep (&cursor_idsn, ",/|")) != NULL)
  {
    char *name_idsn;
    if ((name_idsn = ddsrt_strsep (&tok_idsn, "=")) == NULL || tok_idsn == NULL)
      goto err;
    DDS_Security_Property_t const * const prop = DDS_Security_PropertySeq_find_property (&prop_pmsn, name_idsn);
    if (prop == NULL || strcmp (tok_idsn, prop->value) != 0)
      goto err;
  }
  result = true;

err:
  ddsrt_free (copy_idsn);
  DDS_Security_PropertySeq_deinit (&prop_pmsn);
  return result;
}

size_t ac_regular_file_size(const char *filename)
{
  if (filename)
  {
#if _WIN32
    struct _stat stat_info;
    if (_stat (filename, &stat_info) == 0)
      if (stat_info.st_mode & _S_IFREG)
        return (size_t) stat_info.st_size;
#else
    struct stat stat_info;
    if (stat (filename, &stat_info) == 0)
      if (S_ISREG(stat_info.st_mode))
        return (size_t) stat_info.st_size;
#endif
  }
  return 0;
}

static int sequencematch(const char *pat, char c, char **new_pat)
{
  char patc = *pat;
  char rpatc;
  const bool neg = (patc == '!');
  bool m = false;

  if (neg)
    ++pat;
  for (patc = *pat; patc != ']'; pat++)
  {
    patc = *pat;
    if (patc == '\0')
      return SEQ_ERR;
    if (*(pat + 1) == '-')
    {
      rpatc = *(pat + 2);
      if (rpatc == '\0' || rpatc == ']')
        return SEQ_ERR;
      if ((uint8_t)patc <= (uint8_t)c && (uint8_t)c <= (uint8_t)rpatc)
        m = true;
      pat += 2;
    }
    else if (patc == c)
      m = true;
  }
  *new_pat = (char *) pat;
  return (m != neg) ? SEQ_MATCH : SEQ_NOMATCH;
}

bool ac_fnmatch(const char* pat, const char* str)
{
  char patc;
  bool ret;
  char *new_pat;

  assert(pat != NULL);
  assert(str != NULL);

  for (;;)
  {
    switch (patc = *pat++)
    {
    case '\0':
      return (*str == '\0');
    case '?':
      if (*str == '\0')
        return false;
      ++str;
      break;
    case '*':
      patc = *pat;
      while (patc == '*')
        patc = *++pat;
      if (patc == '\0')
        return true;
      while (*str != '\0')
      {
        ret = ac_fnmatch(pat, str);
        if (ret)
          return true;
        ++str;
      }
      return false;
      break;
    case '[':
      if (*str == '\0')
        return false;
      switch (sequencematch(pat, *str, &new_pat))
      {
      case SEQ_MATCH:
        pat = new_pat;
        ++str;
        break;
      case SEQ_NOMATCH:
      case SEQ_ERR:
        return false;
      }
      break;
    default: /* Regular character */
      if (*str != patc)
        return false;
      str++;
      break;
    }
  }
}

