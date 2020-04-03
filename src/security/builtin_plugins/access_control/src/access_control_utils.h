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
#ifndef ACCESS_CONTROL_UTILS_H
#define ACCESS_CONTROL_UTILS_H

#include <openssl/x509.h>
#include "dds/ddsrt/types.h"
#include "dds/ddsrt/attributes.h"
#include "dds/security/dds_security_api.h"
#include "dds/security/export.h"

#define DDS_ACCESS_CONTROL_PLUGIN_CONTEXT "Access Control"

#define GOTO_ERR_MSG(label, code, ...) do { \
    (void) ac_exc_code (ex, DDS_SECURITY_ERR_##code##_CODE, __VA_ARGS__); \
    goto label; \
  } while (0)
#define GOTO_SSLERR_MSG(label, code, ...) do { \
    (void) ac_exc_ssl (ex, DDS_SECURITY_ERR_##code##_CODE, __VA_ARGS__); \
    goto label; \
  } while (0)
#define GOTO_ERR(label, code) GOTO_ERR_MSG (label, code, DDS_SECURITY_ERR_##code##_MESSAGE)
#define GOTO_SSLERR(label, code) GOTO_SSLERR_MSG (label, code, DDS_SECURITY_ERR_##code##_MESSAGE)

bool ac_exc_code (DDS_Security_SecurityException *ex, int code, const char *fmt, ...) ddsrt_attribute_format ((printf, 3, 4));

bool ac_exc_ssl (DDS_Security_SecurityException *ex, int code, const char *fmt, ...) ddsrt_attribute_format ((printf, 3, 4));

bool ac_X509_certificate_read(const char *data, X509 **x509Cert, DDS_Security_SecurityException *ex);
bool ac_X509_certificate_from_data(const char *data, size_t len, X509 **x509Cert, DDS_Security_SecurityException *ex);
char *ac_get_certificate_subject_name(X509 *cert, DDS_Security_SecurityException *ex);
bool ac_PKCS7_document_check(const char *data, size_t len, X509 *cert, char **document, DDS_Security_SecurityException *ex);
bool ac_check_subjects_are_equal(const char *permissions_sn, const char *identity_sn);
size_t ac_regular_file_size(const char *filename);
SECURITY_EXPORT bool ac_fnmatch(const char* pattern, const char* string);

#endif /* ACCESS_CONTROL_UTILS_H */
