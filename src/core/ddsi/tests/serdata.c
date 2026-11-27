// Copyright(c) 2026 ZettaScale Technology and others
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License v. 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
// v. 1.0 which is available at
// http://www.eclipse.org/org/documents/edl-v10.php.
//
// SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

#include <string.h>

#include "CUnit/Theory.h"
#include "dds/ddsrt/bswap.h"
#include "dds/ddsrt/heap.h"
#include "dds/ddsrt/string.h"
#include "dds/cdr/dds_cdrstream.h"
#include "ddsi__protocol.h"
#include "ddsi__serdata_plist.h"
#include "ddsi__serdata_pserop.h"

static const ddsi_keyhash_t keyhash = {
  .value = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 }
};

static void check_serialized_bytes (const struct ddsi_serdata *data, const unsigned char *expected, size_t size)
{
  unsigned char copy[28];
  CU_ASSERT_EQ_FATAL (ddsi_serdata_size (data), size);
  CU_ASSERT_LEQ_FATAL (size, sizeof (copy));
  // Include slices crossing the identifier, options and payload boundaries.
  for (size_t off = 0; off < size; off++)
  {
    ddsi_serdata_to_ser (data, off, size - off, copy);
    CU_ASSERT_EQ (memcmp (copy, expected + off, size - off), 0);
    ddsrt_iovec_t ref;
    struct ddsi_serdata *refdata = ddsi_serdata_to_ser_ref (data, off, size - off, &ref);
    CU_ASSERT_EQ (ref.iov_len, size - off);
    CU_ASSERT_EQ (memcmp (ref.iov_base, expected + off, size - off), 0);
    ddsi_serdata_to_ser_unref (refdata, &ref);
  }
}

static void check_header_roundtrip (const struct ddsi_sertype *type, unsigned char *wire, size_t size)
{
  ddsrt_iovec_t iov = { .iov_base = wire, .iov_len = (ddsrt_iov_len_t) size };
  struct ddsi_serdata *data;
  dds_return_t rc = ddsi_serdata_from_ser_iov_err (&data, type, SDK_DATA, 1, &iov, size);
  CU_ASSERT_EQ_FATAL (rc, DDS_RETCODE_OK);
  check_serialized_bytes (data, wire, size);

  ddsi_keyhash_t actual_keyhash;
  ddsi_serdata_get_keyhash (data, &actual_keyhash, false);
  CU_ASSERT_EQ (memcmp (&actual_keyhash, &keyhash, sizeof (keyhash)), 0);

  // This conversion passes the stored CDR header back through from_ser_iov.
  struct ddsi_serdata *key = ddsi_serdata_to_untyped (data);
  CU_ASSERT_NEQ_FATAL (key, NULL);
  CU_ASSERT_EQ (key->type, NULL);
  CU_ASSERT_EQ (key->kind, SDK_KEY);
  CU_ASSERT (ddsi_serdata_eqkey (data, key));
  check_serialized_bytes (key, wire, size);
  ddsi_serdata_unref (key);
  ddsi_serdata_unref (data);

  wire[0] = wire[1] = 0xff;
  rc = ddsi_serdata_from_ser_iov_err (&data, type, SDK_DATA, 1, &iov, size);
  CU_ASSERT_EQ (rc, DDS_RETCODE_BAD_PARAMETER);
  CU_ASSERT_EQ (data, NULL);
}

CU_TheoryDataPoints (ddsi_serdata, pserop_header) = {
  CU_DataPoints (bool, false, false, true, true),
  CU_DataPoints (unsigned, 0, 1, 0, 1)
};

CU_Theory ((bool little_endian, unsigned offset), ddsi_serdata, pserop_header)
{
  static const enum ddsi_pserop ops[] = { XK, XSTOP };
  struct ddsi_sertype_pserop *type = ddsrt_calloc (1, sizeof (*type));
  ddsi_sertype_init (&type->c, "header_pserop", &ddsi_sertype_ops_pserop, &ddsi_serdata_ops_pserop, false);
  type->encoding_format = DDSI_RTPS_CDR_ENC_FORMAT_PLAIN;
  type->memsize = sizeof (keyhash);
  type->nops = type->nops_key = sizeof (ops) / sizeof (ops[0]);
  type->ops = type->ops_key = ops;

  // Offset one makes the header unaligned, while retaining a complete byte buffer.
  union { uint16_t align; unsigned char bytes[21]; } storage;
  unsigned char *wire = storage.bytes + offset;
  const struct dds_cdr_header header = {
    .identifier = little_endian ? DDSI_RTPS_CDR_LE : DDSI_RTPS_CDR_BE,
    .options = ddsrt_toBE2u (0x1234)
  };
  memcpy (wire, &header, sizeof (header));
  memcpy (wire + sizeof (header), &keyhash, sizeof (keyhash));
  check_header_roundtrip (&type->c, wire, sizeof (header) + sizeof (keyhash));
  ddsi_sertype_unref (&type->c);
}

struct pserop_message {
  ddsi_keyhash_t id;
  uint8_t value;
};

static struct ddsi_sertype *make_pserop_type (bool keyless, size_t memsize, const enum ddsi_pserop *ops, size_t nops)
{
  static const enum ddsi_pserop key_ops[] = { XK, XSTOP };
  struct ddsi_sertype_pserop *type = ddsrt_calloc (1, sizeof (*type));
  ddsi_sertype_init (&type->c, "pserop_message", &ddsi_sertype_ops_pserop, &ddsi_serdata_ops_pserop, keyless);
  type->encoding_format = DDSI_RTPS_CDR_ENC_FORMAT_PLAIN;
  type->memsize = memsize;
  type->ops = ops;
  type->nops = nops;
  if (!keyless)
  {
    type->ops_key = key_ops;
    type->nops_key = sizeof (key_ops) / sizeof (key_ops[0]);
  }
  return &type->c;
}

static struct ddsi_sertype *make_pserop_message_type (bool keyless)
{
  static const enum ddsi_pserop ops[] = { XK, Xo, XSTOP };
  return make_pserop_type (keyless, sizeof (struct pserop_message), ops, sizeof (ops) / sizeof (ops[0]));
}

static void check_empty_key (const struct ddsi_sertype *type, const struct ddsi_serdata *key, bool typed)
{
  CU_ASSERT_EQ (key->kind, SDK_KEY);
  CU_ASSERT_EQ (key->type, typed ? type : NULL);
  CU_ASSERT_EQ (key->hash, type->serdata_basehash);
  struct dds_cdr_header header;
  CU_ASSERT_EQ_FATAL (ddsi_serdata_size (key), sizeof (header));
  ddsi_serdata_to_ser (key, 0, sizeof (header), &header);
  CU_ASSERT (header.identifier == DDSI_RTPS_CDR_LE || header.identifier == DDSI_RTPS_CDR_BE);
  CU_ASSERT_EQ (header.options, 0);

  struct pserop_message sample = { .id = keyhash, .value = 99 };
  static const char expected[] = "(no payload)";
  char scratch[16], buf[sizeof (expected)], truncated[1] = { '?' };
  void *ptr = scratch;
  if (typed)
  {
    CU_ASSERT (ddsi_serdata_to_sample (key, &sample, NULL, NULL));
    CU_ASSERT (ddsi_serdata_to_sample (key, &sample, &ptr, scratch + sizeof (scratch)));
    CU_ASSERT_EQ (ddsi_serdata_print (key, buf, sizeof (buf)), sizeof (expected) - 1);
    CU_ASSERT_EQ (ddsi_serdata_print (key, truncated, sizeof (truncated)), sizeof (expected) - 1);
  }
  else
  {
    CU_ASSERT (ddsi_serdata_untyped_to_sample (type, key, &sample, NULL, NULL));
    CU_ASSERT (ddsi_serdata_untyped_to_sample (type, key, &sample, &ptr, scratch + sizeof (scratch)));
    CU_ASSERT_EQ (ddsi_serdata_print_untyped (type, key, buf, sizeof (buf)), sizeof (expected) - 1);
    CU_ASSERT_EQ (ddsi_serdata_print_untyped (type, key, truncated, sizeof (truncated)), sizeof (expected) - 1);
  }
  CU_ASSERT_EQ (memcmp (&sample.id, &keyhash, sizeof (keyhash)), 0);
  CU_ASSERT_EQ (sample.value, 99);
  CU_ASSERT (ptr == scratch);
  CU_ASSERT_STREQ (buf, expected);
  CU_ASSERT_EQ (truncated[0], '\0');
}

CU_Test (ddsi_serdata, pserop_keyless)
{
  struct ddsi_sertype *type = make_pserop_message_type (true);
  const struct pserop_message sample = { .id = keyhash, .value = 1 };
  const ddsi_keyhash_t empty_hash = { { 0 } };
  struct dds_cdr_header header = { DDSI_RTPS_CDR_BE, 0 };
  ddsrt_iovec_t iov = { .iov_base = &header, .iov_len = sizeof (header) };
  struct ddsi_serdata *from_sample, *from_wire, *from_hash;
  CU_ASSERT_EQ_FATAL (ddsi_serdata_from_sample_err (&from_sample, type, SDK_KEY, &sample), DDS_RETCODE_OK);
  CU_ASSERT_EQ_FATAL (ddsi_serdata_from_ser_iov_err (&from_wire, type, SDK_KEY, 1, &iov, iov.iov_len), DDS_RETCODE_OK);
  CU_ASSERT_EQ_FATAL (ddsi_serdata_from_keyhash_err (&from_hash, type, &empty_hash), DDS_RETCODE_OK);
  check_empty_key (type, from_sample, true);
  check_empty_key (type, from_wire, true);
  check_empty_key (type, from_hash, true);
  CU_ASSERT (ddsi_serdata_eqkey (from_sample, from_wire));
  CU_ASSERT (ddsi_serdata_eqkey (from_sample, from_hash));

  // Exercise both a local sample and incoming data with three bytes of CDR padding.
  struct {
    struct dds_cdr_header header;
    struct pserop_message sample;
    unsigned char padding[3];
  } wire = { .header = { DDSI_RTPS_CDR_BE, ddsrt_toBE2u (3) }, .sample = { .value = 2 } };
  DDSRT_STATIC_ASSERT (sizeof (wire) == 24);
  iov.iov_base = &wire;
  iov.iov_len = sizeof (wire);
  struct ddsi_serdata *data[2];
  CU_ASSERT_EQ_FATAL (ddsi_serdata_from_sample_err (&data[0], type, SDK_DATA, &sample), DDS_RETCODE_OK);
  CU_ASSERT_EQ_FATAL (ddsi_serdata_from_ser_iov_err (&data[1], type, SDK_DATA, 1, &iov, iov.iov_len), DDS_RETCODE_OK);
  CU_ASSERT (ddsi_serdata_eqkey (data[0], data[1]));
  for (unsigned i = 0; i < 2; i++)
  {
    struct pserop_message decoded;
    CU_ASSERT_FATAL (ddsi_serdata_to_sample (data[i], &decoded, NULL, NULL));
    CU_ASSERT_EQ (decoded.value, i + 1);
    ddsi_keyhash_t actual_hash = keyhash;
    ddsi_serdata_get_keyhash (data[i], &actual_hash, false);
    CU_ASSERT_EQ (memcmp (&actual_hash, &empty_hash, sizeof (empty_hash)), 0);
    struct ddsi_serdata *key = ddsi_serdata_to_untyped (data[i]);
    CU_ASSERT_NEQ_FATAL (key, NULL);
    check_empty_key (type, key, false);
    CU_ASSERT (ddsi_serdata_eqkey (data[i], key));
    CU_ASSERT_EQ (data[i]->hash, key->hash);
    ddsi_serdata_unref (key);
    ddsi_serdata_unref (data[i]);
  }
  ddsi_serdata_unref (from_hash);
  ddsi_serdata_unref (from_wire);
  ddsi_serdata_unref (from_sample);
  ddsi_sertype_unref (type);
}

CU_Test (ddsi_serdata, pserop_print_key)
{
  struct ddsi_sertype *type = make_pserop_message_type (false);
  const struct pserop_message sample = { .id = keyhash, .value = 7 };
  struct ddsi_serdata *keys[3];
  CU_ASSERT_EQ_FATAL (ddsi_serdata_from_sample_err (&keys[0], type, SDK_KEY, &sample), DDS_RETCODE_OK);
  CU_ASSERT_EQ_FATAL (ddsi_serdata_from_keyhash_err (&keys[1], type, &keyhash), DDS_RETCODE_OK);
  keys[2] = ddsi_serdata_to_untyped (keys[0]);
  CU_ASSERT_NEQ_FATAL (keys[2], NULL);
  static const char expected[] = "{01020304:05060708:090a0b0c:0d0e0f10}";
  char buf[64];
  for (size_t i = 0; i < sizeof (keys) / sizeof (keys[0]); i++)
  {
    CU_ASSERT_EQ (ddsi_serdata_print_untyped (type, keys[i], buf, sizeof (buf)), sizeof (expected) - 1);
    CU_ASSERT_STREQ (buf, expected);
    ddsi_serdata_unref (keys[i]);
  }
  ddsi_sertype_unref (type);
}

CU_TheoryDataPoints (ddsi_serdata, pserop_free_key) = {
  CU_DataPoints (bool, false, true)
};

CU_Theory ((bool keyless), ddsi_serdata, pserop_free_key)
{
  static const enum ddsi_pserop ops[] = { XK, XS, XSTOP };
  struct {
    ddsi_keyhash_t id;
    char *text;
  } sample = { .id = keyhash, .text = ddsrt_strdup ("non-key field") };
  struct ddsi_sertype *type = make_pserop_type (keyless, sizeof (sample), ops, sizeof (ops) / sizeof (ops[0]));
  ddsi_sertype_free_sample (type, &sample, DDS_FREE_KEY);
  CU_ASSERT_STREQ (sample.text, "non-key field");
  ddsi_sertype_free_sample (type, &sample, DDS_FREE_CONTENTS);
  ddsi_sertype_unref (type);
}

CU_TheoryDataPoints (ddsi_serdata, plist_header) = {
  CU_DataPoints (bool, false, false, true, true),
  CU_DataPoints (unsigned, 0, 1, 0, 1)
};

CU_Theory ((bool little_endian, unsigned offset), ddsi_serdata, plist_header)
{
  struct ddsi_sertype_plist *type = ddsrt_calloc (1, sizeof (*type));
  ddsi_sertype_init (&type->c, "header_plist", &ddsi_sertype_ops_plist, &ddsi_serdata_ops_plist, false);
  type->encoding_format = DDSI_RTPS_CDR_ENC_FORMAT_PL;
  type->keyparam = DDSI_PID_PARTICIPANT_GUID;

  union { uint16_t align; unsigned char bytes[29]; } storage;
  unsigned char *wire = storage.bytes + offset;
  const struct {
    struct dds_cdr_header header;
    ddsi_parameter_t parameter;
    ddsi_keyhash_t key;
    ddsi_parameter_t sentinel;
  } sample = {
    .header = {
      .identifier = little_endian ? DDSI_RTPS_PL_CDR_LE : DDSI_RTPS_PL_CDR_BE,
      .options = ddsrt_toBE2u (0x1234)
    },
    .parameter = {
      .parameterid = little_endian ? ddsrt_toLE2u (DDSI_PID_PARTICIPANT_GUID) : ddsrt_toBE2u (DDSI_PID_PARTICIPANT_GUID),
      .length = little_endian ? ddsrt_toLE2u (16) : ddsrt_toBE2u (16)
    },
    .key = keyhash,
    .sentinel = {
      .parameterid = little_endian ? ddsrt_toLE2u (DDSI_PID_SENTINEL) : ddsrt_toBE2u (DDSI_PID_SENTINEL),
      .length = 0
    }
  };
  DDSRT_STATIC_ASSERT (sizeof (sample) == 28);
  memcpy (wire, &sample, sizeof (sample));
  check_header_roundtrip (&type->c, wire, sizeof (sample));
  ddsi_sertype_unref (&type->c);
}
