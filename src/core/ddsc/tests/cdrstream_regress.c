/*
 * Copyright(c) 2021 ADLINK Technology Limited and others
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v. 1.0 which is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 */

#include "CUnit/Theory.h"
#include "dds/dds.h"
#include "dds/ddsrt/environ.h"
#include "dds/ddsrt/heap.h"
#include "dds/ddsrt/io.h"
#include "dds/ddsrt/cdtors.h"
#include "dds/ddsrt/random.h"
#include "dds/ddsrt/string.h"
#include "dds/ddsc/dds_public_impl.h"
#include "dds__topic.h"
#include "dds/ddsi/ddsi_serdata.h"
#include "dds/ddsi/ddsi_cdrstream.h"
#include "test_util.h"
#include "cdrstream_regress_types.h"

static uint16_t get_encoding (const unsigned char *cdr)
{
  uint16_t tmp16;
  memcpy (&tmp16, cdr, sizeof (tmp16));
  return tmp16;
}

static uint16_t get_options (const unsigned char *cdr)
{
  uint16_t tmp16;
  memcpy (&tmp16, cdr + 2, sizeof (tmp16));
  return ddsrt_fromBE2u (tmp16);
}

static bool cdrstream_regress (const dds_topic_descriptor_t *desc, const unsigned char *cdr, uint32_t cdrsz, bool (*cmp) (const void *exp, const void *act, bool valid_data), const void *exp)
{
  // CDR inclusive of encoding header
  ddsrt_init ();
  struct ddsi_sertype_default st;
  struct ddsi_sertype_default_desc_key *keys;
  memset (&st, 0, sizeof (st));
  keys = ddsrt_malloc (desc->m_nkeys * sizeof (*keys));
  for (uint32_t i = 0; i < desc->m_nkeys; i++)
  {
    keys[i].idx = desc->m_keys[i].m_idx;
    keys[i].ops_offs = desc->m_keys[i].m_offset;
  }
  st.type = (struct ddsi_sertype_default_desc) {
    .size = desc->m_size,
    .align = desc->m_align,
    .flagset = desc->m_flagset,
    .keys.nkeys = desc->m_nkeys,
    .keys.keys = keys,
    .ops.nops = dds_stream_countops (desc->m_ops, desc->m_nkeys, desc->m_keys),
    .ops.ops = (uint32_t *) desc->m_ops
  };

  assert (cdrsz >= 4);
  const uint16_t encoding = get_encoding (cdr);
  const uint16_t options = get_options (cdr);
  assert (cdrsz >= 4 + (options & 3));

  const uint32_t xcdrver = ddsi_sertype_enc_id_xcdr_version (encoding);
  const bool bswap = ! CDR_ENC_IS_NATIVE (encoding);

  uint32_t actsz;
  unsigned char *cdrcopy = ddsrt_memdup (cdr, cdrsz);
  CU_ASSERT_FATAL (cdrcopy != NULL);
  const bool normresult = dds_stream_normalize (cdrcopy + 4, cdrsz - 4 - (options & 3), bswap, xcdrver, &st, false, &actsz);
  CU_ASSERT_FATAL (normresult);

  dds_istream_t is;
  is = (dds_istream_t) { .m_buffer = cdrcopy + 4, .m_index = 0, .m_size = actsz, .m_xcdr_version = xcdrver };

  void *act = ddsrt_malloc (desc->m_size);
  memset (act, 0, desc->m_size);
  dds_stream_read_sample (&is, act, &st);
  CU_ASSERT_FATAL (cmp (exp, act, true));
  dds_stream_free_sample (act, st.type.ops.ops);

  is = (dds_istream_t) { .m_buffer = cdrcopy + 4, .m_index = 0, .m_size = actsz, .m_xcdr_version = xcdrver };
  dds_ostream_t os = { .m_buffer = 0, .m_index = 0, .m_size = 0, .m_xcdr_version = DDS_DATA_REPRESENTATION_XCDR2 };
  const bool extractresult = dds_stream_extract_key_from_data (&is, &os, &st);
  CU_ASSERT_FATAL (extractresult);
  CU_ASSERT_FATAL (os.m_index <= 16 || !(desc->m_flagset & DDS_TOPIC_FIXED_KEY_XCDR2));

  memset (act, 0, desc->m_size);
  is = (dds_istream_t) { .m_buffer = os.m_buffer, .m_index = 0, .m_size = os.m_index, .m_xcdr_version = os.m_xcdr_version };
  dds_stream_read_key (&is, act, &st);
  CU_ASSERT_FATAL (cmp (exp, act, false));
  dds_stream_free_sample (act, st.type.ops.ops);

  ddsrt_free (act);
  ddsrt_free (cdrcopy);
  ddsrt_free (keys);
  ddsrt_fini ();
  return true;
}

static bool cmpfail (void) { return false; }

static bool fuzzytypes_51959_516422_Gekamen_cmp (const void *vexp, const void *vact, bool valid_data)
{
  const fuzzytypes_51959_516422_Gekamen *exp = vexp;
  const fuzzytypes_51959_516422_Gekamen *act = vact;
  if (valid_data)
  {
    if (exp->foelal._length != act->foelal._length)
      return cmpfail ();
    for (uint32_t i = 0; i < exp->foelal._length; i++)
      if (exp->foelal._buffer[i] != act->foelal._buffer[i])
        return cmpfail ();
    if ((exp->baw != NULL) != (act->baw != NULL))
      return cmpfail ();
    if (exp->baw && strcmp (exp->baw, act->baw) != 0)
      return cmpfail ();
  }
  if (exp->plamal != act->plamal)
    return cmpfail ();
  if (valid_data)
  {
    for (uint32_t i = 0; i < 1; i++)
      for (uint32_t j = 0; j < 1; j++)
        if (strcmp (exp->truvoegik[i][j], act->truvoegik[i][j]) != 0)
          return cmpfail ();
    for (uint32_t i = 0; i < 3; i++)
      if (exp->weduw[i] != act->weduw[i])
        return cmpfail ();
    if (exp->nil._length != act->nil._length)
      return cmpfail ();
    for (uint32_t i = 0; i < exp->nil._length; i++)
      if (strcmp (exp->nil._buffer[i], act->nil._buffer[i]) != 0)
        return cmpfail ();
    if (exp->teinof._length != act->teinof._length)
      return cmpfail ();
    for (uint32_t i = 0; i < exp->teinof._length; i++)
    {
      if (exp->teinof._buffer[i]._length != act->teinof._buffer[i]._length)
        return cmpfail ();
      for (uint32_t j = 0; j < exp->teinof._buffer[i]._length; j++)
        if (strcmp (exp->teinof._buffer[i]._buffer[j], act->teinof._buffer[i]._buffer[j]) != 0)
          return cmpfail ();
    }
    if (strcmp (exp->whuzulev, act->whuzulev) != 0)
      return cmpfail ();
  }
  return true;
}

CU_Test (cdrstream_regress, fuzzytypes_51959_516422_Gekamen)
{
  const unsigned char cdr[] = {
    0x00,0x07,0x00,0x00,0x06,0x00,0x00,0x00,0x3e,0x45,0x55,0x57,0xba,0x94,0x90,0x04,
    0xcb,0x78,0x53,0x4f,0x00,0x00,0x00,0x00,0x60,0x3d,0x71,0x54,0x08,0x00,0x00,0x00,
    0x04,0x00,0x00,0x00,0x6a,0x78,0x66,0x00,0x0c,0x00,0x00,0x00,0xad,0x89,0x00,0x00,
    0x5c,0xfa,0x00,0x00,0x93,0x92,0x00,0x00,0x0f,0x00,0x00,0x00,0x01,0x00,0x00,0x00,
    0x07,0x00,0x00,0x00,0x76,0x61,0x7a,0x67,0x62,0x72,0x00,0x00,0x11,0x00,0x00,0x00,
    0x01,0x00,0x00,0x00,0x09,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x07,0x00,0x00,0x00,0x63,0x73,0x76,0x72,0x76,0x6e,0x00
  };
  const uint32_t cdrsz = (uint32_t) sizeof (cdr);
  const fuzzytypes_51959_516422_Gekamen exp = {
    .foelal = {
      ._length = 6,
      ._buffer = (int16_t[]){ 17726, 22357, -27462, 1168, 30923, 20307 }
    },
    .baw = NULL,
    .plamal = 1416707424,
    .truvoegik = {{"jxf"}},
    .weduw = {0x89ad, 0xfa5c, 0x9293 },
    .nil = {
      ._length = 1,
      ._buffer = (char[][24]) { "vazgbr" }
    },
    .teinof = {
      ._length = 1,
      ._buffer = &(dds_sequence_string){
        ._length = 1,
        ._buffer = (char *[]) { "" }
      }
    },
    .whuzulev = "csvrvn"
  };
  cdrstream_regress (&fuzzytypes_51959_516422_Gekamen_desc, cdr, cdrsz, fuzzytypes_51959_516422_Gekamen_cmp, &exp);
}

static bool fuzzytypes_156796_926921_Cufoiluv_cmp (const void *vexp, const void *vact, bool valid_data)
{
  const fuzzytypes_156796_926921_Cufoiluv *exp = vexp;
  const fuzzytypes_156796_926921_Cufoiluv *act = vact;
  if (valid_data)
  {
    if (strcmp (exp->doz, act->doz) != 0)
      return cmpfail ();
    if (strcmp (exp->stavaigiw, act->stavaigiw) != 0)
      return cmpfail ();
    if ((exp->knadeukuk != NULL) != (act->knadeukuk != NULL))
      return cmpfail ();
    if (exp->knadeukuk && *exp->knadeukuk != *act->knadeukuk)
      return cmpfail ();
  }
  for (uint32_t i = 0; i < 2; i++)
    for (uint32_t j = 0; j < 2; j++)
      if (exp->drifevad[i][j] != act->drifevad[i][j])
        return cmpfail ();
  return true;
}

CU_Test (cdrstream_regress, fuzzytypes_156796_926921_Cufoiluv)
{
  const unsigned char cdr[] = {
    0x00,0x07,0x00,0x00,0x07,0x00,0x00,0x00,0x74,0x6b,0x67,0x6e,0x6b,0x75,0x00,0x00,
    0x05,0x00,0x00,0x00,0x7a,0x6a,0x78,0x66,0x00,0x01,0x01,0x00,0x10,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x0a,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x0a,0x00,0x00,0x00
  };
  const uint32_t cdrsz = (uint32_t) sizeof (cdr);
  const fuzzytypes_156796_926921_Cufoiluv exp = {
    .doz = "tkgnku",
    .stavaigiw = "zjxf",
    .knadeukuk = &(bool){true},
    .drifevad = {
      { fuzzytypes_156796_926921_NUN, fuzzytypes_156796_926921_DRIVIG },
      { fuzzytypes_156796_926921_CIW, fuzzytypes_156796_926921_DRIVIG }
    }
  };
  cdrstream_regress (&fuzzytypes_156796_926921_Cufoiluv_desc, cdr, cdrsz, fuzzytypes_156796_926921_Cufoiluv_cmp, &exp);
}

