// Copyright(c) 2026 ZettaScale Technology and others
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License v. 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
// v. 1.0 which is available at
// http://www.eclipse.org/org/documents/edl-v10.php.
//
// SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

#define _CRT_SECURE_NO_WARNINGS // mbstowcs, strcpy, wcscpy

#include <locale.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <wchar.h>

#include "dds/ddsrt/string.h"
#include "dds/ddsrt/heap.h"
#include "dds/ddsi/ddsi_xt_typeinfo.h"

#include "xmltype.h"
#include "domtree.h"
#include "type_cache.h"
#include "scan_sample.h"

struct scan_context {
  size_t offset;
  size_t maxalign;
};

static void *align (unsigned char *base, size_t *off, size_t align, size_t size)
{
  if (*off % align)
    *off += align - (*off % align);
  const size_t o = *off;
  *off += size;
  return base + o;
}

static bool simple_alignof_sizeof (const uint8_t disc, size_t *align, size_t *size)
{
#define CASE(type) *align = _Alignof (type); *size = sizeof (type); return true
  switch (disc)
  {
    case DDS_XTypes_TK_BOOLEAN: CASE(uint8_t);
    case DDS_XTypes_TK_CHAR8: CASE(int8_t);
    case DDS_XTypes_TK_CHAR16: CASE(wchar_t);
    case DDS_XTypes_TK_INT8: CASE(int16_t);
    case DDS_XTypes_TK_INT16: CASE(int16_t);
    case DDS_XTypes_TK_INT32: CASE(int32_t);
    case DDS_XTypes_TK_INT64: CASE(int64_t);
    case DDS_XTypes_TK_BYTE: CASE(uint8_t);
    case DDS_XTypes_TK_UINT8: CASE(uint8_t);
    case DDS_XTypes_TK_UINT16: CASE(uint16_t);
    case DDS_XTypes_TK_UINT32: CASE(uint32_t);
    case DDS_XTypes_TK_UINT64: CASE(uint64_t);
    case DDS_XTypes_TK_FLOAT32: CASE(float);
    case DDS_XTypes_TK_FLOAT64: CASE(double);
    case DDS_XTypes_TK_STRING8: CASE(char *);
    case DDS_XTypes_TK_STRING16: CASE(wchar_t *);
    case DDS_XTypes_TK_FLOAT128: // FIXME
      *align = 8;
      *size = 16;
      return true;
  }
  return false;
#undef CASE
}

static size_t simple_size (const uint8_t disc)
{
  size_t a, s;
  if (!simple_alignof_sizeof (disc, &a, &s))
    return 0;
  else
    return s;
}

static size_t simple_align (const uint8_t disc)
{
  size_t a, s;
  if (!simple_alignof_sizeof (disc, &a, &s))
    return 0;
  else
    return a;
}

static void *advance_simple (unsigned char *base, size_t *off, const uint8_t disc)
{
  size_t a, s;
  if (!simple_alignof_sizeof (disc, &a, &s))
    return NULL;
  else
    return align (base, off, a, s);
}

static bool is_unbounded_string_ti (const DDS_XTypes_TypeIdentifier *typeid)
{
  if (typeid->_d == DDS_XTypes_TK_STRING8 || typeid->_d == DDS_XTypes_TK_STRING16)
    return true;
  if (typeid->_d == DDS_XTypes_TI_STRING8_SMALL || typeid->_d == DDS_XTypes_TI_STRING16_SMALL)
    return (typeid->_u.string_sdefn.bound == 0);
  if (typeid->_d == DDS_XTypes_TI_STRING8_LARGE || typeid->_d == DDS_XTypes_TI_STRING16_LARGE)
    return (typeid->_u.string_ldefn.bound == 0);
  return false;
}

static bool is_bounded_string_ti (const DDS_XTypes_TypeIdentifier *typeid)
{
  if (typeid->_d == DDS_XTypes_TI_STRING8_SMALL || typeid->_d == DDS_XTypes_TI_STRING16_SMALL)
    return (typeid->_u.string_sdefn.bound != 0);
  if (typeid->_d == DDS_XTypes_TI_STRING8_LARGE || typeid->_d == DDS_XTypes_TI_STRING16_LARGE)
    return (typeid->_u.string_ldefn.bound != 0);
  return false;
}

static bool is_unbounded_string_to (const DDS_XTypes_CompleteTypeObject *typeobj)
{
  if (typeobj->_d == DDS_XTypes_TK_STRING8 || typeobj->_d == DDS_XTypes_TK_STRING16)
    return true;
  return false;
}

static size_t bounded_string_bound_ti (const DDS_XTypes_TypeIdentifier *typeid)
{
  if (typeid->_d == DDS_XTypes_TI_STRING8_SMALL || typeid->_d == DDS_XTypes_TI_STRING16_SMALL)
    return typeid->_u.string_sdefn.bound;
  if (typeid->_d == DDS_XTypes_TI_STRING8_LARGE || typeid->_d == DDS_XTypes_TI_STRING16_LARGE)
    return typeid->_u.string_ldefn.bound;
  abort ();
}

static void *advance_string_ti (unsigned char *base, size_t *off, const DDS_XTypes_TypeIdentifier *typeid)
{
  uint32_t bound;
  if (typeid->_d == DDS_XTypes_TI_STRING8_SMALL || typeid->_d == DDS_XTypes_TI_STRING16_SMALL)
    bound = typeid->_u.string_sdefn.bound;
  else
    bound = typeid->_u.string_ldefn.bound;
  if (bound == 0)
  {
    if (typeid->_d == DDS_XTypes_TI_STRING8_SMALL || typeid->_d == DDS_XTypes_TI_STRING8_LARGE)
      return advance_simple (base, off, DDS_XTypes_TK_STRING8);
    else
      return advance_simple (base, off, DDS_XTypes_TK_STRING16);
  }
  else
  {
    unsigned char *p;
    // advance call accounts for terminating 0
    if (typeid->_d == DDS_XTypes_TI_STRING8_SMALL || typeid->_d == DDS_XTypes_TI_STRING8_LARGE) {
      p = advance_simple (base, off, DDS_XTypes_TK_CHAR8);
      *off += bound;
    } else {
      p = advance_simple (base, off, DDS_XTypes_TK_CHAR16);
      *off += sizeof (wchar_t) * bound;
    }
    return p;
  }
}

static void *advance_to (unsigned char *base, size_t *off, const DDS_XTypes_CompleteTypeObject *typeobj, bool is_opt_or_ext);

static void *advance_ti (unsigned char *base, size_t *off, const DDS_XTypes_TypeIdentifier *typeid, bool is_opt_or_ext)
{
  // Advancing over an @optional or @external always means advancing over a pointer
  if (is_opt_or_ext)
    return align (base, off, _Alignof (void *), sizeof (void *));

  void *p = advance_simple (base, off, typeid->_d);
  if (p != NULL)
    return p;

  switch (typeid->_d)
  {
    case DDS_XTypes_TI_STRING8_SMALL:
    case DDS_XTypes_TI_STRING8_LARGE:
    case DDS_XTypes_TI_STRING16_SMALL:
    case DDS_XTypes_TI_STRING16_LARGE:
      return advance_string_ti (base, off, typeid);

    case DDS_XTypes_TI_PLAIN_SEQUENCE_SMALL:
    case DDS_XTypes_TI_PLAIN_SEQUENCE_LARGE:
      return align (base, off, _Alignof (dds_sequence_t), sizeof (dds_sequence_t));

    case DDS_XTypes_TI_PLAIN_ARRAY_SMALL:
    case DDS_XTypes_TI_PLAIN_ARRAY_LARGE: {
      const DDS_XTypes_TypeIdentifier *et;
      uint32_t n = 1;
      if (typeid->_d == DDS_XTypes_TI_PLAIN_ARRAY_SMALL) {
        et = typeid->_u.array_sdefn.element_identifier;
        for (uint32_t i = 0; i < typeid->_u.array_sdefn.array_bound_seq._length; i++)
          n *= typeid->_u.array_sdefn.array_bound_seq._buffer[i];
      } else {
        et = typeid->_u.array_ldefn.element_identifier;
        for (uint32_t i = 0; i < typeid->_u.array_ldefn.array_bound_seq._length; i++)
          n *= typeid->_u.array_ldefn.array_bound_seq._buffer[i];
      }
      p = advance_ti (base, off, et, false);
      if (n > 1)
      {
        size_t off1 = *off;
        (void) advance_ti (base, off, et, false);
        size_t elem_size_aligned = *off - off1;
        *off += elem_size_aligned * (n - 2);
      }
      return p;
    }

    case DDS_XTypes_EK_COMPLETE: {
      struct typeinfo templ = { .key = { .key = (uintptr_t) typeid } }, *info = type_cache_lookup (&templ);
      return advance_to (base, off, info->typeobj, false);
    }
  }

  abort ();
  return NULL;
}

static void *advance_to (unsigned char *base, size_t *off, const DDS_XTypes_CompleteTypeObject *typeobj, bool is_opt_or_ext)
{
  // Advancing over an @optional or @external always means advancing over a pointer
  if (is_opt_or_ext)
    return align (base, off, _Alignof (void *), sizeof (void *));

  void *p = advance_simple (base, off, typeobj->_d);
  if (p != NULL)
    return p;

  switch (typeobj->_d)
  {
    case DDS_XTypes_TK_ALIAS:
      return advance_ti (base, off, &typeobj->_u.alias_type.body.common.related_type, false);

    case DDS_XTypes_TK_SEQUENCE:
      return align (base, off, _Alignof (dds_sequence_t), sizeof (dds_sequence_t));

    case DDS_XTypes_TK_ENUM:
      return align (base, off, _Alignof (int), sizeof (int));

    case DDS_XTypes_TK_STRUCTURE:
    case DDS_XTypes_TK_UNION: {
      struct typeinfo templ = { .key = { .key = (uintptr_t) typeobj } }, *info = type_cache_lookup (&templ);
      return align (base, off, info->align, info->size);
    }
  }

  abort ();
  return NULL;
}

static bool getbool (const char *data, bool *v)
{
  if (ddsrt_strcasecmp (data, "true") == 0) { *v = true; return true; }
  else if (ddsrt_strcasecmp (data, "false") == 0) { *v = false; return true; }
  else return false;
}

static bool getfloat128 (const char *data, unsigned char *v)
{
  char *endp;
  const double d = strtod (data, &endp);
  if (!(*data && strspn (endp, " \t") == strlen (endp)))
    return false;
  memset (v, 0, 16);
  uint64_t u;
  memcpy (&u, &d, sizeof (u));
  // no proper handling of NaN, Inf, subnormals, rounding
  // double: sign (1) + exp (11) + mantissa (52 + 1 implicit), exp bias = 16383
  // quad:   sign (1) + exp (15) + mantissa (112 + 1 implicit), exp bias = 1023
  const int exp = (int) ((u >> 52) & 0x7ff) - 1023;
  const uint64_t exp128 = (exp + 16383) & 0x7fff;
  const uint64_t mant = (u & ~((uint64_t)0xfff << 52));
  const uint64_t w = (u & (uint64_t)1 << 63) | (exp128 << 48) | (mant >> 4);
#if DDSRT_ENDIAN == DDSRT_LITTLE_ENDIAN
  memcpy (v + 8, &w, 8);
  v[7] = (uint8_t) (mant << 4);
#else
  memcpy (v, &w, 8);
  v[8] = (uint8_t) (mant << 4);
#endif
  return true;
}

static bool getfloat64 (const char *data, double *v)
{
  char *endp;
  *v = strtod (data, &endp);
  return *data && strspn (endp, " \t") == strlen (endp);
}

static bool getfloat32 (const char *data, float *v)
{
  double x;
  if (!getfloat64 (data, &x))
    return false;
  *v = (float) x;
  return true;
}

static bool getint64 (const char *data, int64_t *v)
{
  char *endp;
  long long x = strtoll (data, &endp, 0);
  if (*data && strspn (endp, " \t") == strlen (endp)) {
    *v = (int64_t) x;
    return true;
  }
  return false;
}

static bool getuint64 (const char *data, uint64_t *v)
{
  char *endp;
  unsigned long long x = strtoull (data, &endp, 0);
  if (*data && strspn (endp, " \t") == strlen (endp)) {
    *v = (uint64_t) x;
    return true;
  }
  return false;
}

static bool getint32 (const char *data, int32_t *v)
{
  int64_t x;
  if (!getint64 (data, &x) || x < INT32_MIN || x > INT32_MAX)
    return false;
  *v = (int32_t) x;
  return true;
}

static bool getuint32 (const char *data, uint32_t *v)
{
  uint64_t x;
  if (!getuint64 (data, &x) || x > UINT32_MAX)
    return false;
  *v = (uint32_t) x;
  return true;
}

static bool getint16 (const char *data, int16_t *v)
{
  int64_t x;
  if (!getint64 (data, &x) || x < INT16_MIN || x > INT16_MAX)
    return false;
  *v = (int16_t) x;
  return true;
}

static bool getuint16 (const char *data, uint16_t *v)
{
  uint64_t x;
  if (!getuint64 (data, &x) || x > UINT16_MAX)
    return false;
  *v = (uint16_t) x;
  return true;
}

static bool getint8 (const char *data, int8_t *v)
{
  int64_t x;
  if (!getint64 (data, &x) || x < INT8_MIN || x > INT8_MAX)
    return false;
  *v = (int8_t) x;
  return true;
}

static bool getuint8 (const char *data, uint8_t *v)
{
  uint64_t x;
  if (!getuint64 (data, &x) || x > UINT8_MAX)
    return false;
  *v = (uint8_t) x;
  return true;
}

static wchar_t *s2w_strdup (const char *s)
{
  // FIXME: Should probably not be setting locale
  setlocale(LC_ALL, "");
  size_t n = mbstowcs (NULL, s, 0);
  wchar_t *w = ddsrt_malloc ((n + 1) * sizeof (*w));
  if (mbstowcs (w, s, n + 1) == (size_t) -1)
  {
    ddsrt_free (w);
    return NULL;
  }
  return w;
}

static bool scan_sample1_simple (unsigned char * const base, const uint8_t disc, struct elem const * const elem)
{
  switch (disc)
  {
    case DDS_XTypes_TK_BOOLEAN:
      return getbool (elem->data, (bool *) base);
    case DDS_XTypes_TK_INT8:
      return getint8 (elem->data, (int8_t *) base);
    case DDS_XTypes_TK_INT16:
      return getint16 (elem->data, (int16_t *) base);
    case DDS_XTypes_TK_INT32:
      return getint32 (elem->data, (int32_t *) base);
    case DDS_XTypes_TK_INT64:
      return getint64 (elem->data, (int64_t *) base);
    case DDS_XTypes_TK_UINT8: case DDS_XTypes_TK_BYTE:
      return getuint8 (elem->data, (uint8_t *) base);
    case DDS_XTypes_TK_UINT16:
      return getuint16 (elem->data, (uint16_t *) base);
    case DDS_XTypes_TK_UINT32:
      return getuint32 (elem->data, (uint32_t *) base);
    case DDS_XTypes_TK_UINT64:
      return getuint64 (elem->data, (uint64_t *) base);
    case DDS_XTypes_TK_CHAR8:
      *(char *) base = elem->data[0];
      return true;
    case DDS_XTypes_TK_STRING8:
      *(char **) base = ddsrt_strdup (elem->data);
      return true;
    case DDS_XTypes_TK_FLOAT32:
      return getfloat32 (elem->data, (float *) base);
    case DDS_XTypes_TK_FLOAT64:
      return getfloat64 (elem->data, (double *) base);
    case DDS_XTypes_TK_FLOAT128:
      return getfloat128 (elem->data, base);
    case DDS_XTypes_TK_CHAR16:
      if (mbtowc ((wchar_t *) base, elem->data, strlen (elem->data)) < 0)
        return false;
      return true;
    case DDS_XTypes_TK_STRING16:
      if ((*((wchar_t **) base) = s2w_strdup (elem->data)) == NULL) {
        exitelem (elem, "invalid multibyte string\n");
        return false;
      }
      return true;
  }
  return false;
}

static bool scan_sample1_to (unsigned char *obj, DDS_XTypes_CompleteTypeObject const * const typeobj, struct elem const * const elem, const bool is_opt_or_ext, const bool ignore_unknown_members);
static bool scan_sample1_ti (unsigned char *obj, DDS_XTypes_TypeIdentifier const * const typeid, struct elem const * const elem, const bool is_opt_or_ext, const bool ignore_unknown_members);

static size_t get_typeid_typeobj_size (const uint8_t disc, void const * const key)
{
  size_t size = simple_size (disc);
  if (size != 0)
    return size;
  else
  {
    struct typeinfo templ = { .key = { .key = (uintptr_t) key } }, *info = type_cache_lookup (&templ);
    return info->size;
  }
}

static size_t get_typeid_typeobj_align (const uint8_t disc, void const * const key)
{
  size_t size = simple_align (disc);
  if (size != 0)
    return size;
  else
  {
    struct typeinfo templ = { .key = { .key = (uintptr_t) key } }, *info = type_cache_lookup (&templ);
    return info->align;
  }
}

static size_t get_typeid_size (DDS_XTypes_TypeIdentifier const * const typeid)
{
  if (is_unbounded_string_ti (typeid))
    return sizeof (char *);
  else if (is_bounded_string_ti (typeid))
  {
    size_t es = (typeid->_d == DDS_XTypes_TI_STRING8_SMALL || typeid->_d == DDS_XTypes_TI_STRING8_LARGE) ? 1 : sizeof (wchar_t);
    return es * (1 + bounded_string_bound_ti (typeid));
  }
  else
  {
    return get_typeid_typeobj_size (typeid->_d, typeid);
  }
}

static size_t get_typeid_align (DDS_XTypes_TypeIdentifier const * const typeid)
{
  if (is_unbounded_string_ti (typeid))
    return _Alignof (char *);
  else if (is_bounded_string_ti (typeid))
    return 1;
  else
  {
    switch (typeid->_d)
    {
      case DDS_XTypes_TI_PLAIN_SEQUENCE_SMALL:
      case DDS_XTypes_TI_PLAIN_SEQUENCE_LARGE:
        return _Alignof (dds_sequence_t);
      case DDS_XTypes_TI_PLAIN_ARRAY_SMALL:
        return get_typeid_align (typeid->_u.array_sdefn.element_identifier);
      case DDS_XTypes_TI_PLAIN_ARRAY_LARGE:
        return get_typeid_align (typeid->_u.array_ldefn.element_identifier);
      default:
        return get_typeid_typeobj_align (typeid->_d, typeid);
    }
  }
}

static size_t get_typeobj_size (DDS_XTypes_CompleteTypeObject const * const typeobj)
{
  return get_typeid_typeobj_size (typeobj->_d, typeobj);
}

#if 0
static size_t get_typeobj_align (DDS_XTypes_CompleteTypeObject const * const typeobj)
{
  return get_typeid_typeobj_align (typeobj->_d, typeobj);
}
#endif

static bool scan_sequence (struct dds_sequence * const seq, DDS_XTypes_TypeIdentifier const * const typeid, uint32_t bound, struct elem const * const elem, const bool ignore_unknown_members)
{
  uint32_t n = 0;
  for (const struct elem *it = elem->children; it; n++, it = it->next)
    if (strcmp (it->name, "item") != 0)
      exitelem (it, "expected \"item\", got \"%s\"\n", it->name);
  if (bound && n > bound)
    exitelem (elem, "%"PRIu32" items but bound is %"PRIu32"\n", n, bound);
  seq->_maximum = seq->_length = n;
  seq->_release = true;
  if (n == 0)
    seq->_buffer = NULL;
  else
  {
    seq->_buffer = ddsrt_calloc (seq->_maximum, get_typeid_size (typeid));
    size_t off = 0;
    // FIXME: @external, @optional?
    for (const struct elem *it = elem->children; it; n++, it = it->next)
    {
      unsigned char *obj = advance_ti (seq->_buffer, &off, typeid, false);
      if (!scan_sample1_ti (obj, typeid, it, false, ignore_unknown_members))
        return false;
    }
  }
  return true;
}

static bool scan_array (void * const ary, DDS_XTypes_TypeIdentifier const * const typeid, uint32_t bound, struct elem const * const elem, const bool ignore_unknown_members)
{
  const struct elem *it;
  uint32_t idx = 0;
  size_t off = 0;
  for (it = elem->children; it && idx < bound; idx++, it = it->next)
  {
    if (strcmp (it->name, "item") != 0)
      exitelem (it, "expected \"item\", got \"%s\"\n", it->name);
    if (!scan_sample1_ti (advance_ti (ary, &off, typeid, false), typeid, it, false, ignore_unknown_members))
      return false;
  }
  if (it != NULL || idx != bound)
    exitelem (elem, "wrong number of items\n");
  return true;
}

static bool scan_sample1_ti (unsigned char * obj, DDS_XTypes_TypeIdentifier const * const typeid, struct elem const * const elem, const bool is_opt_or_ext, const bool ignore_unknown_members)
{
  if (is_opt_or_ext && !is_unbounded_string_ti (typeid))
  {
    *((void **) obj) = ddsrt_calloc (1, get_typeid_size (typeid));
    obj = *((void **) obj);
  }

  if (scan_sample1_simple (obj, typeid->_d, elem))
    return true;

  switch (typeid->_d)
  {
    case DDS_XTypes_TI_STRING8_SMALL:
    case DDS_XTypes_TI_STRING8_LARGE:
      if (is_unbounded_string_ti (typeid))
        *(char **) obj = ddsrt_strdup (elem->data);
      else if (!elem->data)
        strcpy ((char *) obj, "");
      else if (strlen (elem->data) > bounded_string_bound_ti (typeid))
        exitelem (elem, "oversize bounded string\n");
      else
        strcpy ((char *) obj, elem->data);
      return true;

    case DDS_XTypes_TI_STRING16_SMALL:
    case DDS_XTypes_TI_STRING16_LARGE: {
      wchar_t *ws = s2w_strdup (elem->data);
      if (ws == NULL) {
        exitelem (elem, "invalid multibyte string\n");
        return false;
      }
      if (is_unbounded_string_ti (typeid))
        *(wchar_t **) obj = ws;
      else if (wcslen (ws) > bounded_string_bound_ti (typeid))
        exitelem (elem, "oversize bounded string\n");
      else
      {
        wcscpy ((wchar_t *) obj, ws);
        ddsrt_free (ws);
      }
      return true;
    }

    case DDS_XTypes_TI_PLAIN_SEQUENCE_SMALL:
      return scan_sequence ((struct dds_sequence *) obj, typeid->_u.seq_sdefn.element_identifier, typeid->_u.seq_sdefn.bound, elem, ignore_unknown_members);

    case DDS_XTypes_TI_PLAIN_SEQUENCE_LARGE:
      return scan_sequence ((struct dds_sequence *) obj, typeid->_u.seq_ldefn.element_identifier, typeid->_u.seq_ldefn.bound, elem, ignore_unknown_members);

    case DDS_XTypes_TI_PLAIN_ARRAY_SMALL: {
      uint32_t nelem = 1;
      for (uint32_t i = 0; i < typeid->_u.array_sdefn.array_bound_seq._length; i++)
        nelem *= typeid->_u.array_sdefn.array_bound_seq._buffer[i];
      return scan_array (obj, typeid->_u.array_sdefn.element_identifier, nelem, elem, ignore_unknown_members);
    }

    case DDS_XTypes_TI_PLAIN_ARRAY_LARGE: {
      uint32_t nelem = 1;
      for (uint32_t i = 0; i < typeid->_u.array_ldefn.array_bound_seq._length; i++)
        nelem *= typeid->_u.array_ldefn.array_bound_seq._buffer[i];
      return scan_array (obj, typeid->_u.array_ldefn.element_identifier, nelem, elem, ignore_unknown_members);
    }

    case DDS_XTypes_EK_COMPLETE: {
      struct typeinfo templ = { .key = { .key = (uintptr_t) typeid } }, *info = type_cache_lookup (&templ);
      return scan_sample1_to (obj, info->typeobj, elem, false, ignore_unknown_members);
    }
  }

  abort ();
  return false;
}

static const DDS_XTypes_CompleteStructType *get_base_struct_type_ti (DDS_XTypes_TypeIdentifier const * const typeid);

static const DDS_XTypes_CompleteStructType *get_base_struct_type_to (DDS_XTypes_CompleteTypeObject const * const typeobj)
{
  switch (typeobj->_d)
  {
    case DDS_XTypes_TK_ALIAS:
      return get_base_struct_type_ti (&typeobj->_u.alias_type.body.common.related_type);
    case DDS_XTypes_TK_STRUCTURE:
      return &typeobj->_u.struct_type;
  }
  abort ();
  return NULL;
}

static const DDS_XTypes_CompleteStructType *get_base_struct_type_ti (DDS_XTypes_TypeIdentifier const * const typeid)
{
  struct typeinfo templ = { .key = { .key = (uintptr_t) typeid } }, *info = type_cache_lookup (&templ);
  return get_base_struct_type_to (info->typeobj);
}

static const DDS_XTypes_CompleteStructMember *find_struct_member1 (unsigned char ** const m_base, unsigned char * const obj, size_t *off, DDS_XTypes_CompleteStructType const * const t, const char *name)
{
  if (t->header.base_type._d != DDS_XTypes_TK_NONE)
  {
    DDS_XTypes_CompleteStructType const * const bt = get_base_struct_type_ti (&t->header.base_type);
    DDS_XTypes_CompleteStructMember const * const m = find_struct_member1 (m_base, obj, off, bt, name);
    if (m != NULL)
      return m;
  }
  for (uint32_t i = 0; i < t->member_seq._length; i++)
  {
    const DDS_XTypes_CompleteStructMember *m = &t->member_seq._buffer[i];
    const bool m_is_opt_or_ext = m->common.member_flags & (DDS_XTypes_IS_OPTIONAL | DDS_XTypes_IS_EXTERNAL);
    *m_base = advance_ti (obj, off, &m->common.member_type_id, m_is_opt_or_ext);
    if (strcmp (name, m->detail.name) == 0)
      return m;
  }
  return NULL;
}

static const DDS_XTypes_CompleteStructMember *find_struct_member (unsigned char ** const m_base, unsigned char * const obj, DDS_XTypes_CompleteStructType const * const t, const char *name)
{
  size_t off = 0;
  return find_struct_member1 (m_base, obj, &off, t, name);
}

static bool scan_sample1_to (unsigned char *obj, DDS_XTypes_CompleteTypeObject const * const typeobj, struct elem const * const elem, const bool is_opt_or_ext, const bool ignore_unknown_members)
{
  if (is_opt_or_ext && !is_unbounded_string_to (typeobj))
  {
    *((void **) obj) = ddsrt_calloc (1, get_typeobj_size (typeobj));
    obj = *((void **) obj);
  }

  if (scan_sample1_simple (obj, typeobj->_d, elem))
  {
    return true;
  }

  switch (typeobj->_d)
  {
    case DDS_XTypes_TK_ALIAS:
      return scan_sample1_ti (obj, &typeobj->_u.alias_type.body.common.related_type, elem, false, ignore_unknown_members);

    case DDS_XTypes_TK_SEQUENCE:
      return scan_sequence ((struct dds_sequence *) obj, &typeobj->_u.sequence_type.element.common.type, typeobj->_u.sequence_type.header.common.bound, elem, ignore_unknown_members);

    case DDS_XTypes_TK_STRUCTURE: {
      const DDS_XTypes_CompleteStructType *t = &typeobj->_u.struct_type;
      for (const struct elem *melem = elem->children; melem; melem = melem->next)
      {
        const DDS_XTypes_CompleteStructMember *m;
        unsigned char *m_base;
        if ((m = find_struct_member (&m_base, obj, t, melem->name)) == NULL)
        {
          if (!ignore_unknown_members)
          {
            exitelem (melem, "member %s not found\n", melem->name);
            return false;
          }
        }
        else
        {
          const bool m_is_opt_or_ext = m->common.member_flags & (DDS_XTypes_IS_OPTIONAL | DDS_XTypes_IS_EXTERNAL);
          scan_sample1_ti (m_base, &m->common.member_type_id, melem, m_is_opt_or_ext, ignore_unknown_members);
        }
      }
      return true;
    }

    case DDS_XTypes_TK_ENUM: {
      const DDS_XTypes_CompleteEnumeratedType *t = &typeobj->_u.enumerated_type;
      for (uint32_t l = 0; l < t->literal_seq._length; l++)
      {
        if (elem->data == NULL)
          exitelem (elem, "enum value expected\n");
        if (strcmp (t->literal_seq._buffer[l].detail.name, elem->data) == 0)
        {
          // FIXME: bit bound
          *((int *) obj) = (int) t->literal_seq._buffer[l].common.value;
          return true;
        }
      }
      exitelem (elem, "literal \"%s\" not found in enum\n", elem->data);
      return false;
    }

    case DDS_XTypes_TK_UNION: {
      const DDS_XTypes_CompleteUnionType *t = &typeobj->_u.union_type;
      uint64_t disc_value = 0;
      // discriminator is always at offset 0
      if (elem->children == NULL ||
          strcmp (elem->children->name, "discriminator") != 0 ||
          elem->children->next == NULL || elem->children->next->next != NULL)
      {
        exitelem (elem, "union: expected first child 'discriminator' and second child matching union case\n");
        return false;
      }
      if (!scan_sample1_ti (obj, &t->discriminator.common.type_id, elem->children, false, false))
        return false;
      const size_t disc_size = get_typeid_size (&t->discriminator.common.type_id);
      switch (t->discriminator.common.type_id._d)
      {
        case DDS_XTypes_TK_INT8:  disc_value = (uint64_t) *((int8_t *) obj); break;
        case DDS_XTypes_TK_INT16: disc_value = (uint64_t) *((int16_t *) obj); break;
        case DDS_XTypes_TK_INT32: disc_value = (uint64_t) *((int32_t *) obj); break;
        case DDS_XTypes_TK_INT64: disc_value = (uint64_t) *((int64_t *) obj); break;
        default:
          switch (disc_size)
          {
            case 1: disc_value = *((uint8_t *) obj); break;
            case 2: disc_value = *((uint16_t *) obj); break;
            case 4: disc_value = *((uint32_t *) obj); break;
            case 8: disc_value = *((uint64_t *) obj); break;
            default: abort ();
          }
          break;
      }
      size_t data_off = disc_size;
      for (uint32_t i = 0; i < t->member_seq._length; i++)
      {
        // FIXME: shouldn't need to recompute this every time
        DDS_XTypes_CompleteUnionMember const * const m = &t->member_seq._buffer[i];
        size_t a;
        if (m->common.member_flags & (DDS_XTypes_IS_OPTIONAL | DDS_XTypes_IS_EXTERNAL))
          a = _Alignof (char *);
        else
          a = get_typeid_align (&m->common.type_id);
        if (a > data_off)
          data_off = a;
      }
      uint32_t memberidx;
      for (memberidx = 0; memberidx < t->member_seq._length; memberidx++)
      {
        DDS_XTypes_CompleteUnionMember const * const m = &t->member_seq._buffer[memberidx];
        if (strcmp (m->detail.name, elem->children->next->name) == 0)
          break;
      }
      if (memberidx == t->member_seq._length)
      {
        exitelem (elem, "union case not found");
        return false;
      }
      DDS_XTypes_CompleteUnionMember const * const m = &t->member_seq._buffer[memberidx];
      if (!(m->common.member_flags & DDS_XTypes_IS_DEFAULT))
      {
        uint32_t labelidx;
        for (labelidx = 0; labelidx < m->common.label_seq._length; labelidx++)
        {
          // FIXME: it looks like label_seq holds 32-bit ints in type obj. If so, how are
          // 64-bit discriminators supposed to be supported?
          if (disc_value == (uint64_t) m->common.label_seq._buffer[labelidx])
            break;
        }
        if (labelidx == m->common.label_seq._length)
        {
          exitelem (elem, "case labels do not include discriminator");
          return false;
        }
      }
      const bool case_is_opt_or_ext = m->common.member_flags & (DDS_XTypes_IS_OPTIONAL | DDS_XTypes_IS_EXTERNAL);
      scan_sample1_ti (obj + data_off, &m->common.type_id, elem->children->next, case_is_opt_or_ext, ignore_unknown_members);
      return true;
    }
  }

  abort ();
  return false;
}

void *scan_sample (const struct elem *input, const DDS_XTypes_CompleteTypeObject *typeobj, const bool ignore_unknown_members)
{
  unsigned char *sample = ddsrt_calloc (1, get_typeobj_size (typeobj));
  if (scan_sample1_to (sample, typeobj, input, false, ignore_unknown_members))
    return sample;
  else
  {
    // FIXME: leaks
    ddsrt_free (sample);
    return NULL;
  }
}
