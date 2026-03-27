/*
 * Copyright(c) 2026 ZettaScale Technology and others
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v. 1.0 which is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 */

#define _CRT_SECURE_NO_WARNINGS // sscanf

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "dds/dds.h"
#include "dds/ddsrt/hopscotch.h"
#include "dds/ddsrt/md5.h"
#include "dds/ddsrt/string.h"
#include "dds/ddsrt/heap.h"
#include "dds/ddsrt/io.h"

#include "xmltype.h"
#include "domtree.h"
#include "scan_sample.h"
#include "type_cache.h"
#include "print_type.h"
#include "print_sample.h"

ddsrt_nonnull_all
ddsrt_attribute_noreturn
ddsrt_attribute_format_printf (1, 2)
void exitfmt (const char *fmt, ...)
{
  va_list ap;
  va_start (ap, fmt);
  vfprintf (stderr, fmt, ap);
  va_end (ap);
  exit (1);
}

ddsrt_nonnull_all
ddsrt_attribute_noreturn
ddsrt_attribute_format_printf (2, 3)
void exitelem (const struct elem *elem, const char *fmt, ...)
{
  fprintf (stderr, "%s:%d: ", elem->file, elem->line);
  va_list ap;
  va_start (ap, fmt);
  vfprintf (stderr, fmt, ap);
  va_end (ap);
  exit (1);
}

struct type {
  char *name;
  dds_dynamic_type_t *dtype;
  struct ddsi_typeinfo *typeinfo;
  DDS_XTypes_TypeObject *typeobj;
};

struct make_context {
  const char *file;
  dds_entity_t dp;
  struct ddsrt_hh *typelib;
};

static void make_types (const struct make_context *ctxt, const struct elem *elem, const char *ns);

static void make_module (const struct make_context *ctxt, const struct elem *elem, const char *ns)
{
  const char *name = getattr (elem, "name");
  if (name == NULL)
    exitelem (elem, "module is missing name\n");
  char *newns;
  ddsrt_asprintf (&newns, "%s::%s", ns, name);
  for (struct elem *e = elem->children; e; e = e->next)
    make_types (ctxt, e, newns);
  ddsrt_free (newns);
}

static struct type *lookup_type (const struct make_context *ctxt, const char *ns, const char *nbtype)
{
  struct type *t;
  if (strncmp (nbtype, "::", 2) == 0)
  {
    //printf ("fqname lookup %s\n", nbtype);
    t = ddsrt_hh_lookup (ctxt->typelib, &(struct type){ .name = (char *) nbtype });
  }
  else
  {
    char *nscopy = ddsrt_strdup (ns);
    char *colon = strrchr (nscopy, ':');
    char *fqnbtype;
    ddsrt_asprintf (&fqnbtype, "%s::%s", nscopy, nbtype);
    //printf ("name lookup %s\n", fqnbtype);
    while ((t = ddsrt_hh_lookup (ctxt->typelib, &(struct type){ .name = fqnbtype })) == NULL && colon != NULL)
    {
      memmove (fqnbtype + (colon - 1 - nscopy), nbtype, strlen (nbtype) + 1);
      colon = (colon >= nscopy + 2) ? strrchr (colon - 2, ':') : NULL;
      //printf ("name lookup %s\n", fqnbtype);
    }
    ddsrt_free (fqnbtype);
    ddsrt_free (nscopy);
  }
  if (t == NULL)
    exitfmt ("%s: type lookup namespace=%s type=%s failed\n", ctxt->file, ns, nbtype);
  return t;
}

static void register_type (const struct make_context *ctxt, const struct elem *elem, dds_dynamic_type_t *dtype, char *fqname)
{
  struct ddsi_typeinfo *typeinfo = NULL;
  dds_return_t rc = dds_dynamic_type_register (dtype, &typeinfo);
  if (rc != DDS_RETCODE_OK)
    exitelem (elem, "dynamic_type_register %s failed: %s\n", fqname, dds_strretcode (rc));

  struct type *t = ddsrt_malloc (sizeof (*t));
  t->name = fqname;
  t->dtype = dtype;
  t->typeinfo = typeinfo;

  DDS_XTypes_TypeInformation const * const xti = (const DDS_XTypes_TypeInformation *) typeinfo;
  dds_typeid_t const * const ti = (const dds_typeid_t *) &xti->complete.typeid_with_size.type_id;
  dds_typeobj_t *typeobj;
  if ((rc = dds_get_typeobj (ctxt->dp, ti, 0, &typeobj)) < 0)
    exitelem (elem, "dds_get_typeobj %s failed to get typeobj: %s\n", fqname, dds_strretcode (rc));
  t->typeobj = (DDS_XTypes_TypeObject *) typeobj;

  if (!ddsrt_hh_add (ctxt->typelib, t))
    exitelem (elem, "hh_add failed for %s\n", t->name);

  assert (xti->complete.typeid_with_size.type_id._d == DDS_XTypes_EK_COMPLETE);
  struct type_hashid_map *info = ddsrt_malloc (sizeof (*info));
  memcpy (info->id, &xti->complete.typeid_with_size.type_id._u.equivalence_hash, sizeof (info->id));
  info->typeobj = t->typeobj;
  info->lineno = 0;
  type_hashid_map_add (info);

  //printf ("added %s\n", t->name);
}

static uint32_t get_max_length (const struct elem *elem, const char *name, uint32_t def)
{
  const char *str = getattr (elem, name);
  if (str == NULL)
    return def;

  int tmp, pos;
  if (sscanf (str, "%d%n", &tmp, &pos) != 1 || str[pos] != 0 || tmp < -1)
    exitelem (elem, "unexpected value for %s: %s\n", name, str);
  return (tmp <= 0) ? UINT32_MAX : (uint32_t) tmp;
}

static void set_member_flag (dds_dynamic_type_t *dtype, const struct elem *m, const char *name, dds_return_t (*setter) (dds_dynamic_type_t *type, uint32_t member_id, bool is_must_understand))
{
  const char *flagstr = getattr (m, name);
  if (flagstr != NULL)
  {
    bool flag = false;
    if (strcmp (flagstr, "true") == 0)
      flag = true;
    else if (strcmp (flagstr, "false") != 0)
      exitelem (m, "unsupported value for %s: %s\n", name, flagstr);
    dds_return_t rc;
    rc = setter (dtype, DDS_DYNAMIC_MEMBER_ID_AUTO, flag);
    if (rc != DDS_RETCODE_OK)
      exitelem (m, "set_flag failed for %s: %s\n", name, dds_strretcode (rc));
  }
}

static enum dds_dynamic_type_try_construct get_try_construct (const struct elem *m, const char *name)
{
  const char *tc = getattr (m, name);
  enum dds_dynamic_type_try_construct res = DDS_DYNAMIC_MEMBER_TRY_CONSTRUCT_DISCARD;
  if (tc == NULL || strcmp (tc, "discard") == 0)
    res = DDS_DYNAMIC_MEMBER_TRY_CONSTRUCT_DISCARD;
  else if (strcmp (tc, "") == 0 || strcmp (tc, "use_default") == 0)
    res = DDS_DYNAMIC_MEMBER_TRY_CONSTRUCT_USE_DEFAULT;
  else if (strcmp (tc, "trim") == 0)
    res = DDS_DYNAMIC_MEMBER_TRY_CONSTRUCT_TRIM;
  else
    exitelem (m, "unknown try_construct %s\n", tc);
  return res;
}

static dds_dynamic_type_spec_t get_typespec (const struct make_context *ctxt, const struct elem *m, const char *ns)
{
  const char *type = getattr (m, "type");
  if (type == NULL)
    exitfmt ("%s:%d: type missing\n", ctxt->file, m->line);

  dds_dynamic_type_spec_t mtspec;
  if (strcmp (type, "int8") == 0)
    mtspec = DDS_DYNAMIC_TYPE_SPEC_PRIM (DDS_DYNAMIC_INT8);
  else if (strcmp (type, "uint8") == 0)
    mtspec = DDS_DYNAMIC_TYPE_SPEC_PRIM (DDS_DYNAMIC_UINT8);
  else if (strcmp (type, "int16") == 0)
    mtspec = DDS_DYNAMIC_TYPE_SPEC_PRIM (DDS_DYNAMIC_INT16);
  else if (strcmp (type, "uint16") == 0)
    mtspec = DDS_DYNAMIC_TYPE_SPEC_PRIM (DDS_DYNAMIC_UINT16);
  else if (strcmp (type, "int32") == 0)
    mtspec = DDS_DYNAMIC_TYPE_SPEC_PRIM (DDS_DYNAMIC_INT32);
  else if (strcmp (type, "uint32") == 0)
    mtspec = DDS_DYNAMIC_TYPE_SPEC_PRIM (DDS_DYNAMIC_UINT32);
  else if (strcmp (type, "int64") == 0)
    mtspec = DDS_DYNAMIC_TYPE_SPEC_PRIM (DDS_DYNAMIC_INT64);
  else if (strcmp (type, "uint64") == 0)
    mtspec = DDS_DYNAMIC_TYPE_SPEC_PRIM (DDS_DYNAMIC_UINT64);
  else if (strcmp (type, "boolean") == 0)
    mtspec = DDS_DYNAMIC_TYPE_SPEC_PRIM (DDS_DYNAMIC_BOOLEAN);
  else if (strcmp (type, "float32") == 0)
    mtspec = DDS_DYNAMIC_TYPE_SPEC_PRIM (DDS_DYNAMIC_FLOAT32);
  else if (strcmp (type, "float64") == 0)
    mtspec = DDS_DYNAMIC_TYPE_SPEC_PRIM (DDS_DYNAMIC_FLOAT64);
  else if (strcmp (type, "float128") == 0)
    mtspec = DDS_DYNAMIC_TYPE_SPEC_PRIM (DDS_DYNAMIC_FLOAT128);
  else if (strcmp (type, "byte") == 0)
    mtspec = DDS_DYNAMIC_TYPE_SPEC_PRIM (DDS_DYNAMIC_BYTE);
  else if (strcmp (type, "char8") == 0)
    mtspec = DDS_DYNAMIC_TYPE_SPEC_PRIM (DDS_DYNAMIC_CHAR8);
  else if (strcmp (type, "char16") == 0) // missing in testsuite, it seems
    mtspec = DDS_DYNAMIC_TYPE_SPEC_PRIM (DDS_DYNAMIC_CHAR16);
  else if (strcmp (type, "string") == 0 || strcmp (type, "wstring") == 0)
  {
    dds_dynamic_type_descriptor_t desc = {
      .kind = (strcmp (type, "string") == 0) ? DDS_DYNAMIC_STRING8 : DDS_DYNAMIC_STRING16
    };
    const uint32_t strmaxlength = get_max_length (m, "stringMaxLength", UINT32_MAX);
    if (strmaxlength != UINT32_MAX)
    {
      desc.bounds = &strmaxlength;
      desc.num_bounds = 1;
    }
    mtspec = DDS_DYNAMIC_TYPE_SPEC (dds_dynamic_type_create (ctxt->dp, desc));
  }
  else if (strcmp (type, "nonBasic") == 0)
  {
    const char *nbtype = getattr (m, "nonBasicTypeName");
    if (nbtype == NULL)
      exitelem (m, "non-basic type, but nonBasicTypeName missing\n");
    mtspec = DDS_DYNAMIC_TYPE_SPEC (dds_dynamic_type_ref (lookup_type (ctxt, ns, nbtype)->dtype));
  }
  else
  {
    exitelem (m, "unsupported type %s\n", type);
  }

  // anonymous sequence
  const uint32_t seqmaxlength = get_max_length (m, "sequenceMaxLength", 0);
  if (seqmaxlength != 0)
  {
    char *seqname;
    ddsrt_asprintf (&seqname, "dds_sequence_%s", type);
    for (char *c = seqname; *c; c++)
      *c = (*c == ':') ? '_': *c;
    dds_dynamic_type_t dseq = dds_dynamic_type_create (ctxt->dp, (dds_dynamic_type_descriptor_t) {
      .kind = DDS_DYNAMIC_SEQUENCE,
      .name = seqname,
      .element_type = mtspec,
      .bounds = (uint32_t[]) { seqmaxlength },
      .num_bounds = (seqmaxlength == UINT32_MAX) ? 0 : 1
    });
    // FIXME: spec doesn't define a way to specify try-construct for a sequence element, this is my own hack
    dds_return_t rc = dds_dynamic_type_set_try_construct (&dseq, get_try_construct (m, "elementTryConstruct"));
    if (rc != DDS_RETCODE_OK)
      exitelem (m, "set_try_construct failed: %s\n", dds_strretcode (rc));
    mtspec = DDS_DYNAMIC_TYPE_SPEC (dseq);
  }

  // anonymous array (not sure it if sequence/array can be combined)
  const char *arydimstr = getattr (m, "arrayDimensions");
  if (arydimstr)
  {
#define MAXDIMS 10
    uint32_t ndims = 0, dims[MAXDIMS];
    char *aryname; // Should I bake this name?
    ddsrt_asprintf (&aryname, "dds_array_%s", type);
    for (char *c = aryname; *c; c++)
      *c = (*c == ':') ? '_': *c;
    while (*arydimstr)
    {
      char *endptr;
      dims[ndims++] = (uint32_t) strtoul (arydimstr, &endptr, 0);
      if (*endptr != 0 && *endptr != ',')
        exitelem (m, "unsupported content in arrayDimensions\n");
      arydimstr = endptr + (*endptr == ',');
    } while (*arydimstr);
    if (ndims == 0)
      exitelem (m, "arrayDimensions is empty\n");
    dds_dynamic_type_t dary = dds_dynamic_type_create (ctxt->dp, (dds_dynamic_type_descriptor_t) {
      .kind = DDS_DYNAMIC_ARRAY,
      .name = aryname,
      .element_type = mtspec,
      .bounds = dims,
      .num_bounds = ndims
    });
    mtspec = DDS_DYNAMIC_TYPE_SPEC (dary);
#undef MAXDIMS
  }

  return mtspec;
}

static void add_member (const struct make_context *ctxt, struct dds_dynamic_type *dtype, const struct elem *m, const char *ns, uint32_t nlabels, const int32_t *labels, bool isdefault)
{
  const char *mname = getattr (m, "name");
  if (mname == NULL)
    exitelem (m, "name missing\n");

  const dds_dynamic_type_spec_t mtspec = get_typespec (ctxt, m, ns);
  uint32_t id = DDS_DYNAMIC_MEMBER_ID_AUTO;
  const char *idstr = getattr (m, "id");
  if (idstr)
  {
    int pos;
    if (sscanf (idstr, "%"SCNu32"%n", &id, &pos) != 1 || idstr[pos] != 0 || id >= 0x0fffffff)
      exitelem (m, "id attribute empty, contains non-digits or out-of-range\n");
  }

  dds_return_t rc;
  rc = dds_dynamic_type_add_member (dtype, ((dds_dynamic_member_descriptor_t) {
    .name = mname,
    .id = id,
    .type = mtspec,
    .index = DDS_DYNAMIC_MEMBER_INDEX_END,
    .num_labels = nlabels,
    .labels = (int32_t *) labels,
    .default_label = isdefault
  }));
  if (rc != DDS_RETCODE_OK)
    exitelem (m, "add_member failed: %s\n", dds_strretcode (rc));

  const char *hashidstr = getattr (m, "hashid");
  if (hashidstr)
    rc = dds_dynamic_member_set_hashid (dtype, DDS_DYNAMIC_MEMBER_ID_AUTO, hashidstr);
  if (rc != DDS_RETCODE_OK)
    exitelem (m, "set_hashid failed: %s\n", dds_strretcode (rc));

  set_member_flag (dtype, m, "key", dds_dynamic_member_set_key);
  set_member_flag (dtype, m, "mustUnderstand", dds_dynamic_member_set_must_understand);

  rc = dds_dynamic_member_set_try_construct (dtype, DDS_DYNAMIC_MEMBER_ID_AUTO, get_try_construct (m, "tryConstruct"));
  if (rc != DDS_RETCODE_OK)
    exitelem (m, "set_try_construct failed: %s\n", dds_strretcode (rc));

  // not in test suite, they are just guesses:
  set_member_flag (dtype, m, "optional", dds_dynamic_member_set_optional);
  set_member_flag (dtype, m, "external", dds_dynamic_member_set_external);
}

static void add_struct_member (const struct make_context *ctxt, struct dds_dynamic_type *dtype, const struct elem *m, const char *ns)
{
  add_member (ctxt, dtype, m, ns, 0, NULL, false);
}

static void set_extensibility (dds_dynamic_type_t *dtype, const struct elem *elem)
{
  const char *ext = getattr (elem, "extensibility");
  if (ext)
  {
    dds_return_t rc;
    if (strcmp (ext, "final") == 0)
      rc = dds_dynamic_type_set_extensibility (dtype, DDS_DYNAMIC_TYPE_EXT_FINAL);
    else if (strcmp (ext, "appendable") == 0)
      rc = dds_dynamic_type_set_extensibility (dtype, DDS_DYNAMIC_TYPE_EXT_APPENDABLE);
    else if (strcmp (ext, "mutable") == 0)
      rc = dds_dynamic_type_set_extensibility (dtype, DDS_DYNAMIC_TYPE_EXT_MUTABLE);
    else
      exitelem (elem, "unknown extensibility %s\n", ext);
    if (rc != DDS_RETCODE_OK)
      exitelem (elem, "set_extensibility failed: %s\n", dds_strretcode (rc));
  }
}

static void set_autoid (dds_dynamic_type_t *dtype, const struct elem *elem)
{
  const char *autoid = getattr (elem, "autoid");
  if (autoid)
  {
    dds_return_t rc;
    if (strcmp (autoid, "sequential") == 0)
      rc = dds_dynamic_type_set_autoid (dtype, DDS_DYNAMIC_TYPE_AUTOID_SEQUENTIAL);
    else if (strcmp (autoid, "hash") == 0)
      rc = dds_dynamic_type_set_autoid (dtype, DDS_DYNAMIC_TYPE_AUTOID_HASH);
    else
      exitelem (elem, "unknown autoid %s\n", autoid);
    if (rc != DDS_RETCODE_OK)
      exitelem (elem, "set_autoid failed: %s\n", dds_strretcode (rc));
  }
}

static void make_struct (const struct make_context *ctxt, const struct elem *elem, const char *ns)
{
  const char *name = getattr (elem, "name");
  if (name == NULL)
    exitelem (elem, "name missing\n");
  char *fqname;
  ddsrt_asprintf (&fqname, "%s::%s", ns, name);
  dds_dynamic_type_t *dstruct = ddsrt_malloc (sizeof (*dstruct));
  *dstruct = dds_dynamic_type_create (ctxt->dp, (dds_dynamic_type_descriptor_t) {
    .kind = DDS_DYNAMIC_STRUCTURE, .name = fqname
  });
  set_extensibility (dstruct, elem);
  set_autoid (dstruct, elem);
  for (const struct elem *m = elem->children; m; m = m->next)
    add_struct_member (ctxt, dstruct, m, ns);
  register_type (ctxt, elem, dstruct, fqname);
}

static void make_union (const struct make_context *ctxt, const struct elem *elem, const char *ns)
{
  const char *name = getattr (elem, "name");
  if (name == NULL)
    exitelem (elem, "name missing\n");
  char *fqname;
  ddsrt_asprintf (&fqname, "%s::%s", ns, name);

  // We require the discriminator type at the time of creating the union, so go look for it
  const struct elem *discriminator_elem = NULL;
  dds_dynamic_type_spec_t discts = DDS_DYNAMIC_TYPE_SPEC_PRIM (DDS_DYNAMIC_BOOLEAN);
  {
    bool discts_set = false;
    for (const struct elem *c = elem->children; c; c = c->next)
    {
      if (strcmp (c->name, "discriminator") != 0)
        continue;
      discriminator_elem = c;
      discts = get_typespec (ctxt, c, ns);
      discts_set = true;
      break;
    }
    if (!discts_set)
      exitelem (elem, "discriminator missing\n");
  }

  dds_dynamic_type_t *dunion = ddsrt_malloc (sizeof (*dunion));
  *dunion = dds_dynamic_type_create (ctxt->dp, (dds_dynamic_type_descriptor_t) {
    .kind = DDS_DYNAMIC_UNION, .name = fqname, .discriminator_type = discts
  });

  set_extensibility (dunion, elem);
  set_autoid (dunion, elem);

  for (const struct elem *c = elem->children; c; c = c->next)
  {
    if (strcmp (c->name, "case") != 0)
      continue; // presumably "discriminator"

    uint32_t nlabs = 0;
    int32_t labs[10];
    bool isdefault = false;

    for (const struct elem *m = c->children; m; m = m->next)
    {
      if (strcmp (m->name, "caseDiscriminator") != 0) // presumably "member"
        continue;
      const char *valstr = getattr (m, "value");
      if (valstr == NULL)
        exitelem (m, "no value in caseDiscriminator\n");
      if (strcmp (valstr, "default") == 0) // what about an enum where "default" is a literal?
        isdefault = true;
      else if (*valstr == 0)
        exitelem (m, "empty value in caseDiscriminator\n");
      else if (nlabs == sizeof (labs) / sizeof (labs[0]))
        exitelem (m, "too many labels\n");
      else
      {
        char *endptr;
        labs[nlabs++] = (int32_t) strtol (valstr, &endptr, 0);
        if (*endptr)
        {
          if (strcmp(getattr(discriminator_elem, "type"), "nonBasic") != 0)
            exitelem (m, "junk at end of value\n");
          struct type* d_enum = lookup_type(ctxt, ns, getattr(discriminator_elem, "nonBasicTypeName"));
          if (d_enum->typeobj->_u.complete._d != DDS_XTypes_TK_ENUM)
            exitelem (m, "Non eunm type for literal values\n");
          const DDS_XTypes_CompleteEnumeratedType *c_enum = &d_enum->typeobj->_u.complete._u.enumerated_type;
          bool enum_contains_value = false;
          for (uint32_t i = 0; i < c_enum->literal_seq._length; i++)
          {
            if (strcmp(valstr, c_enum->literal_seq._buffer[i].detail.name) != 0)
              continue;
            enum_contains_value = true;
            labs[nlabs - 1] = c_enum->literal_seq._buffer[i].common.value;
            break;
          }
          if (!enum_contains_value)
            exitelem(m, "Enum does not contain value\n");
        }
      }
    }

    const struct elem *m;
    for (m = c->children; m; m = m->next)
      if (strcmp (m->name, "member") == 0)
        break;
    if (m == NULL)
      exitelem (c, "member missing in case\n");
    add_member (ctxt, dunion, m, ns, nlabs, labs, isdefault);
  }

  register_type (ctxt, elem, dunion, fqname);
}

static void make_enum (const struct make_context *ctxt, const struct elem *elem, const char *ns)
{
  dds_return_t rc = DDS_RETCODE_OK;
  const char *name = getattr (elem, "name");
  if (name == NULL)
    exitelem (elem, "name missing\n");
  char *fqname;
  ddsrt_asprintf (&fqname, "%s::%s", ns, name);
  dds_dynamic_type_t *denum = ddsrt_malloc (sizeof (*denum));
  *denum = dds_dynamic_type_create (ctxt->dp, (dds_dynamic_type_descriptor_t) {
    .kind = DDS_DYNAMIC_ENUMERATION, .name = fqname
  });

  set_extensibility (denum, elem);

  const char *bitboundstr = getattr (elem, "bitBound");
  if (bitboundstr != NULL)
  {
    uint16_t bitbound;
    int pos;
    if (sscanf (bitboundstr, "%"SCNu16"%n", &bitbound, &pos) != 1 || bitboundstr[pos] != 0)
      exitelem (elem, "invalid bitbound: %s\n", bitboundstr);
    rc = dds_dynamic_type_set_bit_bound (denum, bitbound);
    if (rc != DDS_RETCODE_OK)
      exitelem (elem, "set_bit_bound failed: %s\n", dds_strretcode (rc));
  }

  for (const struct elem *m = elem->children; m; m = m->next)
  {
    if (strcmp (m->name, "enumerator") != 0)
      exitelem (m, "expected \"enumerator\", got \"%s\"\n", m->name);

    const char *mname = getattr (m, "name");
    if (mname == NULL)
      exitelem (m, "name missing\n");
    const char *valuestr = getattr (m, "value");
    if (valuestr == NULL)
      exitelem (m, "value missing\n");
    int32_t value;
    int pos;
    if (sscanf (valuestr, "%"SCNd32"%n", &value, &pos) != 1 || valuestr[pos] != 0)
      exitelem (m, "value not a plain integer %s\n", valuestr);

    rc = dds_dynamic_type_add_enum_literal (denum, mname, DDS_DYNAMIC_ENUM_LITERAL_VALUE(value), false);
    if (rc != DDS_RETCODE_OK)
      exitelem (m, "add_enum_literal failed: %s\n",  dds_strretcode (rc));
  }

  register_type (ctxt, elem, denum, fqname);
}

static void make_bitmask (const struct make_context *ctxt, const struct elem *elem, const char *ns)
{
  dds_return_t rc = DDS_RETCODE_OK;
  const char *name = getattr (elem, "name");
  if (name == NULL)
    exitelem (elem, "name missing\n");
  char *fqname;
  ddsrt_asprintf (&fqname, "%s::%s", ns, name);
  dds_dynamic_type_t *dbitmask = ddsrt_malloc (sizeof (*dbitmask));
  *dbitmask = dds_dynamic_type_create (ctxt->dp, (dds_dynamic_type_descriptor_t) {
    .kind = DDS_DYNAMIC_BITMASK, .name = fqname
  });

  set_extensibility (dbitmask, elem);

  const char *bitboundstr = getattr (elem, "bitBound");
  if (bitboundstr != NULL)
  {
    uint16_t bitbound;
    int pos;
    if (sscanf (bitboundstr, "%"SCNu16"%n", &bitbound, &pos) != 1 || bitboundstr[pos] != 0)
      exitelem (elem, "invalid bitbound: %s\n", bitboundstr);
    rc = dds_dynamic_type_set_bit_bound (dbitmask, bitbound);
    if (rc != DDS_RETCODE_OK)
      exitelem (elem, "set_bit_bound failed: %s\n", dds_strretcode (rc));
  }

  for (const struct elem *m = elem->children; m; m = m->next)
  {
    if (strcmp (m->name, "flag") != 0)
      exitelem (m, "expected \"flag\", got \"%s\"\n", m->name);

    const char *mname = getattr (m, "name");
    if (mname == NULL)
      exitelem (m, "name missing\n");
    const char *valuestr = getattr (m, "position"); // XSD says "position"
    if (valuestr == NULL)
      valuestr = getattr (m, "value"); // interop test uses "value" ...
    if (valuestr == NULL)
      exitelem (m, "value missing\n");
    int32_t value;
    int pos;
    if (sscanf (valuestr, "%"SCNd32"%n", &value, &pos) != 1 || valuestr[pos] != 0)
      exitelem (m, "value not a plain integer %s\n", valuestr);

    rc = dds_dynamic_type_add_bitmask_field (dbitmask, mname, (uint16_t) value);
    if (rc != DDS_RETCODE_OK)
      exitelem (m, "add_enum_literal failed: %s\n", dds_strretcode (rc));
  }

  register_type (ctxt, elem, dbitmask, fqname);
}

static void make_types (const struct make_context *ctxt, const struct elem *elem, const char *ns)
{
  if (strcmp (elem->name, "module") == 0)
    make_module (ctxt, elem, ns);
  else if (strcmp (elem->name, "struct") == 0)
    make_struct (ctxt, elem, ns);
  else if (strcmp (elem->name, "union") == 0)
    make_union (ctxt, elem, ns);
  else if (strcmp (elem->name, "enum") == 0)
    make_enum (ctxt, elem, ns);
  else if (strcmp (elem->name, "bitmask") == 0)
    make_bitmask (ctxt, elem, ns);
  else
    exitelem (elem, "unrecognized element %s\n", elem->name);
}

static uint32_t namehash (const void *va)
{
  const struct type *a = va;
  ddsrt_md5_state_t st;
  ddsrt_md5_init (&st);
  ddsrt_md5_append (&st, (const ddsrt_md5_byte_t *) a->name, (unsigned) (strlen (a->name) + 1));
  ddsrt_md5_byte_t digest[16];
  ddsrt_md5_finish (&st, digest);
  uint32_t hash;
  memcpy (&hash, digest, sizeof (hash));
  return hash;
}

static bool nameequal (const void *va, const void *vb)
{
  const struct type *a = va;
  const struct type *b = vb;
  return strcmp (a->name, b->name) == 0;
}

static struct type *find_type (struct ddsrt_hh *typelib, const char *name)
{
  if (*name == ':') // fq name: hash lookup
    return ddsrt_hh_lookup (typelib, &(struct type){ .name = (char *) name });
  else // non-fq name: pick the shortest match (breaking ties arbitrarily)
  {
    struct ddsrt_hh_iter it;
    size_t matchlen = SIZE_MAX;
    for (struct type *t = ddsrt_hh_iter_first (typelib, &it); t; t = ddsrt_hh_iter_next (&it))
    {
      size_t arglen = strlen (name);
      size_t len = strlen (t->name);
      if (len < matchlen
          && len >= arglen + 2
          && strncmp (t->name + len - arglen - 2, "::", 2) == 0
          && strcmp (t->name + len - arglen, name) == 0)
      {
        return t;
      }
    }
  }
  return NULL;
}

static bool find_type_pair (struct ddsrt_hh *typelib, const char *names, struct type **wrtype, struct type **rdtype)
{
  char *wtname = strdup (names);
  char *rtname = strchr (wtname, '/');
  bool res = true;
  if (rtname)
    *rtname++ = 0;
  else
    rtname = wtname;
  *wrtype = *rdtype = NULL;
  if (*wtname) {
    printf ("T wr %s = ", wtname); fflush (stdout);
    if ((*wrtype = find_type (typelib, wtname)) == NULL) {
      printf ("unknown\n");
      res = false;
    } else {
      printf ("%s\n", (*wrtype)->name);
    }
  }
  if (*rtname) {
    printf ("T rd %s = ", rtname); fflush (stdout);
    if ((*rdtype = find_type (typelib, rtname)) == NULL) {
      printf ("unknown\n");
      res = false;
    } else {
      printf ("%s\n", (*rdtype)->name);
    }
  }
  free (wtname);
  return res;
}

static bool doread (const dds_entity_t ws, const dds_entity_t rd, DDS_XTypes_TypeObject const * const typeobj, bool exit_on_timeout)
{
  dds_return_t rc;
  rc = dds_waitset_wait (ws, NULL, 0, DDS_SECS (1));
  if (rc < 0)
    exitfmt ("dds_waitset_wait: %s\n", dds_strretcode (rc));
  if (rc == 0 && exit_on_timeout)
    return false;
  void *ptr = NULL;
  dds_sample_info_t si;
  while ((rc = dds_take (rd, &ptr, &si, 1, 1)) == 1)
  {
    print_sample (si.valid_data, ptr, &typeobj->_u.complete);
    dds_return_loan (rd, &ptr, 1);
  }
  if (rc < 0)
    exitfmt ("dds_take: %s\n", dds_strretcode (rc));

  dds_requested_incompatible_qos_status_t riq;
  rc = dds_get_requested_incompatible_qos_status (rd, &riq);
  if (rc < 0)
    exitfmt ("dds_get_requested_incompatible_qos_status: %s\n", dds_strretcode (rc));
  if (riq.total_count_change != 0)
    printf ("riq policy %"PRIu32"\n", riq.last_policy_id);

  dds_subscription_matched_status_t sm;
  rc = dds_get_subscription_matched_status (rd, &sm);
  if (rc < 0)
    exitfmt ("dds_get_subscription_matched_status: %s\n", dds_strretcode (rc));
  return (riq.total_count == 0 && (sm.current_count > 0 || sm.current_count_change >= 0));
}

static void usage (const char *argv0)
{
  fprintf (stderr, "usage: %s [OPTIONS] xmlfile TYPE DATA...\n\
\n\
OPTIONS:\n\
-c BINDIGITS   set type consistency enforcement to BINDIGITS, which must\n\
               consist of five 0 or 1 digits:\n\
                - ignore sequence bounds\n\
                - ignore string bounds\n\
                - ignore member names\n\
                - prevent type widening\n\
                - force type validation\n\
",
           argv0);
  exit (2);
}

int main (int argc, char **argv)
{
  int opt;
  uint32_t tce = 0x18; // default true,true,false,false,false
  while ((opt = getopt (argc, argv, "c:")) != EOF)
  {
    switch (opt)
    {
      case 'c':
        if (strspn (optarg, "01") != 5 || optarg[5] != 0) {
          fprintf (stderr, "%s: %s is not a valid type consistency enforcement setting\n", argv[0], optarg);
          exit (2);
        }
        tce = 0;
        for (const char *p = optarg; *p; p++)
          tce = (tce << 1) | (*p == '1');
        break;
      default:
        usage (argv[0]);
        break;
    }
  }

  if (argc - optind < 2)
    usage (argv[0]);

  struct elem *root = domtree_from_file (argv[optind]);
  if (root == NULL)
  {
    fprintf (stderr, "%s: %s: can't read type definition\n", argv[0], argv[optind]);
    return 2;
  }
  //domtree_print (root);

  if (root == NULL || strcmp (root->name, "dds") != 0 || root->children == NULL || strcmp (root->children->name, "types") != 0)
    exitfmt ("%s: %s: expected <dds><types>...\n", argv[0], argv[optind]);

  dds_entity_t dp = dds_create_participant (DDS_DOMAIN_DEFAULT, NULL, NULL);
  if (dp < 0)
    exitfmt ("%s: create_participant failed: %s\n", argv[0], dds_strretcode (dp));

  type_cache_init ();

  struct ddsrt_hh *typelib = ddsrt_hh_new (32, namehash, nameequal);
  struct make_context ctxt = {
    .file = argv[optind],
    .dp = dp,
    .typelib = typelib
  };
  make_types (&ctxt, root->children->children, "");

  struct type *wrtype = NULL, *rdtype = NULL;
  dds_topic_descriptor_t *wrdescriptor = NULL, *rddescriptor = NULL;
  dds_entity_t wrtp = 0, rdtp = 0, wr = 0, rd = 0, ws = 0;
  for (int argi = optind + 1; argi < argc; argi++)
  {
    size_t arglen = strlen (argv[argi]);
    dds_return_t rc;
    if (arglen <= 4 || strcmp (argv[argi] + arglen - 4, ".xml") != 0)
    {
      if (!find_type_pair (typelib, argv[argi], &wrtype, &rdtype))
        exitfmt ("\ncreate topic: type lookup failed\n");

      // Can be freed immediately after creating topic, but we use it for freeing samples
      if (wrdescriptor)
        dds_delete_topic_descriptor (wrdescriptor);
      if (rddescriptor)
        dds_delete_topic_descriptor (rddescriptor);

      dds_delete (ws); ws = 0;
      dds_delete (rd); rd = 0;
      dds_delete (wr); wr = 0;
      dds_delete (wrtp); wrtp = 0;
      dds_delete (rdtp); rdtp = 0;

      dds_qos_t *tpqos = dds_create_qos ();
      dds_qset_reliability (tpqos, DDS_RELIABILITY_RELIABLE, DDS_SECS (1));
      dds_qos_t *epqos = dds_create_qos ();
      dds_qset_type_consistency (
              epqos, DDS_TYPE_CONSISTENCY_ALLOW_TYPE_COERCION,
              (tce >> 4) & 1,
              (tce >> 3) & 1,
              (tce >> 2) & 1,
              (tce >> 1) & 1,
              tce & 1);

      if (wrtype) {
        rc = dds_create_topic_descriptor (DDS_FIND_SCOPE_LOCAL_DOMAIN, dp, wrtype->typeinfo, 0, &wrdescriptor);
        if (rc != 0)
          exitfmt ("dds_create_topic_descriptor: %s\n", dds_strretcode (rc));
        wrtp = dds_create_topic (dp, wrdescriptor, "T", tpqos, NULL);
        if (wrtp < 0)
          exitfmt ("dds_create_topic: %s\n", dds_strretcode (wrtp));
        wr = dds_create_writer (dp, wrtp, epqos, NULL);
        if (wr < 0)
          exitfmt ("dds_create_writer: %s\n", dds_strretcode (wr));
        rc = dds_set_status_mask (wr, DDS_OFFERED_INCOMPATIBLE_QOS_STATUS);
        if (rc != 0)
          exitfmt ("dds_set_status_mask: %s\n", dds_strretcode (rc));
      }
      if (rdtype) {
        rc = dds_create_topic_descriptor (DDS_FIND_SCOPE_LOCAL_DOMAIN, dp, rdtype->typeinfo, 0, &rddescriptor);
        if (rc != 0)
          exitfmt ("dds_create_topic_descriptor: %s\n", dds_strretcode (rc));
        rdtp = dds_create_topic (dp, rddescriptor, "T", tpqos, NULL);
        if (rdtp < 0)
          exitfmt ("dds_create_topic: %s\n", dds_strretcode (rdtp));
        rd = dds_create_reader (dp, rdtp, epqos, NULL);
        if (rd < 0)
          exitfmt ("dds_create_reader: %s\n", dds_strretcode (rd));
        rc = dds_set_status_mask (rd, DDS_DATA_AVAILABLE_STATUS | DDS_SUBSCRIPTION_MATCHED_STATUS | DDS_REQUESTED_INCOMPATIBLE_QOS_STATUS);
        if (rc != 0)
          exitfmt ("dds_set_status_mask: %s\n", dds_strretcode (rc));
        ws = dds_create_waitset (dp);
        if (ws < 0)
          exitfmt ("dds_create_waitset: %s\n", dds_strretcode (rd));
        rc = dds_waitset_attach (ws, rd, 0);
        if (rc != 0)
          exitfmt ("dds_waitset_attach reader: %s\n", dds_strretcode (rc));
      }

      dds_delete_qos (epqos);
      dds_delete_qos (tpqos);

      struct ppc ppc;
      ppc_init (&ppc);
      size_t align, size;
      if (wrtype)
      {
        build_typecache_to (&wrtype->typeobj->_u.complete, &align, &size);
        ppc_print_to (&ppc, &wrtype->typeobj->_u.complete);
      }
      if (rdtype)
      {
        build_typecache_to (&rdtype->typeobj->_u.complete, &align, &size);
        ppc_print_to (&ppc, &rdtype->typeobj->_u.complete);
      }

      // short sleep before writing so a remote reader is likely to have been discovered before the sample is written
      dds_sleepfor (DDS_MSECS (100));
    }
    else
    {
      // data file
      if (wr == 0)
        exitfmt ("%s: data file given, but no writer type set yet\n", argv[argi]);

      struct elem *input = domtree_from_file (argv[argi]);
      if (input == NULL)
        exitfmt ("%s: %s: can't read sample\n", argv[0], argv[argi]);
      domtree_print (input);
      void *sample = scan_sample (input, &wrtype->typeobj->_u.complete, true);
      if (sample == NULL)
        exitfmt ("%s: %s: can't convert to sample\n", argv[0], argv[argi]);
      if ((rc = dds_write (wr, sample)) != 0)
        exitfmt ("%s: %s: can't write: %s\n", argv[0], argv[argi], dds_strretcode (rc));
      const struct dds_cdrstream_allocator a = {
        .malloc = ddsrt_malloc,
        .free = ddsrt_free,
        .realloc = ddsrt_realloc };
      dds_stream_free_sample (sample, &a, wrdescriptor->m_ops);
      ddsrt_free (sample);

      if (rd)
        doread (ws, rd, rdtype->typeobj, true);

      // sleep a bit after writing data
      if (argi < argc)
        dds_sleepfor (DDS_MSECS (500));
    }
  }

  if (wr)
  {
    dds_offered_incompatible_qos_status_t oiq;
    dds_return_t rc = dds_get_offered_incompatible_qos_status (wr, &oiq);
    if (rc < 0)
      exitfmt ("dds_get_offered_incompatible_matched_status: %s\n", dds_strretcode (rc));
    if (oiq.total_count_change != 0)
      printf ("oiq policy %"PRIu32"\n", oiq.last_policy_id);
  }

  if (wr)
    dds_delete (wr);
  if (rd)
  {
    while (doread (ws, rd, rdtype->typeobj, false))
      ;
  }

  type_cache_free ();

  struct ddsrt_hh_iter it;
  for (struct type *t = ddsrt_hh_iter_first (typelib, &it); t; t = ddsrt_hh_iter_next (&it))
  {
    //printf ("free %s\n", t->name);
    dds_free_typeobj ((dds_typeobj_t *) t->typeobj);
    dds_dynamic_type_unref (t->dtype);
    dds_free_typeinfo (t->typeinfo);
    ddsrt_free (t->dtype);
    ddsrt_free (t->name);
    ddsrt_free (t);
  }
  ddsrt_hh_free (typelib);
  dds_delete (dp);
  return 0;
}
