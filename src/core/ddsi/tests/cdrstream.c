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
#include <assert.h>
#include <limits.h>

#include "CUnit/Theory.h"

#include "dds/ddsrt/cdtors.h"
#include "dds/ddsrt/heap.h"
#include "dds/ddsrt/string.h"
#include "dds/ddsrt/bswap.h"
#include "dds/ddsrt/static_assert.h"

#include "dds/dds.h"
#include "dds/ddsi/ddsi_cdrstream.h"
#include "mem_ser.h"

/* VM instructions generated with IDLC and copied in to avoid a dependency on the IDL
   compiler for these tests and because it keeps the hand-crafted, invalid payloads next
   to the VM instructions.

     sed -ne '/^\/\/==IDL==/,/^\/\/==END==/p' .../cdrstream.c | bin/idlc /dev/fd/0

   works to regenerate.
*/

#define MK_STDEF(ops_, format_, version_)                      \
  &(struct ddsi_sertype_default){                              \
    .encoding_format = (format_),                              \
    .encoding_version = (version_),                            \
    .type = {                                                  \
      .flagset = DDS_TOPIC_NO_OPTIMIZE,                        \
      .keys = { 0, NULL },                                     \
      .ops = {                                                 \
        .nops = (uint32_t) (sizeof (ops_) / sizeof (*(ops_))), \
        .ops = (uint32_t *) (ops_)                             \
      }                                                        \
    }                                                          \
  }

#define MK_PLAIN1(ops) MK_STDEF (ops, CDR_ENC_FORMAT_PLAIN, CDR_ENC_VERSION_1)
#define MK_PLAIN2(ops) MK_STDEF (ops, CDR_ENC_FORMAT_PLAIN, CDR_ENC_VERSION_2)
#define MK_DEL2(ops)   MK_STDEF (ops, CDR_ENC_FORMAT_DELIMITED, CDR_ENC_VERSION_2)
#define MK_PL2(ops)    MK_STDEF (ops, CDR_ENC_FORMAT_PL, CDR_ENC_VERSION_2)

typedef unsigned char U;
typedef struct patch P;

enum mode {
  P_FAIL,     // input invalid even without patching
  P_DELIM4,   // 4-byte "delimiter": -0, -1, UINT32_MAX
  P_DELIM4_3, // like DELIM4, but padding causes +1,+2,+3 to be valid
  P_LEN4,     // 4-byte length value: +0, +1, UINT32_MAX
  P_LEN4_3,   // like LEN4, but padding causes +1,+2,+3 to be valid
  P_BOOL,     // bool: original, 2, 0xff
  P_STR,      // string length: original, orig with final byte patched, 0, +1, UINT32_MAX
  P_STOP      // end marker
};

#define FAIL    { P_FAIL }
#define D4(o)   { P_DELIM4, o }
#define D4_3(o) { P_DELIM4_3, o }
#define L4(o)   { P_LEN4, o }
#define L4_3(o) { P_LEN4_3, o }
#define STR(o)  { P_STR, o }
#define BOOL(o) { P_BOOL, o }
#define STOP    { P_STOP }

#define PAD1 0
#define PAD2 PAD1,0
#define PAD3 PAD2,0
#define PAD4 PAD3,0
#define PAD5 PAD4,0
#define PAD6 PAD5,0
#define PAD7 PAD6,0

struct patch {
  enum mode mode;
  size_t off;
};

struct data {
  size_t n;         // size of input
  const U *xs;      // correct input
  struct patch *po; // patch instructions
};

struct type {
  const struct ddsi_sertype_default *st;
  const struct data *pl; // terminated by a 0,0 entry
};

static void printbytes (const unsigned char *xs, uint32_t n)
{
  for (uint32_t i = 0; i < n; i++)
    printf ("%s%02x", i == 0 ? "" : " ", xs[i]);
}

static void checknormalize (const struct ddsi_sertype_default *st, unsigned char *xs, uint32_t size, bool expect_ok)
{
  uint32_t actsize = UINT32_MAX;
  printf ("  [%c %2"PRIu32"] { ", expect_ok ? '+' : ' ', size);
  printbytes (xs, size);
  printf (" }");
  fflush (stdout);
  bool res = dds_stream_normalize (xs, size, false, st->encoding_version, st, false, &actsize);
  if (res == expect_ok)
    printf (" ok\n");
  else if (res)
    printf (" fail: incorrectly accepted with actsize = %"PRIu32"\n", actsize);
  else
    printf (" fail: incorrectly rejected\n");
  fflush (stdout);
  CU_ASSERT_FATAL (res == expect_ok);
  if (res)
    CU_ASSERT_FATAL (actsize == size);
}

static bool patch (unsigned char *xs, const unsigned char *xs_orig, struct patch patch, int *state, bool *valid)
{
  switch (patch.mode)
  {
    case P_STOP:
      *valid = true;
      return true;
    case P_FAIL:
      *valid = false;
      return true;
    case P_DELIM4: {
      uint32_t * const v = (uint32_t *) (xs + patch.off);
      uint32_t const * const v0 = (const uint32_t *) (xs_orig + patch.off);
      switch (++*state)
      {
        case 0: case 1:
          *v = *v0 - (uint32_t) *state;
          *valid = (*v >= *v0);
          break;
        case 2:
          *v = UINT32_MAX;
          *valid = false;
          *state = -1;
          break;
      }
      break;
    }
    case P_DELIM4_3: {
      uint32_t * const v = (uint32_t *) (xs + patch.off);
      uint32_t const * const v0 = (const uint32_t *) (xs_orig + patch.off);
      switch (++*state)
      {
        case 0: case 1:
          *v = *v0 - (uint32_t) *state;
          *valid = (*v >= *v0);
          break;
        case 2: case 3: case 4: case 5:
          *v = *v0 + ((unsigned) *state - 1);
          *valid = (*v <= *v0 + 3);
          break;
        case 6:
          *v = UINT32_MAX;
          *valid = false;
          *state = -1;
          break;
      }
      break;
    }
    case P_LEN4: {
      uint32_t * const v = (uint32_t *) (xs + patch.off);
      uint32_t const * const v0 = (const uint32_t *) (xs_orig + patch.off);
      switch (++*state)
      {
        case 0: case 1:
          *v = *v0 + (uint32_t) *state;
          *valid = (*v <= *v0);
          break;
        case 2:
          *v = UINT32_MAX;
          *valid = false;
          *state = -1;
          break;
      }
      break;
    }
    case P_LEN4_3: {
      uint32_t * const v = (uint32_t *) (xs + patch.off);
      uint32_t const * const v0 = (const uint32_t *) (xs_orig + patch.off);
      switch (++*state)
      {
        case 0: case 1: case 2: case 3: case 4:
          *v = *v0 + (uint32_t) *state;
          *valid = (*v <= *v0 + 3);
          break;
        case 5:
          *v = UINT32_MAX;
          *valid = false;
          *state = -1;
          break;
      }
      break;
    }
    case P_STR: {
      uint32_t * const v = (uint32_t *) (xs + patch.off);
      uint32_t const * const v0 = (const uint32_t *) (xs_orig + patch.off);
      unsigned char * const vz = (xs + patch.off + 4 + *v0 - 1);
      switch (++*state)
      {
        case 0: *v = *v0; *vz = 0; *valid = true; break;
        case 1: *v = *v0; *vz = 1; *valid = false; break;
        case 2: *v = 0; *vz = 0; *valid = false; break;
        case 3: *v = *v0 + 1; *vz = 0; *valid = false; break;
        case 4: *v = UINT32_MAX; *vz = 0; *valid = false; *state = -1; break;
      }
      break;
    }
    case P_BOOL: {
      uint8_t * const v = (uint8_t *) (xs + patch.off);
      uint8_t const * const v0 = (const uint8_t *) (xs_orig + patch.off);
      switch (++*state)
      {
        case 0: *v = *v0;  *valid = true;  break;
        case 1: *v = 2;    *valid = false; break;
        case 2: *v = 0xff; *valid = false; *state = -1; break;
      }
    }
  }
  return *state == 0;
}

static bool expect (const bool *v, unsigned np)
{
  bool exp = true;
  for (unsigned j = 0; exp && j < np; j++)
    exp = exp && v[j];
  return exp;
}

static const char *formatstr (struct ddsi_sertype_default const * const st)
{
  switch (st->encoding_format)
  {
    case CDR_ENC_FORMAT_PLAIN: return "plain"; break;
    case CDR_ENC_FORMAT_DELIMITED: return "delimited"; break;
    case CDR_ENC_FORMAT_PL: return "pl"; break;
  }
  abort ();
  return "?";
}

static const char *versionstr (struct ddsi_sertype_default const * const st)
{
  switch (st->encoding_version)
  {
    case CDR_ENC_VERSION_1: return "v1"; break;
    case CDR_ENC_VERSION_2: return "v2"; break;
  }
  abort ();
  return "?";
}

static void dotest (const struct type *types, const char *name)
{
  ddsrt_init ();
  for (size_t ti = 0; types[ti].st; ti++)
  {
    for (size_t pi = 0; types[ti].pl[pi].n; pi++)
    {
      // tweaking inputs is done on a copy of the input
      struct ddsi_sertype_default const * const st = types[ti].st;
      struct data const * const d = &types[ti].pl[pi];
      unsigned char *xs = ddsrt_memdup (d->xs, d->n);
      // initialize number of patch points & patching state
      unsigned np = 0;
      while (d->po[np].mode != P_STOP)
        np++;
      int *p = malloc (np * sizeof (*p));
      bool *v = malloc (np * sizeof (*v));
      for (unsigned i = 0; i < np; i++)
      {
        p[i] = 0;
        v[i] = (d->po[i].mode != P_FAIL);
      }
      
      printf ("%s type %zu payload %zu (%s %s):\n", name, ti, pi, formatstr (st), versionstr (st));

      // must fail if the input is shortened
      if (d->n > 0)
        checknormalize (st, xs, (uint32_t) d->n - 1, false);

      // loop over patch offsets
      unsigned i = 0;
      while (1)
      {
        checknormalize (st, xs, (uint32_t) d->n, expect (v, np));
        while (i < np && patch (xs, d->xs, d->po[i], &p[i], &v[i]))
          i++;
        if (i == np)
          break;
        i = 0;
      }

      free (v);
      free (p);
      ddsrt_free (xs);
    }
  }
  ddsrt_fini ();
}

/* Simple octet sequence
//==IDL==
module octseq_len {
  typedef sequence<octet> os;
  @topic struct X0 { os s; };
  @topic struct X1 { os s[2]; string z; };
  @topic union X2 switch (boolean) { case true: os s; };
};
//==END==
*/

typedef struct octseq_len_os
{
  uint32_t _maximum;
  uint32_t _length;
  uint8_t *_buffer;
  bool _release;
} octseq_len_os;

typedef struct octseq_len_X0
{
  octseq_len_os s;
} octseq_len_X0;

static const uint32_t octseq_len_X0_ops [] =
{
  /* X0 */
  DDS_OP_ADR | DDS_OP_TYPE_SEQ | DDS_OP_SUBTYPE_1BY, offsetof (octseq_len_X0, s),
  DDS_OP_RTS
};

typedef struct octseq_len_X1
{
  octseq_len_os s[2];
  char * z;
} octseq_len_X1;
static const uint32_t octseq_len_X1_ops [] =
{
  /* X1 */
  DDS_OP_ADR | DDS_OP_TYPE_ARR | DDS_OP_SUBTYPE_SEQ, offsetof (octseq_len_X1, s), 2u, (8u << 16u) + 5u, sizeof (octseq_len_os),
  DDS_OP_ADR | DDS_OP_TYPE_SEQ | DDS_OP_SUBTYPE_1BY, 0u,
  DDS_OP_RTS,
  DDS_OP_ADR | DDS_OP_TYPE_STR, offsetof (octseq_len_X1, z),
  DDS_OP_RTS
};

typedef struct octseq_len_X2
{
  bool _d;
  union
  {
    octseq_len_os s;
  } _u;
} octseq_len_X2;

static const uint32_t octseq_len_X2_ops [] =
{
  /* X2 */
  DDS_OP_ADR | DDS_OP_TYPE_UNI | DDS_OP_SUBTYPE_1BY, offsetof (octseq_len_X2, _d), 1u, (11u << 16u) + 4u,
  DDS_OP_JEQ4 | DDS_OP_TYPE_SEQ | 4, true, offsetof (octseq_len_X2, _u.s), 0u,
  DDS_OP_ADR | DDS_OP_TYPE_SEQ | DDS_OP_SUBTYPE_1BY, 0u,
  DDS_OP_RTS,
  DDS_OP_RTS
};

static const struct type octseq_len[] = {
  { .st = MK_PLAIN1 (octseq_len_X0_ops), .pl = (struct data[]){
    { 4, (U[]){ SER32(0) },   (P[]){ L4(0), STOP } },
    { 5, (U[]){ SER32(1),1 }, (P[]){ L4(0), STOP } },
    { 0 }
  } },
  { .st = MK_PLAIN2 (octseq_len_X0_ops), .pl = (struct data[]){
    { 4, (U[]){ SER32(0) },   (P[]){ L4(0), STOP } },
    { 5, (U[]){ SER32(1),1 }, (P[]){ L4(0), STOP } },
    { 0 }
  } },
  { .st = MK_PLAIN1 (octseq_len_X1_ops), .pl = (struct data[]){
    { 13, (U[]){ SER32(0),         SER32(0),         SER32(1),0 }, (P[]){ L4(0),   L4(4),   STR(8),  STOP } },
    { 17, (U[]){ SER32(1),1, PAD3, SER32(0),         SER32(1),0 }, (P[]){ L4_3(0), L4(8),   STR(12), STOP } },
    { 17, (U[]){ SER32(0),         SER32(1),2, PAD3, SER32(1),0 }, (P[]){ L4(0),   L4_3(4), STR(12), STOP } },
    { 21, (U[]){ SER32(1),1, PAD3, SER32(1),2, PAD3, SER32(1),0 }, (P[]){ L4_3(0), L4_3(8), STR(16), STOP } },
    { 0 }
  } },
  // array-of-sequence, plain cdr2: array preceded by length in bytes
  // there are some more cases that'd be interesting to test, but those require additional constraints
  // i.e., the dheader in the 4th case may be larger, and if it is, then the second sequence may also
  // be a bit longer
  //
  // perhaps I should add additional constraints in a string ...
  { .st = MK_PLAIN2 (octseq_len_X1_ops), .pl = (struct data[]){
    { 17, (U[]){ SER32( 8), SER32(0),         SER32(0),         SER32(1),0 }, (P[]){ D4(0),  L4(4),   L4(8),  STR(12), STOP } },
    { 21, (U[]){ SER32(12), SER32(1),1, PAD3, SER32(0),         SER32(1),0 }, (P[]){ D4(0),  L4_3(4), L4(12), STR(16), STOP } },
    { 21, (U[]){ SER32( 9), SER32(0),         SER32(1),2, PAD3, SER32(1),0 }, (P[]){ D4(0),  L4(4),   L4(8),  STR(16), STOP } },
    { 25, (U[]){ SER32(13), SER32(1),1, PAD3, SER32(1),2, PAD3, SER32(1),0 }, (P[]){ D4(0),  L4_3(4), L4(12), STR(20), STOP } },
    // 1 <= #1 < 4 && 1 <= #2 < 4 && #0 == 12 + #2
    { 0 }
  } },
  { .st = MK_PLAIN1 (octseq_len_X2_ops), .pl = (struct data[]){
#if 0 // FIXME: booleans are treated as bytes so aren't validated properly
    {  1, (U[]){ 0 }, (P[]){ BOOL(0), STOP } },
    {  8, (U[]){ 1, PAD3, SER32(0) },   (P[]){ BOOL(0), L4(4), STOP } },
    {  9, (U[]){ 1, PAD3, SER32(1),1 }, (P[]){ BOOL(0), L4(4), STOP } },
#endif
    {  1, (U[]){ 0 }, (P[]) { STOP } },
    {  1, (U[]){ 1 }, (P[]) { FAIL, STOP } },
    {  8, (U[]){ 1, PAD3, SER32(0) },   (P[]){ L4(4), STOP } },
    {  9, (U[]){ 1, PAD3, SER32(1),1 }, (P[]){ L4(4), STOP } },
    { 0 }
  } },
  { 0 }
};

#include <ctype.h>
enum cexpwhat {
  COP_LPAR, COP_RPAR, // abusing cexp as a token representation ...
  // Env -> Integer
  COP_CONST, COP_PATCHREF,
  // Bool -> Bool
  COP_NOT,
  // Bool -> Bool -> Bool
  COP_AND, COP_OR,
  // Integer -> Integer -> Bool
  COP_LT, COP_LEQ, COP_EQ, COP_NEQ, COP_GEQ, COP_GT,
  // Integer -> Integer -> Integer
  COP_ADD, COP_SUB, COP_MUL
};
enum ctype {
  CTY_BOOL,
  CTY_UINT32
};
struct cexp {
  enum cexpwhat what;
  enum ctype type;
  union {
    uint32_t k;
    uint32_t ref;
    struct cexp *un;
    struct cexp *bin[2];
  } u;
};
static struct cexp *newcexp (struct cexp x0)
{
  struct cexp *x = ddsrt_malloc (sizeof (*x));
  if (x == NULL) abort ();
  *x = x0;
  return x;
}
static struct cexp nexttok (const char **s)
{
  // aborts on invalid input, the inputs are part of test definition anyway
  while (isspace ((unsigned char) **s))
    ;
  char const * const * const s0 = s;
  enum cexpwhat what = COP_CONST;
  const char c = *(*s)++;
  switch (c)
  {
    case '#':
      what = COP_PATCHREF;
      /* fall through */
    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9': {
      uint32_t k = 0;
      while (**s >= '0' && **s <= '9')
        k = 10u * k + (uint32_t) (*(*s)++ - '0');
      if (what == COP_PATCHREF && s - s0 == 1)
        abort (); // #x for x not a digit
      return (struct cexp){ .what = what, .u = { .k = k } };
    }
    case '(': return (struct cexp){ .what = COP_LPAR };
    case ')': return (struct cexp){ .what = COP_RPAR };
    case '*': return (struct cexp){ .what = COP_MUL };
    case '+': return (struct cexp){ .what = COP_ADD };
    case '-': return (struct cexp){ .what = COP_SUB };
    case '!':
      if (**s != '=') return (struct cexp){.what = COP_NOT };
      else { (*s)++; return (struct cexp){.what = COP_NEQ }; }
    case '<': case '>':
      if (**s != '=') return (struct cexp){ .what = (c == '<') ? COP_LT : COP_GT };
      else { (*s)++; return (struct cexp){ .what = (c == '<') ? COP_LEQ : COP_GEQ }; }
    case '=':
      if (**s != '=') abort ();
      else { (*s)++; return (struct cexp){ .what = COP_EQ }; }
    case '&': case '|':
      if (**s != c) abort ();
      else { (*s)++; return (struct cexp){ .what = (c == '&') ? COP_AND : COP_OR }; }
    default:
      abort ();
  }
}
static struct cexp *parse (const char **s, int prec)
{
  struct cexp x = nexttok (s);
  switch (x.what)
  {
    case COP_NOT:
      x.type = CTY_BOOL;
      x.u.un = parse (s, prec + 1);
      if (x.u.un->type != CTY_BOOL)
        abort ();
      return newcexp (x);
    case COP_LPAR: {
      struct cexp *y = parse (s, 0);
      if (nexttok (s).what != COP_RPAR)
        abort();
      return y;
    }
    case COP_CONST: case COP_PATCHREF: {
      x.type = CTY_UINT32;
      const char *s0 = *s;
      struct cexp y = nexttok (s);
      int prec1 = -1; enum ctype ty, sty;
      switch (y.what)
      {
        case COP_ADD: case COP_SUB:
          prec1 = 3; ty = CTY_UINT32; sty = CTY_UINT32;
          break;
        case COP_MUL:
          prec1 = 4; ty = CTY_UINT32; sty = CTY_UINT32;
          break;
        case COP_EQ: case COP_NEQ: case COP_LEQ: case COP_GEQ: case COP_LT: case COP_GT:
          prec1 = 1; ty = CTY_BOOL; sty = CTY_UINT32;
          break;
        default:
          abort ();
      }
      if (prec1 < prec) {
        *s = s0; // undo consequences of looking ahead
        return newcexp (x);
      } else {
        struct cexp *z = parse (s, prec1);
        if (x.type != sty || sty != z->type)
          abort ();
        y.type = ty;
        y.u.bin[0] = newcexp (x);
        y.u.bin[1] = z;
        return newcexp (y);
      }
    }
    default: abort ();
  }
}
static int64_t evalk (const struct cexp *exp, const unsigned char *input, const struct patch *ps)
{
  // eval in 64-bit signed so we can mostly ignore overflow and underflow issues
  switch (exp->what)
  {
    case COP_CONST:    return (int64_t) exp->u.k;
    case COP_PATCHREF: return (int64_t) (*((const uint32_t *) (input + ps[exp->u.k].off)));
    case COP_ADD:      return (int64_t) evalk (exp->u.bin[0], input, ps) + evalk (exp->u.bin[1], input, ps);
    case COP_SUB:      return (int64_t) evalk (exp->u.bin[0], input, ps) - evalk (exp->u.bin[1], input, ps);
    case COP_MUL:      return (int64_t) evalk (exp->u.bin[0], input, ps) * evalk (exp->u.bin[1], input, ps);
    default: abort (); return 0;
  }
}
static bool evalb (const struct cexp *exp, const unsigned char *input, const struct patch *ps)
{
  switch (exp->what)
  {
    case COP_LT:  return evalk (exp->u.bin[0], input, ps) <  evalk (exp->u.bin[1], input, ps);
    case COP_LEQ: return evalk (exp->u.bin[0], input, ps) <= evalk (exp->u.bin[1], input, ps);
    case COP_EQ:  return evalk (exp->u.bin[0], input, ps) == evalk (exp->u.bin[1], input, ps);
    case COP_NEQ: return evalk (exp->u.bin[0], input, ps) != evalk (exp->u.bin[1], input, ps);
    case COP_GEQ: return evalk (exp->u.bin[0], input, ps) >= evalk (exp->u.bin[1], input, ps);
    case COP_GT:  return evalk (exp->u.bin[0], input, ps) <  evalk (exp->u.bin[1], input, ps);
    case COP_AND: return evalb (exp->u.bin[0], input, ps) && evalb (exp->u.bin[1], input, ps);
    case COP_OR:  return evalb (exp->u.bin[0], input, ps) || evalb (exp->u.bin[1], input, ps);
    case COP_NOT: return evalb (exp->u.un, input, ps);
    default: abort (); return false;
  }
}
static void freecexp (struct cexp *exp)
{
  if (exp->what > COP_NOT) {
    freecexp (exp->u.bin[0]);
    freecexp (exp->u.bin[1]);
  } else if (exp->what == COP_NOT) {
    freecexp (exp->u.un);
  }
  free (exp);
}

CU_Test (ddsi_cdrstream, octseq_len)
{
  dotest (octseq_len, "octseq_len");
}
