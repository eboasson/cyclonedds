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
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "idl/string.h"
#include "descriptor.h"
#include "plugin.h"

#include "CUnit/Theory.h"

static void generate_test_descriptor (idl_pstate_t *pstate, const char *idl, struct descriptor *descriptor)
{
  idl_retcode_t ret = idl_parse_string(pstate, idl);
  CU_ASSERT_EQUAL_FATAL (ret, IDL_RETCODE_OK);

  bool topic_found = false;
  for (idl_node_t *node = pstate->root; node; node = idl_next (node))
  {
    if (idl_is_topic (node, (pstate->flags & IDL_FLAG_KEYLIST)))
    {
      ret = generate_descriptor_impl(pstate, node, descriptor);
      CU_ASSERT_EQUAL_FATAL (ret, IDL_RETCODE_OK);
      topic_found = true;
      break;
    }
  }
  CU_ASSERT_FATAL (topic_found);
}

#define TEST_MAX_KEYS 10
CU_Test(idlc_descriptor, keys_nested)
{
  static const struct {
    const char *idl;
    uint32_t n_keys;
    uint32_t n_key_offs; // number of key offset: the sum of (1 + number of nesting levels) for all keys
    bool keylist; // indicates if pragma keylist is used
    uint32_t key_size[TEST_MAX_KEYS]; // key size in bytes
    uint32_t key_order[TEST_MAX_KEYS];
    const char *key_name[TEST_MAX_KEYS];
  } tests[] = {
    { "struct test { @key @id(2) long a; short b; }; ",
      1, 2, false, { 4 }, { 2 }, { "a" } },
    { "struct test { @key long a; @key short b; }; ",
      2, 4, false, { 4, 2 }, { 0, 1 }, { "a", "b" } },
    { "@nested struct inner { @id(3) long i1; @id(1) short i2; }; struct outer { @key inner o1; }; ",
      2, 6, false, { 2, 4 }, { 1, 3 }, { "o1.i2", "o1.i1" } },
    { "@nested struct inner { long i1; @key short i2; }; struct outer { @key inner o1; }; ",
      1, 3, false, { 2 }, { 1 }, { "o1.i2" } },
    { "@nested struct inner { @key short i1; }; struct outer { @key inner o1; @key inner o2; }; ",
      2, 6, false, { 2, 2 }, { 0, 1 }, { "o1.i1", "o2.i1" } },
    { "@nested struct inner { @key short i1; }; @nested struct mid { @key char m1; @key inner m2; long m3; }; struct outer { @key mid o1; @key inner o2; }; ",
      3, 10, false, { 1, 2, 2 }, { 0, 1, 1 }, { "o1.m1", "o1.m2.i1", "o2.i1" } },
    { "@nested struct inner { char i1; @key @id(1) char i2; }; struct outer { @key @id(3) inner o1; @key @id(2) short o2; }; ",
      2, 5, false, { 2, 1 }, { 2, 3 }, { "o2", "o1.i2" } },
    { "@nested struct inner { char i1; @key @id(1) char i2; }; struct outer { @key @id(2) inner o1; @key @id(3) short o2; }; ",
      2, 5, false, { 1, 2 }, { 2, 3 }, { "o1.i2", "o2" } },

    { "struct test { long a; short b; }; \n#pragma keylist test a",
      1, 2, true, { 4 }, { 1 }, { "a" } },
    { "struct test { long a; short b; }; \n#pragma keylist test a b",
      2, 4, true, { 4, 2 }, { 1, 2 }, { "a", "b" } },
    { "struct inner { long i1; short i2; }; struct outer { inner o1; inner o2; }; \n#pragma keylist outer o1.i1",
      1, 3, true, { 4 }, { 1 }, { "o1.i1" } },
    { "struct inner { long i1; short i2; }; struct outer { inner o1; inner o2; }; \n#pragma keylist outer o1.i1 o2.i1",
      2, 6, true, { 4, 4 }, { 1, 2 }, { "o1.i1", "o2.i1" } },
    { "struct inner { long long i1; }; struct outer { inner o1; inner o2; }; \n#pragma keylist outer o2.i1 o1.i1",
      2, 6, true, { 8, 8 }, { 1, 2 }, { "o2.i1", "o1.i1" } },
    { "struct inner { char i1; }; struct mid { short m1; inner m2; long m3; }; struct outer { mid o1; inner o2; }; \n#pragma keylist outer o1.m1 o1.m2.i1 o2.i1",
      3, 10, true, { 2, 1, 1 }, { 1, 2, 3 }, { "o1.m1", "o1.m2.i1", "o2.i1" } },
  };

  idl_retcode_t ret;
  uint32_t flags = IDL_FLAG_EXTENDED_DATA_TYPES |
                   IDL_FLAG_ANONYMOUS_TYPES |
                   IDL_FLAG_ANNOTATIONS;
  for (size_t i = 0; i < sizeof (tests) / sizeof (tests[0]); i++) {
    static idl_pstate_t *pstate = NULL;
    struct descriptor descriptor;

    printf ("running test for idl: %s\n", tests[i].idl);

    ret = idl_create_pstate (flags | (tests[i].keylist ? IDL_FLAG_KEYLIST : 0), NULL, &pstate);
    CU_ASSERT_EQUAL_FATAL (ret, IDL_RETCODE_OK);

    generate_test_descriptor (pstate, tests[i].idl, &descriptor);

    CU_ASSERT_EQUAL_FATAL (descriptor.n_keys, tests[i].n_keys);
    CU_ASSERT_EQUAL_FATAL (descriptor.key_offsets.count, tests[i].n_key_offs);
    CU_ASSERT_EQUAL_FATAL (pstate->keylists, tests[i].keylist);

    uint32_t sz = 0;
    struct key_print_meta *keys = get_key_print_meta(&descriptor, tests[i].keylist, &sz);
    for (uint32_t k = 0; k < descriptor.n_keys; k++) {
      CU_ASSERT_EQUAL_FATAL (keys[k].size, tests[i].key_size[k]);
      CU_ASSERT_EQUAL_FATAL (keys[k].order, tests[i].key_order[k]);
      CU_ASSERT_STRING_EQUAL_FATAL (keys[k].name, tests[i].key_name[k]);
    }

    ret = descriptor_fini (&descriptor);
    CU_ASSERT_EQUAL_FATAL (ret, IDL_RETCODE_OK);

    idl_delete_pstate (pstate);
    free (keys);
  }
}
