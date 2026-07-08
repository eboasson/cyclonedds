// Copyright(c) 2026 ZettaScale Technology and others
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License v. 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
// v. 1.0 which is available at
// http://www.eclipse.org/org/documents/edl-v10.php.
//
// SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

#include "idl/processor.h"

#include "CUnit/Test.h"

static idl_pstate_t *
parse_string_flags(uint32_t flags, const char *str)
{
  idl_pstate_t *pstate = NULL;
  idl_retcode_t ret;

  ret = idl_create_pstate(flags, NULL, &pstate);
  CU_ASSERT_EQ_FATAL(ret, IDL_RETCODE_OK);
  CU_ASSERT_NEQ_FATAL(pstate, NULL);

  ret = idl_parse_string(pstate, str);
  CU_ASSERT_EQ_FATAL(ret, IDL_RETCODE_OK);
  CU_ASSERT_EQ(pstate->scope, pstate->global_scope);
  return pstate;
}

static idl_pstate_t *
parse_string(const char *str)
{
  return parse_string_flags(0u, str);
}

CU_Test(idl_hand_parser, module_with_empty_struct)
{
  idl_pstate_t *pstate;
  idl_module_t *module;
  idl_struct_t *strct;

  pstate = parse_string("module outer { struct Leaf { }; };");
  module = (idl_module_t *) pstate->root;
  CU_ASSERT_NEQ_FATAL(module, NULL);
  CU_ASSERT_FATAL(idl_is_module(module));
  CU_ASSERT_EQ(idl_parent(module), NULL);
  CU_ASSERT_EQ(idl_next(module), NULL);
  CU_ASSERT_STREQ(idl_identifier(module), "outer");

  strct = (idl_struct_t *) module->definitions;
  CU_ASSERT_NEQ_FATAL(strct, NULL);
  CU_ASSERT_FATAL(idl_is_struct(strct));
  CU_ASSERT_EQ(idl_parent(strct), module);
  CU_ASSERT_EQ(idl_next(strct), NULL);
  CU_ASSERT_STREQ(idl_identifier(strct), "Leaf");
  CU_ASSERT_EQ(strct->members, NULL);

  idl_delete_pstate(pstate);
}

CU_Test(idl_hand_parser, nested_module_with_empty_struct)
{
  idl_pstate_t *pstate;
  idl_module_t *outer;
  idl_module_t *inner;
  idl_struct_t *strct;
  const char str[] =
    "module outer {\n"
    "  // comments and newlines should not reach the grammar\n"
    "  module inner { struct Leaf { }; };\n"
    "};\n";

  pstate = parse_string(str);
  outer = (idl_module_t *) pstate->root;
  CU_ASSERT_NEQ_FATAL(outer, NULL);
  CU_ASSERT_FATAL(idl_is_module(outer));
  CU_ASSERT_EQ(idl_parent(outer), NULL);
  CU_ASSERT_EQ(idl_next(outer), NULL);
  CU_ASSERT_STREQ(idl_identifier(outer), "outer");

  inner = (idl_module_t *) outer->definitions;
  CU_ASSERT_NEQ_FATAL(inner, NULL);
  CU_ASSERT_FATAL(idl_is_module(inner));
  CU_ASSERT_EQ(idl_parent(inner), outer);
  CU_ASSERT_EQ(idl_next(inner), NULL);
  CU_ASSERT_STREQ(idl_identifier(inner), "inner");

  strct = (idl_struct_t *) inner->definitions;
  CU_ASSERT_NEQ_FATAL(strct, NULL);
  CU_ASSERT_FATAL(idl_is_struct(strct));
  CU_ASSERT_EQ(idl_parent(strct), inner);
  CU_ASSERT_EQ(idl_next(strct), NULL);
  CU_ASSERT_STREQ(idl_identifier(strct), "Leaf");
  CU_ASSERT_EQ(strct->members, NULL);

  idl_delete_pstate(pstate);
}

CU_Test(idl_hand_parser, strips_identifier_escape)
{
  idl_pstate_t *pstate;
  idl_module_t *module;
  idl_struct_t *strct;

  pstate = parse_string("module _module { struct _struct { }; };");
  module = (idl_module_t *) pstate->root;
  CU_ASSERT_NEQ_FATAL(module, NULL);
  CU_ASSERT_FATAL(idl_is_module(module));
  CU_ASSERT_STREQ(idl_identifier(module), "module");

  strct = (idl_struct_t *) module->definitions;
  CU_ASSERT_NEQ_FATAL(strct, NULL);
  CU_ASSERT_FATAL(idl_is_struct(strct));
  CU_ASSERT_STREQ(idl_identifier(strct), "struct");

  idl_delete_pstate(pstate);
}

CU_Test(idl_hand_parser, struct_with_primitive_member)
{
  idl_pstate_t *pstate;
  idl_struct_t *strct;
  idl_member_t *member;
  idl_declarator_t *declarator;

  pstate = parse_string("struct Sample { long value; };");
  strct = (idl_struct_t *) pstate->root;
  CU_ASSERT_NEQ_FATAL(strct, NULL);
  CU_ASSERT_FATAL(idl_is_struct(strct));
  CU_ASSERT_STREQ(idl_identifier(strct), "Sample");

  member = strct->members;
  CU_ASSERT_NEQ_FATAL(member, NULL);
  CU_ASSERT_FATAL(idl_is_member(member));
  CU_ASSERT_EQ(idl_parent(member), strct);
  CU_ASSERT_EQ(idl_next(member), NULL);
  CU_ASSERT_EQ(idl_mask(member->type_spec), IDL_LONG);
  CU_ASSERT_EQ(idl_parent(member->type_spec), member);

  declarator = member->declarators;
  CU_ASSERT_NEQ_FATAL(declarator, NULL);
  CU_ASSERT_FATAL(idl_is_declarator(declarator));
  CU_ASSERT_EQ(idl_parent(declarator), member);
  CU_ASSERT_EQ(idl_next(declarator), NULL);
  CU_ASSERT_STREQ(idl_identifier(declarator), "value");

  idl_delete_pstate(pstate);
}

CU_Test(idl_hand_parser, struct_with_primitive_member_list)
{
  idl_pstate_t *pstate;
  idl_struct_t *strct;
  idl_member_t *member;
  idl_declarator_t *declarator;
  const char str[] =
    "struct Numbers {"
    "  unsigned long a, b;"
    "  long long c;"
    "  long double d;"
    "  uint32 e;"
    "};";

  pstate = parse_string_flags(IDL_FLAG_EXTENDED_DATA_TYPES, str);
  strct = (idl_struct_t *) pstate->root;
  CU_ASSERT_NEQ_FATAL(strct, NULL);
  CU_ASSERT_FATAL(idl_is_struct(strct));

  member = strct->members;
  CU_ASSERT_NEQ_FATAL(member, NULL);
  CU_ASSERT_EQ(idl_mask(member->type_spec), IDL_ULONG);
  declarator = member->declarators;
  CU_ASSERT_NEQ_FATAL(declarator, NULL);
  CU_ASSERT_STREQ(idl_identifier(declarator), "a");
  declarator = idl_next(declarator);
  CU_ASSERT_NEQ_FATAL(declarator, NULL);
  CU_ASSERT_STREQ(idl_identifier(declarator), "b");
  CU_ASSERT_EQ(idl_next(declarator), NULL);

  member = idl_next(member);
  CU_ASSERT_NEQ_FATAL(member, NULL);
  CU_ASSERT_EQ(idl_mask(member->type_spec), IDL_LLONG);
  CU_ASSERT_STREQ(idl_identifier(member->declarators), "c");

  member = idl_next(member);
  CU_ASSERT_NEQ_FATAL(member, NULL);
  CU_ASSERT_EQ(idl_mask(member->type_spec), IDL_LDOUBLE);
  CU_ASSERT_STREQ(idl_identifier(member->declarators), "d");

  member = idl_next(member);
  CU_ASSERT_NEQ_FATAL(member, NULL);
  CU_ASSERT_EQ(idl_mask(member->type_spec), IDL_UINT32);
  CU_ASSERT_STREQ(idl_identifier(member->declarators), "e");
  CU_ASSERT_EQ(idl_next(member), NULL);

  idl_delete_pstate(pstate);
}

CU_Test(idl_hand_parser, struct_with_local_type_ref)
{
  idl_pstate_t *pstate;
  idl_module_t *module;
  idl_struct_t *s1;
  idl_struct_t *s2;
  idl_member_t *member;
  const char str[] =
    "module m { struct s1 { char c; }; struct s2 { s1 s; }; };";

  pstate = parse_string(str);
  module = (idl_module_t *) pstate->root;
  CU_ASSERT_NEQ_FATAL(module, NULL);
  CU_ASSERT_FATAL(idl_is_module(module));

  s1 = (idl_struct_t *) module->definitions;
  CU_ASSERT_NEQ_FATAL(s1, NULL);
  CU_ASSERT_FATAL(idl_is_struct(s1));
  s2 = idl_next(s1);
  CU_ASSERT_NEQ_FATAL(s2, NULL);
  CU_ASSERT_FATAL(idl_is_struct(s2));

  member = s2->members;
  CU_ASSERT_NEQ_FATAL(member, NULL);
  CU_ASSERT_EQ(member->type_spec, s1);
  CU_ASSERT_STREQ(idl_identifier(member->declarators), "s");

  idl_delete_pstate(pstate);
}

CU_Test(idl_hand_parser, struct_with_cross_module_type_ref)
{
  idl_pstate_t *pstate;
  idl_module_t *m1;
  idl_module_t *m2;
  idl_struct_t *s1;
  idl_struct_t *s2;
  idl_member_t *member;
  const char str[] =
    "module m1 { struct s1 { char c; }; };"
    "module m2 { struct s2 { m1::s1 r; ::m1::s1 a; }; };";

  pstate = parse_string(str);
  m1 = (idl_module_t *) pstate->root;
  CU_ASSERT_NEQ_FATAL(m1, NULL);
  CU_ASSERT_FATAL(idl_is_module(m1));
  s1 = (idl_struct_t *) m1->definitions;
  CU_ASSERT_NEQ_FATAL(s1, NULL);
  CU_ASSERT_FATAL(idl_is_struct(s1));

  m2 = idl_next(m1);
  CU_ASSERT_NEQ_FATAL(m2, NULL);
  CU_ASSERT_FATAL(idl_is_module(m2));
  s2 = (idl_struct_t *) m2->definitions;
  CU_ASSERT_NEQ_FATAL(s2, NULL);
  CU_ASSERT_FATAL(idl_is_struct(s2));

  member = s2->members;
  CU_ASSERT_NEQ_FATAL(member, NULL);
  CU_ASSERT_EQ(member->type_spec, s1);
  CU_ASSERT_STREQ(idl_identifier(member->declarators), "r");

  member = idl_next(member);
  CU_ASSERT_NEQ_FATAL(member, NULL);
  CU_ASSERT_EQ(member->type_spec, s1);
  CU_ASSERT_STREQ(idl_identifier(member->declarators), "a");
  CU_ASSERT_EQ(idl_next(member), NULL);

  idl_delete_pstate(pstate);
}

CU_Test(idl_hand_parser, typedef_with_simple_declarators)
{
  idl_pstate_t *pstate;
  idl_typedef_t *t;
  idl_declarator_t *d;

  pstate = parse_string("typedef char foo, bar, baz;");
  t = (idl_typedef_t *) pstate->root;
  CU_ASSERT_NEQ_FATAL(t, NULL);
  CU_ASSERT_FATAL(idl_is_typedef(t));
  CU_ASSERT_EQ(idl_next(t), NULL);
  CU_ASSERT_EQ(idl_parent(t), NULL);
  CU_ASSERT_EQ(idl_type(t->type_spec), IDL_CHAR);

  d = t->declarators;
  CU_ASSERT_NEQ_FATAL(d, NULL);
  CU_ASSERT_FATAL(idl_is_declarator(d));
  CU_ASSERT_EQ(idl_parent(d), t);
  CU_ASSERT_STREQ(idl_identifier(d), "foo");

  d = idl_next(d);
  CU_ASSERT_NEQ_FATAL(d, NULL);
  CU_ASSERT_FATAL(idl_is_declarator(d));
  CU_ASSERT_EQ(idl_parent(d), t);
  CU_ASSERT_STREQ(idl_identifier(d), "bar");

  d = idl_next(d);
  CU_ASSERT_NEQ_FATAL(d, NULL);
  CU_ASSERT_FATAL(idl_is_declarator(d));
  CU_ASSERT_EQ(idl_parent(d), t);
  CU_ASSERT_STREQ(idl_identifier(d), "baz");
  CU_ASSERT_EQ(idl_next(d), NULL);

  idl_delete_pstate(pstate);
}

CU_Test(idl_hand_parser, typedef_used_as_member_type)
{
  idl_pstate_t *pstate;
  idl_typedef_t *t;
  idl_struct_t *strct;
  idl_member_t *member;
  const char str[] = "typedef long my_long; struct Sample { my_long value; };";

  pstate = parse_string(str);
  t = (idl_typedef_t *) pstate->root;
  CU_ASSERT_NEQ_FATAL(t, NULL);
  CU_ASSERT_FATAL(idl_is_typedef(t));
  CU_ASSERT_EQ(idl_type(t->type_spec), IDL_LONG);

  strct = idl_next(t);
  CU_ASSERT_NEQ_FATAL(strct, NULL);
  CU_ASSERT_FATAL(idl_is_struct(strct));
  member = strct->members;
  CU_ASSERT_NEQ_FATAL(member, NULL);
  CU_ASSERT_EQ(member->type_spec, t->declarators);
  CU_ASSERT_STREQ(idl_identifier(member->declarators), "value");

  idl_delete_pstate(pstate);
}
