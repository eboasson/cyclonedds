// Copyright(c) 2006 to 2019 ZettaScale Technology and others
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License v. 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
// v. 1.0 which is available at
// http://www.eclipse.org/org/documents/edl-v10.php.
//
// SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

#include <stdio.h>
#include <string.h>
#include "CUnit/CUnit.h"
#include "CUnit/Test.h"
#include "assert.h"
#include "access_control_utils.h"


CU_Test(ddssec_builtin_access_control_fnmatch, basic)
{
  CU_ASSERT_NEQ (ac_fnmatch("", ""), 0);
  CU_ASSERT_NEQ (ac_fnmatch("abc", "abc"), 0);
  CU_ASSERT_NEQ (!ac_fnmatch("abc", "ab"), 0);
  CU_ASSERT_NEQ (!ac_fnmatch("", "a"), 0);
  CU_ASSERT_NEQ (!ac_fnmatch("a", ""), 0);

  CU_ASSERT_NEQ (ac_fnmatch("a?", "ab"), 0);
  CU_ASSERT_NEQ (ac_fnmatch("?b", "ab"), 0);
  CU_ASSERT_NEQ (ac_fnmatch("a?c", "abc"), 0);
  CU_ASSERT_NEQ (!ac_fnmatch("a?", "abc"), 0);
  CU_ASSERT_NEQ (!ac_fnmatch("?c", "abc"), 0);

  CU_ASSERT_NEQ (ac_fnmatch("a*", "a"), 0);
  CU_ASSERT_NEQ (ac_fnmatch("a*", "abc"), 0);
  CU_ASSERT_NEQ (ac_fnmatch("a*c", "abc"), 0);
  CU_ASSERT_NEQ (ac_fnmatch("a*c", "abbc"), 0);
  CU_ASSERT_NEQ (ac_fnmatch("*c", "abc"), 0);
  CU_ASSERT_NEQ (ac_fnmatch("*c", "c"), 0);
  CU_ASSERT_NEQ (!ac_fnmatch("a*", ""), 0);
  CU_ASSERT_NEQ (!ac_fnmatch("a*c", "bc"), 0);

  CU_ASSERT_NEQ (ac_fnmatch("[ab]", "a"), 0);
  CU_ASSERT_NEQ (ac_fnmatch("[ab]", "b"), 0);
  CU_ASSERT_NEQ (ac_fnmatch("a[bc]", "ab"), 0);
  CU_ASSERT_NEQ (ac_fnmatch("a[bc]", "ac"), 0);
  CU_ASSERT_NEQ (ac_fnmatch("a[bc]d", "abd"), 0);
  CU_ASSERT_NEQ (ac_fnmatch("a[b-d]", "ab"), 0);
  CU_ASSERT_NEQ (ac_fnmatch("a[b-d]", "ac"), 0);
  CU_ASSERT_NEQ (ac_fnmatch("a[b-d]", "ad"), 0);
  CU_ASSERT_NEQ (ac_fnmatch("a[-b]", "ab"), 0);
  CU_ASSERT_NEQ (ac_fnmatch("a[!b]", "ac"), 0);
  CU_ASSERT_NEQ (ac_fnmatch("a[!bc]d", "aad"), 0);
  CU_ASSERT_NEQ (ac_fnmatch("a]", "a]"), 0);
  CU_ASSERT_NEQ (!ac_fnmatch("[ab]", "c"), 0);
  CU_ASSERT_NEQ (!ac_fnmatch("a[bc]", "ad"), 0);
  CU_ASSERT_NEQ (!ac_fnmatch("a[bc]", "abc"), 0);
  CU_ASSERT_NEQ (!ac_fnmatch("a[b-]", "ab"), 0);
  CU_ASSERT_NEQ (!ac_fnmatch("a[-", "a"), 0);
  CU_ASSERT_NEQ (!ac_fnmatch("a[", "a["), 0);
  CU_ASSERT_NEQ (!ac_fnmatch("a[-", "a[-"), 0);
  CU_ASSERT_NEQ (!ac_fnmatch("a[!b]", "ab"), 0);
  CU_ASSERT_NEQ (!ac_fnmatch("a[!bc]d", "abd"), 0);
  CU_ASSERT_NEQ (!ac_fnmatch("a[!b-d]", "ac"), 0);
  CU_ASSERT_NEQ (!ac_fnmatch("a[!-b]", "ab"), 0);
}
