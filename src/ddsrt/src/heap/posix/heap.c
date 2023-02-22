/*
 * Copyright(c) 2006 to 2019 ZettaScale Technology and others
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v. 1.0 which is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 */
#include <stdlib.h>

#include "dds/ddsrt/attributes.h"
#include "dds/ddsrt/heap.h"

#ifdef DDS_HAS_MIMALLOC
#include "mimalloc-override.h"
#else
#include "c__mmbase.h"
#include <string.h>
static struct c_mm_s *mm;
#endif

void *
ddsrt_malloc_s(size_t size)
{
  if (mm == NULL)
  {
    mm = c_mmCreate(0, 80*1024*1024, 0);
    if (mm == NULL)
      abort ();
  }
  return c_mmMalloc(mm,size ? size : 1); /* Allocate memory even if size == 0 */
}

void *
ddsrt_malloc(size_t size)
{
  void *ptr = ddsrt_malloc_s(size);

  if (ptr == NULL) {
    /* Heap exhausted */
    abort();
  }

  return ptr;
}

void *
ddsrt_calloc(size_t count, size_t size)
{
  char *ptr;

  ptr = ddsrt_calloc_s(count, size);

  if (ptr == NULL) {
    /* Heap exhausted */
    abort();
  }

  return ptr;
}

void *
ddsrt_calloc_s(size_t count, size_t size)
{
  if (count == 0 || size == 0) {
    count = size = 1;
  }
  void *ptr = ddsrt_malloc (count * size);
  if (ptr)
    memset (ptr, 0, count * size);
  return ptr;
}

void *
ddsrt_realloc(void *memblk, size_t size)
{
  void *ptr;

  ptr = ddsrt_realloc_s(memblk, size);

  if (ptr == NULL){
    /* Heap exhausted */
    abort();
  }

  return ptr;
}

void *
ddsrt_realloc_s(void *memblk, size_t size)
{
  /* Even though newmem = realloc(mem, 0) is equivalent to calling free(mem),
     not all platforms will return newmem == NULL. We consistently do, so the
     result of a non-failing ddsrt_realloc_s always needs to be free'd, like
     ddsrt_malloc_s(0). */
  if (mm == NULL)
  {
    mm = c_mmCreate(0, 80*1024*1024, 0);
    if (mm == NULL)
      abort ();
  }
  return c_mmRealloc(mm, memblk, size ? size : 1);
}

void
ddsrt_free(void *ptr)
{
  if (ptr) {
    c_mmFree (mm, ptr);
  }
}
