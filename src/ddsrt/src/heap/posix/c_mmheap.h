/* (progn (c-set-style "k&r") (setq c-basic-offset 4)) */

/*
 * Copyright(c) 2006 to 2023 ZettaScale Technology and others
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v. 1.0 which is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 */

#ifndef C_MMHEAP_H
#define C_MMHEAP_H

#if defined (__cplusplus)
extern "C" {
#endif
#ifdef OSPL_BUILD_CORE
#define OS_API OS_API_EXPORT
#else
#define OS_API OS_API_IMPORT
#endif

#include "dds/ddsrt/sync.h"

#define C_MMHEAP_SHARED 1u

struct c_mmheap_tree;
struct c_mmheap_list;

struct c_mmheap_region {
    uintptr_t off, size;
    void *base;
    struct c_mmheap_region *next;
};

struct c_mmheap {
    ddsrt_mutex_t lock;
    struct c_mmheap_tree *free;
    struct c_mmheap_list *free1;
    struct c_mmheap_list *free2;
    uint32_t flags;
    int dump;
    int check;
    uint32_t heap_check_serial;
    uintptr_t n_free_bytes;
    uintptr_t n_free_blocks;
    uintptr_t n_allocated_blocks;
    uintptr_t n_failed_allocations;
    struct c_mmheap_region heap_region;
};

struct c_mmheapStats {
    uintptr_t nused;
    uintptr_t nfails;
    uintptr_t totfree;
};

int c_mmheapInit (struct c_mmheap *heap, uintptr_t off, uintptr_t size, unsigned flags);
void c_mmheapFini (struct c_mmheap *heap);
int c_mmheapAddRegion (struct c_mmheap *heap, void *block, uintptr_t size);
void c_mmheapDropRegion (struct c_mmheap *heap, uintptr_t minfree, uintptr_t minsize, uintptr_t align, void (*dropped_cb) (void *arg, void *addr, uintptr_t size), void *arg);
void *c_mmheapMalloc (struct c_mmheap *heap, uintptr_t size);
void c_mmheapFree (struct c_mmheap *heap, void *b);
size_t c_mmheapBlockSize (struct c_mmheap *heap, void *b);
void c_mmheapStats (struct c_mmheap *heap, struct c_mmheapStats *st);
void *c_mmheapCheckPtr (struct c_mmheap *heap, void *ptr);
uintptr_t c_mmheapLargestAvailable (struct c_mmheap *heap);

#undef OS_API
#if defined (__cplusplus)
}
#endif
#endif /* C_MMHEAP_H */
