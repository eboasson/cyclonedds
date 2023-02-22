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

#ifndef C_MM__H
#define C_MM__H

#include <stdio.h>
#include <stdbool.h>

#if defined (__cplusplus)
extern "C" {
#endif

#define C_MM_STATS 2

#define C_MM_RESERVATION_NO_CHECK    ((uintptr_t)-1)
#define C_MM_RESERVATION_ZERO        (0)
#define C_MM_RESERVATION_LOW         (10000)
#define C_MM_RESERVATION_HIGH        (100000)

struct c_mm_s;

typedef enum c_mm_mode {
    MM_SHARED,  /* really using shared memory */
    MM_PRIVATE, /* this allocator in process-private memory */
    MM_HEAP     /* forward to os_malloc/os_free */
} c_mm_mode;

struct c_mmStatus_s {
    size_t size;
    size_t used;
    size_t maxUsed;
    size_t garbage;
    int64_t count;
    uint64_t fails;
    /* The cached field will be filled with the amount of memory allocated for
     * caches (including all headers). */
    size_t cached;
    /* The preallocated field will be filled with the amount of memory that is
     * preallocated in caches, but is not in use. So in order to retain the
     * total amount of memory in use:
     *      totalInUse = used - preallocated;
     * And in order to get all free memory (including allocated, but available
     * in caches):
     *      totalFree = size - totalInUse */
    size_t preallocated;
    /* The mmMode field indicates if the memory map is in shared memory, private
     * memory or heap memory. */
    c_mm_mode mmMode;
};

struct c_mm_s * c_mmCreate (void *address, size_t size, size_t threshold);
struct c_mmStatus_s c_mmListState (struct c_mm_s * mm);
struct c_mmStatus_s c_mmState (struct c_mm_s * mm, uint32_t flags);
c_mm_mode c_mmMode (struct c_mm_s * mm);

int64_t c_mmGetUsedMem (struct c_mm_s * mm);

void c_mmSuspend(struct c_mm_s * mm);
int c_mmResume(struct c_mm_s * mm);

void *c_mmCheckPtr(struct c_mm_s * mm, void *ptr);
size_t c_mmSize (struct c_mm_s * mm);

#define C_MMTRACKOBJECT_CODE_MIN 2

void  c_mmDestroy (struct c_mm_s * mm);
void *c_mmAddress (struct c_mm_s * mm);

void *c_mmMalloc  (struct c_mm_s * mm, size_t size);
void *c_mmMallocThreshold (struct c_mm_s * mm, size_t size);
void *c_mmRealloc (struct c_mm_s * mm, void *memory, size_t newsize);
void  c_mmFree    (struct c_mm_s * mm, void *memory);
void c_mmTrackObject (struct c_mm_s *mm, const void *ptr, uint32_t code);
void c_mmPrintObjectHistory(FILE *fp, struct c_mm_s * mm, void *ptr);

void *c_mmBind    (struct c_mm_s * mm, const char *name, void *memory);
void  c_mmUnbind  (struct c_mm_s * mm, const char *name);
void *c_mmLookup  (struct c_mm_s * mm, const char *name);

typedef enum c_memoryThreshold_e
{
    C_MEMTHRESHOLD_OK,
    C_MEMTHRESHOLD_APP_REACHED,
    C_MEMTHRESHOLD_SERV_REACHED
} c_memoryThreshold;

c_memoryThreshold
c_mmbaseGetMemThresholdStatus(
    struct c_mm_s * mm);

bool
c_mmbaseMakeReservation (
    struct c_mm_s * mm,
    uintptr_t amount);

void
c_mmbaseReleaseReservation (
    struct c_mm_s * mm,
    uintptr_t amount);

#undef OS_API

#if defined (__cplusplus)
}
#endif

#endif /* C_MM__H */
