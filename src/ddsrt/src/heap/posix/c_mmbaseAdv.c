/* -*- mode: c; c-file-style: "k&r"; c-basic-offset: 4; -*- */

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
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>

#include "dds/ddsrt/atomics.h"
#include "dds/ddsrt/sync.h"
#include "dds/ddsrt/attributes.h"
#include "dds/ddsrt/threads.h"
#include "dds/ddsrt/string.h"
#include "dds/ddsrt/environ.h"
#include "dds/ddsrt/strtol.h"

#include "c_mmheap.h"
#include "c__mmbase.h"

/* If DEBUG_SUPPORT is defined externally, leave it alone; else try to
 * whitelist known-good platforms
 */
#ifndef DEBUG_SUPPORT
/* The debugging support relies on atomic operations using the
 * built-in operations provided by GCC >= 4.1.  Some other compilers
 * (for example, Clang) claim to be such a GCC, and that is very
 * practical provided they indeed implement these functions.
 */
#if (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__) >= 40100
/* Debugging support also relies on some features that may not be
 * available on all platforms: the backtrace() function, in
 * particular; and moreover requires support for dumping the process'
 * memory map to a file. Those are currently implemented only for
 * Linux, Mac OS X and Solaris >= 10
 */
#if defined __linux || defined __APPLE__ || defined __sun
#define DEBUG_SUPPORT 1
#endif /* Known supported operating system */
#elif defined __sun /* We support Solaris >= 10 */
#include <inttypes.h>
#ifdef PRIxPTR /* not in Solaris 9 */
#define DEBUG_SUPPORT 1
#endif
#endif /* GNUC >= 4.1 or equivalent OR Solaris */
#endif /* DEBUG_SUPPORT */

#if DEBUG_SUPPORT
#ifdef __sun
#include <ucontext.h>
#include <sys/lwp.h>
#include <procfs.h>
#endif
#ifdef __linux
#include <sys/syscall.h>
#endif
#if defined __linux || defined __APPLE__
#include <execinfo.h>
#endif
#include <unistd.h>
#include <fcntl.h>
#endif

/* The allocator internally uses MM_ASSERT() rather than assert() to
 * make the most of the built-in debugging support when it is
 * available Therefore map MM_ASSERT to our own routines if NDEBUG is
 * not defined and DEBUG_SUPPORT is set.
 */
#ifdef NDEBUG
#define MM_ASSERT(e) ((void) 0)
#elif DEBUG_SUPPORT
#define MM_ASSERT(e) ((void) ((e) ? (void) 0 : MM_ASSERT2 (#e, __FILE__, __LINE__)))
#define MM_ASSERT2(e, file, line) ospl_allocator_error (NULL, NULL, 0xffffffff, "%s:%u: failed assertion `%s'\n", file, line, e)
#else
#define MM_ASSERT(e) assert(e)
#endif

#define STATIC_ASSERT_CODE(pred) do { switch(0) { case 0: case pred: ; } } while (0)

/* A best-fit heap for "large objects" (c_mmheap.c, see there for some
 * high-level info on the implementation) combined with a parallel
 * slab allocator for "small objects" (this file). The heap grows
 * upwards in the memory region, the slab allocator downwards.
 *
 * See:
 *
 * - Bonwick, Jeff: "The Slab Allocator: An Object-Caching Kernel
 *   Memory Allocator", Summer 1994 Usenix Conference, pp. 87-98.
 *
 * - Bonwick, Jeff & Adams, Jonathan: "Magazines and Vmem: Extending
 *   the Slab Allocator to Many CPU's and Arbitrary Resources", USENIX
 *   2001, pp 15-34.
 *
 * - Wilson, Paul R.; Johnstone, Mark S.; Neely, Michael & Boles,
 *   David: "Dynamic Storage Allocation: A Survey and Critical
 *   Review", Proceedings of the International Workshop on Memory
 *   Management, September 1995
 *
 * The "small object" allocator has a fixed, smallish number of object
 * sizes it is willing to allocate: see smobj_sizes32 & smobj_sizes64.
 * General procedure is:
 *
 * Malloc(size) computes the size idx and determines thread's
 * preferred context idx, and from that, the address of an inner
 * allocator.  (The "allocator" is per-size, and has a number of
 * parallel "inner allocators".)  Free(obj) instead obtains the size
 * idx using a bit of address manipulation to locate the associated
 * allocator metadata.
 *
 *   Each inner allocator contains two loaded magazines.  Each
 *   magazine is a small array of pointers to available objects, and
 *   when loaded in a context, is private to that context.  So
 *   mallocs/frees operating on different inner allocators can run in
 *   parallel, even if they are of the same allocator (= size bucket).
 *
 *   For malloc, if either has an object left (for free, if either has
 *   a slot left), use it; otherwise exchange an empty (full, if free)
 *   magazine for a full (empty) with the magazine cache.  Magazines
 *   in the magazine cache are either full or empty.
 *
 *   If the magazine cache can't accept the incoming one, it frees it
 *   to the slab layer; if it can't deliver the requested one, it
 *   allocates it from the slab layer.  It always allocates/frees
 *   magazines straight from/to the slab layer.
 *
 *     The slab layer operates on slabs, arrays of same-sized objects,
 *     each of which is currently 4kB (32-bit) or 8kB (64-bit) and
 *     contains as many objects as will fit in "contents" part and a
 *     small amount of administrative data in its "adm" part.
 *
 *     A slab is either "empty", "full", or "partially filled".  Full
 *     ones are generally ignored, empty ones are stored in
 *     "slablist_free", and partially filled ones are tracked in
 *     "slablist_partial" & friends.
 *
 *     When servicing a request for N objects of size idx K, the slab
 *     layer first uses the partially filled slabs for size index K,
 *     and if that doesn't suffice, also allocates one new slab from
 *     the free list (growing the slab area when the free list is
 *     empty).
 *
 *     Freeing N objects of size idx K is the opposite process: full
 *     slabs go to partial, partial slabs may go to empty, and those
 *     that become empty are moved to the free list, or the slab area
 *     is shrunk.
 *
 * The allocator could still do with a bit of refining:
 *
 * - The magazine caches and the partially allocated slab lists each
 *   have a lock per object size and the slab free list has a lock as
 *   well.  Some of which can be merged without really reducing
 *   parallelism, but to do so, allocating/freeing magazines needs to
 *   be done differently or a deadlock may occur.
 *
 * - Magazine cache size adaptation is based on a gut feeling.  It is
 *   silly to cache empty magazines in the cache, it would be far
 *   nicer to use magazine of magazines for obtaining empty magazines.
 *   That would immediately help with the above, as well.
 *
 * - Some of the current object sizes waste some space in a slab.
 *
 * - The idea is that a thread that consistently runs into contention
 *   on a context should hop to do a different one, but with the
 *   current algorithm, it is the busy thread that's hopping, where
 *   ideally the ones doing fewer allocations would move away to make
 *   room for the ones doing more allocations.
 *
 * But it appears to not be a bottleneck as it currently is.
 *
 * The small-object allocator includes some rough debugging support
 * for detecting double frees and for detecting scribbling in freed
 * memory, and also for increasing the likelihood of a crash in case
 * of a using memory immediately after freeing it.  Whether or not
 * these features are present is determined at compile time, by the
 * "DEBUG_SUPPORT" macro.
 *
 * If support is included, the slab administration is grown by a bit
 * to accomodate space for a worst-case bitset tracking which of the
 * objects in a slab are free and which are not.  This is a bit of a
 * waste of space, as it reserves room for as many of the smallest
 * blocks will fit in a slab, even when the slab is used for larger
 * objects.
 *
 * If the feature is enabled at run-time by setting the CHK_FREESET
 * bit in the "checking" flags, these bitsets are manipulated
 * atomically in the low-level (small object) allocator routines.  A
 * simple double-free (one without the object being reallocated
 * elsewhere) will be detected provided the slab containing the object
 * hasn't become entirely free.
 *
 * The second feature is the scribbling of patterns in memory,
 * controlled by the CHK_PATTERNS bit in the "checking" flags.  All
 * unallocated slab memory is marked with specific patterns, with
 * different patterns depending on where the free object is
 * administered -- e.g., whether it is in a magazine or not.  All
 * operations verify the patterns match, but the system is not
 * entirely watertight as some bytes of the objects are used to
 * construct freelists within slabs; if an application scribbles over
 * those bytes, it won't be detected.
 *
 * The patterns are as simple as possible: byte values 0xeb, 0xed and
 * 0xef.  These are all odd, making it highly unlikely to be a valid
 * pointer.
 *
 * The third feature is recording a stack trace upon freeing an
 * object.  The stack trace is stored in a separate hash table, keyed
 * on object address, and will remain there until the object is
 * allocated again or the slab becomes entirely free.
 *
 * Upon detecting a double free, the allocator will print the stack
 * traces it has and abort.  The stack traces include the process id,
 * and the allocator initialisation dumps the memory map of the
 * process to disk.  The combination of this map file and the symbol
 * tables of the executable and libraries allows recovery of symbol
 * names without core files or live processes.
 *
 * To avoid recursive allocation (and thus deadlock), and also to
 * reduce pressure on the allocator to allocate very large chunks of
 * memory for this feature, a number of complications have been
 * introduced:
 *
 * - The hash table is in 2 levels, with only the outer level
 *   growable.  The outer level is allocated in the large object heap,
 *   because it can easily grow to sizes too large for the slab
 *   allocator to handle.
 *
 * - The inner level is fixed in size (256 bytes on 32-bit systems,
 *   512 bytes on 64-bit systems) and allocated using a dedicated
 *   allocator, rather than the "normal" allocator for those sizes.
 *
 * - The stacks themselves are also fixed in size (whatever that size
 *   may be), and similarly allocated using a dedicated allocator.
 *
 * The reason for using these two dedicated allocators is that the
 * mm_free_slab operation takes a slab with possibly associated stack
 * traces, and it must release these traces.  However, once it gets
 * there the thread is already holding the inner allocator lock, the
 * magazine cache lock, and the allocator slab lock, and so if the
 * stack traces or parts of the hash table were allocated using the
 * normal allocators, freeing the stack traces would run into a
 * deadlock for certain sizes.
 */

/* Note: constants marked with WFV are simply based on gut feeling */

#define DBG_ISFREE 1u
#define DBG_MEMSET 2u /* mm->debug & all allocator->debug must agree on MEMSET */
#define DBG_OBJHIST 4u
#define DBG_TRACK_MALLOC 8u
#define DBG_TRACK_FREE 16u
#define DBG_EXPENSIVE 32u
#define DBG_PRINT_DEBUG_FLAGS 64u

#define C_MMTRACKOBJECT_CODE_MALLOC 0
#define C_MMTRACKOBJECT_CODE_FREE 1
#if C_MMTRACKOBJECT_CODE_FREE >= C_MMTRACKOBJECT_CODE_MIN
#error "Overlap between internal & external object tracking codes"
#endif

#define HEAP_ALIGN (128 * 1024)     /* must be power of 2 and >= SLAB_SIZE [WFV] */
#define HEAP_INCREMENT (64 * 1024)  /* must be power of 2 and >= SLAB_SIZE [WFV] */
#define SLAB_SIZE (1024 * (int) sizeof (void *)) /* must be power of 2 [WFV] */

/* Number of different sizes in the parallel slab allocator [WFV], see
 * below for tables & conversion functions.  18 is the tried and
 * tested one, 22 allows slightly larger objects (such as v_group) to
 * be allocated from the slab allocator, which allows the slab
 * allocator's debugging features to also be used for those objects,
 * but also increases memory overhead.
 */
#ifndef N_SMOBJ_SIZES
#define N_SMOBJ_SIZES 18 /* 22 is also supported */
#endif

#define CONTEXT_SWITCH_THRESHOLD 16 /* switch contexts if # contention events reaches this [WFV] */
#define INCREASE_MAGCACHE_THRESHOLD 100 /* at least 100 misses/s => grow [WFV] */
#define DECREASE_MAGCACHE_THRESHOLD 10 /* at most 10 misses/s <= shrink [WFV] */
#define MAGCACHE_HARD_MAXSIZE 128 /* never grow magazine caches beyond this size [WFV] */

#define NOTE_SLABLOCK_CONTENTION 1 /* use a trylock/lock combination and maintain mm->contended? */

#define MALLOC_SMOBJ_VERSION 0 /* 1 collects freelists from slabs, unlocks, then walks the lists */
#define FREE_SMOBJ_VERSION 0 /* 1 sorts objs & then performs the frees per slab */

#define N_PAR_ALLOCATORS_LG2 3
#define N_PAR_ALLOCATORS (1 << N_PAR_ALLOCATORS_LG2)

/* slab->allocator is used both as a pointer to the owning allocator
 * and as a marker indicating whether the slab is free or not, but we
 * prefer doing the slab initialisation outside the lock. A null
 * pointer means free, UNINITIALIZED_SLAB_MARKER means allocated but
 * not properly initialised yet.  I.e., don't touch for everyone but
 * the initialising thread.
 */
#define UNINITIALIZED_SLAB_MARKER ((struct mm_allocator *) 0x1)

#if __GNUC__
#define UNUSED __attribute__ ((unused))
#else
#define UNUSED
#endif
#if !defined NDEBUG
#define UNUSED_NDEBUG
#else
#define UNUSED_NDEBUG UNUSED
#endif

struct mm_allocator;

struct mm_slab_obj {
    struct mm_slab_obj *next;
};

struct mm_slab_obj_list {
    struct mm_slab_obj *first;
    struct mm_slab_obj *last;
};

struct mm_slab {
    /* Number of objects in slab (both free & allocated), always
     * greater than 1 for allocated slabs; 0 for free slabs.
     */
    unsigned nobjs;
    unsigned nfree;
    unsigned objsize;
    unsigned objoffset;
    struct mm_allocator *allocator;
    struct mm_slab_obj_list freelist;
    struct mm_slab *next;
    struct mm_slab *prev;
    /* isfree (if debug & DBG_ISFREE); objects follow */
};

struct mm_magcache_inner {
    struct mm_magazine *list;
    unsigned size;
    uint32_t misses_grab;
    uint32_t misses_drop;
};

struct mm_magcache {
    ddsrt_mutex_t lock;
    unsigned maxsize;
    unsigned hard_maxsize;
    struct mm_magcache_inner empty;
    struct mm_magcache_inner full;
};

struct mm_slablist {
    uintptr_t length;
    struct mm_slab *head;
};

struct mm_magazine {
    /* outside magazine_pair, magazines are either full or empty */
    struct mm_magazine *next; /* for magazine cache */
    void *objs[1]; /* a fixed-length array, length is determined from object size */
};

struct mm_loaded_magazine {
    /* Loaded magazines track the number of objects in the magazine.
     * While "nobjs" could easily be in a union with
     * mm_magazine::next, obviating the need for the loaded magazine
     * type, doing it this way shaves off a dependent load at the very
     * beginning of smobj_malloc() and smobj_free().  Whether that
     * advantage is really worth the price is another matter.
     */
    struct mm_magazine *m;
    unsigned nobjs;
};

struct mm_allocator_inner {
    ddsrt_mutex_t lock;
    struct mm_loaded_magazine lm[2];
    uint32_t swaps;
    uint32_t grabs_full;
    uint32_t grabs_empty;
    /* Number of mallocs & number of frees in this context, used for
     * computing memory statistics. Note that mallocs < frees is
     * possible, if the mallocs happen in another context than the
     * frees.
     */
    uint64_t mallocs;
    uint64_t frees;
};

struct mm_allocator {
    struct mm_allocator_inner inner[N_PAR_ALLOCATORS];
    struct mm_magcache magcache;
  ddsrt_mutex_t slab_lock;
    struct mm_slablist slablist_partial; /* [lock] */
    uintptr_t slablist_partial_nfree; /* [lock] - total # free objs/bin */
    unsigned debug; /* [constant] */
    unsigned objsize; /* [constant] - size of objects allocated by this allocator */
    unsigned slab_object_offset; /* [constant] - offset of first object in slab */
    unsigned slab_nobjs; /* [constant] - number of objects in slab */
    unsigned m_size; /* [constant] - number of objects in a magazine */
    struct mm_allocator *m_allocator; /* [constant, init'd late] - magazine allocator */
    ddsrt_atomic_uint32_t contended; /* [atomic updates] */
    ddsrt_atomic_uint32_t switch_away; /* [atomic updates] */
};

#if DEBUG_SUPPORT
#define OBJHIST_LEVEL2_BITS 6
#define OBJHIST_LEVEL2_SIZE (1 << OBJHIST_LEVEL2_BITS)

#if defined __linux
typedef pid_t our_tid_t;
static our_tid_t our_gettid (void) { return (our_tid_t) syscall (SYS_gettid); }
#define PRINTF_FMT_THREADID "%d"
#define PRINTF_ARGS_THREADID(tid) ((int) (tid))
#elif defined __APPLE__
typedef pthread_t our_tid_t;
static our_tid_t our_gettid (void) { return pthread_self (); }
#define PRINTF_FMT_THREADID "0x%"PRIxPTR
#define PRINTF_ARGS_THREADID(tid) ((uintptr_t) (tid))
#elif defined __sun
typedef lwpid_t our_tid_t;
static our_tid_t our_gettid (void) { return _lwp_self (); }
#define PRINTF_FMT_THREADID "%u"
#define PRINTF_ARGS_THREADID(tid) ((unsigned) (tid))
#else
#error "objhist_print1: no definition for printing a tid on this platform"
#endif

struct objhist {
    struct objhist *next_hash; /* only in use for most recent objhist for object */
    struct objhist *older_hist;
    void *object;
    pid_t pid;
    our_tid_t tid;
    uint32_t code;
    int depth;
    void *stack[32];
};

struct objhist_admin {
    ddsrt_mutex_t lock[16];
    ddsrt_atomic_uint32_t nobjects;
    uint32_t hashsize; /* = 1 << hashsize_lg2 */
    uint32_t hashsize_lg2;
    struct objhist ***hash;
};
#endif

struct c_mm_s {
    c_mm_mode mode;
    void *mm_heapblock_ptr; /* [constant] -- points to block in which mm resides */
    unsigned debug; /* [constant] */

    ddsrt_mutex_t lock;
    ddsrt_atomic_uint32_t contended; /* [atomic] */

    /* a very minimalistic implementation of the erstwhile bindings */
    void *bound; /* [lock] */

    /* actual allocator state: */
    ddsrt_atomic_uint32_t initialized; /* [written once, atomically + membars] */
    struct c_mm_s *address; /* [constant] */
    uintptr_t size; /* [constant] usefull size, max value that is a multiple of SLAB_SIZE and < then config_size */
    uintptr_t config_size; /* [constant] configured size */
    uintptr_t threshold; /* [constant] */
    uintptr_t heap_end_off; /* [lock] -- rel. to mm; grows up */
    uintptr_t slab_start_off; /* [lock] -- rel. to mm; grows down */
    uintptr_t max_reservation; /* [constant] */

    ddsrt_atomic_uint64_t unreserved; /* slab_start_off - heap_end - SUM(reservations); really signed */

    struct mm_slablist slablist_free; /* [lock] */

    struct c_mmheap mmheap; /* [protects itself] */
    ddsrt_atomic_uint32_t lgobj_mallocs;

    uint64_t n_smobj_fails; /* [lock] */
    uint64_t n_lgobj_fails; /* [lock] */
    uintptr_t max_used; /* [lock] -- est. from heap_end & slab_start */

    /* PRNG for hopping through mm_contexts */
    ddsrt_mutex_t prng_lock;
    uint64_t prng_state; /* [prng_lock] */

    /* allocator adaptation thread sizing */
    ddsrt_mutex_t aat_lock;
    ddsrt_cond_t aat_cond;
    ddsrt_thread_t aat_tid;
    int aat_stop; /* [aat_lock] */

    struct mm_allocator allocator[N_SMOBJ_SIZES];

#if DEBUG_SUPPORT
    int max_objhist_depth;
    struct objhist_admin objhist_admin;
    struct mm_allocator objhist_allocator;
    struct mm_allocator objhist_m_allocator;
    struct mm_allocator objhist_hash_allocator;
    struct mm_allocator objhist_hash_m_allocator;
#endif
};

struct mm_tsd {
    /* Can't cache a pointer because that really breaks multi-domain
     * use. Can only cache an index if we guarantee all domains ues
     * the same number of contexts. Consequently, dynamically
     * adjusting the number of contexts is not going to be
     * trivial.
     */
    unsigned context_idx;
#if DEBUG_SUPPORT
    our_tid_t tid;
#endif
};

/* c_mmPrintAllocatorInfo is a debugging tool, hence declared here
 * rather than in the header files
 */
void c_mmPrintAllocatorInfo (struct c_mm_s *mm);

static struct mm_magazine *grab_magazine_from_slab (struct c_mm_s *mm, struct mm_allocator *allocator, uintptr_t threshold, int full);
static void drop_magazine_to_slab (struct c_mm_s *mm, struct mm_allocator *allocator, struct mm_magazine *m, unsigned nobjs);
static void *mm_malloc_smobj (struct c_mm_s *mm, unsigned size, uintptr_t threshold);
static void mm_free_smobj (struct c_mm_s *mm, void *obj);
static void mm_free_smobj_to_slab (struct c_mm_s *mm, struct mm_allocator *allocator, void *objs[], unsigned nobjs);
static uint32_t aat_thread (void *vmm);
static struct mm_slab *slab_from_obj (const void *obj);

#if DEBUG_SUPPORT
static int objhist_admin_init (struct c_mm_s * mm, struct objhist_admin *fs);
static void objhist_admin_init_client (struct c_mm_s * mm, struct objhist_admin *fs);
static void objhist_admin_fini (struct c_mm_s * mm, struct objhist_admin *fs);
static void objhist_print (FILE *fp, struct c_mm_s *mm, const void *obj);
static void objhist_print1 (FILE *fp, const struct objhist *stk);
static void objhist_init_stack (struct objhist *stk, our_tid_t tid, const void *ptr, uint32_t code);
#endif
static void objhist_insert (struct c_mm_s * mm, const struct mm_tsd *tsd, const void *ptr, uint32_t code);
static void objhist_delete_if_exists (struct c_mm_s * mm, const void *ptr);

/* small-object sizes [WFV]:
 *
 *           vx8                      vx16           vx32            vx64
 *   32-bit:  8 16 24 32 40 48 56 64  80  96 112 128 160 192 224 256 320 384
 *  indices:  0  1  2  3  4  5  6  7   8   9  10  11  12  13  14  15  16  17
 *   64-bit: 16 24 32 40 48 64 80 96 112 128 160 192 224 256 320 384 448 512
 *           ^x8            ^x16             ^x32            ^x64
 *
 * Notes:
 *
 * - The exact distribution of sizes is based on gut feeling
 *
 * - The sizes ought to be changed slightly (256 => 272, 320 => 336
 *   and 384 => 408 for 32-bit; 256 => 264 and 512 => 544 for 64-bit),
 *   because those sizes result in the same number of objects per
 *   slab, and hence allow for slightly lower memory usage.  For the
 *   sizes currently used, a table lookup appears to be significantly
 *   slower than a combination of a few tests and a bit of arithmetic,
 *   but the tests and the arithmetic become more complex when the
 *   sizes become less regular.  So optimizing for space slows down
 *   the allocator a bit for the larger objects.
 */

#if N_SMOBJ_SIZES == 18
static const unsigned smobj_sizes32[N_SMOBJ_SIZES] = {
    8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384
};
static const unsigned smobj_sizes64[N_SMOBJ_SIZES] = {
    16, 24, 32, 40, 48, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 448, 512
};
#define MAX_SMOBJ_SIZE ((sizeof (void *) == 4) ? 384 : 512) /* this size & smaller => slab, larger => heap */
#elif N_SMOBJ_SIZES == 22
static const unsigned smobj_sizes32[N_SMOBJ_SIZES] = {
    8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 448, 512, 576, 640
};
static const unsigned smobj_sizes64[N_SMOBJ_SIZES] = {
    16, 24, 32, 40, 48, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 448, 512, 576, 640, 704, 768
};
#define MAX_SMOBJ_SIZE ((sizeof (void *) == 4) ? 640 : 768) /* this size & smaller => slab, larger => heap */
#endif
#define MIN_SMOBJ_SIZE ((int) (2 * sizeof (void *)))

static size_t align8size (size_t x)
{
    return ((x + 7) & (size_t)-8);
}

static unsigned align8uint (unsigned x)
{
    return ((x + 7) & (unsigned)-8);
}

static const char *config_entry (const char *name)
{
    /* OSPL_ALLOCATOR_OPTIONS consists of space-separated NAME=VALUE
     * pairs.  We return a pointer into the string, which is therefore
     * terminated by a space or end-of-string
     */
    const char *e = NULL;
    if (ddsrt_getenv ("OSPL_ALLOCATOR_OPTIONS", &e) != 0 || e == NULL) {
        return NULL;
    } else {
        size_t namelen = strlen (name);
        const char *pos = strstr (e, name);
        while (pos && ((pos > e && pos[-1] != ' ') || pos[namelen] != '='))
            pos = strstr (pos + namelen, name);
        return pos ? pos + namelen + 1 : NULL;
    }
}

static uint64_t config_decimal (const char *name, uint64_t def)
{
    /* If OSPL_ALLOCATOR_OPTIONS/name is a decimal integer > 0, we use this
     * allocator in single-process mode with a memory size of that
     * many MiB.  If it is undefined, 0, or not an integer, we use the
     * heap.
     */
    const char *e = config_entry (name);
    if (e == NULL) {
        return def;
    } else {
        char *ee;
        uint64_t sz;
        if (ddsrt_strtoull (e, &ee, 10, &sz) == 0) {
            /* Output of config_entry must've started with a digit and
             * end at a space (end-of-option) or the end of the
             * string: else there's junk in the input
             */
            return sz;
        } else {
            fprintf (stderr, "OSPL_ALLOCATOR_OPTIONS/%s invalid", name);
            return def;
        }
    }
}


#if DEBUG_SUPPORT

static void ospl_allocator_error (struct c_mm_s *mm, const void *obj, uint32_t code, const char *fmt, ...) ddsrt_attribute_noreturn;

static void ospl_allocator_error (struct c_mm_s *mm, const void *obj, uint32_t code, const char *fmt, ...)
{
    /* NOTE: mm and obj may be NULL, in which case it degenerates to a
     * simple printf */
    va_list ap;
    struct objhist stk;
    objhist_init_stack (&stk, our_gettid (), obj, code);
    va_start (ap, fmt);
    vfprintf (stderr, fmt, ap);
    va_end (ap);
    objhist_print1 (stderr, &stk);
    objhist_print (stderr, mm, obj);
#ifndef NDEBUG
    assert (0);
#else
    abort ();
#endif
}


static unsigned config_debug_flags (void)
{
    static const struct { const char *name; unsigned value; } opts[] = {
        { "double_free", DBG_ISFREE },
        { "memset", DBG_MEMSET },
        { "objhist", DBG_OBJHIST },
        { "malloc_stack", DBG_TRACK_MALLOC },
        { "free_stack", DBG_TRACK_FREE },
        { "expensive", DBG_EXPENSIVE },
        { "print_flags", DBG_PRINT_DEBUG_FLAGS }
    };
    const char *entry = config_entry ("debug");
    char *entrydup, *cursor, *kw;
    unsigned debug = 0;
    if (entry == NULL || (entrydup = strdup (entry)) == NULL) {
        /* default is to disable all options (and we do that also when
         * we run out of memory)
         */
        return 0;
    }
    if ((cursor = strchr (entrydup, ' ')) != NULL) {
        /* option entries in OSPL_ALLOCATOR_OPTIONS are
         * space-separated and config_entry just gives us a pointer
         * into the string - but since we had to make a copy, it is
         * easier to properly terminate it now
         */
        *cursor = 0;
    }
    cursor = entrydup;
    while ((kw = ddsrt_strsep (&cursor, ",")) != NULL) {
        int i;
        for (i = 0; i < (int) (sizeof (opts) / sizeof (*opts)); i++) {
            if (strcmp (kw, opts[i].name) == 0) {
                break;
            }
        }
        if (i == (int) (sizeof (opts) / sizeof (*opts))) {
            fprintf (stderr, "OSPL_ALOCATOR_OPTIONS/debug: unrecognised flag: %s\n", kw);
        } else {
            debug |= opts[i].value;
        }
    }
    free (entrydup);
    return debug;
}

static int config_max_objhist_depth (void)
{
    return (int) config_decimal ("max_objhist_depth", 1);
}

static char *config_mappath (void)
{
    /* Allow user to configure that directory to which the map file is
     * written.  Don't bother to support spaces in path names.
     */
    const char *entry = config_entry ("mappath");
    char *path, *cursor;
    if (entry == NULL || (path = strdup (entry)) == NULL) {
        /* default (or on out-of-memory): /tmp, but NULL is more
         * practical because we can't free a string constant
         */
        return NULL;
    }
    if ((cursor = strchr (path, ' ')) != NULL) {
        /* deal with space-separated options */
        *cursor = 0;
    }
    return path;
}
#endif /* DEBUG_SUPPORT */


static unsigned size_to_smobj_sizeidx (unsigned size)
{
    unsigned idx;
    MM_ASSERT (size > 0);
    if (sizeof (void *) == 4) {
        if (size <= 64) {
            idx = (size + 7) / 8 - 1;
        } else if (size <= 128) {
            idx = (size + 15) / 16 + 3;
        } else if (size <= 256) {
            idx = (size + 31) / 32 + 7;
        } else {
            idx = (size + 63) / 64 + 11;
        }
        MM_ASSERT (idx == 0 || smobj_sizes32[idx-1] < size);
        MM_ASSERT (size <= smobj_sizes32[idx]);
    } else {
        MM_ASSERT (sizeof (void *) == 8);
        if (size <= 16) {
            idx = 0;
        } else if (size <= 48) {
            idx = (size + 7) / 8 - 2;
        } else if (size <= 128) {
            idx = (size + 15) / 16 + 1;
        } else if (size <= 256) {
            idx = (size + 31) / 32 + 5;
        } else {
            idx = (size + 63) / 64 + 9;
        }
        MM_ASSERT (idx == 0 || smobj_sizes64[idx-1] < size);
        MM_ASSERT (size <= smobj_sizes64[idx]);
    }
    MM_ASSERT (idx < N_SMOBJ_SIZES);
    return idx;
}

static unsigned sizeidx_to_smobj_size (unsigned sizeidx)
{
    unsigned size;
    MM_ASSERT (sizeidx < N_SMOBJ_SIZES);
    if (sizeof (void *) == 4) {
        size = smobj_sizes32[sizeidx];
    } else {
        MM_ASSERT (sizeof (void *) == 8);
        size = smobj_sizes64[sizeidx];
    }
    return size;
}

static void update_max_used (struct c_mm_s *mm)
{
    uintptr_t used = mm->heap_end_off + (mm->size - mm->slab_start_off);
    if (used >= mm->max_used) {
        mm->max_used = used;
    }
}

static uint64_t mm_prng_mmix (uint64_t *state)
{
    /* PRNG taken from Don Knuth's MMIX, just because I can, dropping
     * the low order bits, though, they have such short cycles.
     *
     * Returns old state.
     */
    const uint64_t a = DDSRT_ATOMIC_UINT64_INIT (6364136223846793005);
    const uint64_t c = DDSRT_ATOMIC_UINT64_INIT (1442695040888963407);
    uint64_t st = *state;
    *state = a * *state + c;
    return st;
}

static unsigned choose_mm_context (struct c_mm_s *mm)
{
    unsigned idx;
    ddsrt_mutex_lock (&mm->prng_lock);
    idx = (unsigned) (mm_prng_mmix (&mm->prng_state) >> (64 - N_PAR_ALLOCATORS_LG2));
    ddsrt_mutex_unlock (&mm->prng_lock);
    return idx;
}

static void choose_another_mm_context (struct c_mm_s *mm, struct mm_tsd *tsd)
{
    tsd->context_idx = choose_mm_context (mm);
}

static ddsrt_thread_local struct mm_tsd *mm_tsd;

static struct mm_tsd *get_mm_tsd (struct c_mm_s *mm)
{
    if (mm_tsd == NULL) {
        mm_tsd = malloc (sizeof (*mm_tsd));
        mm_tsd->context_idx = choose_mm_context (mm);
#if DEBUG_SUPPORT
        mm_tsd->tid = our_gettid ();
#endif
    }
    return mm_tsd;
}


static void mm_slablist_init (struct mm_slablist *sl)
{
    sl->length = 0;
    sl->head = NULL;
}

static int mm_magcache_inner_init (struct mm_magcache_inner *mci)
{
    mci->size = 0;
    mci->misses_grab = 0;
    mci->misses_drop = 0;
    mci->list = NULL;
    return 0;
}

static void mm_magcache_inner_setmaxsize_lockheld (struct c_mm_s *mm, struct mm_allocator *allocator, struct mm_magcache *mc, struct mm_magcache_inner *mci, int full)
{
    const unsigned m_size = allocator->m_size;
    while (mci->size > mc->maxsize) {
        struct mm_magazine *m = mci->list;
        mci->list = m->next;
        mci->size--;
        drop_magazine_to_slab (mm, allocator, m, full ? m_size : 0);
    }
}

static void mm_magcache_setmaxsize_lockheld (struct c_mm_s *mm, struct mm_allocator *allocator, struct mm_magcache *mc, unsigned maxsize)
{
    MM_ASSERT (maxsize <= mc->hard_maxsize);
    if (maxsize >= mc->maxsize) {
        mc->maxsize = maxsize;
    } else {
        mc->maxsize = maxsize;
        mm_magcache_inner_setmaxsize_lockheld (mm, allocator, mc, &mc->empty, 0);
        mm_magcache_inner_setmaxsize_lockheld (mm, allocator, mc, &mc->full, 1);
    }
}

static void mm_magcache_inner_fini (struct mm_magcache_inner *mci UNUSED_NDEBUG)
{
    MM_ASSERT (mci->list == NULL);
}

static int mm_magcache_init (struct c_mm_s *mm, struct mm_magcache *mc)
{
    (void)mm;
    ddsrt_mutex_init (&mc->lock);
    mc->hard_maxsize = MAGCACHE_HARD_MAXSIZE;
    mc->maxsize = 0;
    mm_magcache_inner_init (&mc->empty);
    mm_magcache_inner_init (&mc->full);
    return 0;
}

static void mm_magcache_fini (struct c_mm_s *mm, struct mm_allocator *allocator, struct mm_magcache *mc)
{
    ddsrt_mutex_lock (&mc->lock);
    if (allocator->m_allocator == NULL) {
        /* cleaning up after an error halfway through initialization -- it is safe to call
         * setmaxsize_lockheld as mc is empty, but that's a bit hard on a static analyzer.
         */
        assert (mc->empty.size == 0);
        assert (mc->full.size == 0);
    } else {
        mm_magcache_setmaxsize_lockheld (mm, allocator, mc, 0);
    }
    ddsrt_mutex_unlock (&mc->lock);
    mm_magcache_inner_fini (&mc->empty);
    mm_magcache_inner_fini (&mc->full);
    ddsrt_mutex_destroy (&mc->lock);
}

static int mm_allocator_inner_init_1 (struct c_mm_s *mm, struct mm_allocator_inner *inner)
{
    (void)mm;
    ddsrt_mutex_init (&inner->lock);
    inner->swaps = 0;
    inner->grabs_full = 0;
    inner->grabs_empty = 0;
    inner->mallocs = 0;
    inner->frees = 0;
    return 0;
}

static int mm_allocator_inner_init_2 (struct c_mm_s *mm, struct mm_allocator *allocator, struct mm_allocator_inner *inner)
{
    if (allocator->m_allocator == NULL) {
        /* Only ever used to allocate magazines, i.e., really only an
         * identifier used for allocating directly from a slab.  So it
         * doesn't even need magazines itself.  (Perhaps I should
         * distinguish better between the two levels, who knows.
         * Currently the main issue is that of avoiding any use of the
         * "normal" allocators when tracking object history.)
         */
        return 0;
    } else {
        int i;
        for (i = 0; i < (int) (sizeof (inner->lm) / sizeof (inner->lm[0])); i++) {
            const int want_full = (i == 0);
            if ((inner->lm[i].m = grab_magazine_from_slab (mm, allocator, 0, want_full)) != NULL) {
                inner->lm[i].nobjs = want_full ? allocator->m_size : 0;
            } else {
                while (i--) {
                    drop_magazine_to_slab (mm, allocator, inner->lm[i].m, inner->lm[i].nobjs);
                }
                return -1;
            }
        }
        return 0;
    }
}

static void mm_allocator_inner_fini_2 (struct c_mm_s *mm, struct mm_allocator *allocator, struct mm_allocator_inner *inner)
{
    if (allocator->m_allocator != NULL) {
        int i;
        for (i = 0; i < (int) (sizeof (inner->lm) / sizeof (inner->lm[0])); i++) {
            drop_magazine_to_slab (mm, allocator, inner->lm[i].m, inner->lm[i].nobjs);
        }
    }
}

static void mm_allocator_inner_fini_1 (struct c_mm_s *mm, struct mm_allocator *allocator, struct mm_allocator_inner *inner)
{
    (void)mm;
    (void)allocator;
    ddsrt_mutex_destroy (&inner->lock);
}

static unsigned magazine_size_bytes (unsigned m_size)
{
    unsigned sz = (unsigned) (offsetof (struct mm_magazine, objs) + m_size * sizeof (((struct mm_magazine *) 0)->objs[0]));
    MM_ASSERT (sz <= MAX_SMOBJ_SIZE);
    return sz;
}

static int mm_allocator_init_1 (struct c_mm_s *mm, struct mm_allocator *a, unsigned objsize, unsigned debug)
{
    const unsigned max_m_size = (MAX_SMOBJ_SIZE - (unsigned) offsetof (struct mm_magazine, objs)) / (unsigned) sizeof (void *);
    unsigned nobjs, i;

    STATIC_ASSERT_CODE ((sizeof (struct mm_slab) % sizeof (uint32_t)) == 0);
    nobjs = (SLAB_SIZE - sizeof (struct mm_slab)) / objsize;
    if (debug & DBG_ISFREE) {
        while (sizeof (struct mm_slab) + align8uint ((nobjs+7)/8) + nobjs * objsize > SLAB_SIZE) {
            --nobjs;
        }
    }
    MM_ASSERT (nobjs > 0);

    ddsrt_mutex_init (&a->slab_lock);
    mm_slablist_init (&a->slablist_partial);
    a->slablist_partial_nfree = 0;
    a->debug = debug;
    a->objsize = objsize;
    a->slab_nobjs = nobjs;
    a->slab_object_offset = (unsigned) align8size (sizeof (struct mm_slab));
    if (debug & DBG_ISFREE) {
        a->slab_object_offset += align8uint ((nobjs+7)/8);
    }
    a->m_size = (nobjs  > max_m_size) ? max_m_size : nobjs;
    a->m_allocator = NULL; /* can't init yet */
    ddsrt_atomic_st32 (&a->contended, 0);
    ddsrt_atomic_st32 (&a->switch_away, 0);

    /* Initialise magazine cache after initialising all "static" data
     * on the allocator
     */
    if (mm_magcache_init (mm, &a->magcache) < 0) {
        ddsrt_mutex_destroy (&a->slab_lock);
    }

    /* Initialise inner allocators (the actual allocators) last, so
     * they can rely on the existence of initialised magazine caches,
     * &c.
     */
    for (i = 0; i < N_PAR_ALLOCATORS; i++) {
        if (mm_allocator_inner_init_1 (mm, &a->inner[i]) < 0) {
            while (i--) {
                mm_allocator_inner_fini_1 (mm, a, &a->inner[i]);
            }
            mm_magcache_fini (mm, a, &a->magcache);
            ddsrt_mutex_destroy (&a->slab_lock);
            return -1;
        }
    }
    return 0;
}

static struct mm_allocator *get_m_allocator (struct c_mm_s *mm, struct mm_allocator * const allocator)
{
    const unsigned m_size_bytes = magazine_size_bytes (allocator->m_size);
    const unsigned m_sizeidx = size_to_smobj_sizeidx (m_size_bytes);
    return &mm->allocator[m_sizeidx];
}

static int mm_allocator_init_2 (struct c_mm_s *mm, struct mm_allocator *a, struct mm_allocator *m_a)
{
    int i;
    /* Initialise inner allocators (the actual allocators) last, so
     * they can rely on the existence of initialised magazine caches,
     * &c.
     */
    for (i = 0; i < N_PAR_ALLOCATORS; i++) {
        a->m_allocator = m_a;
        if (mm_allocator_inner_init_2 (mm, a, &a->inner[i]) < 0) {
            while (i--) {
                mm_allocator_inner_fini_2 (mm, a, &a->inner[i]);
            }
            return -1;
        }
    }
    return 0;
}

static void mm_allocator_fini_2 (struct c_mm_s *mm, struct mm_allocator *a)
{
    int i;
    for (i = 0; i < N_PAR_ALLOCATORS; i++) {
        mm_allocator_inner_fini_2 (mm, a, &a->inner[i]);
    }
}

static void mm_allocator_fini_1 (struct c_mm_s *mm, struct mm_allocator *a)
{
    int i;
    for (i = 0; i < N_PAR_ALLOCATORS; i++) {
        mm_allocator_inner_fini_1 (mm, a, &a->inner[i]);
    }
    mm_magcache_fini (mm, a, &a->magcache);
}

static size_t calc_mm_size (struct c_mm_s *mm)
{
    return sizeof (*mm);
}

static int mm_init_async_processing (struct c_mm_s *mm) {
    ddsrt_threadattr_t tattr;

    /* Start the thread for adaptive magcache sizing (mutex & cond
     * could probably be private all the time)
     */
    ddsrt_mutex_init (&mm->aat_lock);
    ddsrt_cond_init (&mm->aat_cond);
    mm->aat_stop = 0;
    ddsrt_threadattr_init (&tattr);
    if (ddsrt_thread_create (&mm->aat_tid, "allocator_adaptation", &tattr, aat_thread, mm) != 0) {
        goto fail_aat_thread;
    }
    return 0;

fail_aat_thread:
    ddsrt_cond_destroy (&mm->aat_cond);
    ddsrt_mutex_destroy (&mm->aat_lock);
    return -1;
}

static int mm_allocator_objhist_init_1 (struct c_mm_s *mm)
{
#if DEBUG_SUPPORT
    const unsigned debug = mm->debug & (DBG_ISFREE | DBG_MEMSET);
    if (mm->debug & DBG_OBJHIST) {
        if (mm_allocator_init_1 (mm, &mm->objhist_allocator, sizeof (struct objhist), debug) < 0) {
            goto fail_allocator_objhist_init_1;
        }
        if (mm_allocator_init_1 (
                mm, &mm->objhist_m_allocator, magazine_size_bytes (mm->objhist_allocator.m_size), debug) < 0) {
            goto fail_allocator_objhist_m_init_1;
        }
        if (mm_allocator_init_1 (mm, &mm->objhist_hash_allocator, OBJHIST_LEVEL2_SIZE * sizeof (struct objhist *), debug) < 0) {
            goto fail_allocator_objhist_hash_init_1;
        }
        if (mm_allocator_init_1 (mm, &mm->objhist_hash_m_allocator, magazine_size_bytes (mm->objhist_hash_allocator.m_size), debug) < 0) {
            goto fail_allocator_objhist_hash_m_init_1;
        }
    }
    return 0;

fail_allocator_objhist_hash_m_init_1:
    mm_allocator_fini_1 (mm, &mm->objhist_hash_allocator);
fail_allocator_objhist_hash_init_1:
    mm_allocator_fini_1 (mm, &mm->objhist_m_allocator);
fail_allocator_objhist_m_init_1:
    mm_allocator_fini_1 (mm, &mm->objhist_allocator);
fail_allocator_objhist_init_1:
    return -1;
#else
    OS_UNUSED_ARG (mm);
    return 0;
#endif
}

static int mm_allocator_objhist_init_2 (struct c_mm_s *mm)
{
#if DEBUG_SUPPORT
    if (mm->debug & DBG_OBJHIST) {
        if (mm_allocator_init_2 (mm, &mm->objhist_allocator, &mm->objhist_m_allocator) < 0) {
            goto fail_allocator_objhist_init_2;
        }
        if (mm_allocator_init_2 (mm, &mm->objhist_m_allocator, NULL) < 0) {
            goto fail_allocator_objhist_m_init_2;
        }
        if (mm_allocator_init_2 (mm, &mm->objhist_hash_allocator, &mm->objhist_hash_m_allocator) < 0) {
            goto fail_allocator_objhist_hash_init_2;
        }
        if (mm_allocator_init_2 (mm, &mm->objhist_hash_m_allocator, NULL) < 0) {
            goto fail_allocator_objhist_hash_m_init_2;
        }
    }
    return 0;

fail_allocator_objhist_hash_m_init_2:
    mm_allocator_fini_2 (mm, &mm->objhist_hash_allocator);
fail_allocator_objhist_hash_init_2:
    mm_allocator_fini_2 (mm, &mm->objhist_m_allocator);
fail_allocator_objhist_m_init_2:
    mm_allocator_fini_2 (mm, &mm->objhist_allocator);
fail_allocator_objhist_init_2:
    return -1;
#else
    OS_UNUSED_ARG (mm);
    return 0;
#endif
}

static void mm_allocator_objhist_fini_2 (struct c_mm_s *mm)
{
#if DEBUG_SUPPORT
    if (mm->debug & DBG_OBJHIST) {
        mm_allocator_fini_2 (mm, &mm->objhist_hash_m_allocator);
        mm_allocator_fini_2 (mm, &mm->objhist_hash_allocator);
        mm_allocator_fini_2 (mm, &mm->objhist_m_allocator);
        mm_allocator_fini_2 (mm, &mm->objhist_allocator);
    }
#else
    OS_UNUSED_ARG (mm);
#endif
}

static void mm_allocator_objhist_fini_1 (struct c_mm_s *mm)
{
#if DEBUG_SUPPORT
    if (mm->debug & DBG_OBJHIST) {
        mm_allocator_fini_1 (mm, &mm->objhist_hash_m_allocator);
        mm_allocator_fini_1 (mm, &mm->objhist_hash_allocator);
        mm_allocator_fini_1 (mm, &mm->objhist_m_allocator);
        mm_allocator_fini_1 (mm, &mm->objhist_allocator);
    }
#else
    OS_UNUSED_ARG (mm);
#endif
}

static int mm_toplevel_init (struct c_mm_s *mm, uintptr_t size, uintptr_t threshold)
{
    ddsrt_mtime_t tnow;
    unsigned i;

    if (size < HEAP_ALIGN + HEAP_INCREMENT + 2 * SLAB_SIZE) {
        return -1;
    }

    mm->address = mm;
    mm->config_size = size;
    mm->size = (uintptr_t)size & (uintptr_t)-SLAB_SIZE;
    mm->threshold = threshold;

    ddsrt_mutex_init (&mm->prng_lock);
    ddsrt_atomic_st32 (&mm->contended, 0);

    tnow = ddsrt_time_monotonic ();
    mm->prng_state = (uint64_t) tnow.v;
    for (i = 0; i < 10; i++) {
        /* mix initial value a bit, or else the initial top bits are
         * essentially constant instead of pseudo random
         */
        mm_prng_mmix (&mm->prng_state);
    }

    mm_slablist_init (&mm->slablist_free);

    /* We grow the heap in fixed increments, with an initial size in
     * [increment,2*incremented) such that the end of the heap will be
     * aligned at a multiple of increment.
     */
    mm->heap_end_off = (((uintptr_t) mm + HEAP_ALIGN - 1) & (uintptr_t)-HEAP_ALIGN) - (uintptr_t) mm + HEAP_INCREMENT;
    mm->slab_start_off = (((uintptr_t) mm + mm->size) & (uintptr_t)-SLAB_SIZE) - (uintptr_t) mm;
    MM_ASSERT (mm->heap_end_off <= mm->slab_start_off);
    MM_ASSERT (mm->slab_start_off <= mm->size);
    ddsrt_atomic_st64 (&mm->unreserved, mm->slab_start_off - mm->heap_end_off);

    if (c_mmheapInit (&mm->mmheap,
                      calc_mm_size (mm) - offsetof (struct c_mm_s, mmheap),
                      mm->heap_end_off - offsetof (struct c_mm_s, mmheap),
                      (mm->mode == MM_SHARED) ? C_MMHEAP_SHARED : 0) < 0) {
        goto fail_heap_init;
    }
    ddsrt_atomic_st32 (&mm->lgobj_mallocs, 0);
    mm->n_smobj_fails = 0;
    mm->n_lgobj_fails = 0;
    mm->max_used = 0;

    for (i = 0; i < N_SMOBJ_SIZES; i++) {
        const unsigned objsize = sizeidx_to_smobj_size (i);
        if (mm_allocator_init_1 (mm, &mm->allocator[i], objsize, mm->debug) < 0) {
            while (i--) {
                mm_allocator_fini_1 (mm, &mm->allocator[i]);
            }
            goto fail_allocator_init_1;
        }
    }
    if (mm_allocator_objhist_init_1 (mm) < 0) {
        goto fail_allocator_objhist_init_1;
    }

    for (i = 0; i < N_SMOBJ_SIZES; i++) {
        struct mm_allocator * const allocator = &mm->allocator[i];
        if (mm_allocator_init_2 (mm, allocator, get_m_allocator (mm, allocator)) < 0) {
            while (i--) {
                mm_allocator_fini_2 (mm, allocator);
            }
            goto fail_allocator_init_2;
        }
    }
    if (mm_allocator_objhist_init_2 (mm) < 0) {
        goto fail_allocator_objhist_init_2;
    }

    if (mm_init_async_processing (mm)) {
        goto fail_init_async_processing;
    }

    update_max_used (mm);
    ddsrt_atomic_fence ();
    ddsrt_atomic_st32 (&mm->initialized, 1);
    return 0;

fail_init_async_processing:
    mm_allocator_objhist_fini_2 (mm);
fail_allocator_objhist_init_2:
    for (i = 0; i < N_SMOBJ_SIZES; i++) {
        mm_allocator_fini_2 (mm, &mm->allocator[i]);
    }
fail_allocator_init_2:
    mm_allocator_objhist_fini_1 (mm);
fail_allocator_objhist_init_1:
    for (i = 0; i < N_SMOBJ_SIZES; i++) {
        mm_allocator_fini_1 (mm, &mm->allocator[i]);
    }
fail_allocator_init_1:
    c_mmheapFini (&mm->mmheap);
fail_heap_init:
    ddsrt_mutex_destroy (&mm->prng_lock);
    return -1;
}

static void mm_fini_async_processing (struct c_mm_s *mm)
{
    ddsrt_mutex_lock (&mm->aat_lock);
    mm->aat_stop = 1;
    ddsrt_cond_broadcast (&mm->aat_cond);
    ddsrt_mutex_unlock (&mm->aat_lock);
    ddsrt_thread_join (mm->aat_tid, NULL);
    ddsrt_cond_destroy (&mm->aat_cond);
    ddsrt_mutex_destroy (&mm->aat_lock);
}

static void mm_toplevel_fini (struct c_mm_s *mm)
{
    int i;
    mm_allocator_objhist_fini_2 (mm);
    for (i = 0; i < N_SMOBJ_SIZES; i++) {
        mm_allocator_fini_2 (mm, &mm->allocator[i]);
    }
    mm_allocator_objhist_fini_1 (mm);
    for (i = 0; i < N_SMOBJ_SIZES; i++) {
        mm_allocator_fini_1 (mm, &mm->allocator[i]);
    }
    c_mmheapFini (&mm->mmheap);
    ddsrt_mutex_destroy (&mm->prng_lock);
}

static int mm_init (struct c_mm_s *mm, struct c_mm_s *mm_heapblock_ptr, uintptr_t size, uintptr_t threshold, c_mm_mode mode)
{
    MM_ASSERT (mode == MM_SHARED || mode == MM_PRIVATE || mode == MM_HEAP);
    mm->mode = mode;
#if DEBUG_SUPPORT
    mm->debug = config_debug_flags ();
    if (mm->debug & (DBG_TRACK_MALLOC | DBG_TRACK_FREE)) {
        /* Object history support is required for malloc, free
         * tracking.  From a usability point of view, the tracking is
         * what's relevant, not how it gets implemented, and so we
         * implicitly enable the history support when we know we need
         * it.
         */
        mm->debug |= DBG_OBJHIST;
    }
    mm->max_objhist_depth = config_max_objhist_depth ();
    if (mm->debug & DBG_PRINT_DEBUG_FLAGS) {
      fprintf (stderr, "OSPL_ALLOCATOR_OPTIONS debug 0x%x max_objhist_depth %d\n", mm->debug, mm->max_objhist_depth);
      mm->debug &= ~DBG_PRINT_DEBUG_FLAGS;
    }
#else
    mm->debug = 0;
#endif
    mm->mm_heapblock_ptr = mm_heapblock_ptr;
    mm->bound = NULL;
    mm->max_reservation = (uintptr_t) config_decimal("maxreservation", UINT64_MAX);
    if (mm->mode == MM_HEAP) {
        /* Some mm properties need to be initialized even if mm itself
         * is not used to manage heap.
         *
         * "slab_start_off" is initialised such that
         * mm+mm->slab_start_off points to the last byte in the
         * address space, which can't ever be returned by the
         * underlying operating system malloc because it would be
         * misaligned.  This allows c_mmFree to optimise the common
         * case of having to call mm_free_smobj().
         */
        mm->threshold = 0;
        mm->slab_start_off = (~(uintptr_t) 0) - (uintptr_t) mm;
        mm->heap_end_off = 0;
        ddsrt_atomic_st64 (&mm->unreserved, (~(uintptr_t)0) / 2);
        mm->mmheap.n_free_bytes = 0;
        mm->slablist_free.length = 0;
        return 0;
    } else {
        /* FIXME: move mm->lock initialisation to mm_toplevel_init */
        ddsrt_mutex_init (&mm->lock);
        if (mm_toplevel_init (mm, size, threshold) < 0) {
            goto fail_toplevel_init;
        }
#if DEBUG_SUPPORT
        if (objhist_admin_init (mm, &mm->objhist_admin) < 0) {
            goto fail_objhist_admin_init;
        }
#endif
        return 0;

#if DEBUG_SUPPORT
    fail_objhist_admin_init:
        mm_fini_async_processing (mm);
        mm_toplevel_fini (mm);
#endif
    fail_toplevel_init:
        ddsrt_mutex_destroy (&mm->lock);
        return -1;
    }
}

static void mm_fini (struct c_mm_s *mm)
{
    switch (mm->mode) {
    case MM_HEAP:
        break;
    case MM_PRIVATE:
#if DEBUG_SUPPORT
        objhist_admin_fini (mm, &mm->objhist_admin);
#endif
        mm_fini_async_processing (mm);
        mm_toplevel_fini (mm);
        ddsrt_mutex_destroy (&mm->lock);
        break;
    case MM_SHARED:
        /* In shared mode, can't really clean up because other
         * processes may still be attached to the shared memory.
         * Could do reference counting, but that might cause a future
         * application process to reinitialize the allocator & create
         * the background services.  So instead do as we always did,
         * but for the stopping of the thread.
         */
        //if (mm->aat_pid == os_procIdSelf ()) {
            mm_fini_async_processing (mm);
        //}
        break;
    }
}

static size_t size_for_singleprocess (void)
{
    return 1048576 * (size_t) config_decimal ("spsize", 0);
}

/**
 * Create a new memory manager. The memory manager will manage the piece of
 * memory starting at #address# of size #size#. If size is 0, the memory manager
 * will not initialize the datastructures of the memory manager. This is
 * necessary for other threads/processes to be able to use a memory manager that
 * manages a piece of shared memory.
 * If address is NULL, the memory manager won't use the special memory manager
 * features and will just map straight to #malloc()# and #free()#. After
 * initializing the admin of the memory manager, the status are reset
 * to 0. It is the responsibility of the calling process to create a
 * \Ref{spl_stc_stat_man} to manage the status on behalf of the memory
 * manager and afterwards make a call to \Ref{c_mm_set_status_manager}
 *
 * @param address The address where the block of memory to manage starts
 * @param size The length of the block of memory, 0 if there is already a
 *    memory manager active in this piece of memory
 *
 * @return a pointer to the new created memory manager
 */
struct c_mm_s * c_mmCreate (void *address, size_t size, size_t threshold)
{
    const dds_duration_t poll_delay = DDS_MSECS(100);
    struct c_mm_s *mm;
    int i;

    if (size > SIZE_MAX / 2) {
        /* the introduction of "unreserved" adds some signed arithmetic/testing, which
         * of course can be worked around, but it seems reasonable to limit the size of
         * the memory instead
         */
        return NULL;
    }

    if (threshold == 0) {
        /* There's no threshold checking at all when mm->threshold is 0 (intentionally,
         * the threshold is used internally with the dual purpose of indicating whether
         * to check, and if yes, against what value).  By setting it to 1 instead of 0,
         * we'll have checking and in practice will never be able to tell the difference
         * -- especially not since it gets allocated typically in much larger units
         */
        threshold = 1;
    }

    if (address == NULL) {
        size_t sizeSetByOSPL_ALLOCATOR_OPTIONS = 0;
        sizeSetByOSPL_ALLOCATOR_OPTIONS = size_for_singleprocess ();
        if (sizeSetByOSPL_ALLOCATOR_OPTIONS != 0) {
            /* overrule size by size set by OSPL_ALLOCATOR_OPTIONS */
            size = sizeSetByOSPL_ALLOCATOR_OPTIONS;
        }
        if (size == 0) {
            /* Use heap */
            mm = malloc (sizeof (*mm));
            if (mm_init (mm, mm, 0, 0, MM_HEAP) < 0) {
                free (mm);
                return NULL;
            }
        } else {
            /* Use our own */
            struct c_mm_s *mm1;
            /* Allocate a few bytes more, so we can align everything
             * to SLAB_SIZE (though many allocators do huge blocks at
             * aligned addresses anyway) */
            mm1 = malloc (size + 2 * SLAB_SIZE);
            mm = (struct c_mm_s *) (((uintptr_t) mm1 + SLAB_SIZE - 1) & (uintptr_t)-SLAB_SIZE);
            if (mm_init (mm, mm1, size, threshold, MM_PRIVATE) < 0) {
                free (mm1);
                return NULL;
            }
        }
        return mm;
    } else {
        mm = address;
        if (size != 0) {
            if (mm_init (mm, 0, size, threshold, MM_SHARED) < 0) {
                return NULL;
            }
        } else {
            /* Wait a maximum of 5 sec until the memory manager is initialized, on the
             * assumption that the shared memory is zero'd initially
             */
            i = 0;
            while (!ddsrt_atomic_ld32 (&mm->initialized) && (i < 50)) {
                dds_sleepfor (poll_delay);
                i++;
            }

            if (!ddsrt_atomic_ld32 (&mm->initialized)) {
                return NULL;
            }
            ddsrt_atomic_fence ();
#if DEBUG_SUPPORT
            objhist_admin_init_client (mm, &mm->objhist_admin);
#endif
        }
        MM_ASSERT (mm->mode == MM_SHARED);
        if (mm->address != address) { /* address mismatch */
            fprintf (stderr, "c_mmCreate shared memory address mismatch");
            return NULL;
        }
        return mm;
    }
}

void c_mmDestroy (struct c_mm_s * mm)
{
    mm_fini (mm);
    if (mm->mm_heapblock_ptr) {
        void *ptr = mm->mm_heapblock_ptr;
        memset (mm->mm_heapblock_ptr, 0xdd, sizeof (*mm));
        free (ptr);
    }
}

int c_mmResume (struct c_mm_s * mm)
{
    return mm_init_async_processing (mm);
}

void c_mmSuspend (struct c_mm_s * mm)
{
    switch (mm->mode) {
    case MM_HEAP:
        break;
    case MM_PRIVATE:
        mm_fini_async_processing (mm);
        break;
    case MM_SHARED:
        //if (mm->aat_pid == os_procIdSelf ()) {
            mm_fini_async_processing (mm);
        //}
        break;
    }
}

size_t
c_mmSize (struct c_mm_s * mm)
{
    return (mm?mm->config_size:0);
}

static void report_memory_exhaustion (struct c_mm_s *mm, uintptr_t threshold, uintptr_t size)
{
    if (mm->mode == MM_HEAP) {
        fprintf (stderr, "Memory exhausted: required amount of %"PRIuPTR" bytes exceeds available heap space", size);
    } else {
        uintptr_t pristine, lg_free, sm_free;
        ddsrt_mutex_lock (&mm->lock);
        pristine = mm->slab_start_off - mm->heap_end_off;
        lg_free = c_mmheapLargestAvailable (&mm->mmheap) + pristine;
        sm_free = mm->slablist_free.length * SLAB_SIZE + pristine;
        ddsrt_mutex_unlock (&mm->lock);
        fprintf (stderr, "Memory exhausted: required %s amount of %"PRIuPTR" bytes exceeds available space (approximately %"PRIuPTR" bytes, "
                 "threshold %"PRIuPTR", unreserved %"PRIdPTR"))", (size <= MAX_SMOBJ_SIZE) ? "small" : "large", size, (size <= MAX_SMOBJ_SIZE) ? sm_free : lg_free,
                 threshold, (intptr_t) ddsrt_atomic_ld64 (&mm->unreserved));
    }
}

static int check_update_unreserved (struct c_mm_s *mm, uintptr_t threshold, uintptr_t amount)
{
    assert((intptr_t)amount >= 0);
    if (threshold == 0) {
        ddsrt_atomic_sub64 (&mm->unreserved, amount);
    } else {
        /* note: the pristine space can't shrink to negative size, but the reservations can
           bring it down to the threshold and subsequent allocation may cause "unreserved"
           to drop even further, hence the signed check. */
        uintptr_t unres, unres1;
        do {
            unres = ddsrt_atomic_ld64 (&mm->unreserved);
            unres1 = unres - amount;
            if ((intptr_t)unres1 < (intptr_t)threshold) {
                return 0;
            }
        } while (!ddsrt_atomic_cas64 (&mm->unreserved, unres, unres1));
    }
    return 1;
}

static void *mm_malloc_arbobj_growable_heap (struct c_mm_s *mm, size_t size, uintptr_t threshold)
{
    void *ptr;
    while ((ptr = c_mmheapMalloc (&mm->mmheap, size)) == NULL) {
        /* Claim at least 2 * HEAP_INCREMENT to reduce the risk of
         * another thread stealing our memory
         */
        uintptr_t morespace = (size + 2 * HEAP_INCREMENT - 1) & (uintptr_t)-HEAP_INCREMENT;

        ddsrt_mutex_lock (&mm->lock);
        if (morespace > mm->slab_start_off - mm->heap_end_off) {
            /* memory exhausted: heap ran into slab space */
            ++mm->n_lgobj_fails;
            ddsrt_mutex_unlock (&mm->lock);
            report_memory_exhaustion (mm, threshold, size);
            return NULL;
        } else if (!check_update_unreserved (mm, threshold, morespace)) {
            /* not allowed to grow heap */
            ++mm->n_lgobj_fails;
            ddsrt_mutex_unlock (&mm->lock);
            report_memory_exhaustion (mm, threshold, size);
            return NULL;
        } else if (c_mmheapAddRegion (&mm->mmheap, (char *) mm + mm->heap_end_off, morespace) < 0) {
            /* can't grow heap, even though memory is available
             * ... can't happen with today's implementation of
             * AddRegion, but we pretend it may, in case a future
             * change breaks that assumption.
             */
            ddsrt_atomic_add64 (&mm->unreserved, morespace);
            ++mm->n_lgobj_fails;
            ddsrt_mutex_unlock (&mm->lock);
            report_memory_exhaustion (mm, threshold, size);
            return NULL;
        } else {
            /* heap has grown, so retry (but it may fail again, there
             * may be others allocating in parallel)
             */
            mm->heap_end_off += morespace;
            update_max_used (mm);
            ddsrt_mutex_unlock (&mm->lock);
        }
    }
    return ptr;
}

void *c_mmMalloc (struct c_mm_s * mm, size_t size)
{
    /* We always return NULL for size = 0 because the system can deal
     * with that behaviour (indeed, may even require it!).  Do so
     * explicitly here, as os_malloc() may behave differently (not
     * sure - but there certainly exist malloc() implementations in
     * standard C libraries that return a unique address for each
     * 0-byte allocation) and mm_malloc_smobj doesn't like it.
     */
    if (size == 0) {
        return NULL;
    } else if (mm->mode == MM_HEAP) {
        return malloc (size);
    } else if (size <= MAX_SMOBJ_SIZE) {
        return mm_malloc_smobj (mm, (unsigned) size, 0);
    } else {
        ddsrt_atomic_inc32 (&mm->lgobj_mallocs);
        return mm_malloc_arbobj_growable_heap (mm, size, 0);
    }
}

void *c_mmRealloc (struct c_mm_s * mm, void *memory, size_t newsize)
{
    if (memory == NULL) {
        return c_mmMalloc (mm, newsize);
    } else if (newsize == 0) {
        c_mmFree (mm, memory);
        return NULL;
    } else {
        size_t oldsize;
        if ((uintptr_t) memory >= (uintptr_t) mm + mm->slab_start_off) {
            struct mm_slab * const slab = slab_from_obj (memory);
            oldsize = slab->objsize;
        } else {
            oldsize = c_mmheapBlockSize (&mm->mmheap, memory);
        }
        void *ptr = c_mmMalloc (mm, newsize);
        if (ptr == NULL) {
            return NULL;
        }
        memcpy (ptr, memory, newsize < oldsize ? newsize : oldsize);
        c_mmFree (mm, memory);
        return ptr;
    }
}

void *c_mmMallocThreshold (struct c_mm_s * mm, size_t size)
{
    /* Allocation that will not cause unreserved to drop below the threshold */
    if (size == 0) {
        return NULL;
    } else if (mm->mode == MM_HEAP) {
        return malloc (size);
    } else if (size <= MAX_SMOBJ_SIZE) {
        return mm_malloc_smobj (mm, (unsigned) size, mm->threshold);
    } else {
        ddsrt_atomic_inc32 (&mm->lgobj_mallocs);
        return mm_malloc_arbobj_growable_heap (mm, size, mm->threshold);
    }
}

void c_mmFree (struct c_mm_s * mm, void *memory)
{
    /* Note: memory is (assumed to point to) allocated memory, and
     * therefore heap_end_off or slab_start_off can't concurrently
     * change in ways that would make the two tests below fail.
     *
     * Note also that mm+mm->slab_start_off is initialised when mode
     * is MM_HEAP to avoid jumping into mm_free_smobj.
     *
     * Note that one may call c_mmFree only on addresses returned by
     * c_mmMalloc, so the assertion in mm_init for null pointer
     * representations is good unless os_malloc() returns a weird null
     * pointer representation (different from NULL, but equivalent to
     * it) in case it runs out of memory.  It is not very likely we'll
     * be running on such weird platforms, as most of the code already
     * assumes "all bits 0" is the only null pointer representation.
     * We should already be doing slightly better here :)
     */
    if ((uintptr_t) memory >= (uintptr_t) mm + mm->slab_start_off) {
        mm_free_smobj (mm, memory);
    } else if (memory == NULL) {
        return;
    } else if (mm->mode == MM_HEAP) {
        free (memory);
    } else {
        MM_ASSERT ((char *) memory < (char *) mm + mm->heap_end_off);
        c_mmheapFree (&mm->mmheap, memory);
    }
}

void *c_mmBind (struct c_mm_s * mm, const char *name, void *memory)
{
    (void)name;
    if (mm->mode == MM_HEAP) {
        return memory;
    } else {
        void *res;
        ddsrt_mutex_lock (&mm->lock);
        if (mm->bound == NULL) {
            /* just store the address, name isn't used anyway */
            mm->bound = memory;
        }
        res = mm->bound;
        ddsrt_mutex_unlock (&mm->lock);
        return res;
    }
}

void *c_mmLookup (struct c_mm_s * mm, const char *name)
{
    (void)name;
    if (mm->mode == MM_HEAP) {
        return NULL;
    } else {
        void *ptr;
        ddsrt_mutex_lock (&mm->lock);
        ptr = mm->bound;
        ddsrt_mutex_unlock (&mm->lock);
        return ptr;
    }
}

struct c_mmStatus_s c_mmListState (struct c_mm_s * mm)
{
    /* mmstat does:
     *
     * available: L.size + L.garbage + M.garbage
     *     count: L.count + M.count
     *      used: L.used + M.used
     *   maxUsed: L.maxUsed + M.maxUsed
     *  reusable: L.garbage + M.garbage
     *     fails: L.fails + M.fails
     *
     * where L is the result of c_mmListState and M is the result of
     * c_mmMapState.
     *
     * So we have two options: fix mmstat to do something sane, or do
     * weird things in c_mmMapState and c_mmListState to get the right
     * output from mmstat.  Eventually, we'll have to take the first
     * option, but for now, we take the second one.
     *
     * We define:
     *
     * available: between heap_end and slab_start (reason: it is the
     *            "pristine" region and will satisfy any request for
     *            memory) + reusable (because that's what it used to
     *            be, more-or-less)
     *
     *            so we have to return the size of the pristine region
     *            in "size", mmstat will add the amount of reusable
     *            memory to it.
     *
     *     count: the number of allocated objects, both large & small
     *
     *      used: used bytes including overhead
     *
     *   maxUsed: self-evident, but it does require constant tracking
     *            of the amount of allocated memory in the parallel
     *            allocators and the slab layer
     *
     *  reusable: interior free space in the heap and the slab layer,
     *            including free slabs -- all available memory outside
     *            the pristine region
     *
     *     fails: obvious
     *
     * And use just L to return the state to mmstat.  We're ignoring
     * the offset of the heap, and therfore, slightly overestimate
     * memory use (or: properly accounting for the static overhead of
     * the allocator :-) )
     */
    struct c_mmStatus_s s = { 0, 0, 0, 0, 0, 0, 0, 0, MM_HEAP };
    struct c_mmheapStats hs;
    uintptr_t partial_slabs_freebytes;
    int i, j;

    if (mm->mode == MM_HEAP) {
        return s;
    }
    s.mmMode = mm->mode;

    /* Partially free slab list have their own locks, which can't be
     * taken when mm->lock is held. So compute free bytes in partial
     * slabs first.
     */
    partial_slabs_freebytes = 0;
    for (j = 0; j < N_SMOBJ_SIZES; j++) {
        struct mm_allocator * const a = &mm->allocator[j];
        ddsrt_mutex_lock (&a->slab_lock);
        partial_slabs_freebytes += a->slablist_partial_nfree * a->objsize;
        ddsrt_mutex_unlock (&a->slab_lock);
    }

    /* Query heap statistics with mm->lock held: that ensures the heap
     * & slab regions don't change while computing available
     */
    ddsrt_mutex_lock (&mm->lock);
    c_mmheapStats (&mm->mmheap, &hs);

    s.size = mm->slab_start_off - mm->heap_end_off;

    /* Max used is an estimate based solely on heap_end and
     * slab_start, but both typically only grow when available memory
     * is essentially exhausted.  So it is usually slightly
     * overestimated.
     */
    s.maxUsed = mm->max_used;

    /* Free slabs & unused space in partial slabs is the reusable part
     * of the slab memory.  Unused space in partial slabs is
     * precomputed because of the locking hierarchy.  This is
     * therefore but an estimate and not a consistent snapshot.
     */
    s.garbage = mm->slablist_free.length * SLAB_SIZE + partial_slabs_freebytes;
    /* Within the slabs, used memory is by definition all slab space
     * minus the reusable bits: that even accounts for all allocator
     * overhead.
     */
    s.used = (mm->size - mm->slab_start_off) - s.garbage;

    /* Need to also account for the heap in used and reusable */
    s.garbage += hs.totfree;
    s.used += mm->heap_end_off - hs.totfree;

    /* n_..._fails: within lock -- ignoring hs.nfails because the heap
     * experiences "soft failures", where the heap is grown on
     * failure
     */
    s.fails = (uint64_t) (mm->n_smobj_fails + mm->n_lgobj_fails);
    ddsrt_mutex_unlock (&mm->lock);

    /* Magazine caches are reusable memory as well - this is imprecise
     * because of the allocations that occur in parallel
     */
    for (j = 0; j < N_SMOBJ_SIZES; j++) {
        struct mm_allocator * const a = &mm->allocator[j];
        struct mm_magcache * const mc = &a->magcache;
        ddsrt_mutex_lock (&mc->lock);
        s.garbage += mc->full.size * a->objsize;
        ddsrt_mutex_unlock (&mc->lock);
    }

    /* Object count in the slab layer can't be computed exactly, we
     * can't lock all the allocator contexts (well, we can, with
     * trylock & backtracking & whatnot, but we won't)
     */
    s.count = (int64_t) hs.nused;
    for (i = 0; i < N_SMOBJ_SIZES; i++) {
        struct mm_allocator * const a = &mm->allocator[i];
        for (j = 0; j < N_PAR_ALLOCATORS; j++) {
            struct mm_allocator_inner * const ai = &a->inner[j];
            ddsrt_mutex_lock (&ai->lock);
            s.count = (int64_t) ((uint64_t) s.count + ai->mallocs - ai->frees);
            s.garbage += (ai->lm[0].nobjs + ai->lm[1].nobjs) * a->objsize;
            ddsrt_mutex_unlock (&ai->lock);
        }
    }

    return s;
}

/* returns the exact amount of memory used in the system do not use
 * outside test environment due to extensive locking
 */
int64_t c_mmGetUsedMem (struct c_mm_s * mm)
{
    uint64_t totalalloc, totalfree, used;
    struct c_mmheapStats hs;
    int i, j;

    if (mm->mode == MM_HEAP) {
        return 0;
    }

    /* Lock all inner allocators (N_SMOBJ_SIZES * N_PAR_ALLOCATORS) */
    for (i = 0; i < N_SMOBJ_SIZES; i++) {
        struct mm_allocator * const a = &mm->allocator[i];
        for (j = 0; j < N_PAR_ALLOCATORS; j++) {
            struct mm_allocator_inner * const ai = &a->inner[j];
            ddsrt_mutex_lock (&ai->lock);
        }
    }
    ddsrt_mutex_lock (&mm->lock);

    totalalloc = 0;
    totalfree = 0;
    for (i = 0; i < N_SMOBJ_SIZES; i++) {
        struct mm_allocator * const a = &mm->allocator[i];
        for (j = 0; j < N_PAR_ALLOCATORS; j++) {
            struct mm_allocator_inner * const ai = &a->inner[j];
            totalalloc += (size_t) ai->mallocs * a->objsize;
            totalfree += (size_t) ai->frees * a->objsize;
        }
    }
    used = totalalloc - totalfree;
    c_mmheapStats (&mm->mmheap, &hs);
    used += mm->heap_end_off - hs.totfree;

    /*fprintf(stdout,"ALLOC %10"PRId64" FREE %10"PRId64" RESULT %10"PRId64" HEAP %10"PRId64" \n",totalalloc,totalfree,used,((os_int64)mm->heap_end_off - (os_int64)hs.totfree));*/

    ddsrt_mutex_unlock (&mm->lock);
    for (i = 0; i < N_SMOBJ_SIZES; i++) {
        struct mm_allocator * const a = &mm->allocator[i];
        for (j = 0; j < N_PAR_ALLOCATORS; j++) {
            struct mm_allocator_inner * const ai = &a->inner[j];
            ddsrt_mutex_unlock (&ai->lock);
        }
    }
    return (int64_t) used;
}

struct c_mmStatus_s c_mmState (struct c_mm_s * mm, uint32_t flags)
{
    struct c_mmStatus_s cmm_stat;
    /* flags:
     * TRUE = print Allocator info
     * FALSE =  do not print Allocator info
     * C_MM_STATS = do an exact memory count (warning do not use outside test environment)
     */
    switch (flags)
    {
    case 1:
        cmm_stat = c_mmListState (mm);
        c_mmPrintAllocatorInfo (mm);
        break;
    case 0:
        cmm_stat = c_mmListState (mm);
        break;
    case C_MM_STATS:
        cmm_stat = c_mmListState (mm);
        cmm_stat.used = (size_t) c_mmGetUsedMem (mm);
        break;
    default:
        cmm_stat = c_mmListState (mm);
        break;
    }
    return cmm_stat;
}

c_mm_mode
c_mmMode (
    struct c_mm_s * mm)
{
    return mm->mode;
}

c_memoryThreshold c_mmbaseGetMemThresholdStatus (struct c_mm_s * mm)
{
    /* Determine available free space by reading pointer-sized &
     * 32-bit integers straight from memory without bothering with
     * locks.  Don't bother using proper interfaces either.  Ignore
     * partial slabs, as they tend to not have large amounts of memory
     * available, and debug them is fairly expensive.  If someone
     * complains about it, we'll reconsider.
     *
     * In MM_HEAP mode: all arithmetic is unsigned and threshold = 0,
     * so avail >=_def mm->threshold.
     */
    const intptr_t unreserved = (intptr_t) ddsrt_atomic_ld64 (&mm->unreserved);
    const intptr_t heap_free_bytes = (intptr_t) *((volatile uintptr_t *) &mm->mmheap.n_free_bytes);
    const intptr_t n_free_slabs = (intptr_t) *((volatile uintptr_t *) &mm->slablist_free.length);
    const intptr_t avail = heap_free_bytes + unreserved + (intptr_t) (n_free_slabs * SLAB_SIZE);
    if (avail >= (intptr_t) mm->threshold) { /* T <= A => all's well */
        return C_MEMTHRESHOLD_OK;
    } else if (avail >= (intptr_t) mm->threshold / 2) { /* T/2 <= A < T => ok for services but not apps */
        return C_MEMTHRESHOLD_APP_REACHED;
    } else { /* 0 <= A < T => not even services may continue normal operation */
        return C_MEMTHRESHOLD_SERV_REACHED;
    }
}


bool c_mmbaseMakeReservation (struct c_mm_s * mm, uintptr_t amount)
{
    amount = (amount < mm->max_reservation) ? amount : mm->max_reservation;
    return check_update_unreserved (mm, mm->threshold, amount) != 0;
}

void c_mmbaseReleaseReservation (struct c_mm_s * mm, uintptr_t amount)
{
    amount = (amount < mm->max_reservation) ? amount : mm->max_reservation;
    ddsrt_atomic_add64 (&mm->unreserved, amount);
}

static void *mm_check_smobj_ptr_lockheld (struct mm_slab const * const slab, struct mm_allocator * const allocator, const void *ptr)
{
    /* precondition: slab->allocator->inner[i].lock held for all i */
    /* determine object start addresses
     */
    const unsigned objsize = slab->objsize;
    struct mm_slab_obj *freeobj, *obj;
    unsigned objidx, i;
    if ((char *) ptr < (char *) slab + slab->objoffset) {
        return NULL; /* before first object in slab */
    } else if ((char *) ptr >= (char *) slab + slab->objoffset + slab->nobjs * objsize) {
        return NULL; /* beyond last object in slab (more precise than just SLAB_SIZE) */
    }
    objidx = (unsigned) ((char *) ptr - ((char *) slab + slab->objoffset)) / objsize;
    obj = (struct mm_slab_obj *) ((char *) slab + slab->objoffset + objidx * objsize);
    for (freeobj = slab->freelist.first; freeobj; freeobj = freeobj->next) {
        if (obj == freeobj) {
            /* not currently allocated */
            return NULL;
        }
    }
    /* not in freelist, but perhaps somewhere in a magazine, or in a
     * magazine cache? (note that nothing can change when we hold all
     * inner locks)
     */
    for (i = 0; i < N_PAR_ALLOCATORS; i++) {
        struct mm_allocator_inner *ai = &allocator->inner[i];
        struct mm_magazine *ms;
        unsigned j, k;
        for (j = 0; j < sizeof (ai->lm) / sizeof (ai->lm[0]); j++) {
            for (k = 0; k < ai->lm[j].nobjs; k++) {
                if (obj == ai->lm[j].m->objs[k]) {
                    return NULL;
                }
            }
        }
        for (ms = allocator->magcache.full.list; ms; ms = ms->next) {
            for (k = 0; k < allocator->m_size; k++) {
                if (obj == ms->objs[k]) {
                    return NULL;
                }
            }
        }
    }
    /* not in freelist, not in a magazine, not in a magazine cache, so
     * must really be allocated (which does not mean it cannot be a
     * magazine, a magazine cache, a stack trace, &c.!)
     */
    return obj;
}

static int mm_check_ptr_in_slab (const struct c_mm_s *mm, const void *ptr)
{
    /* mm->slab_start_off must be guaranteed to not increase between
     * evaluating this expression and using the result; there are --
     * in principle -- two ways: holding mm->lock and "ptr" pointing
     * to an allocated block.
     */
    return ((char *) ptr >= (char *) mm + mm->slab_start_off &&
            (char *) ptr < (char *) (((uintptr_t) mm + mm->size) & (uintptr_t)-SLAB_SIZE));
}

void *c_mmCheckPtr (struct c_mm_s *mm, void *ptr)
{
    if (mm->mode == MM_HEAP) {
        return NULL;
    }

retry:
    ddsrt_mutex_lock (&mm->lock);
    if ((char *) ptr < (char *) mm + mm->heap_end_off) {
        ddsrt_mutex_unlock (&mm->lock);
        return c_mmheapCheckPtr (&mm->mmheap, ptr);
    } else if (!mm_check_ptr_in_slab (mm, ptr)) {
        ddsrt_mutex_unlock (&mm->lock);
        return NULL;
    } else {
        struct mm_slab const * const slab = (struct mm_slab const *) ((uintptr_t) ptr & (uintptr_t)-SLAB_SIZE);
        struct mm_allocator *allocator;
        void *obj = NULL;
        int i, retry;

        allocator = *((struct mm_allocator * volatile *) &slab->allocator);
        if (allocator == NULL || allocator == UNINITIALIZED_SLAB_MARKER) {
            /* Free slab => ptr can't be pointing into a valid object */
            ddsrt_mutex_unlock (&mm->lock);
            return NULL;
        }

        /* Slab can't be freed while we hold mm->lock, but the
         * freelist inside the slab can change unless we hold
         * allocator->lock.  Locking allocator->lock while holding
         * mm->lock violates lock order, so we drop mm->lock.
         *
         * Dropping mm->lock means "slab" need no longer point to a
         * slab (may even have been gobbled up by the large object
         * heap.  Therefore, once we have locked the allocator's inner
         * locks, we also need to verify that it still is a slab
         * before we can draw any further conclusions.
         */
        ddsrt_mutex_unlock (&mm->lock);

        for (i = 0; i < N_PAR_ALLOCATORS; i++) {
            ddsrt_mutex_lock (&allocator->inner[i].lock);
        }

        /* Verify "slab" still points to a slab owned by "allocator".
         * We don't want to hold mm->lock longer than necessary, so we
         * decide whether it is safe to check (by virtue of holding
         * allocator->inner[i].lock), then drop mm->lock.
         *
         * We simply retry the entire operation if something has
         * changed.
         */
        ddsrt_mutex_lock (&mm->lock);
        if (!mm_check_ptr_in_slab (mm, ptr)) {
            retry = 1;
        } else if (slab->allocator != allocator) {
            retry = 1;
        } else {
            retry = 0;
        }
        ddsrt_mutex_unlock (&mm->lock);

        if (!retry) {
            obj = mm_check_smobj_ptr_lockheld (slab, allocator, ptr);
        }
        for (i = 0; i < N_PAR_ALLOCATORS; i++) {
            ddsrt_mutex_unlock (&allocator->inner[i].lock);
        }

        if (retry) {
            goto retry;
        }
        return obj;
    }
}

/*
 *
 * SLAB ALLOCATOR -- should move it to another file, but reorg can wait
 *
 *
 * */

#ifndef NDEBUG
static int check_slab_not_in_list (struct c_mm_s * mm, struct mm_slablist *list, struct mm_slab *slab)
{
    if (mm->debug & DBG_EXPENSIVE) {
        struct mm_slab *px = NULL, *x = list->head;
        int length = 0, selfseen = 0;
        while (x) {
            selfseen += (x == slab);
            MM_ASSERT (x->prev == px);
            length++;
            px = x;
            x = x->next;
        }
        MM_ASSERT (selfseen == 0);
        MM_ASSERT (length == (int) list->length);
    }
    return 1;
}

static int check_slab_in_list (struct c_mm_s * mm, struct mm_slablist *list, struct mm_slab *slab)
{
    if (mm->debug & DBG_EXPENSIVE) {
        struct mm_slab *px = NULL, *x = list->head;
        int length = 0, selfseen = 0;
        while (x) {
            selfseen += (x == slab);
            MM_ASSERT (x->prev == px);
            length++;
            px = x;
            x = x->next;
        }
        MM_ASSERT (selfseen == 1);
        MM_ASSERT (length == (int) list->length);
    }
    return 1;
}
#endif

static void mm_link_slab_descaddr (struct c_mm_s * mm UNUSED_NDEBUG, struct mm_slablist *list, struct mm_slab *slab)
{
    MM_ASSERT (check_slab_not_in_list (mm, list, slab));
    list->length++;
#if 0
    /* Complexity is linear in length of list, but for now I'm more
     * interested in memory use than speed, and so a trivial one beats
     * a more efficient one that is also more complex. */
    struct mm_slab *px = NULL, *x = list->head;
    while (x && slab < x) {
        MM_ASSERT (px == NULL || x < px);
        px = x;
        x = x->next;
    }
    MM_ASSERT (slab != x && slab != px);
    /* insert slab between px and x */
    slab->next = x;
    slab->prev = px;
    if (x) {
        x->prev = slab;
    }
    if (px) {
        px->next = slab;
    } else {
        list->head = slab;
    }
#else
    slab->prev = NULL;
    slab->next = list->head;
    if (slab->next) {
        slab->next->prev = slab;
    }
    list->head = slab;
#endif
}

static struct mm_slab *mm_unlink_slab (struct c_mm_s * mm UNUSED_NDEBUG, struct mm_slablist *list, struct mm_slab *slab)
{
    MM_ASSERT (check_slab_in_list (mm, list, slab));
    MM_ASSERT (list->length > 0);
    list->length--;
    if (slab->next) {
        slab->next->prev = slab->prev;
    }
    if (slab->prev) {
        slab->prev->next = slab->next;
    } else {
        list->head = slab->next;
    }
    return slab;
}

static void check_magic (struct c_mm_s *mm, const void *obj, uint32_t code, const unsigned char *cs, unsigned char magic, size_t n)
{
#if DEBUG_SUPPORT
    size_t i;
    for (i = 0; i < n; i++) {
        if (cs[i] != magic) {
            ospl_allocator_error (mm, obj, code, "check_magic: dirty\n");
        }
    }
#else
    (void) mm;
    (void) obj;
    (void) code;
    (void) cs;
    (void) n;
    (void) magic;
#endif
}

static void check_cachedfree (struct c_mm_s *mm, const void *obj, size_t objsize)
{
    check_magic (mm, obj, C_MMTRACKOBJECT_CODE_MALLOC, obj, 0xeb, objsize);
}

static void mark_cachedfree (void *obj, unsigned objsize)
{
    memset (obj, 0xeb, objsize);
}

static void check_listfree (struct c_mm_s *mm, const void *obj, size_t objsize)
{
    assert (objsize >= 2 * sizeof (void *));
    check_magic (mm, obj, C_MMTRACKOBJECT_CODE_MALLOC, (unsigned char *) obj + sizeof (void *), 0xed, objsize - sizeof (void *));
}

static void mark_listfree (void *obj, size_t objsize)
{
    assert (objsize >= 2 * sizeof (void *));
    memset ((unsigned char *) obj + sizeof (void *), 0xed, objsize - sizeof (void *));
}

static void check_allfree (struct c_mm_s *mm, const struct mm_slab *slab)
{
    unsigned offset = sizeof (*slab);
    check_magic (mm, NULL, C_MMTRACKOBJECT_CODE_MALLOC, (unsigned char *) slab + offset, 0xef, SLAB_SIZE - offset);
}

static void mark_allfree (struct mm_slab *slab)
{
    unsigned offset = sizeof (*slab);
    memset ((unsigned char *) slab + offset, 0xef, SLAB_SIZE - offset);
}

static struct mm_slab *mm_malloc_slab_raw (struct c_mm_s *mm, uintptr_t threshold)
{
    /* Prefer slabs from the free list, but if none available, grow
     * the slab region, if possible
     */
    struct mm_slab *slab;
    ddsrt_mutex_lock (&mm->lock);
    if (!check_update_unreserved (mm, threshold, SLAB_SIZE)) {
       /* not allowed to claim slab */
       slab = NULL;
    } else if (mm->slablist_free.head) {
        slab = mm_unlink_slab (mm, &mm->slablist_free, mm->slablist_free.head);
        if (mm->debug & DBG_MEMSET) {
            check_allfree (mm, slab);
        }
        slab->allocator = UNINITIALIZED_SLAB_MARKER;
    } else if (mm->heap_end_off + SLAB_SIZE > mm->slab_start_off) {
        /* no free slabs, no space to add new ones */
        slab = NULL;
    } else {
        mm->slab_start_off -= SLAB_SIZE;
        update_max_used (mm);
        slab = (struct mm_slab *) ((char *) mm + mm->slab_start_off);
        if (mm->debug & DBG_MEMSET) {
            mark_allfree (slab);
        }
        memset (slab, 0, sizeof (*slab));
        slab->allocator = UNINITIALIZED_SLAB_MARKER;
    }
    ddsrt_mutex_unlock (&mm->lock);
    MM_ASSERT (((uintptr_t) slab & (uintptr_t)(SLAB_SIZE - 1)) == 0);
    return slab;
}

static void mm_free_slab (struct c_mm_s *mm, struct mm_slab *slab)
{
    /* If freeing the slab at the low end of the slab region, free it
     * by shrinking the region, else add it to the free list.  This is
     * a bit too primitve, but'll do for the first hack: we want to
     * preferably use the highest addresses, and release the lowest
     * ones when possible.  For that, we need something like an
     * ordered doubly-linked list, or so.
     */
    MM_ASSERT (slab->nfree == slab->nobjs);
    if (mm->debug) {
        if (mm->debug & DBG_MEMSET) {
            unsigned i;
            for (i = 0; i < slab->nobjs; i++) {
                char *obj = (char *) slab + slab->allocator->slab_object_offset + i * slab->objsize;
                check_listfree (mm, obj, slab->objsize);
            }
            mark_allfree (slab);
        }
        if (mm->debug & DBG_OBJHIST) {
            unsigned i;
            for (i = 0; i < slab->nobjs; i++) {
                char *obj = (char *) slab + slab->allocator->slab_object_offset + i * slab->objsize;
                objhist_delete_if_exists (mm, obj);
            }
        }
    }
    ddsrt_mutex_lock (&mm->lock);
    slab->allocator = NULL;
    mm_link_slab_descaddr (mm, &mm->slablist_free, slab);
    ddsrt_atomic_add64 (&mm->unreserved, SLAB_SIZE);
    /* If this is the slab at the lowest used address, move
     * slab_start_off upwards as far as we can.
     */
    if ((char *) slab == (char *) mm + mm->slab_start_off) {
        do {
            mm_unlink_slab (mm, &mm->slablist_free, slab);
            mm->slab_start_off += SLAB_SIZE;
            slab = (struct mm_slab *) ((char *) slab + SLAB_SIZE);
        } while (mm->slab_start_off < mm->size && slab->allocator == NULL);
    }
    ddsrt_mutex_unlock (&mm->lock);
}

static unsigned mutex_lock_notecontention (ddsrt_mutex_t *mtx, volatile ddsrt_atomic_uint32_t *count)
{
#if NOTE_SLABLOCK_CONTENTION
    if (ddsrt_mutex_trylock (mtx)) {
        return 0;
    } else {
        ddsrt_mutex_lock (mtx);
        return ddsrt_atomic_inc32_nv (count);
    }
#else
    ddsrt_mutex_lock (mtx);
#endif
}

static void mutex_unlock_notecontention (ddsrt_mutex_t *mtx)
{
    ddsrt_mutex_unlock (mtx);
}

static void insert_slab_into_partial_list_lockheld (struct c_mm_s *mm, struct mm_allocator *allocator, struct mm_slab *slab)
{
    MM_ASSERT (0 < slab->nfree && slab->nfree < slab->nobjs);
    allocator->slablist_partial_nfree += slab->nfree;
    mm_link_slab_descaddr (mm, &allocator->slablist_partial, slab);
}

static struct mm_slab *slab_from_obj (const void *obj)
{
    return (struct mm_slab *) ((uintptr_t) obj & (uintptr_t)-SLAB_SIZE);
}

static unsigned allocate_from_raw_slab (struct mm_allocator *allocator, struct mm_slab *slab, void *objs[], unsigned n)
{
    const unsigned objsize = allocator->objsize;
    const unsigned nobjs = allocator->slab_nobjs;
    const unsigned objoffset = allocator->slab_object_offset;
    struct mm_slab_obj *pobj = NULL;
    char *objects;
    unsigned i;

    MM_ASSERT (nobjs > 1);
    MM_ASSERT (0 < n && n <= nobjs);

    /* Init slab header, freelist */
    slab->nobjs = nobjs;
    slab->objsize = objsize;
    slab->objoffset = objoffset;
    objects = (char *) slab + objoffset;
    for (i = nobjs - 1; i >= n; i--) {
        struct mm_slab_obj *obj = (void *) (objects + i * objsize);
        obj->next = pobj;
        pobj = obj;
    }
    slab->freelist.first = (void *) pobj;
    slab->freelist.last = (void *) (objects + (nobjs - 1) * objsize);
    slab->nfree = nobjs - n;
    if (allocator->debug & DBG_ISFREE) {
        memset ((char *) (slab + 1), 0xff, align8uint ((nobjs+7)/8));
    }
    ddsrt_atomic_fence_rel ();
    slab->allocator = allocator;

    /* Fill objs[] with pointers to the objects we did not insert into
     * the freelist
     */
    for (i = 0; i < n; i++) {
        objs[i] = (void *) (objects + i * objsize);
    }

    if (allocator->debug & DBG_MEMSET) {
        for (i = 0; i < n; i++) {
            mark_cachedfree (objs[i], objsize);
        }
        for (pobj = slab->freelist.first; pobj; pobj = pobj->next) {
            mark_listfree (pobj, objsize);
        }
    }
    return n;
}

#if MALLOC_SMOBJ_VERSION == 0
static int mm_malloc_smobj_from_slab (struct c_mm_s *mm, struct mm_allocator *allocator, uintptr_t threshold, void *objs[], unsigned nobjs)
{
    /* Try to allocate nobjs, storing pointers in objs[] and returning
     * actual number allocated, which may be smaller when insufficient
     * memory is available
     */
    struct mm_slab *slab = NULL; /* superfluous, but for a compiler warning */
    unsigned idx;
    MM_ASSERT (nobjs > 0);
    /* First, allocate objects from slabs on the partially allocated
     * list, these we may have to remove from the list
     */
    idx = 0;
    mutex_lock_notecontention (&allocator->slab_lock, &mm->contended);
    while (idx < nobjs && (slab = allocator->slablist_partial.head) != NULL) {
#ifndef NDEBUG
        char * const objects = (char *) slab + slab->objoffset;
#endif
        unsigned i, n = nobjs - idx;
        if (n > slab->nfree) {
            n = slab->nfree;
        }
        MM_ASSERT (n > 0);
        MM_ASSERT ((uintptr_t) n <= allocator->slablist_partial_nfree);
        MM_ASSERT ((char *) slab->freelist.first >= objects);
        MM_ASSERT ((char *) slab->freelist.first < objects + slab->nobjs * slab->objsize);
        allocator->slablist_partial_nfree -= (uintptr_t) n;
        for (i = 0; i < n; i++) {
            MM_ASSERT (slab->freelist.first);
            objs[idx] = slab->freelist.first;
            slab->freelist.first = slab->freelist.first->next;
            MM_ASSERT ((slab->nfree-i-1 == 0 && slab->freelist.first == NULL) ||
                       (slab->nfree-i-1 != 0 && (char *) slab->freelist.first >= objects));
            MM_ASSERT ((slab->nfree-i-1 == 0 && slab->freelist.first == NULL) ||
                       (slab->nfree-i-1 != 0 && (char *) slab->freelist.first < objects + slab->nobjs * slab->objsize));
            if (allocator->debug & DBG_MEMSET) {
                check_listfree (mm, objs[idx], slab->objsize);
                mark_cachedfree (objs[idx], slab->objsize);
            }
            idx++;
        }
        slab->nfree -= n;
        if (slab->freelist.first == NULL) {
            /* allocate last free entry => no longer on list of partially used slabs */
            mm_unlink_slab (mm, &allocator->slablist_partial, slab);
        }
    }
    if (idx < nobjs && (slab = mm_malloc_slab_raw (mm, threshold)) != NULL) {
        /* Second, if not done yet, allocate a fresh slab.  We never
         * need more than one, by limiting the magazine size.  We
         * still need to initialize the slab by constructing the free
         * list, &c., but we'll only do so for the objects we don't
         * allocate ourselves.
         */
        idx += allocate_from_raw_slab (allocator, slab, objs + idx, nobjs - idx);
        MM_ASSERT (slab->nfree < slab->nobjs);
        if (slab->nfree > 0) {
            insert_slab_into_partial_list_lockheld (mm, allocator, slab);
        }
    }
    mutex_unlock_notecontention (&allocator->slab_lock);
    if (idx < nobjs) {
        mm_free_smobj_to_slab (mm, allocator, objs, idx);
        return 0;
    } else {
        return 1;
    }
}
#elif MALLOC_SMOBJ_VERSION == 1
static void slobj_freelist_append (struct mm_slab_obj_list *to, struct mm_slab_obj_list *x)
{
    MM_ASSERT (x->first != NULL);
    if (to->first) {
        to->last->next = x->first;
        to->last = x->last;
    } else {
        *to = *x;
    }
}

static void return_freelist_to_slab (struct c_mm_s *mm, struct mm_allocator *allocator, struct mm_slab *slab, struct mm_slab_obj_list *freelist, int listlength)
{
    MM_ASSERT (0 <= slab->nfree && slab->nfree < slab->nobjs);
    MM_ASSERT (freelist->first != NULL);
    MM_ASSERT (listlength > 0);
    slobj_freelist_append (&slab->freelist, freelist);
    if (slab->nfree == 0) {
        slab->nfree = listlength;
        insert_slab_into_partial_list_lockheld (mm, allocator, slab);
    } else {
        slab->nfree += listlength;
    }
    MM_ASSERT (0 < slab->nfree && slab->nfree < slab->nobjs);
}

static int mm_malloc_smobj_from_slab (struct c_mm_s *mm, struct mm_allocator *allocator, uintptr_t threshold, void *objs[], int nobjs)
{
    /* Try to allocate nobjs, storing pointers in objs[].  Returns
     * true if nobjs allocated, false if unsuccessful, in which case
     * it leaves the system essentially unchanged.
     */
    struct mm_slab_obj_list freelist = { NULL, NULL };
    struct mm_slab *slab, *new_slab = NULL;
    int idx, objcount;
    MM_ASSERT (nobjs > 0);

    /* First, collect enough free objects in a private list so we can
     * allocate objects from them without holding the lock.
     */
    objcount = 0;
    mutex_lock_notecontention (&allocator->slab_lock, &mm->contended);
    if ((slab = allocator->slablist_partial.head) != NULL) {
        do {
            MM_ASSERT (slab->freelist.first != NULL && slab->freelist.last != NULL);
            slobj_freelist_append (&freelist, &slab->freelist);
            objcount += slab->nfree;

            slab->freelist.first = slab->freelist.last = NULL;
            slab->nfree = 0;
            mm_unlink_slab (mm, &allocator->slablist_partial, slab);
        } while (objcount < nobjs && (slab = allocator->slablist_partial.head) != NULL);
    }
    MM_ASSERT ((uintptr_t) objcount <= allocator->slablist_partial_nfree);
    allocator->slablist_partial_nfree -= (uintptr_t) objcount;
    mutex_unlock_notecontention (&allocator->slab_lock);

    /* Second, allocate a new raw slab if we couldn't get enough free
     * objects from the partially filled slabs
     */
    if (objcount < nobjs && (new_slab = mm_malloc_slab_raw (mm, threshold)) == NULL) {
        /* Need one more slab, but can't get one. This is _VERY_ rare:
         * you never want to run out of memory, and so we can do it
         * the easy way
         */
        struct mm_slab_obj *obj = freelist.first;
        while (obj != NULL) {
            void *vobj = obj;
            obj = obj->next;
            if (allocator->debug & DBG_MEMSET) {
                check_listfree (mm, vobj, slab->objsize);
                mark_cachedfree (vobj, slab->objsize);
            }
            mm_free_smobj_to_slab (mm, allocator, &vobj, 1);
        }
        return 0;
    }

    /* Finally, fill objs[] from the slabs we pulled from the list */
    idx = 0;
    if (nobjs < objcount) {
        /* Freelist contains more objects than we need, use the ones
         * we need & return the rest
         */
        struct mm_slab_obj *obj = freelist.first;
        while (idx < nobjs) {
            objs[idx++] = obj;
            obj = obj->next;
        }
        freelist.first = obj;
        mutex_lock_notecontention (&allocator->slab_lock, &mm->contended);
        return_freelist_to_slab (mm, allocator, slab, &freelist, objcount - nobjs);
        allocator->slablist_partial_nfree += objcount - nobjs;
        mutex_unlock_notecontention (&allocator->slab_lock);
    } else {
        /* Use all objects on the freelist, and if that is not enough,
         * continue with the new slab (which we could put on the
         * freelist, except we don't build a freelist for the objects
         * we allocate)
         */
        struct mm_slab_obj *obj = freelist.first;
        while (obj) {
            objs[idx++] = obj;
            obj = obj->next;
        }
        MM_ASSERT (idx <= nobjs);
        if (idx < nobjs) {
            /* Use some or all of the new slab we claimed */
            idx += allocate_from_raw_slab (allocator, new_slab, objs + idx, nobjs - idx);
            MM_ASSERT (new_slab->nfree < new_slab->nobjs);
            if (new_slab->nfree > 0) {
                /* some objects remain free: build free list & insert in list */
                mutex_lock_notecontention (&allocator->slab_lock, &mm->contended);
                insert_slab_into_partial_list_lockheld (mm, allocator, new_slab);
                mutex_unlock_notecontention (&allocator->slab_lock);
            }
        }
    }
    MM_ASSERT (idx == nobjs);

    if (allocator->debug & DBG_MEMSET) {
        const int n_needing_conv = (objcount < nobjs) ? objcount : nobjs;
        for (idx = 0; idx < n_needing_conv; idx++) {
            check_listfree (mm, objs[idx], allocator->objsize);
            mark_cachedfree (objs[idx], allocator->objsize);
        }
    }
    return 1;
}
#endif /* MALLOC_SMOBJ_VERSION */

#if FREE_SMOBJ_VERSION == 0
static void mm_free_smobj_to_slab (struct c_mm_s *mm, struct mm_allocator *allocator, void *objs[], unsigned nobjs)
{
    /* Frees the nobjs objects pointed to by objs[] */
    unsigned i;

    if (allocator->debug & DBG_MEMSET) {
        for (i = 0; i < nobjs; i++)
        {
            void * const obj = objs[i];
            check_cachedfree (mm, obj, allocator->objsize);
            mark_listfree (obj, allocator->objsize);
        }
    }

    mutex_lock_notecontention (&allocator->slab_lock, &mm->contended);
    for (i = 0; i < nobjs; i++)
    {
        void * const obj = objs[i];
        struct mm_slab * const slab = slab_from_obj (obj);
        struct mm_slab_obj * const slobj = obj;
        MM_ASSERT (slab->nfree < slab->nobjs);
        MM_ASSERT (slab->allocator == allocator);
        slobj->next = slab->freelist.first;
        slab->freelist.first = slobj;
        if (slobj->next == NULL) {
            slab->freelist.last = slobj;
        }
        ++slab->nfree;
        ++allocator->slablist_partial_nfree;
        if (slab->nfree == slab->nobjs) {
            /* transition to entirely free => release slab entirely */
            MM_ASSERT (slab->nfree > 1);
            MM_ASSERT ((uintptr_t) slab->nfree <= allocator->slablist_partial_nfree);
            allocator->slablist_partial_nfree -= slab->nfree;
            mm_unlink_slab (mm, &allocator->slablist_partial, slab);
            mm_free_slab (mm, slab);
        } else if (slab->nfree == 1) {
            /* none free to one free => put into list of partially
             * allocated slabs
             */
            mm_link_slab_descaddr (mm, &allocator->slablist_partial, slab);
        }
    }
    mutex_unlock_notecontention (&allocator->slab_lock);
}
#elif FREE_SMOBJ_VERSION == 1
static int compare_uneq_ptr (const void *va, const void *vb)
{
    const void *a = *((const void **) va);
    const void *b = *((const void **) vb);
    MM_ASSERT (a != b);
    return a < b ? -1 : 1;
}

static void mm_free_smobj_to_slab (struct c_mm_s *mm, struct mm_allocator *allocator, void *objs[], unsigned nobjs)
{
    /* Frees the nobjs objects pointed to by objs[] */
#define FREELIST_LENGTH (SLAB_SIZE / MIN_SMOBJ_SIZE)
    struct mm_slab_obj_list freelist[FREELIST_LENGTH];
    unsigned freelist_length[FREELIST_LENGTH];
#undef FREELIST_LENGTH
    unsigned idx, i;
    MM_ASSERT (nobjs <= sizeof (freelist) / sizeof (freelist[0]));

    if (allocator->debug & DBG_MEMSET) {
        for (i = 0; i < nobjs; i++) {
            check_cachedfree (mm, objs[i], allocator->objsize);
            mark_listfree (objs[i], allocator->objsize);
        }
    }

    if (nobjs == 1) {
        freelist[0].first = freelist[0].last = objs[0];
        freelist_length[0] = 1;
        idx = 1;
    } else {
        struct mm_slab *slab;
        unsigned j;
        qsort (objs, nobjs, sizeof (objs[0]), compare_uneq_ptr);
        i = 0;
        idx = 0;
        slab = slab_from_obj (objs[0]);
        while (i < nobjs) {
            struct mm_slab * slab_j = NULL;
            struct mm_slab_obj * const slobj_first = objs[i];
            struct mm_slab_obj *slobj_last = objs[i];
            for (j = i + 1; j < nobjs; j++) {
                if ((slab_j = slab_from_obj (objs[j])) != slab) {
                    break;
                } else {
                    struct mm_slab_obj *slobj_j = objs[j];
                    slobj_last->next = slobj_j;
                    slobj_last = slobj_j;
                }
            }
            freelist[idx].first = slobj_first;
            freelist[idx].last = slobj_last;
            freelist_length[idx] = j - i;
            idx++;
            i = j;
            slab = slab_j;
        }
    }

    mutex_lock_notecontention (&allocator->slab_lock, &mm->contended);
    for (i = 0; i < idx; i++) {
        struct mm_slab *slab = slab_from_obj (freelist[i].first);
        freelist[i].last->next = slab->freelist.first;
        slab->freelist.first = freelist[i].first;
        if (freelist[i].last->next == NULL) { /* transitioning from none free to N free */
            MM_ASSERT (slab->nfree == 0);
            slab->freelist.last = freelist[i].last;
            slab->nfree = freelist_length[i];
            if (slab->nfree < slab->nobjs) { /* partially free */
                allocator->slablist_partial_nfree += freelist_length[i];
                mm_link_slab_descaddr (mm, &allocator->slablist_partial, slab);
            } else { /* all objects free */
                mm_free_slab (mm, slab);
            }
        } else { /* transitioning from some free to N free */
            const int new_nfree = slab->nfree + freelist_length[i];
            MM_ASSERT (slab->nfree > 0);
            MM_ASSERT (new_nfree <= slab->nobjs);
            if (new_nfree < slab->nobjs) { /* partially free */
                slab->nfree = new_nfree;
                allocator->slablist_partial_nfree += freelist_length[i];
            } else { /* all objects free */
                allocator->slablist_partial_nfree -= slab->nfree;
                slab->nfree = new_nfree;
                mm_unlink_slab (mm, &allocator->slablist_partial, slab);
                mm_free_slab (mm, slab);
            }
        }
    }
    mutex_unlock_notecontention (&allocator->slab_lock);
}
#endif /* FREE_SMOBJ_VERSION */

/*
 *
 * SMALL OBJECT ALLOCATOR -- should move it to another file, but reorg can wait
 *
 *
 * */

static struct mm_magazine *grab_magazine_from_slab (struct c_mm_s *mm, struct mm_allocator *a, uintptr_t threshold, int full)
{
    struct mm_magazine *m;
    void *vm;
    if (!mm_malloc_smobj_from_slab (mm, a->m_allocator, threshold, &vm, 1)) {
        return NULL;
    }
    m = vm;
    if (!full || mm_malloc_smobj_from_slab (mm, a, threshold, m->objs, a->m_size)) {
        return m;
    } else {
        /* Can't allocate enough free objects of the requested size
         * from the slab layer, but must provide a full magazine, or
         * nothing
         */
        if (a->debug & DBG_MEMSET) {
            mark_cachedfree (vm, magazine_size_bytes (a->m_size));
        }
        mm_free_smobj_to_slab (mm, a->m_allocator, &vm, 1);
        return NULL;
    }
}

static void drop_magazine_to_slab (struct c_mm_s *mm, struct mm_allocator *a, struct mm_magazine *m, unsigned nobjs)
{
    void *vm = m;
    mm_free_smobj_to_slab (mm, a, m->objs, nobjs);
    if (a->debug & DBG_MEMSET) {
        mark_cachedfree (vm, magazine_size_bytes (a->m_size));
    }
    mm_free_smobj_to_slab (mm, a->m_allocator, &vm, 1);
}

static int magcache_exchange (struct c_mm_s *mm, struct mm_allocator *allocator, uintptr_t threshold, struct mm_loaded_magazine *lm)
{
    struct mm_magcache * const mc = &allocator->magcache;
    struct mm_magcache_inner *src, *dst;
    struct mm_magazine *newm;
    int want_full;
    if (lm->nobjs == 0) { /* lm is empty, need a full one */
        want_full = 1;
        dst = &mc->empty;
        src = &mc->full;
    } else { /* lm is full, need an empty one */
        MM_ASSERT (lm->nobjs == allocator->m_size);
        want_full = 0;
        dst = &mc->full;
        src = &mc->empty;
    }

    ddsrt_mutex_lock (&mc->lock);

    MM_ASSERT (src->size <= mc->maxsize);
    MM_ASSERT (dst->size <= mc->maxsize);
    if (src->size == 0) {
        MM_ASSERT (src->list == NULL);
        src->misses_grab++;
        if ((newm = grab_magazine_from_slab (mm, allocator, threshold, want_full)) == NULL) {
            /* nothing in the cache and the slab layer can't satisfy
             * the request - leave lm unchanged so that at least the
             * invariant that there are two magazines loaded at all
             * times is maintained
             */
            ddsrt_mutex_unlock (&mc->lock);
            return 0;
        }
    } else {
        MM_ASSERT (src->size > 0);
        newm = src->list;
        src->list = newm->next;
        src->size--;
    }

    if (dst->size == mc->maxsize) {
        dst->misses_drop++;
        ddsrt_mutex_unlock (&mc->lock);
        drop_magazine_to_slab (mm, allocator, lm->m, lm->nobjs);
    } else {
        struct mm_magazine * const oldm = lm->m;
        MM_ASSERT (dst->size < mc->maxsize);
        oldm->next = dst->list;
        dst->list = oldm;
        dst->size++;
        ddsrt_mutex_unlock (&mc->lock);
    }

    lm->m = newm;
    lm->nobjs = want_full ? allocator->m_size : 0;
    return 1;
}

static void swap_loaded_magazines (struct mm_allocator_inner *inner)
{
    struct mm_loaded_magazine tmp;
    tmp = inner->lm[0];
    inner->lm[0] = inner->lm[1];
    inner->lm[1] = tmp;
}

static void deal_with_contention (struct c_mm_s *mm, struct mm_tsd *tsd, struct mm_allocator *allocator)
{
    /* reset to 0 without locking may cause a few updates to
     * contended to be lost, but I don't think that will cause any
     * harm, just delay the next context switch by a tiny bit
     */
    ddsrt_atomic_st32 (&allocator->contended, 0);
    ddsrt_atomic_inc32 (&allocator->switch_away);
    choose_another_mm_context (mm, tsd);
}

#if DEBUG_SUPPORT
static void isfree_markused (struct c_mm_s *mm, const void *obj)
{
    struct mm_slab * const slab = slab_from_obj (obj);
    ddsrt_atomic_uint32_t * const isfree = (ddsrt_atomic_uint32_t *) (slab + 1);
    const char * const objects = (char *) slab + slab->objoffset;
    const int idx = (int) ((uintptr_t)((char *) obj - objects) / slab->objsize);
    const uint32_t mask = 1u << (idx%32);
    MM_ASSERT ((char *) slab < (char *) isfree && (char *) isfree < (char *) objects);
    if ((ddsrt_atomic_and32_ov (&isfree[idx/32], ~mask) & mask) == 0) {
        ospl_allocator_error (mm, obj, C_MMTRACKOBJECT_CODE_MALLOC, "allocator: double allocate\n");
    }
}

static void isfree_markfree (struct c_mm_s *mm, const void *obj)
{
    struct mm_slab * const slab = slab_from_obj (obj);
    ddsrt_atomic_uint32_t * const isfree = (ddsrt_atomic_uint32_t *) (slab + 1);
    const char * const objects = (char *) slab + slab->objoffset;
    const int idx = (int) ((uintptr_t)((char *) obj - objects) / slab->objsize);
    const uint32_t mask = 1u << (idx%32);
    MM_ASSERT ((char *) slab < (char *) isfree && (char *) isfree < (char *) objects);
    if ((ddsrt_atomic_or32_ov (&isfree[idx/32], mask) & mask) != 0) {
        ospl_allocator_error (mm, obj, C_MMTRACKOBJECT_CODE_FREE, "allocator: double free %p\n", (void *) obj);
    }
}
#else
static void isfree_markused (struct c_mm_s *mm UNUSED, const void *obj UNUSED)
{
}

static void isfree_markfree (struct c_mm_s *mm UNUSED, const void *obj UNUSED)
{
}
#endif

static void *allocator_report_memory_exhaustion (struct c_mm_s *mm, struct mm_allocator *allocator, uintptr_t threshold)
{
    ddsrt_mutex_lock (&mm->lock);
    ++mm->n_smobj_fails;
    ddsrt_mutex_unlock (&mm->lock);
    report_memory_exhaustion (mm, threshold, allocator->objsize);
    return NULL;
}

static void *allocator_malloc (struct c_mm_s *mm, struct mm_allocator *allocator, uintptr_t threshold)
{
    struct mm_tsd * const tsd = get_mm_tsd (mm);
    struct mm_allocator_inner * const inner = &allocator->inner[tsd->context_idx];
    struct mm_loaded_magazine *lm;
    void *obj;
    if (mutex_lock_notecontention (&inner->lock, &allocator->contended) >= CONTEXT_SWITCH_THRESHOLD) {
        deal_with_contention (mm, tsd, allocator);
    }
    if (threshold && (intptr_t)ddsrt_atomic_ld64 (&mm->unreserved) < (intptr_t)threshold) {
        mutex_unlock_notecontention (&inner->lock);
        return allocator_report_memory_exhaustion (mm, allocator, threshold);
    }
    inner->mallocs++;
    if (inner->lm[0].nobjs == 0) {
        if (inner->lm[1].nobjs > 0) {
            inner->swaps++;
            swap_loaded_magazines (inner);
        } else {
            inner->grabs_full++;
            if (!magcache_exchange (mm, allocator, threshold, &inner->lm[0])) {
                mutex_unlock_notecontention (&inner->lock);
                return allocator_report_memory_exhaustion (mm, allocator, threshold);
            }
        }
    }
    lm = &inner->lm[0];
    MM_ASSERT (lm->nobjs > 0);
    obj = lm->m->objs[--lm->nobjs];
    mutex_unlock_notecontention (&inner->lock);

    if (allocator->debug) {
        if (allocator->debug & DBG_MEMSET) {
            check_cachedfree (mm, obj, allocator->objsize);
        }
        if (allocator->debug & DBG_ISFREE) {
            isfree_markused (mm, obj);
        }
        if (allocator->debug & DBG_TRACK_MALLOC) {
            objhist_insert (mm, tsd, obj, C_MMTRACKOBJECT_CODE_MALLOC);
        }
    }
    return obj;
}

static void allocator_free (struct c_mm_s *mm, struct mm_allocator *allocator, void *obj)
{
    struct mm_tsd * const tsd = get_mm_tsd (mm);
    struct mm_allocator_inner * const inner = &allocator->inner[tsd->context_idx];
    const unsigned m_size = allocator->m_size;
    struct mm_loaded_magazine *lm;

    if (allocator->debug) {
        if (allocator->debug & DBG_ISFREE) {
            isfree_markfree (mm, obj);
        }
        if (allocator->debug & DBG_MEMSET) {
            mark_cachedfree (obj, allocator->objsize);
        }
        if (allocator->debug & DBG_TRACK_FREE) {
            objhist_insert (mm, tsd, obj, C_MMTRACKOBJECT_CODE_FREE);
        }
    }

    if (mutex_lock_notecontention (&inner->lock, &allocator->contended) >= CONTEXT_SWITCH_THRESHOLD) {
        deal_with_contention (mm, tsd, allocator);
    }
    inner->frees++;
    MM_ASSERT (inner->lm[0].nobjs <= m_size);
    MM_ASSERT (inner->lm[1].nobjs <= m_size);
    if (inner->lm[0].nobjs == m_size) {
        if (inner->lm[1].nobjs < m_size) {
            inner->swaps++;
            swap_loaded_magazines (inner);
        } else {
            inner->grabs_empty++;
            if (!magcache_exchange (mm, allocator, 0, &inner->lm[0])) {
                /* Yikes! need a free magazine to release an object,
                 * but can't get one!  Luckily we can still release it
                 * directly to the slab layer.
                 */
                mm_free_smobj_to_slab (mm, allocator, &obj, 1);
                mutex_unlock_notecontention (&inner->lock);
                return;
            }
        }
    }
    lm = &inner->lm[0];
    MM_ASSERT (lm->nobjs < m_size);
    lm->m->objs[lm->nobjs++] = obj;
    mutex_unlock_notecontention (&inner->lock);
}

static void *mm_malloc_smobj (struct c_mm_s *mm, unsigned size, uintptr_t threshold)
{
    const unsigned sizeidx = size_to_smobj_sizeidx (size);
    return allocator_malloc (mm, &mm->allocator[sizeidx], threshold);
}

static void mm_free_smobj (struct c_mm_s *mm, void *obj)
{
    struct mm_slab * const slab = slab_from_obj (obj);
    struct mm_allocator * const allocator = slab->allocator;
    allocator_free (mm, allocator, obj);
}

static void aat_thread_lgobj_heap_drop_cb (void *arg, void *base UNUSED_NDEBUG, uintptr_t size)
{
    struct c_mm_s *mm = arg;
    MM_ASSERT ((uintptr_t) base + size == (uintptr_t) mm + mm->heap_end_off);
    mm->heap_end_off -= size;
    ddsrt_atomic_add64 (&mm->unreserved, size);
}

static uint32_t aat_adjust_allocator (struct c_mm_s * const mm, struct mm_allocator * const allocator, uint32_t misses_drop_old)
{
    struct mm_magcache * const mc = &allocator->magcache;
    uint32_t misses_drop_new, delta;
    unsigned new_maxsize;
    ddsrt_mutex_lock (&mc->lock);

    new_maxsize = mc->maxsize;
    misses_drop_new = mc->empty.misses_drop + mc->full.misses_drop;
    delta = misses_drop_new - misses_drop_old;

    if (delta >= INCREASE_MAGCACHE_THRESHOLD) {
        const unsigned newmax_raw = mc->maxsize < 5 ? 10 : 2 * mc->maxsize;
        new_maxsize = newmax_raw > mc->hard_maxsize ? mc->hard_maxsize : newmax_raw;
    } else if (delta <= DECREASE_MAGCACHE_THRESHOLD) {
        const unsigned step = 1;
        new_maxsize = mc->maxsize < step ? 0 : mc->maxsize - step;
    }
    if (new_maxsize != mc->maxsize) {
        mm_magcache_setmaxsize_lockheld (mm, allocator, mc, new_maxsize);
    }

    ddsrt_mutex_unlock (&mc->lock);
    return misses_drop_new;
}

static uint32_t aat_thread (void *vmm)
{
    struct c_mm_s * const mm = vmm;
    uint32_t misses_drop_old[N_SMOBJ_SIZES + 2];
    unsigned i;
    for (i = 0; i < sizeof (misses_drop_old) / sizeof (*misses_drop_old); i++) {
        misses_drop_old[i] = 0;
    }
    ddsrt_mutex_lock (&mm->aat_lock);
    while (!mm->aat_stop) {
        const dds_duration_t delay = DDS_SECS(1); /* adjust once every second */
        ddsrt_cond_waitfor (&mm->aat_cond, &mm->aat_lock, delay);
        ddsrt_mutex_unlock (&mm->aat_lock);

        for (i = 0; i < N_SMOBJ_SIZES; i++) {
            misses_drop_old[i] = aat_adjust_allocator (mm, &mm->allocator[i], misses_drop_old[i]);
        }
#if DEBUG_SUPPORT
        if (mm->debug & DBG_OBJHIST) {
            misses_drop_old[N_SMOBJ_SIZES+0] =
                aat_adjust_allocator (mm, &mm->objhist_allocator, misses_drop_old[N_SMOBJ_SIZES+0]);
            misses_drop_old[N_SMOBJ_SIZES+1] =
                aat_adjust_allocator (mm, &mm->objhist_hash_allocator, misses_drop_old[N_SMOBJ_SIZES+1]);
        }
#endif

        ddsrt_mutex_lock (&mm->lock);
        c_mmheapDropRegion (&mm->mmheap, HEAP_INCREMENT, HEAP_INCREMENT, HEAP_ALIGN, aat_thread_lgobj_heap_drop_cb, mm);
        ddsrt_mutex_unlock (&mm->lock);

        ddsrt_mutex_lock (&mm->aat_lock);
    }
    ddsrt_mutex_unlock (&mm->aat_lock);
    return 0;
}

/********/

static size_t count_slab_list_length (struct mm_slab *slab, size_t *nobj, size_t *nfree)
{
    size_t n = 0;
    if (nobj) *nobj = 0;
    if (nfree) *nfree = 0;
    while (slab) {
        n++;
        if (nobj) *nobj += slab->nobjs;
        if (nfree) *nfree += slab->nfree;
        slab = slab->next;
    }
    return n;
}

static void print_allocator_info (size_t *totn, size_t *totbfree, struct mm_allocator *a)
{
    /* mmstat fiddles with tty => \r\n */
    int i;
#define FOREACH_INNER_ALLOCATOR(stmt) do {                      \
        for (i = 0; i < N_PAR_ALLOCATORS; i++) {                \
            struct mm_allocator_inner *inner = &a->inner[i];    \
            ddsrt_mutex_lock (&inner->lock);                        \
            stmt;                                               \
            ddsrt_mutex_unlock (&inner->lock);                      \
        } } while (0)

    struct mm_magcache * const mc = &a->magcache;
    size_t nobj, nfree, nslabs;
    ddsrt_mutex_lock (&mc->lock);
    printf ("%5d: magsz %d ctxsw %"PRIu32" contn %"PRIu32" nobjs %u ooff %u",
            a->objsize, a->m_size,
            ddsrt_atomic_ld32 (&a->switch_away),
            ddsrt_atomic_ld32 (&a->contended),
            a->slab_nobjs,
            a->slab_object_offset);
    printf ("\r\n magc: size: max %d empty %d full %d missed-grabs: empty %"PRIu32" full %"PRIu32" missed-drops empty %"PRIu32" full %"PRIu32,
            mc->maxsize,
            mc->empty.size,
            mc->full.size,
            mc->empty.misses_grab,
            mc->full.misses_grab,
            mc->empty.misses_drop,
            mc->full.misses_drop);

    ddsrt_mutex_lock (&a->slab_lock);
    nslabs = count_slab_list_length (a->slablist_partial.head, &nobj, &nfree);
    ddsrt_mutex_unlock (&a->slab_lock);
    *totn += nslabs;
    *totbfree += nfree * a->objsize;
    ddsrt_mutex_unlock (&mc->lock);
    printf ("\r\n pslb: slabs: %"PRIuSIZE" objects: allocated %"PRIuSIZE" free %"PRIuSIZE, nslabs, nobj, nfree);

    printf ("\r\n mag0:");
    FOREACH_INNER_ALLOCATOR ({ printf (" %10"PRIu32, inner->lm[0].nobjs); });
    printf ("\r\n mag1:");
    FOREACH_INNER_ALLOCATOR ({ printf (" %10"PRIu32, inner->lm[1].nobjs); });
    printf ("\r\n swap:");
    FOREACH_INNER_ALLOCATOR ({ printf (" %10"PRIu32, inner->swaps); });
    printf ("\r\n grbf:");
    FOREACH_INNER_ALLOCATOR ({ printf (" %10"PRIu32, inner->grabs_full); });
    printf ("\r\n grbe:");
    FOREACH_INNER_ALLOCATOR ({ printf (" %10"PRIu32, inner->grabs_empty); });
    printf ("\r\n mllc:");
    FOREACH_INNER_ALLOCATOR ({ printf (" %10"PRId64, inner->mallocs); });
    printf ("\r\n free:");
    FOREACH_INNER_ALLOCATOR ({ printf (" %10"PRId64, inner->frees); });
    printf ("\r\n");
}

void c_mmPrintAllocatorInfo (struct c_mm_s *mm)
{
    /* mmstat fiddles with tty => \r\n */
    size_t totn = 0, totbfree = 0;
    int i;

    if (mm->mode == MM_HEAP) {
        return;
    }

    for (i = 0; i < N_SMOBJ_SIZES; i++) {
        print_allocator_info (&totn, &totbfree, &mm->allocator[i]);
    }
#if DEBUG_SUPPORT
    if (mm->debug & DBG_OBJHIST) {
        print_allocator_info (&totn, &totbfree, &mm->objhist_allocator);
        print_allocator_info (&totn, &totbfree, &mm->objhist_m_allocator);
        print_allocator_info (&totn, &totbfree, &mm->objhist_hash_allocator);
        print_allocator_info (&totn, &totbfree, &mm->objhist_hash_m_allocator);
    }
#endif

    ddsrt_mutex_lock (&mm->lock);
    printf ("heap-end: %"PRIdPTR" lgobjmallocs: %"PRIu32" slab-start: %"PRIdPTR" bytes: %"PRIdPTR" slabs: %"PRIdPTR" freeslabs: %"PRIuSIZE" partialslabs: %"PRIuSIZE" bytes: %"PRIuSIZE" contended: %"PRIu32"\r\n",
            mm->heap_end_off, ddsrt_atomic_ld32 (&mm->lgobj_mallocs),
            mm->slab_start_off, mm->size - mm->slab_start_off, (mm->size - mm->slab_start_off) / SLAB_SIZE,
            count_slab_list_length (mm->slablist_free.head, NULL, NULL), totn, totbfree,
            ddsrt_atomic_ld32 (&mm->contended));
    ddsrt_mutex_unlock (&mm->lock);
}

/********/

#if ! DEBUG_SUPPORT

static void objhist_delete_if_exists (struct c_mm_s *mm UNUSED, const void *ptr UNUSED) { }
static void objhist_insert (struct c_mm_s *mm UNUSED, const struct mm_tsd *tsd UNUSED, const void *ptr UNUSED, uint32_t code UNUSED) { }
void c_mmTrackObject (struct c_mm_s *mm UNUSED, const void *ptr UNUSED, uint32_t code UNUSED) { }
void c_mmPrintObjectHistory (FILE *fp, struct c_mm_s * mm UNUSED, void *ptr UNUSED)
{
    fprintf (fp, "no object history tracing available\n");
}

#else
#include <errno.h>
#include <unistd.h>

static pid_t selfpid;

static unsigned objhist_hash (const void *ptr, unsigned nbits)
{
    uint32_t k = (uint32_t) ((uintptr_t) ptr);
    const uint64_t c = ((uint64_t) 16292676 * 1000000 + 669999) * 1000000 + 574021;
    return (unsigned) ((k * c) >> (64 - nbits));
}

#if defined __APPLE__ || defined __linux
static void dump_memory_map_sysdep (int fd)
{
    char str[256];
    pid_t pid;
    const char *argv[3];
    int argi = 0;

    /* Fork/exec/wait command, pmap and vmmap take the process id as
     * argument.  We start as normal in case of errors, but do report
     * them as warnings.  Note that we exec with a very dirty
     * environment, but that's ok - vmmap and pmap are
     * well-behaved.
     */
#if defined __linux
    snprintf (str, sizeof (str), "/proc/%d/maps", (int) getpid ());
    argv[argi++] = "/bin/cat";
    argv[argi++] = str;
#elif defined __APPLE__
    snprintf (str, sizeof (str), "%d", (int) getpid ());
    argv[argi++] = "/usr/bin/vmmap";
    argv[argi++] = str;
#else
#error
#endif
    argv[argi++] = NULL;
    MM_ASSERT (argi <= (int) (sizeof (argv) / sizeof (*argv)));

    if ((pid = fork ()) < 0) {
        fprintf (stderr, "allocator: fork error %s\n", strerror (errno));
    } else if (pid == 0) {
        (void)dup2 (fd, 1);
        execv (argv[0], (char **) argv);
        _exit (127);
    } else {
        int ret, stat;
        while ((ret = waitpid(pid, &stat, 0)) == -1 && errno == EINTR) {
            ;
        }
        if (ret < 0) {
            fprintf (stderr, "allocator: waitpid error %s\n", strerror (errno));
        } else if (!WIFEXITED (stat) || WEXITSTATUS (stat) != 0) {
            fprintf (stderr, "allocator: child exited abnormally (%x)\n", stat);
        }
    }
}
#elif defined __sun
static void dump_memory_map_sysdep (int fd)
{
    int fdmap;
    prmap_t mapping;
    if ((fdmap = open ("/proc/self/map", O_RDONLY)) < 0) {
        fprintf (stderr, "allocator: can't open memory map /proc/self/map\n");
        return;
    }
    /* Note that theoretically, perhaps read could return a partial
     * entry (or return -1 with errno = EINTR), in which case the map
     * would be truncated.  We'll deal with that if it turns out to be
     * necessary.
     */
    while (read (fdmap, &mapping, sizeof (mapping)) == sizeof (mapping)) {
        char str[256 + PATH_MAX], objname[PATH_MAX+1];
        int n;
        /* Output format follows Linux: START-ENDP1 [r-][w-][x-][p-]
         * OFFSET MAJOR:MINOR INODE FILE, but since we don't care
         * about the device and inode, we just print 0.  (If at any
         * point in time we do need it, should be reading prxmap
         * instead.)
         */
        if (mapping.pr_mapname[0] == 0) {
            strcpy (objname, "(anon)");
        } else if (snprintf (str, sizeof (str), "/proc/self/path/%s", mapping.pr_mapname) >= sizeof (str)) {
            snprintf (objname, sizeof (objname), "toolong %s", mapping.pr_mapname);
        } else if ((n = readlink (str, objname, sizeof (objname) - 1)) == -1) {
            snprintf (objname, sizeof (objname), "errno=%d %s", os_getErrno (), str);
        } else {
            objname[n] = 0;
        }
        n = snprintf (str, sizeof (str), "%"PRIxPTR"-%"PRIxPTR" %c%c%c%c %"PRIxPTR" 0:0 0 %s\n",
                      mapping.pr_vaddr, mapping.pr_vaddr + mapping.pr_size,
                      (mapping.pr_mflags & MA_READ) ? 'r' : '-',
                      (mapping.pr_mflags & MA_WRITE) ? 'w' : '-',
                      (mapping.pr_mflags & MA_EXEC) ? 'x' : '-',
                      (mapping.pr_mflags & MA_SHARED) ? '-' : 'p',
                      (uintptr_t) mapping.pr_offset,
                      objname);
        if (write (fd, str, n) != n) {
            /* Similar reasoning as with reading mappings */
            break;
        }
    }
    (void) close (fdmap);
}
#endif

static void dump_memory_map (struct c_mm_s *mm)
{
    char str[256];
    int fd, n;

    /* Write to file MAPPATH/ospl-map.PID (/tmp is default) */
    {
        char *mappath = config_mappath ();
        n = snprintf (str, sizeof (str), "%s/ospl-map.%d", mappath ? mappath : "/tmp", (int) getpid ());
        free (mappath);
        if (n >= (int) sizeof (str)) {
            fprintf (stderr, "allocator: configured map file path too long, no memory map written\n");
            return;
        }
    }

    if ((fd = open (str, O_WRONLY | O_CREAT | O_TRUNC, 0644)) < 0) {
        fprintf (stderr, "allocator: can't write memory map to %s\n", str);
        return;
    }

    /* First line is always MM=<address of memory manager object>.  If
     * the write fails, just continue, we don't really care.  */
    n = snprintf (str, sizeof (str), "MM=%p\n", (void *) mm);
    assert (n > 0);

    if (write (fd, str, (size_t) n) < 0) {
        fprintf (stderr, "allocator: can't write memory map to %s (%d)\n", str, errno);
        (void) close(fd);
        return;
    }
    dump_memory_map_sysdep (fd);

    /* All major Unixes (HP-UX is the odd one out) close the file when
     * an error occurs.  EINTR is the most intriguing possibility, as
     * on the vast majority of platforms it results in a fd not being
     * an open file descriptor upon return, regardless of the return
     * code, but there are platforms on which it is left open.
     * Properly handling this in multi-threaded code is impossible
     * without knowing which choice has been made.  Since this is such
     * an odd case, and this being debug-support code at that, we
     * might as well ignore the return code.
     */
    (void) close (fd);
}

#ifdef __sun
struct backtrace_emu_walker_arg {
    int idx;
    int size;
    void **array;
};

static int backtrace_emu_walker (uintptr_t pc, int sig, void *varg)
{
    struct backtrace_emu_walker_arg *arg = varg;
    OS_UNUSED_ARG (sig);
    assert (arg->idx < arg->size);
    arg->array[arg->idx++] = (void *) pc;
    return (arg->idx == arg->size);
}

static int backtrace_emu (void **array, int size)
{
    struct backtrace_emu_walker_arg arg;
    ucontext_t uctx;
    assert (size > 0);
    if (getcontext (&uctx) != 0) {
        return 0;
    }
    arg.idx = 0;
    arg.size = size;
    arg.array = array;
    (void) walkcontext (&uctx, &backtrace_emu_walker, &arg);
    return arg.idx;
}
#else
static int backtrace_emu (void **array, int size)
{
    return backtrace (array, size);
}
#endif

static int objhist_admin_init (struct c_mm_s *mm, struct objhist_admin *fs)
{
    const unsigned nlocks = sizeof (fs->lock) / sizeof (fs->lock[0]);
    unsigned i;

    selfpid = getpid ();

    if (!(mm->debug & DBG_OBJHIST)) {
        return 0;
    }

    for (i = 0; i < nlocks; i++) {
        ddsrt_mutex_init (&fs->lock[i]);
    }
    ddsrt_atomic_st32 (&fs->nobjects, 0);
    fs->hashsize_lg2 = OBJHIST_LEVEL2_BITS + 1;
    fs->hashsize = 1u << fs->hashsize_lg2;
    if ((fs->hash = mm_malloc_arbobj_growable_heap (mm, (fs->hashsize / OBJHIST_LEVEL2_SIZE) * sizeof (*fs->hash), 0)) == NULL) {
        for (i = 0; i < nlocks; i++) {
            ddsrt_mutex_destroy (&fs->lock[i]);
        }
        return -1;
    }
    for (i = 0; i < fs->hashsize / OBJHIST_LEVEL2_SIZE; i++) {
        fs->hash[i] = NULL;
    }

    /* Dump the memory map to disk */
    dump_memory_map (mm);
    return 0;
}

static void objhist_admin_init_client (struct c_mm_s *mm, struct objhist_admin *fs)
{
    (void)fs;
    selfpid = getpid ();
    if (mm->debug & DBG_OBJHIST) {
        dump_memory_map (mm);
    }
}

static void free_objhists (struct c_mm_s *mm, struct objhist *head)
{
    struct objhist *t;
    while ((t = head) != NULL) {
        head = head->older_hist;
        allocator_free (mm, &mm->objhist_allocator, t);
    }
}

static void objhist_admin_fini (struct c_mm_s *mm, struct objhist_admin *fs)
{
    if (mm->debug & DBG_OBJHIST) {
        const unsigned nlocks = sizeof (fs->lock) / sizeof (fs->lock[0]);
        unsigned i, j;
        for (i = 0; i < fs->hashsize / OBJHIST_LEVEL2_SIZE; i++) {
            if (fs->hash[i]) {
                for (j = 0; j < OBJHIST_LEVEL2_SIZE; j++) {
                    while (fs->hash[i][j]) {
                        struct objhist *stk = fs->hash[i][j];
                        fs->hash[i][j] = stk->next_hash;
                        free_objhists (mm, stk);
                    }
                }
                allocator_free (mm, &mm->objhist_hash_allocator, fs->hash[i]);
            }
        }
        c_mmheapFree (&mm->mmheap, fs->hash);
        for (i = 0; i < nlocks; i++) {
            ddsrt_mutex_destroy (&fs->lock[i]);
        }
    }
}

static struct objhist *objhist_lookup (struct objhist ***ppptr, const struct objhist_admin *fs, const void *ptr, unsigned bucket)
{
    /* Returns most recent object in the history, but you can always
     * walk the list (what about locking)?
     */
    const unsigned a = bucket / OBJHIST_LEVEL2_SIZE;
    const unsigned b = bucket % OBJHIST_LEVEL2_SIZE;
    const struct objhist *stk;
    struct objhist * const *pptr;
    if (fs->hash[a] == NULL) {
        return NULL;
    }
    pptr = (struct objhist * const *) &fs->hash[a][b];
    for (stk = *pptr; stk; pptr = &stk->next_hash, stk = stk->next_hash) {
        if (stk->object == ptr) {
            *ppptr = (struct objhist **) pptr;
            return (struct objhist *) stk;
        }
    }
    return NULL;
}

static int objhist_insert1 (struct objhist **mustfree, struct c_mm_s *mm, struct objhist ***tl, struct objhist *stk, unsigned bucket)
{
    const unsigned a = bucket / OBJHIST_LEVEL2_SIZE;
    const unsigned b = bucket % OBJHIST_LEVEL2_SIZE;
    struct objhist **pstk1, *stk1;
    int is_new_object;
    int i;

    /* create level-2 hash table if it doesn't exist */
    if (tl[a] == NULL) {
        struct objhist **bl;
        if ((bl = allocator_malloc (mm, &mm->objhist_hash_allocator, 0)) == NULL) {
            ospl_allocator_error (NULL, NULL, C_MMTRACKOBJECT_CODE_MALLOC, "objhist_insert1: out of memory\n");
        }
        for (i = 0; i < OBJHIST_LEVEL2_SIZE; i++) {
            bl[i] = NULL;
        }
        /* FIXME: work on the types a bit - for now, we restrict ourselves to cases where pa_voidp_t <=> void * */
        if (!ddsrt_atomic_casvoidp ((ddsrt_atomic_voidp_t *) &tl[a], NULL, bl)) {
            c_mmFree (mm, bl);
        }
    }

    /* pull out previous stack for object and chain it behind this one, if any */
    is_new_object = 1;
    for (pstk1 = &tl[a][b], stk1 = tl[a][b]; stk1; pstk1 = &stk1->next_hash, stk1 = stk1->next_hash) {
        if (stk1->object == stk->object) {
            *pstk1 = stk1->next_hash;
            stk->older_hist = stk1;
            is_new_object = 0;
            break;
        }
    }

    /* stk becomes new head of hash chain */
    stk->next_hash = tl[a][b];
    tl[a][b] = stk;

    /* purge some history - FIXME: wouldn't you want to distinguish
     * between malloc, free and the rest; and keep at least malloc and
     * free, rather than just keeping the last N stacks?
     */
    if (mustfree) {
        const int maxdepth = mm->max_objhist_depth;
        for (i = 1, stk1 = stk; stk1 && i < maxdepth; i++, stk1 = stk1->older_hist)
            ;
        if (stk1 && stk1->older_hist) {
            *mustfree = stk1->older_hist;
            stk1->older_hist = NULL;
        } else {
            *mustfree = NULL;
        }
    }

    return is_new_object;
}

static void objhist_maybe_growhash (struct c_mm_s *mm, struct objhist_admin *fs)
{
    const unsigned nlocks = sizeof (fs->lock) / sizeof (fs->lock[0]);
    unsigned i;
    for (i = 0; i < nlocks; i++) {
        ddsrt_mutex_lock (&fs->lock[i]);
    }
    if (ddsrt_atomic_ld32 (&fs->nobjects) >= 3 * fs->hashsize / 4) {
        unsigned newsize_lg2, newsize, newtlsize;
        struct objhist ***newtl;
        unsigned j;
        newsize_lg2 = fs->hashsize_lg2 + 1;
        newsize = 1u << newsize_lg2;
        newtlsize = newsize / OBJHIST_LEVEL2_SIZE;
        if ((newtl = mm_malloc_arbobj_growable_heap (mm, newtlsize * sizeof (*newtl), 0)) == NULL) {
            ospl_allocator_error (NULL, NULL, C_MMTRACKOBJECT_CODE_MALLOC, "objhist_growhash: out of memory\n");
        }
        for (i = 0; i < newtlsize; i++) {
            newtl[i] = NULL;
        }
        for (i = 0; i < fs->hashsize / OBJHIST_LEVEL2_SIZE; i++) {
            if (fs->hash[i]) {
                for (j = 0; j < OBJHIST_LEVEL2_SIZE; j++) {
                    struct objhist *stk = fs->hash[i][j];
                    while (stk) {
                        struct objhist *stk1 = stk;
                        unsigned newbucket;
                        stk = stk->next_hash;
                        newbucket = objhist_hash (stk1->object, newsize_lg2);
                        (void) objhist_insert1 (NULL, mm, newtl, stk1, newbucket);
                    };
                }
                allocator_free (mm, &mm->objhist_hash_allocator, fs->hash[i]);
            }
        }
        c_mmheapFree (&mm->mmheap, fs->hash);
        fs->hash = newtl;
        fs->hashsize_lg2 = newsize_lg2;
        fs->hashsize = 1u << fs->hashsize_lg2;
    }
    for (i = 0; i < nlocks; i++) {
        ddsrt_mutex_unlock (&fs->lock[i]);
    }
}

static unsigned lock_bucket (struct objhist_admin *fs, const void *ptr)
{
    /* Most of the time, the hash size won't change and the bucket &
     * lock computed and claimed are fine.  However, if the hash does
     * get resized after computing the bucket and claiming the
     * corresponding lock, we may have the wrong lock & the wrong
     * bucket.  So, instead, we optimistically attempt it (while
     * reading the hash size atomically but without holding any lock),
     * then keep trying until we have a consistent readout.
     */
    const unsigned nlocks = sizeof (fs->lock) / sizeof (fs->lock[0]);
    unsigned bucket;
    uint32_t a, b;
    a = *((volatile uint32_t *) &fs->hashsize_lg2);
    bucket = objhist_hash (ptr, a);
    ddsrt_mutex_lock (&fs->lock[bucket % nlocks]);
    while ((b = *((volatile uint32_t *) &fs->hashsize_lg2)) != a) {
        a = b;
        ddsrt_mutex_unlock (&fs->lock[bucket % nlocks]);
        bucket = objhist_hash (ptr, a);
        ddsrt_mutex_lock (&fs->lock[bucket % nlocks]);
    }
    return bucket;
}

static void unlock_bucket (struct objhist_admin *fs, unsigned bucket)
{
    const unsigned nlocks = sizeof (fs->lock) / sizeof (fs->lock[0]);
    ddsrt_mutex_unlock (&fs->lock[bucket % nlocks]);
}

static void objhist_init_stack (struct objhist *stk, our_tid_t tid, const void *ptr, uint32_t code)
{
    stk->object = (void *) ptr;
    stk->older_hist = NULL;
    stk->code = code;
    stk->pid = selfpid;
    stk->tid = tid;
    stk->depth = backtrace_emu (stk->stack, (int) (sizeof (stk->stack) / sizeof (*stk->stack)));
}

static void objhist_insert (struct c_mm_s *mm, const struct mm_tsd *tsd, const void *ptr, uint32_t code)
{
    struct objhist *stk;
    if ((stk = allocator_malloc (mm, &mm->objhist_allocator, 0)) != NULL) {
        struct objhist_admin *fs = &mm->objhist_admin;
        struct objhist *mustfree;
        unsigned bucket;
        int grow;
        objhist_init_stack (stk, tsd->tid, ptr, code);

        bucket = lock_bucket (fs, ptr);
        if (objhist_insert1 (&mustfree, mm, fs->hash, stk, bucket)) {
            unsigned nobjects = ddsrt_atomic_inc32_nv (&fs->nobjects);
            grow = (nobjects >= 3 * fs->hashsize / 4);
        } else {
            grow = 0;
        }
        unlock_bucket (fs, bucket);

        if (mustfree) {
            free_objhists (mm, mustfree);
        }
        if (grow) {
            objhist_maybe_growhash (mm, fs);
        }
    }
}

static void objhist_delete_if_exists (struct c_mm_s *mm, const void *ptr)
{
    struct objhist_admin *fs = &mm->objhist_admin;
    unsigned bucket;
    struct objhist **pptr, *stk;
    bucket = lock_bucket (fs, ptr);
    if ((stk = objhist_lookup (&pptr, fs, ptr, bucket)) != NULL) {
        ddsrt_atomic_dec32 (&fs->nobjects);
        *pptr = stk->next_hash;
    }
    unlock_bucket (fs, bucket);
    if (stk) {
        free_objhists (mm, stk);
    }
}

static const char *code_to_string (char *buf, size_t bufsize, uint32_t code)
{
    /* Note most used returned pointer, which may be a constant string
     * or buf.  There's no guarantee buf gets initialised.
     */
    switch (code) {
    case C_MMTRACKOBJECT_CODE_MALLOC: return "MALLOC";
    case C_MMTRACKOBJECT_CODE_FREE: return "FREE";
    }
    snprintf (buf, bufsize, "%"PRIx32, code);
    return buf;
}

static void objhist_print1 (FILE *fp, const struct objhist *stk)
{
    char buf[16];
    int i;
    fprintf (fp, "OBJECT %p pid %d tid "PRINTF_FMT_THREADID" code %s stack",
             stk->object, (int) stk->pid, PRINTF_ARGS_THREADID (stk->tid),
             code_to_string (buf, sizeof (buf), stk->code));
    for (i = 0; i < stk->depth; i++) {
        fprintf (fp, " %p", stk->stack[i]);
    }
    fprintf (fp, "\n");
#if defined __linux || defined __APPLE__
    /* It isn't hard to do emulate backtrace_symbols on Solaris, but
     * it isn't worth the effort
     */
    if (stk->pid == getpid ()) {
        char **strs;
        strs = backtrace_symbols (stk->stack, stk->depth);
        for (i = 0; i < stk->depth; ++i) {
            fprintf (fp, "  %s\n", strs[i]);
        }
        free (strs);
    }
#endif
}

static void objhist_print (FILE *fp, struct c_mm_s *mm, const void *obj)
{
    if (mm && (mm->debug & DBG_OBJHIST))
    {
        struct objhist_admin *fs = &mm->objhist_admin;
        unsigned bucket;
        struct objhist **dummy, *stk;
        bucket = lock_bucket (fs, obj);
        if ((stk = objhist_lookup (&dummy, fs, obj, bucket)) != NULL) {
            while (stk) {
                objhist_print1 (fp, stk);
                stk = stk->older_hist;
            }
        } else {
            fprintf (fp, "OBJECT %p unknown\n", obj);
        }
        unlock_bucket (fs, bucket);
    }
}

#if 0
unsigned c_mmObjhistHash (const void *ptr, unsigned nbits)
{
    return objhist_hash (ptr, nbits);
}

const struct objhist *c_mmObjhistUnlockedLookup (struct c_mm_s *mm, const void *ptr)
{
    struct objhist_admin *fs = &mm->objhist_admin;
    const unsigned bucket = objhist_hash (ptr, fs->hashsize_lg2);
    struct objhist **dummy;
    return objhist_lookup (&dummy, fs, ptr, bucket);
}
#endif

void c_mmTrackObject (struct c_mm_s *mm, const void *ptr, uint32_t code)
{
    MM_ASSERT (code >= C_MMTRACKOBJECT_CODE_MIN);
    if ((mm->debug & DBG_OBJHIST) && (char *) ptr >= (char *) mm + mm->slab_start_off) {
        objhist_insert (mm, get_mm_tsd (mm), ptr, code);
    }
}

void c_mmPrintObjectHistory (FILE *fp, struct c_mm_s * mm, void *ptr)
{
    if (!(mm->debug & DBG_OBJHIST)) {
        fprintf (fp, "object history tracing not enabled\n");
    } else {
        void *obj = NULL;
        unsigned objsize = 0;

        ddsrt_mutex_lock (&mm->lock);
        if (!mm_check_ptr_in_slab (mm, ptr)) {
            fprintf (fp, "OBJECT %p unknown (outside slab region)\n", ptr);
        } else {
            /* Inside slab region; mm->lock is held so slab_start_off
             * won't change; similarly slab->allocator is constant
             */
            struct mm_slab const * const slab = (struct mm_slab const *) ((uintptr_t) ptr & (uintptr_t)-SLAB_SIZE);
            objsize = slab->objsize;
            if (slab->allocator == NULL || slab->allocator == UNINITIALIZED_SLAB_MARKER) {
                fprintf (fp, "OBJECT %p unknown (in free slab)\n", ptr);
            } else if ((char *) ptr < (char *) slab + slab->objoffset || (char *) ptr >= (char *) slab + slab->objoffset + slab->nobjs * objsize) {
                fprintf (fp, "OBJECT %p unknown (outside object array in slab)\n", ptr);
            } else {
                unsigned objidx;
                objidx = (unsigned) ((char *) ptr - ((char *) slab + slab->objoffset)) / objsize;
                obj = ((char *) slab + slab->objoffset + objidx * objsize);
            }
        }
        ddsrt_mutex_unlock (&mm->lock);

        if (obj) {
            if (obj != ptr) {
                fprintf (fp, "address %p is %"PRIdPTR" bytes in object %p\n", ptr, (uintptr_t) ptr - (uintptr_t) obj, obj);
            }
            if (c_mmCheckPtr (mm, ptr) == NULL) {
                fprintf (fp, "object %p is free\n", obj);
            }
            fprintf (fp, "object occupies %d bytes\n", objsize);
            objhist_print (fp, mm, obj);
        }
    }
}

#endif
