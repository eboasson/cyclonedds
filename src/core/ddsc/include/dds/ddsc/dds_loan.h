/*
 * Copyright(c) 2021 ZettaScale Technology
 * Copyright(c) 2021 Apex.AI, Inc
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v. 1.0 which is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 */

// API extension
// defines functions needed for loaning and shared memory usage

#ifndef _DDS_LOAN_API_H_
#define _DDS_LOAN_API_H_

#include "dds/ddsc/dds_basic_types.h"
#include "dds/ddsrt/retcode.h"
#include "dds/ddsrt/atomics.h"
#include "dds/export.h"

#if defined(__cplusplus)
extern "C" {
#endif

/*state of the data contained in a memory block*/
typedef enum loaned_sample_state {
  LOANED_SAMPLE_STATE_UNITIALIZED,
  LOANED_SAMPLE_STATE_RAW,
  LOANED_SAMPLE_STATE_SERIALIZED_KEY,
  LOANED_SAMPLE_STATE_SERIALIZED_DATA
} loaned_sample_state_t;

/*identifier used to distinguish between raw data types (C/C++/Python/...)*/
typedef uint32_t loan_data_type_t;

/*identifier used to distinguish between types of loans (heap/iceoryx/...)*/
typedef uint32_t loan_origin_type_t;

/*forward declarations of struct, so pointer can be made*/
struct dds_loan_manager;
struct dds_loaned_sample;
struct dds_virtual_interface_metadata;
struct ddsi_virtual_interface_pipe;

/*implementation specific loaned sample cleanup function*/
typedef bool (*dds_loaned_sample_fini_f)(
  struct dds_loaned_sample *to_fini);

/*implementation specific loaned sample reference increment function*/
typedef bool (*dds_loaned_sample_incr_refs_f)(
  struct dds_loaned_sample *to_incr);

/*implementation specific loaned sample reference decrement function*/
typedef bool (*dds_loaned_sample_decr_refs_f)(
  struct dds_loaned_sample *to_decr);

/*implementation specific loaned sample contents reset function*/
typedef bool (*dds_loaned_sample_reset_f)(
  struct dds_loaned_sample *to_reset);

/*container for implementation specific operations*/
typedef struct dds_loaned_sample_ops {
  dds_loaned_sample_fini_f            fini;
  dds_loaned_sample_incr_refs_f       incr;
  dds_loaned_sample_decr_refs_f       decr;
  dds_loaned_sample_reset_f           reset;
} dds_loaned_sample_ops_t;

/* the definition of a block of memory originating
* from a virtual interface
*/
typedef struct dds_loaned_sample {
  dds_loaned_sample_ops_t ops; /*the implementation specific ops for this sample*/
  struct ddsi_virtual_interface_pipe *loan_origin; /*the origin of the loan*/
  struct dds_loan_manager *manager; /*the associated manager*/
  struct dds_virtual_interface_metadata * metadata; /*pointer to the associated metadata*/
  void * sample_ptr; /*pointer to the loaned sample*/
  uint32_t loan_idx; /*the storage index of the loan*/
  ddsrt_atomic_uint32_t refs; /*the number of references to this loan*/
} dds_loaned_sample_t;

/* generic loaned sample cleanup function will be called
   when the loaned sample runs out of refs or is retracted,
   calls the implementation specific functions */
bool dds_loaned_sample_fini(
  dds_loaned_sample_t *to_fini);

/* generic function which increases the references for this sample,
   calls the implementation specific functions*/
bool dds_loaned_sample_incr_refs(
  dds_loaned_sample_t *to_incr);

/* generic function which decreases the references for this sample,
   calls the implementation specific functions*/
bool dds_loaned_sample_decr_refs(
  dds_loaned_sample_t *to_decr);

/* generic function which resets the contents for this sample
   calls the implementation specific functions*/
bool dds_loaned_sample_reset_sample(
  dds_loaned_sample_t *to_reset);

/*an implementation specific loan manager*/
typedef struct dds_loan_manager {
  //map better?
  dds_loaned_sample_t **samples;
  uint32_t n_samples_cap;
  uint32_t n_samples_managed;
  //mutex?
} dds_loan_manager_t;

/*loan manager create function*/
dds_loan_manager_t *dds_loan_manager_create(
  uint32_t initial_cap);

/** loan manager fini function ensures that the containers are
  * cleaned up and all loans are returned*/
bool dds_loan_manager_fini(
  dds_loan_manager_t *to_fini);

/** add a loan to be stored by this manager */
bool dds_loan_manager_add_loan(
  dds_loan_manager_t *manager,
  dds_loaned_sample_t *to_add);

/** removes a loan from storage by this manager */
bool dds_loan_manager_remove_loan(
  dds_loaned_sample_t *to_remove);

/** moves a loan from storage to another */
bool dds_loan_manager_move_loan(
  dds_loan_manager_t *manager,
  dds_loaned_sample_t *to_move);

/** finds a whether a sample corresponds to a loan on this manager */
dds_loaned_sample_t *dds_loan_manager_find_loan(
  const dds_loan_manager_t *manager,
  const void *sample);

/** gets the first managed loan from this manager */
dds_loaned_sample_t *dds_loan_manager_get_loan(
  dds_loan_manager_t *manager);

#if defined(__cplusplus)
}
#endif
#endif
