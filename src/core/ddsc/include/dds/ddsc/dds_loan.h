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

#ifndef _DDS_LOAN_H_
#define _DDS_LOAN_H_

#include "dds/ddsc/dds_basic_types.h"
#include "dds/ddsrt/retcode.h"
#include "dds/ddsrt/atomics.h"
#include "dds/export.h"

#if defined(__cplusplus)
extern "C" {
#endif

/*state of the data contained in a memory block*/
typedef enum dds_loaned_sample_state {
  DDS_LOANED_SAMPLE_STATE_UNITIALIZED,
  DDS_LOANED_SAMPLE_STATE_RAW,
  DDS_LOANED_SAMPLE_STATE_SERIALIZED_KEY,
  DDS_LOANED_SAMPLE_STATE_SERIALIZED_DATA
} dds_loaned_sample_state_t;

/*identifier used to distinguish between raw data types (C/C++/Python/...)*/
typedef uint32_t dds_loan_data_type_t;

/*identifier used to distinguish between types of loans (heap/iceoryx/...)*/
typedef uint32_t dds_loan_origin_type_t;

/*forward declarations of struct, so pointer can be made*/
struct dds_loan_manager;
struct dds_loaned_sample;
struct dds_virtual_interface_metadata;
struct ddsi_virtual_interface_pipe;

/*implementation specific loaned sample cleanup function*/
typedef void (*dds_loaned_sample_free_f)(
  struct dds_loaned_sample *loaned_sample);

/*implementation specific loaned sample reference increment function*/
typedef dds_return_t (*dds_loaned_sample_ref_f)(
  struct dds_loaned_sample *loaned_sample);

/*implementation specific loaned sample reference decrement function*/
typedef dds_return_t (*dds_loaned_sample_unref_f)(
  struct dds_loaned_sample *loaned_sample);

/*implementation specific loaned sample contents reset function*/
typedef void (*dds_loaned_sample_reset_f)(
  struct dds_loaned_sample *loaned_sample);

/*container for implementation specific operations*/
typedef struct dds_loaned_sample_ops {
  dds_loaned_sample_free_f    free;
  dds_loaned_sample_ref_f     ref;
  dds_loaned_sample_unref_f   unref;
  dds_loaned_sample_reset_f   reset;
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
dds_return_t dds_loaned_sample_free(
  dds_loaned_sample_t *loaned_sample);

/* generic function which increases the references for this sample,
   calls the implementation specific functions*/
dds_return_t dds_loaned_sample_ref(
  dds_loaned_sample_t *loaned_sample);

/* generic function which decreases the references for this sample,
   calls the implementation specific functions*/
dds_return_t dds_loaned_sample_unref(
  dds_loaned_sample_t *loaned_sample);

/* generic function which resets the contents for this sample
   calls the implementation specific functions*/
dds_return_t dds_loaned_sample_reset_sample(
  dds_loaned_sample_t *loaned_sample);

/*an implementation specific loan manager*/
typedef struct dds_loan_manager {
  //map better?
  dds_loaned_sample_t **samples;
  uint32_t n_samples_cap;
  uint32_t n_samples_managed;
  //mutex?
} dds_loan_manager_t;

/*loan manager create function*/
dds_return_t dds_loan_manager_create(
  dds_loan_manager_t **manager,
  uint32_t initial_cap);

/** loan manager fini function ensures that the containers are
  * cleaned up and all loans are returned*/
dds_return_t dds_loan_manager_free(
  dds_loan_manager_t *manager);

/** add a loan to be stored by this manager */
dds_return_t dds_loan_manager_add_loan(
  dds_loan_manager_t *manager,
  dds_loaned_sample_t *loaned_sample);

/** removes a loan from storage by this manager */
dds_return_t dds_loan_manager_remove_loan(
  dds_loaned_sample_t *loaned_sample);

/** moves a loan from storage to another */
dds_return_t dds_loan_manager_move_loan(
  dds_loan_manager_t *manager,
  dds_loaned_sample_t *loaned_sample);

/** finds a whether a sample corresponds to a loan on this manager */
dds_loaned_sample_t *dds_loan_manager_find_loan(
  const dds_loan_manager_t *manager,
  const void *loaned_sample);

/** gets the first managed loan from this manager */
dds_loaned_sample_t *dds_loan_manager_get_loan(
  dds_loan_manager_t *manager);

#if defined(__cplusplus)
}
#endif
#endif /* _DDS_LOAN_H_ */
