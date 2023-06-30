// Copyright(c) 2006 to 2021 ZettaScale Technology and others
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License v. 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
// v. 1.0 which is available at
// http://www.eclipse.org/org/documents/edl-v10.php.
//
// SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

#include <assert.h>
#include <string.h>
#include "dds__entity.h"
#include "dds__reader.h"
#include "dds__read.h"
#include "dds/ddsi/ddsi_tkmap.h"
#include "dds/ddsc/dds_rhc.h"
#include "dds/ddsi/ddsi_thread.h"
#include "dds/ddsi/ddsi_entity_index.h"
#include "dds/ddsi/ddsi_entity.h"
#include "dds/ddsi/ddsi_domaingv.h"
#include "dds/ddsi/ddsi_serdata.h"

#include "dds/ddsc/dds_loan_api.h"

void dds_read_collect_sample_arg_init (struct dds_read_collect_sample_arg *arg, void **ptrs, dds_sample_info_t *infos)
{
  arg->first_of_inst_idx = 0;
  arg->next_idx = 0;
  arg->last_iid = 0;
  arg->ptrs = ptrs;
  arg->infos = infos;
}

static void dds_read_patch_generations (dds_sample_info_t *si, uint32_t last_of_inst)
{
  const uint32_t ref = si[last_of_inst].disposed_generation_count + si[last_of_inst].no_writers_generation_count;
  assert (si[last_of_inst].sample_rank == 0);
  assert (si[last_of_inst].generation_rank == 0);
  for (uint32_t i = 0; i < last_of_inst; i++)
  {
    si[i].sample_rank = last_of_inst - i;
    si[i].generation_rank = ref - (si[i].disposed_generation_count + si[i].no_writers_generation_count);
  }
}

void dds_read_check_and_handle_instance_switch (struct dds_read_collect_sample_arg * const arg, dds_instance_handle_t iid)
{
  if (iid != arg->last_iid)
  {
    if (arg->next_idx > arg->first_of_inst_idx + 1)
      dds_read_patch_generations (arg->infos + arg->first_of_inst_idx, arg->next_idx - arg->first_of_inst_idx - 1);
    arg->first_of_inst_idx = arg->next_idx;
    arg->last_iid = iid;
  }
}

dds_return_t dds_read_collect_sample (void *varg, const dds_sample_info_t *si, const struct ddsi_sertype *st, struct ddsi_serdata *sd)
{
  struct dds_read_collect_sample_arg * const arg = varg;
  bool ok;
  dds_read_check_and_handle_instance_switch (arg, si->instance_handle);
  arg->infos[arg->next_idx] = *si;
  if (si->valid_data)
    ok = ddsi_serdata_to_sample (sd, arg->ptrs[arg->next_idx], NULL, NULL);
  else
  {
    /* ddsi_serdata_untyped_to_sample just deals with the key value, without paying any attention to attributes;
       but that makes life harder for the user: the attributes of an invalid sample would be garbage, but would
       nonetheless have to be freed in the end.  Zero'ing it explicitly solves that problem. */
    ddsi_sertype_free_sample (st, arg->ptrs[arg->next_idx], DDS_FREE_CONTENTS);
    ddsi_sertype_zero_sample (st, arg->ptrs[arg->next_idx]);
    ok = ddsi_serdata_untyped_to_sample (st, sd, arg->ptrs[arg->next_idx], NULL, NULL);
  }
  arg->next_idx++;
  return ok ? DDS_RETCODE_OK : DDS_RETCODE_ERROR;
}

dds_return_t dds_read_collect_sample_refs (void *varg, const dds_sample_info_t *si, const struct ddsi_sertype *st, struct ddsi_serdata *sd)
{
  (void) st;
  struct dds_read_collect_sample_arg * const arg = varg;
  dds_read_check_and_handle_instance_switch (arg, si->instance_handle);
  arg->infos[arg->next_idx] = *si;
  arg->ptrs[arg->next_idx] = ddsi_serdata_ref (sd);
  arg->next_idx++;
  return DDS_RETCODE_OK;
}

static dds_return_t dds_read_impl_setup (dds_entity_t reader_or_condition, bool only_reader, struct dds_entity **pentity, struct dds_reader **prd, struct dds_readcond **pcond, uint32_t *mask)
{
  dds_return_t ret;
  if ((ret = dds_entity_pin (reader_or_condition, pentity)) < 0) {
    return ret;
  } else if (dds_entity_kind (*pentity) == DDS_KIND_READER) {
    *prd = (dds_reader *) *pentity;
    *pcond = NULL;
  } else if (only_reader) {
    dds_entity_unpin (*pentity);
    return DDS_RETCODE_ILLEGAL_OPERATION;
  } else if (dds_entity_kind (*pentity) != DDS_KIND_COND_READ && dds_entity_kind (*pentity) != DDS_KIND_COND_QUERY) {
    dds_entity_unpin (*pentity);
    return DDS_RETCODE_ILLEGAL_OPERATION;
  } else {
    *prd = (dds_reader *) (*pentity)->m_parent;
    *pcond = (dds_readcond *) *pentity;
    if (*mask == 0)
      *mask = DDS_RHC_NO_STATE_MASK_SET;
  }
  return DDS_RETCODE_OK;
}

static dds_return_t dds_read_impl_common (bool take, struct dds_reader *rd, struct dds_readcond *cond, uint32_t maxs, uint32_t mask, dds_instance_handle_t hand, dds_read_with_collector_fn_t collect_sample, void *collect_sample_arg)
{
  /* read/take resets data available status -- must reset before reading because
     the actual writing is protected by RHC lock, not by rd->m_entity.m_lock */
  const uint32_t sm_old = dds_entity_status_reset_ov (&rd->m_entity, DDS_DATA_AVAILABLE_STATUS);
  /* reset DATA_ON_READERS status on subscriber after successful read/take if materialized */
  if (sm_old & (DDS_DATA_ON_READERS_STATUS << SAM_ENABLED_SHIFT))
    dds_entity_status_reset (rd->m_entity.m_parent, DDS_DATA_ON_READERS_STATUS);

  dds_return_t ret;
  assert (maxs <= INT32_MAX);
  if (take)
    ret = dds_rhc_take (rd->m_rhc, (int32_t) maxs, mask, hand, cond, collect_sample, collect_sample_arg);
  else
    ret = dds_rhc_read (rd->m_rhc, (int32_t) maxs, mask, hand, cond, collect_sample, collect_sample_arg);
  return ret;
}

static dds_return_t dds_read_with_collector_impl (bool take, dds_entity_t reader_or_condition, uint32_t maxs, uint32_t mask, dds_instance_handle_t hand, bool only_reader, dds_read_with_collector_fn_t collect_sample, void *collect_sample_arg)
{
  dds_return_t ret;
  struct dds_entity *entity;
  struct dds_reader *rd;
  struct dds_readcond *cond;

  if (collect_sample == 0 || maxs == 0 || maxs > INT32_MAX)
    return DDS_RETCODE_BAD_PARAMETER;

  if ((ret = dds_read_impl_setup (reader_or_condition, only_reader, &entity, &rd, &cond, &mask)) < 0)
    return ret;

  struct ddsi_thread_state * const thrst = ddsi_lookup_thread_state ();
  ddsi_thread_state_awake (thrst, &entity->m_domain->gv);
  ret = dds_read_impl_common (take, rd, cond, maxs, mask, hand, collect_sample, collect_sample_arg);
  ddsi_thread_state_asleep (thrst);
  dds_entity_unpin (entity);
  return ret;
}

static dds_return_t dds_readcdr_impl (bool take, dds_entity_t reader_or_condition, struct ddsi_serdata **buf, uint32_t maxs, dds_sample_info_t *si, uint32_t mask, dds_instance_handle_t hand)
{
  if (buf == NULL || si == NULL)
    return DDS_RETCODE_BAD_PARAMETER;
  struct dds_read_collect_sample_arg collect_arg;
  DDSRT_STATIC_ASSERT (sizeof (struct ddsi_serdata *) == sizeof (void *));
  dds_read_collect_sample_arg_init (&collect_arg, (void **) buf, si);
  const dds_return_t ret = dds_read_with_collector_impl (take, reader_or_condition, maxs, mask, hand, true, dds_read_collect_sample_refs, &collect_arg);
  dds_read_check_and_handle_instance_switch (&collect_arg, 0);
  return ret;
}

/*
  dds_read_impl: Core read/take function. Usually maxs is size of buf and si
  into which samples/status are written, when set to zero is special case
  indicating that size set from number of samples in cache and also that cache
  has been locked. This is used to support C++ API reading length unlimited
  which is interpreted as "all relevant samples in cache".
*/
static dds_return_t dds_read_impl (bool take, dds_entity_t reader_or_condition, void **buf, size_t bufsz, uint32_t maxs, dds_sample_info_t *si, uint32_t mask, dds_instance_handle_t hand, bool only_reader)
{
  dds_return_t ret = DDS_RETCODE_OK;
  struct dds_entity *entity;
  struct dds_reader *rd;
  struct dds_readcond *cond;
  unsigned nodata_cleanups = 0;
#define NC_CLEAR_LOAN_OUT 1u
#define NC_FREE_BUF 2u
#define NC_RESET_BUF 4u

  if (buf == NULL || si == NULL || maxs == 0 || bufsz == 0 || bufsz < maxs || maxs > INT32_MAX)
    return DDS_RETCODE_BAD_PARAMETER;

  if ((ret = dds_read_impl_setup (reader_or_condition, only_reader, &entity, &rd, &cond, &mask)) < 0)
    return ret;

  struct ddsi_thread_state * const thrst = ddsi_lookup_thread_state ();
  ddsi_thread_state_awake (thrst, &entity->m_domain->gv);

  /* Allocate samples if not provided (assuming all or none provided) */
  if (buf[0] == NULL)
  {
    /* Allocate, use or reallocate loan cached on reader */
    ddsrt_mutex_lock (&rd->m_entity.m_mutex);
    if (rd->m_loan_out)
    {
      ddsi_sertype_realloc_samples (buf, rd->m_topic->m_stype, NULL, 0, maxs);
      nodata_cleanups = NC_FREE_BUF | NC_RESET_BUF;
    }
    else
    {
      if (rd->m_loan)
      {
        if (rd->m_loan_size >= maxs)
        {
          /* This ensures buf is properly initialized */
          ddsi_sertype_realloc_samples (buf, rd->m_topic->m_stype, rd->m_loan, rd->m_loan_size, rd->m_loan_size);
        }
        else
        {
          ddsi_sertype_realloc_samples (buf, rd->m_topic->m_stype, rd->m_loan, rd->m_loan_size, maxs);
          rd->m_loan_size = maxs;
        }
      }
      else
      {
        ddsi_sertype_realloc_samples (buf, rd->m_topic->m_stype, NULL, 0, maxs);
        rd->m_loan_size = maxs;
      }
      rd->m_loan = buf[0];
      rd->m_loan_out = true;
      nodata_cleanups = NC_RESET_BUF | NC_CLEAR_LOAN_OUT;
    }
    ddsrt_mutex_unlock (&rd->m_entity.m_mutex);
  }

  struct dds_read_collect_sample_arg collect_arg;
  dds_read_collect_sample_arg_init (&collect_arg, buf, si);
  ret = dds_read_impl_common (take, rd, cond, maxs, mask, hand, dds_read_collect_sample, &collect_arg);
  dds_read_check_and_handle_instance_switch (&collect_arg, 0);

  /* if no data read, restore the state to what it was before the call, with the sole
     exception of holding on to a buffer we just allocated and that is pointed to by
     rd->m_loan */
  if (ret <= 0 && nodata_cleanups)
  {
    ddsrt_mutex_lock (&rd->m_entity.m_mutex);
    if (nodata_cleanups & NC_CLEAR_LOAN_OUT)
      rd->m_loan_out = false;
    if (nodata_cleanups & NC_FREE_BUF)
      ddsi_sertype_free_samples (rd->m_topic->m_stype, buf, maxs, DDS_FREE_ALL);
    if (nodata_cleanups & NC_RESET_BUF)
      buf[0] = NULL;
    ddsrt_mutex_unlock (&rd->m_entity.m_mutex);
  }
  ddsi_thread_state_asleep (thrst);
  dds_entity_unpin (entity);
  return ret;
#undef NC_CLEAR_LOAN_OUT
#undef NC_FREE_BUF
#undef NC_RESET_BUF
}

dds_return_t dds_read (dds_entity_t rd_or_cnd, void **buf, dds_sample_info_t *si, size_t bufsz, uint32_t maxs)
{
  return dds_read_impl (false, rd_or_cnd, buf, bufsz, maxs, si, 0, DDS_HANDLE_NIL, false);
}

dds_return_t dds_read_wl (dds_entity_t rd_or_cnd, void **buf, dds_sample_info_t *si, uint32_t maxs)
{
  return dds_read_impl (false, rd_or_cnd, buf, maxs, maxs, si, 0, DDS_HANDLE_NIL, false);
}

dds_return_t dds_read_mask (dds_entity_t rd_or_cnd, void **buf, dds_sample_info_t *si, size_t bufsz, uint32_t maxs, uint32_t mask)
{
  return dds_read_impl (false, rd_or_cnd, buf, bufsz, maxs, si, mask, DDS_HANDLE_NIL, false);
}

dds_return_t dds_read_mask_wl (dds_entity_t rd_or_cnd, void **buf, dds_sample_info_t *si, uint32_t maxs, uint32_t mask)
{
  return dds_read_impl (false, rd_or_cnd, buf, maxs, maxs, si, mask, DDS_HANDLE_NIL, false);
}

dds_return_t dds_readcdr (dds_entity_t rd_or_cnd, struct ddsi_serdata **buf, uint32_t maxs, dds_sample_info_t *si, uint32_t mask)
{
  return dds_readcdr_impl (false, rd_or_cnd, buf, maxs, si, mask, DDS_HANDLE_NIL);
}

dds_return_t dds_read_instance (dds_entity_t rd_or_cnd, void **buf, dds_sample_info_t *si, size_t bufsz, uint32_t maxs, dds_instance_handle_t handle)
{
  if (handle == DDS_HANDLE_NIL)
    return DDS_RETCODE_PRECONDITION_NOT_MET;
  return dds_read_impl (false, rd_or_cnd, buf, bufsz, maxs, si, 0, handle, false);
}

dds_return_t dds_read_instance_wl (dds_entity_t rd_or_cnd, void **buf, dds_sample_info_t *si, uint32_t maxs, dds_instance_handle_t handle)
{
  if (handle == DDS_HANDLE_NIL)
    return DDS_RETCODE_PRECONDITION_NOT_MET;
  return dds_read_impl (false, rd_or_cnd, buf, maxs, maxs, si, 0, handle, false);
}

dds_return_t dds_read_instance_mask (dds_entity_t rd_or_cnd, void **buf, dds_sample_info_t *si, size_t bufsz, uint32_t maxs, dds_instance_handle_t handle, uint32_t mask)
{
  if (handle == DDS_HANDLE_NIL)
    return DDS_RETCODE_PRECONDITION_NOT_MET;
  return dds_read_impl (false, rd_or_cnd, buf, bufsz, maxs, si, mask, handle, false);
}

dds_return_t dds_read_instance_mask_wl (dds_entity_t rd_or_cnd, void **buf, dds_sample_info_t *si, uint32_t maxs, dds_instance_handle_t handle, uint32_t mask)
{
  if (handle == DDS_HANDLE_NIL)
    return DDS_RETCODE_PRECONDITION_NOT_MET;
  return dds_read_impl (false, rd_or_cnd, buf, maxs, maxs, si, mask, handle, false);
}

dds_return_t dds_readcdr_instance (dds_entity_t rd_or_cnd, struct ddsi_serdata **buf, uint32_t maxs, dds_sample_info_t *si, dds_instance_handle_t handle, uint32_t mask)
{
  if (handle == DDS_HANDLE_NIL)
    return DDS_RETCODE_PRECONDITION_NOT_MET;
  return dds_readcdr_impl(false, rd_or_cnd, buf, maxs, si, mask, handle);
}

dds_return_t dds_read_next (dds_entity_t reader, void **buf, dds_sample_info_t *si)
{
  uint32_t mask = DDS_NOT_READ_SAMPLE_STATE | DDS_ANY_VIEW_STATE | DDS_ANY_INSTANCE_STATE;
  return dds_read_impl (false, reader, buf, 1u, 1u, si, mask, DDS_HANDLE_NIL, true);
}

dds_return_t dds_read_next_wl (dds_entity_t reader, void **buf, dds_sample_info_t *si)
{
  uint32_t mask = DDS_NOT_READ_SAMPLE_STATE | DDS_ANY_VIEW_STATE | DDS_ANY_INSTANCE_STATE;
  return dds_read_impl (false, reader, buf, 1u, 1u, si, mask, DDS_HANDLE_NIL, true);
}

dds_return_t dds_read_with_collector (dds_entity_t rd_or_cnd, uint32_t maxs, dds_instance_handle_t handle, uint32_t mask, dds_read_with_collector_fn_t collect_sample, void *collect_sample_arg)
{
  return dds_read_with_collector_impl (false, rd_or_cnd, maxs, mask, handle, false, collect_sample, collect_sample_arg);
}

dds_return_t dds_take (dds_entity_t rd_or_cnd, void **buf, dds_sample_info_t *si, size_t bufsz, uint32_t maxs)
{
  return dds_read_impl (true, rd_or_cnd, buf, bufsz, maxs, si, 0, DDS_HANDLE_NIL, false);
}

dds_return_t dds_take_wl (dds_entity_t rd_or_cnd, void ** buf, dds_sample_info_t * si, uint32_t maxs)
{
  return dds_read_impl (true, rd_or_cnd, buf, maxs, maxs, si, 0, DDS_HANDLE_NIL, false);
}

dds_return_t dds_take_mask (dds_entity_t rd_or_cnd, void **buf, dds_sample_info_t *si, size_t bufsz, uint32_t maxs, uint32_t mask)
{
  return dds_read_impl (true, rd_or_cnd, buf, bufsz, maxs, si, mask, DDS_HANDLE_NIL, false);
}

dds_return_t dds_take_mask_wl (dds_entity_t rd_or_cnd, void **buf, dds_sample_info_t *si, uint32_t maxs, uint32_t mask)
{
  return dds_read_impl (true, rd_or_cnd, buf, maxs, maxs, si, mask, DDS_HANDLE_NIL, false);
}

dds_return_t dds_takecdr (dds_entity_t rd_or_cnd, struct ddsi_serdata **buf, uint32_t maxs, dds_sample_info_t *si, uint32_t mask)
{
  return dds_readcdr_impl (true, rd_or_cnd, buf, maxs, si, mask, DDS_HANDLE_NIL);
}

dds_return_t dds_take_instance (dds_entity_t rd_or_cnd, void **buf, dds_sample_info_t *si, size_t bufsz, uint32_t maxs, dds_instance_handle_t handle)
{
  if (handle == DDS_HANDLE_NIL)
    return DDS_RETCODE_PRECONDITION_NOT_MET;
  return dds_read_impl (true, rd_or_cnd, buf, bufsz, maxs, si, 0, handle, false);
}

dds_return_t dds_take_instance_wl (dds_entity_t rd_or_cnd, void **buf, dds_sample_info_t *si, uint32_t maxs, dds_instance_handle_t handle)
{
  if (handle == DDS_HANDLE_NIL)
    return DDS_RETCODE_PRECONDITION_NOT_MET;
  return dds_read_impl (true, rd_or_cnd, buf, maxs, maxs, si, 0, handle, false);
}

dds_return_t dds_take_instance_mask (dds_entity_t rd_or_cnd, void **buf, dds_sample_info_t *si, size_t bufsz, uint32_t maxs, dds_instance_handle_t handle, uint32_t mask)
{
  if (handle == DDS_HANDLE_NIL)
    return DDS_RETCODE_PRECONDITION_NOT_MET;
  return dds_read_impl (true, rd_or_cnd, buf, bufsz, maxs, si, mask, handle, false);
}

dds_return_t dds_take_instance_mask_wl (dds_entity_t rd_or_cnd, void **buf, dds_sample_info_t *si, uint32_t maxs, dds_instance_handle_t handle, uint32_t mask)
{
  if (handle == DDS_HANDLE_NIL)
    return DDS_RETCODE_PRECONDITION_NOT_MET;
  return dds_read_impl (true, rd_or_cnd, buf, maxs, maxs, si, mask, handle, false);
}

dds_return_t dds_takecdr_instance (dds_entity_t rd_or_cnd, struct ddsi_serdata **buf, uint32_t maxs, dds_sample_info_t *si, dds_instance_handle_t handle, uint32_t mask)
{
  if (handle == DDS_HANDLE_NIL)
    return DDS_RETCODE_PRECONDITION_NOT_MET;
  return dds_readcdr_impl (true, rd_or_cnd, buf, maxs, si, mask, handle);
}

dds_return_t dds_take_next (dds_entity_t reader, void **buf, dds_sample_info_t *si)
{
  uint32_t mask = DDS_NOT_READ_SAMPLE_STATE | DDS_ANY_VIEW_STATE | DDS_ANY_INSTANCE_STATE;
  return dds_read_impl (true, reader, buf, 1u, 1u, si, mask, DDS_HANDLE_NIL, true);
}

dds_return_t dds_take_next_wl (dds_entity_t reader, void **buf, dds_sample_info_t *si)
{
  uint32_t mask = DDS_NOT_READ_SAMPLE_STATE | DDS_ANY_VIEW_STATE | DDS_ANY_INSTANCE_STATE;
  return dds_read_impl (true, reader, buf, 1u, 1u, si, mask, DDS_HANDLE_NIL, true);
}

dds_return_t dds_take_with_collector (dds_entity_t rd_or_cnd, uint32_t maxs, dds_instance_handle_t handle, uint32_t mask, dds_read_with_collector_fn_t collect_sample, void *collect_sample_arg)
{
  return dds_read_with_collector_impl (true, rd_or_cnd, maxs, mask, handle, false, collect_sample, collect_sample_arg);
}

dds_return_t dds_return_reader_loan (dds_reader *rd, void **buf, int32_t bufsz)
{
  if (bufsz <= 0)
  {
    /* No data whatsoever, or an invocation following a failed read/take call.  Read/take
       already take care of restoring the state prior to their invocation if they return
       no data.  Return late so invalid handles can be detected. */
    return DDS_RETCODE_OK;
  }
  assert (buf[0] != NULL);

  const struct ddsi_sertype *st = rd->m_topic->m_stype;

  /* The potentially time consuming part of what happens here (freeing samples)
     can safely be done without holding the reader lock, but that particular
     lock is not used during insertion of data & triggering waitsets (that's
     the observer_lock), so holding it for a bit longer in return for simpler
     code is a fair trade-off. */
  ddsrt_mutex_lock (&rd->m_entity.m_mutex);
  if (buf[0] != rd->m_loan)
  {
    /* Not so much a loan as a buffer allocated by the middleware on behalf of the
       application.  So it really is no more than a sophisticated variant of "free". */
    ddsi_sertype_free_samples (st, buf, (size_t) bufsz, DDS_FREE_ALL);
    buf[0] = NULL;
  }
  else if (!rd->m_loan_out)
  {
    /* Trying to return a loan that has been returned already */
    ddsrt_mutex_unlock (&rd->m_entity.m_mutex);
    return DDS_RETCODE_PRECONDITION_NOT_MET;
  }
  else
  {
    /* Free only the memory referenced from the samples, not the samples themselves.
       Zero them to guarantee the absence of dangling pointers that might cause
       trouble on a following operation.  FIXME: there's got to be a better way */
    ddsi_sertype_free_samples (st, buf, (size_t) bufsz, DDS_FREE_CONTENTS);
    ddsi_sertype_zero_samples (st, rd->m_loan, rd->m_loan_size);
    rd->m_loan_out = false;
    buf[0] = NULL;
  }
  ddsrt_mutex_unlock (&rd->m_entity.m_mutex);
  return DDS_RETCODE_OK;
}
