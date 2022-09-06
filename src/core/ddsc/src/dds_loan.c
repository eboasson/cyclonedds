/*
 * Copyright(c) 2022 ZettaScale Technology and others
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v. 1.0 which is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 */

#include "dds__loan.h"
#include "dds__entity.h"
#include <string.h>

dds_return_t dds_loaned_sample_free(dds_loaned_sample_t *loaned_sample)
{
  dds_return_t ret;
  if (loaned_sample == NULL || ddsrt_atomic_ld32(&loaned_sample->refs) > 0)
    return DDS_RETCODE_BAD_PARAMETER;

  if ((ret = dds_loan_manager_remove_loan(loaned_sample)) != DDS_RETCODE_OK)
    return ret;
  if (loaned_sample->ops.free)
    loaned_sample->ops.free (loaned_sample);

  return DDS_RETCODE_OK;
}

dds_return_t dds_loaned_sample_ref(dds_loaned_sample_t *loaned_sample)
{
  dds_return_t ret;
  if (loaned_sample == NULL)
    return DDS_RETCODE_BAD_PARAMETER;

  if (loaned_sample->ops.ref && (ret = loaned_sample->ops.ref(loaned_sample)) != DDS_RETCODE_OK)
    return ret;

  ddsrt_atomic_inc32(&loaned_sample->refs);
  return DDS_RETCODE_OK;
}

dds_return_t dds_loaned_sample_unref(dds_loaned_sample_t *loaned_sample)
{
  dds_return_t ret;
  if (loaned_sample == NULL || ddsrt_atomic_ld32(&loaned_sample->refs) == 0)
    return DDS_RETCODE_BAD_PARAMETER;

  if (loaned_sample->ops.unref && (ret = loaned_sample->ops.unref(loaned_sample)) != DDS_RETCODE_OK)
    return ret;
  else if (ddsrt_atomic_dec32_ov (&loaned_sample->refs) > 1)
    return DDS_RETCODE_OK;
  else if ((ret = dds_loan_manager_remove_loan(loaned_sample)) != DDS_RETCODE_OK)
    return ret;
  else
    return dds_loaned_sample_free(loaned_sample);
}

dds_return_t dds_loaned_sample_reset_sample(dds_loaned_sample_t *loaned_sample)
{
  assert(loaned_sample && ddsrt_atomic_ld32(&loaned_sample->refs));
  if (loaned_sample->ops.reset)
    loaned_sample->ops.reset(loaned_sample);
  return DDS_RETCODE_OK;
}

static dds_return_t dds_loan_manager_expand_cap(dds_loan_manager_t *manager, uint32_t n)
{
  if (manager == NULL)
    return DDS_RETCODE_BAD_PARAMETER;
  if (n > UINT32_MAX - manager->n_samples_cap)
    return DDS_RETCODE_OUT_OF_RANGE;

  uint32_t newcap = manager->n_samples_cap + n;
  dds_loaned_sample_t **newarray = NULL;
  if (newcap > 0)
  {
    newarray = dds_realloc(manager->samples, sizeof(**newarray) * newcap);
    if (newarray == NULL)
      return DDS_RETCODE_OUT_OF_RESOURCES;
    memset(newarray + manager->n_samples_cap, 0, sizeof(**newarray) * n);
  }
  manager->samples = newarray;
  manager->n_samples_cap = newcap;

  return DDS_RETCODE_OK;
}

dds_return_t dds_loan_manager_create(dds_loan_manager_t **manager, uint32_t initial_cap)
{
  if (manager == NULL)
    return DDS_RETCODE_BAD_PARAMETER;

  dds_return_t ret = DDS_RETCODE_OK;
  if ((*manager = dds_alloc(sizeof(**manager))) == NULL)
    return DDS_RETCODE_OUT_OF_RESOURCES;
  memset (*manager, 0, sizeof (**manager));
  if ((ret = dds_loan_manager_expand_cap(*manager, initial_cap)) != DDS_RETCODE_OK)
    dds_free(*manager);
  return ret;
}

dds_return_t dds_loan_manager_free(dds_loan_manager_t *manager)
{
  dds_return_t ret;
  if (manager == NULL)
    return DDS_RETCODE_BAD_PARAMETER;

  for (uint32_t i = 0; i < manager->n_samples_cap; i++)
  {
    dds_loaned_sample_t *s = manager->samples[i];
    if (s && (ret = dds_loan_manager_remove_loan(s)) != DDS_RETCODE_OK)
      return ret;
    manager->samples[i] = NULL;
  }

  dds_free(manager->samples);
  dds_free(manager);
  return DDS_RETCODE_OK;
}

dds_return_t dds_loan_manager_add_loan(dds_loan_manager_t *manager, dds_loaned_sample_t *loaned_sample)
{
  dds_return_t ret;
  if (manager == NULL || loaned_sample == NULL || loaned_sample->manager != NULL)
    return DDS_RETCODE_BAD_PARAMETER;

  //expand
  if (manager->n_samples_managed == manager->n_samples_cap)
  {
    uint32_t cap = manager->n_samples_cap;
    uint32_t newcap = cap ? cap * 2 : 1;
    if ((ret = dds_loan_manager_expand_cap(manager, newcap - cap)) != DDS_RETCODE_OK)
      return ret;
  }

  //add
  for (uint32_t i = 0; i < manager->n_samples_cap; i++)
  {
    if (!manager->samples[i])
    {
      loaned_sample->loan_idx = i;
      manager->samples[i] = loaned_sample;
      break;
    }
  }
  loaned_sample->manager = manager;
  manager->n_samples_managed++;

  return dds_loaned_sample_ref(loaned_sample);
}

dds_return_t dds_loan_manager_move_loan(dds_loan_manager_t *manager, dds_loaned_sample_t *loaned_sample)
{
  dds_return_t ret;
  if (manager == NULL || loaned_sample == NULL)
    return DDS_RETCODE_BAD_PARAMETER;

  if ((ret = dds_loaned_sample_ref(loaned_sample)) != DDS_RETCODE_OK)
    return ret;

  if ((ret = dds_loan_manager_remove_loan(loaned_sample)) != DDS_RETCODE_OK
      || (ret = dds_loan_manager_add_loan(manager, loaned_sample)) != DDS_RETCODE_OK)
    goto err;

  return dds_loaned_sample_unref(loaned_sample);

err:
  dds_loaned_sample_unref(loaned_sample);
  return ret;
}

dds_return_t dds_loan_manager_remove_loan(dds_loaned_sample_t *loaned_sample)
{
  if (loaned_sample == NULL)
    return DDS_RETCODE_BAD_PARAMETER;

  dds_loan_manager_t *mgr = loaned_sample->manager;
  if (!mgr)
    return DDS_RETCODE_OK;
  if (mgr->n_samples_managed == 0 ||
      loaned_sample->loan_idx >= mgr->n_samples_cap ||
      loaned_sample != mgr->samples[loaned_sample->loan_idx])
    return DDS_RETCODE_BAD_PARAMETER;

  mgr->samples[loaned_sample->loan_idx] = NULL;
  mgr->n_samples_managed--;
  loaned_sample->loan_idx = (uint32_t) - 1;
  loaned_sample->manager = NULL;

  if (ddsrt_atomic_ld32(&loaned_sample->refs) > 0)
    return dds_loaned_sample_unref(loaned_sample);

  return DDS_RETCODE_OK;
}

dds_loaned_sample_t *dds_loan_manager_find_loan(const dds_loan_manager_t *manager, const void *loaned_sample)
{
  if (manager == NULL)
    return NULL;

  for (uint32_t i = 0; i < manager->n_samples_cap && loaned_sample; i++)
  {
    if (manager->samples[i] && manager->samples[i]->sample_ptr == loaned_sample)
      return manager->samples[i];
  }

  return NULL;
}

dds_loaned_sample_t *dds_loan_manager_get_loan(dds_loan_manager_t *manager)
{
  if (manager == NULL || manager->samples == NULL)
    return NULL;

  for (uint32_t i = 0; i < manager->n_samples_cap; i++)
  {
    if (manager->samples[i])
      return manager->samples[i];
  }

  return NULL;
}

typedef struct dds_heap_loan {
  dds_loaned_sample_t c;
  const struct ddsi_sertype *m_stype;
} dds_heap_loan_t;

static void heap_free(dds_loaned_sample_t *loaned_sample)
{
  assert(loaned_sample);
  dds_heap_loan_t *hl = (dds_heap_loan_t*)loaned_sample;
  dds_free(hl->c.metadata);
  ddsi_sertype_free_sample(hl->m_stype, hl->c.sample_ptr, DDS_FREE_ALL);
  dds_free(hl);
}

static void heap_reset(dds_loaned_sample_t *loaned_sample)
{
  assert(loaned_sample);
  dds_heap_loan_t *hl = (dds_heap_loan_t*)loaned_sample;
  memset(hl->c.metadata, 0, sizeof(*(hl->c.metadata)));
  ddsi_sertype_zero_sample(hl->m_stype, hl->c.sample_ptr);
}

const dds_loaned_sample_ops_t dds_heap_loan_ops = {
  .free = heap_free,
  .ref = NULL,
  .unref = NULL,
  .reset = heap_reset
};

dds_return_t dds_heap_loan(const struct ddsi_sertype *type, dds_loaned_sample_t **loaned_sample)
{
  if (type == NULL || loaned_sample == NULL)
    return DDS_RETCODE_BAD_PARAMETER;

  dds_heap_loan_t *s = dds_alloc(sizeof(*s));
  if (s == NULL)
    return DDS_RETCODE_OUT_OF_RESOURCES;

  if ((s->c.metadata = dds_alloc(sizeof(*s->c.metadata))) == NULL)
  {
    dds_free(s);
    return DDS_RETCODE_OUT_OF_RESOURCES;
  }

  s->c.ops = dds_heap_loan_ops;
  s->m_stype = type;
  if ((s->c.sample_ptr = ddsi_sertype_alloc_sample(type)) == NULL)
  {
    dds_free(s);
    dds_free(s->c.metadata);
    return DDS_RETCODE_OUT_OF_RESOURCES;
  }

  s->c.metadata->block_size = sizeof(dds_virtual_interface_metadata_t);
  s->c.metadata->sample_state = DDS_LOANED_SAMPLE_STATE_RAW;
  s->c.metadata->cdr_identifier = CDR_ENC_VERSION_UNDEF;
  s->c.metadata->cdr_options = 0;

  *loaned_sample = (dds_loaned_sample_t *) s;

  return DDS_RETCODE_OK;
}
