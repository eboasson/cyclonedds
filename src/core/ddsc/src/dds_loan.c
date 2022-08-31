#include "dds__loan.h"

#include "dds__entity.h"

#include <string.h>

bool dds_loaned_sample_fini(
  dds_loaned_sample_t *to_fini)
{
  assert(to_fini && (ddsrt_atomic_ld32(&to_fini->refs) == 0));

  if (!dds_loan_manager_remove_loan(to_fini))
    return false;
  if (to_fini->ops.fini)
    return to_fini->ops.fini(to_fini);
  else
    return true;
}

bool dds_loaned_sample_incr_refs(
  dds_loaned_sample_t *to_incr)
{
  assert(to_incr);

  if (to_incr->ops.incr && !to_incr->ops.incr(to_incr))
    return false;

  ddsrt_atomic_inc32(&to_incr->refs);
  return true;
}

bool dds_loaned_sample_decr_refs(
  dds_loaned_sample_t *to_decr)
{
  assert(to_decr && ddsrt_atomic_ld32(&to_decr->refs));

  if (to_decr->ops.decr && !to_decr->ops.decr(to_decr))
    return false;
  else if (ddsrt_atomic_dec32_ov (&to_decr->refs) > 1)
    return true;
  else if (!dds_loan_manager_remove_loan(to_decr))
    return false;
  else
    return dds_loaned_sample_fini(to_decr);
}

bool dds_loaned_sample_reset_sample(
  dds_loaned_sample_t *to_reset)
{
  assert(to_reset && ddsrt_atomic_ld32(&to_reset->refs));

  if (to_reset->ops.reset)
    return to_reset->ops.reset(to_reset);
  else
    return true;
}

static bool dds_loan_manager_expand_cap(
  dds_loan_manager_t *to_expand,
  uint32_t by_this)
{
  assert (to_expand);

  uint32_t newcap = to_expand->n_samples_cap + by_this;

  dds_loaned_sample_t **newarray = dds_realloc(to_expand->samples, sizeof(dds_loaned_sample_t*)*newcap);

  if (newcap && NULL == newarray)
    return false;

  memset(newarray+to_expand->n_samples_cap, 0, sizeof(dds_loaned_sample_t*)*(newcap-to_expand->n_samples_cap));
  to_expand->n_samples_cap = newcap;
  to_expand->samples = newarray;

  return true;
}

dds_loan_manager_t *dds_loan_manager_create(
  uint32_t initial_cap)
{
  dds_loan_manager_t *mgr = dds_alloc(sizeof(dds_loan_manager_t));

  if (!mgr || !dds_loan_manager_expand_cap(mgr, initial_cap))
    goto fail;

  return mgr;

fail:
  dds_free(mgr);
  return NULL;
}

bool dds_loan_manager_fini(
  dds_loan_manager_t *to_fini)
{
  assert(to_fini);

  for (uint32_t i = 0; i < to_fini->n_samples_cap; i++)
  {
    dds_loaned_sample_t *s = to_fini->samples[i];

    if (s && !dds_loan_manager_remove_loan(s))
      return false;
    else
      to_fini->samples[i] = NULL;
  }

  dds_free(to_fini->samples);
  dds_free(to_fini);

  return true;
}

bool dds_loan_manager_add_loan(
  dds_loan_manager_t *manager,
  dds_loaned_sample_t *to_add)
{
  assert(manager && to_add && !to_add->manager);

  //expand
  if (manager->n_samples_managed == manager->n_samples_cap)
  {
    uint32_t cap = manager->n_samples_cap;
    uint32_t newcap = cap ? cap*2 : 1;
    if (!dds_loan_manager_expand_cap(manager, newcap-cap))
      return false;
  }

  //add
  for (uint32_t i = 0; i < manager->n_samples_cap; i++)
  {
    if (!manager->samples[i])
    {
      to_add->loan_idx = i;
      manager->samples[i] = to_add;
      break;
    }
  }
  to_add->manager = manager;
  manager->n_samples_managed++;

  return dds_loaned_sample_incr_refs(to_add);
}
bool dds_loan_manager_move_loan(
  dds_loan_manager_t *manager,
  dds_loaned_sample_t *to_move)
{
  assert(to_move && manager);

  return dds_loaned_sample_incr_refs(to_move) &&
         dds_loan_manager_remove_loan(to_move) &&
         dds_loan_manager_add_loan(manager, to_move) &&
         dds_loaned_sample_decr_refs(to_move);
}

bool dds_loan_manager_remove_loan(
  dds_loaned_sample_t *to_remove)
{
  assert(to_remove);

  dds_loan_manager_t *mgr = to_remove->manager;
  if (!mgr)
    return true;
  if (mgr->n_samples_managed == 0 ||
      to_remove->loan_idx >= mgr->n_samples_cap ||
      to_remove != mgr->samples[to_remove->loan_idx])
    return false;

  mgr->samples[to_remove->loan_idx] = NULL;
  mgr->n_samples_managed--;
  to_remove->loan_idx = (uint32_t)-1;
  to_remove->manager = NULL;

  return ddsrt_atomic_ld32(&to_remove->refs) ? dds_loaned_sample_decr_refs(to_remove) : true;
}

dds_loaned_sample_t *dds_loan_manager_find_loan(
  const dds_loan_manager_t *manager,
  const void *sample)
{
  assert(manager);

  for (uint32_t i = 0; i < manager->n_samples_cap && sample; i++)
  {
    if (manager->samples[i] && manager->samples[i]->sample_ptr == sample)
      return manager->samples[i];
  }

  return NULL;
}

dds_loaned_sample_t *dds_loan_manager_get_loan(
  dds_loan_manager_t *manager)
{
  if (!manager)
    return NULL;

  assert(manager->samples);

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

static bool heap_fini(
  dds_loaned_sample_t *to_fini)
{
  assert(to_fini);

  dds_heap_loan_t *hl = (dds_heap_loan_t*)to_fini;

  dds_free(hl->c.metadata);

  ddsi_sertype_free_sample(hl->m_stype, hl->c.sample_ptr, DDS_FREE_ALL);

  dds_free(hl);

  return true;
}

static bool heap_reset(
  dds_loaned_sample_t *to_reset)
{
  assert(to_reset);

  dds_heap_loan_t *hl = (dds_heap_loan_t*)to_reset;

  memset(hl->c.metadata, 0, sizeof(*(hl->c.metadata)));

  ddsi_sertype_zero_sample(hl->m_stype, hl->c.sample_ptr);

  return true;
}

const dds_loaned_sample_ops_t dds_heap_loan_ops = {
  .fini = heap_fini,
  .incr = NULL,
  .decr = NULL,
  .reset = heap_reset
};

dds_loaned_sample_t* dds_heap_loan(const struct ddsi_sertype *type)
{
  dds_heap_loan_t *s = dds_alloc(sizeof(dds_heap_loan_t));
  dds_virtual_interface_metadata_t *md = dds_alloc(sizeof(dds_virtual_interface_metadata_t));

  if (s)
  {
    s->c.metadata = md;
    s->c.ops = dds_heap_loan_ops;
    s->m_stype = type;
    s->c.sample_ptr = ddsi_sertype_alloc_sample(type);
  }

  if (md)
  {
    md->block_size = sizeof(dds_virtual_interface_metadata_t);
    //md->sample_size =
    md->sample_state = LOANED_SAMPLE_STATE_RAW;
    md->cdr_identifier = CDR_ENC_VERSION_UNDEF;
    md->cdr_options = 0;
  }

  if (!md || !s)
  {
    if (md)
      dds_free(md);
    if (s)
      dds_free(s);

    return NULL;
  }

  return (dds_loaned_sample_t*)s;
}
