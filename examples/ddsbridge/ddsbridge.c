// Copyright(c) 2026 ZettaScale Technology and others
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License v. 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
// v. 1.0 which is available at
// http://www.eclipse.org/org/documents/edl-v10.php.
//
// SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dds/dds.h"
#include "dds/ddsrt/heap.h"
#include "dds/ddsrt/hopscotch.h"
#include "dds/ddsrt/string.h"

enum bridge_side {
  BRIDGE_SIDE_A,
  BRIDGE_SIDE_B
};

enum builtin_endpoint_kind {
  BUILTIN_ENDPOINT_PUBLICATION,
  BUILTIN_ENDPOINT_SUBSCRIPTION
};

struct bridge_domain {
  const char *name;
  dds_domainid_t domain_id;
  dds_entity_t participant;
  dds_instance_handle_t participant_instance_handle;
  dds_entity_t publication_reader;
  dds_entity_t publication_readcond;
  dds_entity_t subscription_reader;
  dds_entity_t subscription_readcond;
};

struct bridge;
struct callback_ctx;

typedef void (*bridge_callback_t) (void *arg);

struct waitset_callback {
  bridge_callback_t fn;
  void *arg;
};

struct callback_ctx {
  struct bridge *bridge;
  struct bridge_domain *source;
  struct bridge_domain *destination;
  enum builtin_endpoint_kind endpoint_kind;
  dds_entity_t readcond;
};

struct bridge {
  struct bridge_domain domains[2];
  dds_entity_t waitset;
  struct callback_ctx callback_ctxs[4];
  struct waitset_callback callbacks[4];
};

struct mirrored_writer {
  dds_instance_handle_t publication_handle;
  dds_entity_t source_endpoint;
  dds_entity_t destination_endpoint;
  dds_entity_t data_reader;
  dds_entity_t data_writer;
  dds_entity_t data_readcond;
  dds_domainid_t data_reader_domain_id;
  dds_domainid_t data_writer_domain_id;
  dds_entity_t writer;
  char *topic_name;
  struct waitset_callback data_callback;
};

static struct ddsrt_hh *g_mirrored_writers;

static const char g_bridge_userdata[] = "cyclonedds-ddsbridge";

static const char *endpoint_kind_name (enum builtin_endpoint_kind kind);

static uint32_t mirrored_writer_hash (const void *v)
{
  const struct mirrored_writer *entry = v;
  uint64_t x = entry->publication_handle;
  x ^= x >> 33;
  x *= UINT64_C (0xff51afd7ed558ccd);
  x ^= x >> 33;
  return (uint32_t) x;
}

static bool mirrored_writer_equal (const void *va, const void *vb)
{
  const struct mirrored_writer *a = va;
  const struct mirrored_writer *b = vb;
  return a->publication_handle == b->publication_handle;
}

static struct mirrored_writer *mirrored_writer_find (dds_instance_handle_t publication_handle)
{
  const struct mirrored_writer templ = { .publication_handle = publication_handle };
  return ddsrt_hh_lookup (g_mirrored_writers, &templ);
}

static void mirrored_writer_delete (struct mirrored_writer *entry)
{
  if (entry->data_readcond > 0)
    (void) dds_delete (entry->data_readcond);
  if (entry->source_endpoint > 0)
    (void) dds_delete (entry->source_endpoint);
  if (entry->destination_endpoint > 0)
    (void) dds_delete (entry->destination_endpoint);
  ddsrt_free (entry->topic_name);
  entry->data_readcond = 0;
  entry->data_reader = 0;
  entry->data_writer = 0;
  entry->source_endpoint = 0;
  entry->destination_endpoint = 0;
  entry->writer = 0;
  entry->topic_name = NULL;
}

static void mirrored_writer_free (void *ventry, void *varg)
{
  struct mirrored_writer *entry = ventry;
  (void) varg;
  mirrored_writer_delete (entry);
  ddsrt_free (entry);
}

static void mirrored_writers_fini (void)
{
  if (g_mirrored_writers != NULL)
  {
    ddsrt_hh_enum (g_mirrored_writers, mirrored_writer_free, NULL);
    ddsrt_hh_free (g_mirrored_writers);
    g_mirrored_writers = NULL;
  }
}

static dds_entity_t find_topic_for_endpoint (const struct bridge_domain *domain, dds_builtintopic_endpoint_t *ep)
{
  const dds_typeinfo_t *type_info = NULL;
#ifdef DDS_HAS_TYPELIB
  (void) dds_builtintopic_get_endpoint_type_info (ep, &type_info);
#endif
  const dds_entity_t topic = dds_find_topic (DDS_FIND_SCOPE_GLOBAL, domain->participant, ep->topic_name, type_info, DDS_SECS (2));
  if (topic <= 0)
    fprintf (stderr, "dds_find_topic(%s in domain %s): %s\n", ep->topic_name, domain->name, dds_strretcode (topic));
  return topic;
}

static bool is_builtin_topic_name (const char *topic_name)
{
  return strncmp (topic_name, "DCPS", 4) == 0;
}

static bool endpoint_is_from_bridge (const dds_builtintopic_endpoint_t *ep)
{
  void *userdata = NULL;
  size_t userdata_size = 0;

  if (!dds_qget_userdata (ep->qos, &userdata, &userdata_size))
    return false;

  const bool is_bridge = userdata_size == sizeof (g_bridge_userdata) - 1 &&
    memcmp (userdata, g_bridge_userdata, sizeof (g_bridge_userdata) - 1) == 0;
  dds_free (userdata);
  return is_bridge;
}

static dds_qos_t *create_bridge_endpoint_qos (const dds_qos_t *src)
{
  dds_qos_t *qos = dds_create_qos ();
  if (qos == NULL)
  {
    fprintf (stderr, "dds_create_qos: out of memory\n");
    return NULL;
  }
  if (dds_copy_qos (qos, src) < 0)
  {
    fprintf (stderr, "dds_copy_qos: failed\n");
    dds_delete_qos (qos);
    return NULL;
  }
  dds_qset_userdata (qos, g_bridge_userdata, sizeof (g_bridge_userdata) - 1);
  return qos;
}

static dds_qos_t *create_bridge_writer_qos (const dds_qos_t *src)
{
  dds_qos_t *qos = create_bridge_endpoint_qos (src);
  if (qos != NULL)
    dds_qset_ignorelocal (qos, DDS_IGNORELOCAL_PARTICIPANT);
  return qos;
}

static dds_entity_t create_destination_topic (const struct bridge_domain *source_domain, const struct bridge_domain *destination_domain, dds_builtintopic_endpoint_t *ep, dds_entity_t source_topic)
{
  dds_qos_t *qos = dds_create_qos ();
  if (qos == NULL)
  {
    fprintf (stderr, "dds_create_qos: out of memory\n");
    return DDS_RETCODE_OUT_OF_RESOURCES;
  }

  dds_return_t ret = dds_get_qos (source_topic, qos);
  if (ret < 0)
  {
    fprintf (stderr, "dds_get_qos(%s): %s\n", ep->topic_name, dds_strretcode (ret));
    dds_delete_qos (qos);
    return ret;
  }

  dds_typeinfo_t *type_info = NULL;
  ret = dds_get_typeinfo (source_topic, &type_info);
  if (ret < 0)
  {
    fprintf (stderr, "dds_get_typeinfo(%s): %s\n", ep->topic_name, dds_strretcode (ret));
    dds_delete_qos (qos);
    return ret;
  }

  dds_topic_descriptor_t *descriptor = NULL;
  ret = dds_create_topic_descriptor (DDS_FIND_SCOPE_GLOBAL, source_domain->participant, type_info, DDS_SECS (2), &descriptor);
  dds_free_typeinfo (type_info);
  if (ret < 0)
  {
    fprintf (stderr, "dds_create_topic_descriptor(%s in domain %s): %s\n", ep->topic_name, source_domain->name, dds_strretcode (ret));
    dds_delete_qos (qos);
    return ret;
  }

  const dds_entity_t topic = dds_create_topic (destination_domain->participant, descriptor, ep->topic_name, qos, NULL);
  dds_delete_topic_descriptor (descriptor);
  dds_delete_qos (qos);
  if (topic < 0)
    fprintf (stderr, "dds_create_topic(%s in domain %s): %s\n", ep->topic_name, destination_domain->name, dds_strretcode (topic));
  return topic;
}

static void delete_mirrored_endpoint (dds_instance_handle_t publication_handle)
{
  struct mirrored_writer *entry = mirrored_writer_find (publication_handle);
  if (entry != NULL)
  {
    (void) ddsrt_hh_remove (g_mirrored_writers, entry);
    mirrored_writer_free (entry, NULL);
  }
}

static bool mirrored_route_exists (struct callback_ctx *ctx, const dds_builtintopic_endpoint_t *ep)
{
  const struct bridge_domain *reader_domain = (ctx->endpoint_kind == BUILTIN_ENDPOINT_PUBLICATION) ? ctx->source : ctx->destination;
  const struct bridge_domain *writer_domain = (ctx->endpoint_kind == BUILTIN_ENDPOINT_PUBLICATION) ? ctx->destination : ctx->source;
  struct ddsrt_hh_iter iter;

  for (struct mirrored_writer *entry = ddsrt_hh_iter_first (g_mirrored_writers, &iter);
       entry != NULL;
       entry = ddsrt_hh_iter_next (&iter))
  {
    if (entry->data_reader_domain_id == reader_domain->domain_id &&
        entry->data_writer_domain_id == writer_domain->domain_id &&
        entry->topic_name != NULL &&
        strcmp (entry->topic_name, ep->topic_name) == 0)
      return true;
  }

  return false;
}

static void republish_data_sample (struct mirrored_writer *entry, void *sample, const dds_sample_info_t *info);

static void republish_data_samples (void *arg)
{
#define MAX_SAMPLES 16
  struct mirrored_writer *entry = arg;
  void *samples[MAX_SAMPLES] = { NULL };
  dds_sample_info_t infos[MAX_SAMPLES];
  int32_t n;

  do {
    n = dds_take (entry->data_readcond, samples, infos, MAX_SAMPLES, MAX_SAMPLES);
    if (n < 0)
    {
      fprintf (stderr, "dds_take(%s): %s\n", entry->topic_name, dds_strretcode (n));
      return;
    }

    for (int32_t i = 0; i < n; i++)
    {
      republish_data_sample (entry, samples[i], &infos[i]);
    }

    (void) dds_return_loan (entry->data_readcond, samples, n);
  } while (n == MAX_SAMPLES);
#undef MAX_SAMPLES
}

static bool data_instance_exists (struct mirrored_writer *entry, dds_instance_handle_t handle)
{
  void *sample = NULL;
  dds_sample_info_t info;
  const dds_return_t ret = dds_peek_instance_mask (entry->data_reader, &sample, &info, 1, 1, handle, DDS_ANY_STATE);
  if (ret > 0)
    (void) dds_return_loan (entry->data_reader, &sample, ret);
  return ret >= 0;
}

static void log_forward_error (const char *op, const struct mirrored_writer *entry, dds_return_t ret)
{
  if (ret < 0)
    fprintf (stderr, "%s(%s): %s\n", op, entry->topic_name, dds_strretcode (ret));
}

static void republish_data_sample (struct mirrored_writer *entry, void *sample, const dds_sample_info_t *info)
{
  dds_return_t ret;

  if (info->valid_data)
  {
    switch (info->instance_state)
    {
      case DDS_ALIVE_INSTANCE_STATE:
        ret = dds_write_ts (entry->data_writer, sample, info->source_timestamp);
        log_forward_error ("dds_write_ts", entry, ret);
        break;
      case DDS_NOT_ALIVE_DISPOSED_INSTANCE_STATE:
        ret = dds_writedispose_ts (entry->data_writer, sample, info->source_timestamp);
        log_forward_error ("dds_writedispose_ts", entry, ret);
        if (!data_instance_exists (entry, info->instance_handle))
        {
          ret = dds_unregister_instance_ts (entry->data_writer, sample, info->source_timestamp);
          log_forward_error ("dds_unregister_instance_ts", entry, ret);
        }
        break;
      case DDS_NOT_ALIVE_NO_WRITERS_INSTANCE_STATE:
        ret = dds_write_ts (entry->data_writer, sample, info->source_timestamp);
        log_forward_error ("dds_write_ts", entry, ret);
        ret = dds_unregister_instance_ts (entry->data_writer, sample, info->source_timestamp);
        log_forward_error ("dds_unregister_instance_ts", entry, ret);
        break;
    }
  }
  else
  {
    switch (info->instance_state)
    {
      case DDS_ALIVE_INSTANCE_STATE:
        fprintf (stderr, "invalid alive sample for %s ignored\n", entry->topic_name);
        break;
      case DDS_NOT_ALIVE_DISPOSED_INSTANCE_STATE:
        ret = dds_dispose_ts (entry->data_writer, sample, info->source_timestamp);
        log_forward_error ("dds_dispose_ts", entry, ret);
        if (!data_instance_exists (entry, info->instance_handle))
        {
          ret = dds_unregister_instance_ts (entry->data_writer, sample, info->source_timestamp);
          log_forward_error ("dds_unregister_instance_ts", entry, ret);
        }
        break;
      case DDS_NOT_ALIVE_NO_WRITERS_INSTANCE_STATE:
        ret = dds_unregister_instance_ts (entry->data_writer, sample, info->source_timestamp);
        log_forward_error ("dds_unregister_instance_ts", entry, ret);
        break;
    }
  }
}

static int attach_data_reader (struct callback_ctx *ctx, struct mirrored_writer *entry, const char *topic_name)
{
  entry->topic_name = ddsrt_strdup (topic_name);
  if (entry->topic_name == NULL)
  {
    fprintf (stderr, "ddsrt_strdup: out of memory\n");
    return -1;
  }

  entry->data_readcond = dds_create_readcondition (entry->data_reader, DDS_NOT_READ_SAMPLE_STATE);
  if (entry->data_readcond < 0)
  {
    fprintf (stderr, "dds_create_readcondition(%s): %s\n", topic_name, dds_strretcode (entry->data_readcond));
    return -1;
  }

  entry->data_callback.fn = republish_data_samples;
  entry->data_callback.arg = entry;

  const dds_return_t ret = dds_waitset_attach (ctx->bridge->waitset, entry->data_readcond, (dds_attach_t) (intptr_t) &entry->data_callback);
  if (ret < 0)
  {
    fprintf (stderr, "dds_waitset_attach(%s): %s\n", topic_name, dds_strretcode (ret));
    return -1;
  }

  return 0;
}

static void create_mirrored_endpoint (struct callback_ctx *ctx, dds_builtintopic_endpoint_t *ep, dds_instance_handle_t publication_handle)
{
  if (is_builtin_topic_name (ep->topic_name))
    return;
  if (ep->participant_instance_handle == ctx->source->participant_instance_handle)
    return;
  if (ctx->endpoint_kind == BUILTIN_ENDPOINT_SUBSCRIPTION && endpoint_is_from_bridge (ep))
    return;

  struct mirrored_writer *entry = mirrored_writer_find (publication_handle);
  if (entry != NULL)
  {
    printf ("TODO: QoS update for %s on topic %s from domain %s ignored\n",
            endpoint_kind_name (ctx->endpoint_kind), ep->topic_name, ctx->source->name);
    return;
  }
  if (mirrored_route_exists (ctx, ep))
    return;

  dds_entity_t source_topic = find_topic_for_endpoint (ctx->source, ep);
  if (source_topic <= 0)
    return;
  dds_entity_t destination_topic = create_destination_topic (ctx->source, ctx->destination, ep, source_topic);
  if (destination_topic <= 0)
  {
    (void) dds_delete (source_topic);
    return;
  }

  entry = ddsrt_calloc (1, sizeof (*entry));
  entry->publication_handle = publication_handle;
  dds_qos_t *endpoint_qos = create_bridge_endpoint_qos (ep->qos);
  if (endpoint_qos == NULL)
  {
    (void) dds_delete (source_topic);
    (void) dds_delete (destination_topic);
    mirrored_writer_free (entry, NULL);
    return;
  }

  if (ctx->endpoint_kind == BUILTIN_ENDPOINT_PUBLICATION)
  {
    entry->source_endpoint = dds_create_reader (ctx->source->participant, source_topic, endpoint_qos, NULL);
    if (entry->source_endpoint < 0)
      fprintf (stderr, "dds_create_reader(%s in domain %s): %s\n", ep->topic_name, ctx->source->name, dds_strretcode (entry->source_endpoint));
    else
    {
      dds_qos_t *writer_qos = create_bridge_writer_qos (ep->qos);
      if (writer_qos == NULL)
        entry->destination_endpoint = DDS_RETCODE_OUT_OF_RESOURCES;
      else
        entry->destination_endpoint = dds_create_writer (ctx->destination->participant, destination_topic, writer_qos, NULL);
      dds_delete_qos (writer_qos);
      if (entry->destination_endpoint < 0)
        fprintf (stderr, "dds_create_writer(%s in domain %s): %s\n", ep->topic_name, ctx->destination->name, dds_strretcode (entry->destination_endpoint));
      else
      {
        entry->data_reader = entry->source_endpoint;
        entry->data_writer = entry->destination_endpoint;
        entry->data_reader_domain_id = ctx->source->domain_id;
        entry->data_writer_domain_id = ctx->destination->domain_id;
        entry->writer = entry->destination_endpoint;
      }
    }
  }
  else
  {
    dds_qos_t *writer_qos = create_bridge_writer_qos (ep->qos);
    if (writer_qos == NULL)
      entry->source_endpoint = DDS_RETCODE_OUT_OF_RESOURCES;
    else
      entry->source_endpoint = dds_create_writer (ctx->source->participant, source_topic, writer_qos, NULL);
    dds_delete_qos (writer_qos);
    if (entry->source_endpoint < 0)
      fprintf (stderr, "dds_create_writer(%s in domain %s): %s\n", ep->topic_name, ctx->source->name, dds_strretcode (entry->source_endpoint));
    else
    {
      entry->destination_endpoint = dds_create_reader (ctx->destination->participant, destination_topic, endpoint_qos, NULL);
      if (entry->destination_endpoint < 0)
        fprintf (stderr, "dds_create_reader(%s in domain %s): %s\n", ep->topic_name, ctx->destination->name, dds_strretcode (entry->destination_endpoint));
      else
      {
        entry->data_reader = entry->destination_endpoint;
        entry->data_writer = entry->source_endpoint;
        entry->data_reader_domain_id = ctx->destination->domain_id;
        entry->data_writer_domain_id = ctx->source->domain_id;
        entry->writer = entry->source_endpoint;
      }
    }
  }

  dds_delete_qos (endpoint_qos);
  (void) dds_delete (source_topic);
  (void) dds_delete (destination_topic);

  if (entry->writer <= 0)
  {
    mirrored_writer_free (entry, NULL);
    return;
  }

  if (attach_data_reader (ctx, entry, ep->topic_name) < 0)
  {
    mirrored_writer_free (entry, NULL);
    return;
  }

  if (!ddsrt_hh_add (g_mirrored_writers, entry))
  {
    fprintf (stderr, "duplicate mirrored endpoint for handle %" PRIu64 "\n", publication_handle);
    mirrored_writer_free (entry, NULL);
    return;
  }

  printf ("Mirroring %s for topic %s from domain %s to domain %s\n",
          endpoint_kind_name (ctx->endpoint_kind), ep->topic_name, ctx->source->name, ctx->destination->name);
}

static void process_builtin_endpoint_samples (struct callback_ctx *ctx, uint32_t mask, bool take)
{
#define MAX_SAMPLES 16
  void *samples[MAX_SAMPLES] = { NULL };
  dds_sample_info_t infos[MAX_SAMPLES];
  int32_t n;

  do {
    n = take
      ? dds_take_mask (ctx->readcond, samples, infos, MAX_SAMPLES, MAX_SAMPLES, mask)
      : dds_read_mask (ctx->readcond, samples, infos, MAX_SAMPLES, MAX_SAMPLES, mask);
    if (n < 0)
    {
      fprintf (stderr, "%s(%s %s): %s\n", take ? "dds_take" : "dds_read",
               ctx->source->name, endpoint_kind_name (ctx->endpoint_kind), dds_strretcode (n));
      return;
    }

    for (int32_t i = 0; i < n; i++)
    {
      dds_builtintopic_endpoint_t *ep = samples[i];
      if (!infos[i].valid_data)
        continue;
      if (infos[i].instance_state == DDS_NOT_ALIVE_DISPOSED_INSTANCE_STATE)
        delete_mirrored_endpoint (infos[i].instance_handle);
      else if (infos[i].instance_state == DDS_ALIVE_INSTANCE_STATE)
        create_mirrored_endpoint (ctx, ep, infos[i].instance_handle);
    }

    (void) dds_return_loan (ctx->readcond, samples, n);
  } while (n == MAX_SAMPLES);
#undef MAX_SAMPLES
}

static const char *endpoint_kind_name (enum builtin_endpoint_kind kind)
{
  switch (kind)
  {
    case BUILTIN_ENDPOINT_PUBLICATION:
      return "publication";
    case BUILTIN_ENDPOINT_SUBSCRIPTION:
      return "subscription";
  }
  return "unknown";
}

static int parse_domain_id (const char *arg, dds_domainid_t *domain_id)
{
  char *endptr = NULL;
  const unsigned long value = strtoul (arg, &endptr, 0);
  if (arg[0] == '\0' || *endptr != '\0' || value > UINT32_MAX)
    return -1;
  *domain_id = (dds_domainid_t) value;
  return 0;
}

static void usage (const char *argv0)
{
  fprintf (stderr, "usage: %s DOMAIN_A DOMAIN_B\n", argv0);
}

static void drain_builtin_endpoint_samples (void *arg)
{
  struct callback_ctx *ctx = arg;

  (void) ctx->bridge;
  process_builtin_endpoint_samples (ctx, DDS_NOT_READ_SAMPLE_STATE | DDS_ANY_VIEW_STATE | DDS_ALIVE_INSTANCE_STATE, false);
  process_builtin_endpoint_samples (ctx, DDS_ANY_SAMPLE_STATE | DDS_ANY_VIEW_STATE | DDS_NOT_ALIVE_DISPOSED_INSTANCE_STATE, true);
}

static int create_builtin_reader (dds_entity_t participant, dds_entity_t builtin_topic, const char *name, dds_entity_t *reader)
{
  *reader = dds_create_reader (participant, builtin_topic, NULL, NULL);
  if (*reader < 0)
  {
    fprintf (stderr, "dds_create_reader(%s): %s\n", name, dds_strretcode (*reader));
    return -1;
  }
  return 0;
}

static int create_readcondition (dds_entity_t reader, const char *name, dds_entity_t *readcond)
{
  *readcond = dds_create_readcondition (reader, DDS_NOT_READ_SAMPLE_STATE | DDS_ANY_VIEW_STATE |
                                        (DDS_ALIVE_INSTANCE_STATE | DDS_NOT_ALIVE_DISPOSED_INSTANCE_STATE));
  if (*readcond < 0)
  {
    fprintf (stderr, "dds_create_readcondition(%s): %s\n", name, dds_strretcode (*readcond));
    return -1;
  }
  return 0;
}

static int attach_readcondition (dds_entity_t waitset, dds_entity_t readcond, struct waitset_callback *callback, const char *name)
{
  const dds_return_t ret = dds_waitset_attach (waitset, readcond, (dds_attach_t) (intptr_t) callback);
  if (ret < 0)
  {
    fprintf (stderr, "dds_waitset_attach(%s): %s\n", name, dds_strretcode (ret));
    return -1;
  }
  return 0;
}

static int create_domain_entities (struct bridge_domain *domain)
{
  domain->participant = dds_create_participant (domain->domain_id, NULL, NULL);
  if (domain->participant < 0)
  {
    fprintf (stderr, "dds_create_participant(%s %" PRIu32 "): %s\n", domain->name, domain->domain_id, dds_strretcode (domain->participant));
    return -1;
  }
  const dds_return_t ret = dds_get_instance_handle (domain->participant, &domain->participant_instance_handle);
  if (ret < 0)
  {
    fprintf (stderr, "dds_get_instance_handle(%s): %s\n", domain->name, dds_strretcode (ret));
    return -1;
  }

  if (create_builtin_reader (domain->participant, DDS_BUILTIN_TOPIC_DCPSPUBLICATION, "DCPSPublication", &domain->publication_reader) < 0)
    return -1;
  if (create_builtin_reader (domain->participant, DDS_BUILTIN_TOPIC_DCPSSUBSCRIPTION, "DCPSSubscription", &domain->subscription_reader) < 0)
    return -1;
  if (create_readcondition (domain->publication_reader, "DCPSPublication", &domain->publication_readcond) < 0)
    return -1;
  if (create_readcondition (domain->subscription_reader, "DCPSSubscription", &domain->subscription_readcond) < 0)
    return -1;

  return 0;
}

static void init_callback (struct bridge *bridge, size_t index, enum bridge_side source_side, enum builtin_endpoint_kind endpoint_kind)
{
  struct callback_ctx *ctx = &bridge->callback_ctxs[index];
  const enum bridge_side destination_side = (source_side == BRIDGE_SIDE_A) ? BRIDGE_SIDE_B : BRIDGE_SIDE_A;

  ctx->bridge = bridge;
  ctx->source = &bridge->domains[source_side];
  ctx->destination = &bridge->domains[destination_side];
  ctx->endpoint_kind = endpoint_kind;
  ctx->readcond = (endpoint_kind == BUILTIN_ENDPOINT_PUBLICATION) ? ctx->source->publication_readcond : ctx->source->subscription_readcond;

  bridge->callbacks[index].fn = drain_builtin_endpoint_samples;
  bridge->callbacks[index].arg = ctx;
}

static int attach_domain_readconditions (struct bridge *bridge)
{
  init_callback (bridge, 0, BRIDGE_SIDE_A, BUILTIN_ENDPOINT_PUBLICATION);
  init_callback (bridge, 1, BRIDGE_SIDE_A, BUILTIN_ENDPOINT_SUBSCRIPTION);
  init_callback (bridge, 2, BRIDGE_SIDE_B, BUILTIN_ENDPOINT_PUBLICATION);
  init_callback (bridge, 3, BRIDGE_SIDE_B, BUILTIN_ENDPOINT_SUBSCRIPTION);

  for (size_t i = 0; i < sizeof (bridge->callbacks) / sizeof (bridge->callbacks[0]); i++)
  {
    const struct callback_ctx *ctx = bridge->callbacks[i].arg;
    char name[64];
    (void) snprintf (name, sizeof (name), "%s %s", ctx->source->name, endpoint_kind_name (ctx->endpoint_kind));
    if (attach_readcondition (bridge->waitset, ctx->readcond, &bridge->callbacks[i], name) < 0)
      return -1;
  }

  return 0;
}

int main (int argc, char **argv)
{
  struct bridge bridge;
  memset (&bridge, 0, sizeof (bridge));

  bridge.domains[BRIDGE_SIDE_A].name = "A";
  bridge.domains[BRIDGE_SIDE_B].name = "B";

  if (argc != 3 ||
      parse_domain_id (argv[1], &bridge.domains[BRIDGE_SIDE_A].domain_id) < 0 ||
      parse_domain_id (argv[2], &bridge.domains[BRIDGE_SIDE_B].domain_id) < 0)
  {
    usage (argv[0]);
    return 1;
  }

  g_mirrored_writers = ddsrt_hh_new (32, mirrored_writer_hash, mirrored_writer_equal);
  if (g_mirrored_writers == NULL)
  {
    fprintf (stderr, "ddsrt_hh_new: out of memory\n");
    return 1;
  }

  if (create_domain_entities (&bridge.domains[BRIDGE_SIDE_A]) < 0 ||
      create_domain_entities (&bridge.domains[BRIDGE_SIDE_B]) < 0)
  {
    mirrored_writers_fini ();
    dds_delete (bridge.domains[BRIDGE_SIDE_A].participant);
    dds_delete (bridge.domains[BRIDGE_SIDE_B].participant);
    return 1;
  }

  bridge.waitset = dds_create_waitset (DDS_CYCLONEDDS_HANDLE);
  if (bridge.waitset < 0)
  {
    fprintf (stderr, "dds_create_waitset: %s\n", dds_strretcode (bridge.waitset));
    mirrored_writers_fini ();
    dds_delete (bridge.domains[BRIDGE_SIDE_A].participant);
    dds_delete (bridge.domains[BRIDGE_SIDE_B].participant);
    return 1;
  }

  if (attach_domain_readconditions (&bridge) < 0)
  {
    mirrored_writers_fini ();
    dds_delete (bridge.waitset);
    dds_delete (bridge.domains[BRIDGE_SIDE_A].participant);
    dds_delete (bridge.domains[BRIDGE_SIDE_B].participant);
    return 1;
  }

  printf ("Bridging discovery between domains %" PRIu32 " and %" PRIu32 "\n",
          bridge.domains[BRIDGE_SIDE_A].domain_id, bridge.domains[BRIDGE_SIDE_B].domain_id);

  while (true)
  {
    dds_attach_t triggered[4];
    const dds_return_t n = dds_waitset_wait (bridge.waitset, triggered, sizeof (triggered) / sizeof (triggered[0]), DDS_INFINITY);
    if (n < 0)
    {
      fprintf (stderr, "dds_waitset_wait: %s\n", dds_strretcode (n));
      break;
    }

    for (dds_return_t i = 0; i < n; i++)
    {
      struct waitset_callback *callback = (struct waitset_callback *) (intptr_t) triggered[i];
      callback->fn (callback->arg);
    }
  }

  mirrored_writers_fini ();
  dds_delete (bridge.waitset);
  dds_delete (bridge.domains[BRIDGE_SIDE_A].participant);
  dds_delete (bridge.domains[BRIDGE_SIDE_B].participant);
  return 1;
}
