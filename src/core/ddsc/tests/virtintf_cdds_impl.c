/*
 * Copyright(c) 2023 ZettaScale Technology and others
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v. 1.0 which is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 */

#include <string.h>
#include "dds/dds.h"
#include "dds/ddsrt/environ.h"
#include "dds/ddsrt/threads.h"
#include "dds/ddsrt/heap.h"
#include "dds/ddsc/dds_virtual_interface.h"
#include "virtintf_cdds_impl.h"
#include "virtintf_cdds_data.h"

#define DDS_DOMAINID 0
#define DDS_CONFIG \
  "<Tracing><OutputFile>cyclonedds_virtintf_impl.${CYCLONEDDS_DOMAIN_ID}.${CYCLONEDDS_PID}.log</OutputFile><Verbosity>finest</Verbosity></Tracing>" \
  "<Discovery><ExternalDomainId>5</ExternalDomainId></Discovery>"

struct cdds_virtual_interface {
  struct dds_virtual_interface c;
  dds_entity_t domain;
  dds_entity_t participant;
};

struct cdds_virtual_interface_topic {
  struct dds_virtual_interface_topic c;
  dds_entity_t topic;
};

struct cdds_virtual_interface_pipe {
  struct dds_virtual_interface_pipe c;
  dds_entity_t vi_endpoint;
  dds_entity_t cdds_endpoint;
  ddsrt_atomic_uint32_t on_data_threads_stop;
  ddsrt_atomic_uint32_t on_data_threads_count;
};

static const uint32_t sample_padding = sizeof (struct dds_virtual_interface_metadata) % 8 ? (sizeof (struct dds_virtual_interface_metadata) / 8 + 1) * 8 : sizeof (struct dds_virtual_interface_metadata);

static bool cdds_vi_data_type_supported (dds_virtual_interface_data_type_properties_t data_type_props);
static bool cdds_vi_qos_supported (const struct dds_qos *qos);
static struct dds_virtual_interface_topic * cdds_vi_topic_create (struct dds_virtual_interface * vi,
    dds_virtual_interface_topic_identifier_t topic_identifier, dds_virtual_interface_data_type_properties_t data_type_props);
static dds_return_t cdds_vi_topic_destruct (struct dds_virtual_interface_topic *vi_topic);
static dds_return_t cdds_vi_deinit (struct dds_virtual_interface *vi);
static dds_virtual_interface_node_identifier_t cdds_vi_get_node_id (const struct dds_virtual_interface *vi);

static const dds_virtual_interface_ops_t vi_ops = {
  .data_type_supported = cdds_vi_data_type_supported,
  .qos_supported = cdds_vi_qos_supported,
  .topic_create = cdds_vi_topic_create,
  .topic_destruct = cdds_vi_topic_destruct,
  .deinit = cdds_vi_deinit,
  .get_node_id = cdds_vi_get_node_id
};

static bool cdds_vt_serialization_required (dds_virtual_interface_data_type_properties_t data_type_props);
static struct dds_virtual_interface_pipe * cdds_vt_pipe_open (struct dds_virtual_interface_topic *topic, dds_virtual_interface_pipe_type_t pipe_type);
static dds_return_t cdds_vt_pipe_close (struct dds_virtual_interface_pipe *pipe);

static const dds_virtual_interface_topic_ops_t vt_ops = {
  .serialization_required = cdds_vt_serialization_required,
  .pipe_open = cdds_vt_pipe_open,
  .pipe_close = cdds_vt_pipe_close
};

static dds_loaned_sample_t * cdds_vp_request_loan (struct dds_virtual_interface_pipe *pipe, uint32_t size_requested);
static dds_return_t cdds_vp_sink_data (struct dds_virtual_interface_pipe *pipe, dds_loaned_sample_t *data);
static dds_loaned_sample_t * cdds_vp_source_data (struct dds_virtual_interface_pipe *pipe);
static dds_return_t cdds_vp_set_on_source (struct dds_virtual_interface_pipe *pipe, dds_entity_t reader);

static const dds_virtual_interface_pipe_ops_t vp_ops = {
  .req_loan = cdds_vp_request_loan,
  .sink_data = cdds_vp_sink_data,
  .source_data = cdds_vp_source_data,
  .set_on_source = cdds_vp_set_on_source
};

static void cdds_loaned_sample_free (struct dds_loaned_sample *loaned_sample);
static void cdds_loaned_sample_reset (struct dds_loaned_sample *loaned_sample);

static const dds_loaned_sample_ops_t ls_ops = {
  .free = cdds_loaned_sample_free,
  .ref = 0,
  .unref = 0,
  .reset = cdds_loaned_sample_reset
};



static bool cdds_vi_data_type_supported (dds_virtual_interface_data_type_properties_t data_type_props)
{
  (void) data_type_props;
  return true;
}

static bool cdds_vi_qos_supported (const struct dds_qos *qos)
{
  (void) qos;
  return true;
}

static struct dds_virtual_interface_topic * cdds_vi_topic_create (struct dds_virtual_interface * vi,
    dds_virtual_interface_topic_identifier_t topic_identifier, dds_virtual_interface_data_type_properties_t data_type_props)
{
  struct cdds_virtual_interface *cvi = (struct cdds_virtual_interface *) vi;
  if (cvi->domain == -1)
  {
    char *conf = ddsrt_expand_envvars (DDS_CONFIG, DDS_DOMAINID);
    cvi->domain = dds_create_domain (DDS_DOMAINID, conf);
    cvi->participant = dds_create_participant (DDS_DOMAINID, NULL, NULL);
    ddsrt_free (conf);
  }

  struct cdds_virtual_interface_topic *cvt = dds_alloc (sizeof (*cvt));
  char topic_name[100];
  snprintf (topic_name, sizeof (topic_name), "cdds_virtintf_topic_%u", topic_identifier);
  cvt->topic = dds_create_topic (cvi->participant, &cdds_virtintf_data_desc, topic_name, NULL, NULL);
  cvt->c.ops = vt_ops;
  cvt->c.virtual_interface = vi;
  cvt->c.data_type_props = data_type_props;
  cvt->c.topic_id = topic_identifier;
  dds_virtual_interface_topic_init_generic (&cvt->c, vi);

  dds_add_vi_topic_to_list (&cvt->c, &cvi->c.topics);

  return (struct dds_virtual_interface_topic *) cvt;
}

static dds_return_t cdds_vi_topic_destruct (struct dds_virtual_interface_topic *vi_topic)
{
  struct cdds_virtual_interface_topic *cvt = (struct cdds_virtual_interface_topic *) vi_topic;
  dds_virtual_interface_topic_cleanup_generic (&cvt->c);
  dds_delete (cvt->topic);
  dds_free (cvt);
  return DDS_RETCODE_OK;
}


static uint32_t deinit_thread (void *arg)
{
  struct cdds_virtual_interface *cvi = (struct cdds_virtual_interface *) arg;
  dds_delete (cvi->domain);
  return 0;
}

static dds_return_t cdds_vi_deinit (struct dds_virtual_interface *vi)
{
  struct cdds_virtual_interface *cvi = (struct cdds_virtual_interface *) vi;

  dds_virtual_interface_cleanup_generic (&cvi->c);

  ddsrt_thread_t tid;
  ddsrt_threadattr_t tattr;
  ddsrt_threadattr_init (&tattr);
  ddsrt_thread_create (&tid, "cdds_vi_deinit", &tattr, deinit_thread, cvi);
  return DDS_RETCODE_OK;
}

static dds_virtual_interface_node_identifier_t cdds_vi_get_node_id (const struct dds_virtual_interface *vi)
{
  struct cdds_virtual_interface *cvi = (struct cdds_virtual_interface *) vi;
  dds_guid_t guid;
  (void) dds_get_guid (cvi->participant, &guid);
  return (dds_virtual_interface_node_identifier_t) *(((char *) &guid) + 4);
}

static bool cdds_vt_serialization_required (dds_virtual_interface_data_type_properties_t data_type_props)
{
  (void) data_type_props;
  return false;
}

static struct dds_virtual_interface_pipe * cdds_vt_pipe_open (struct dds_virtual_interface_topic *topic, dds_virtual_interface_pipe_type_t pipe_type)
{
  struct cdds_virtual_interface_topic * cvt = (struct cdds_virtual_interface_topic *) topic;
  struct cdds_virtual_interface *cvi = (struct cdds_virtual_interface *) cvt->c.virtual_interface;
  struct cdds_virtual_interface_pipe *cvp = dds_alloc (sizeof (*cvp));
  cvp->c.ops = vp_ops;
  cvp->c.topic = topic;
  cvp->c.pipe_type = pipe_type;
  ddsrt_atomic_st32 (&cvp->on_data_threads_stop, 0);
  ddsrt_atomic_st32 (&cvp->on_data_threads_count, 0);

  switch (pipe_type)
  {
    case DDS_VIRTUAL_INTERFACE_PIPE_TYPE_SOURCE:
      cvp->vi_endpoint = dds_create_reader (cvi->participant, cvt->topic, NULL, NULL);
      break;
    case DDS_VIRTUAL_INTERFACE_PIPE_TYPE_SINK:
      cvp->vi_endpoint = dds_create_writer (cvi->participant, cvt->topic, NULL, NULL);
      break;
    case DDS_VIRTUAL_INTERFACE_PIPE_TYPE_UNSET:
      return NULL;
  }
  assert (cvp->vi_endpoint >= 0);

  dds_add_vi_pipe_to_list (&cvp->c, &cvt->c.pipes);

  return (struct dds_virtual_interface_pipe *) cvp;
}

static dds_return_t cdds_vt_pipe_close (struct dds_virtual_interface_pipe *pipe)
{
  struct cdds_virtual_interface_pipe *cvp = (struct cdds_virtual_interface_pipe *) pipe;

  ddsrt_atomic_st32 (&cvp->on_data_threads_stop, 1);
  while (ddsrt_atomic_ld32 (&cvp->on_data_threads_count) > 0)
    dds_sleepfor (DDS_MSECS (100));

  dds_delete (cvp->vi_endpoint);
  dds_free (cvp);
  return DDS_RETCODE_OK;
}

static dds_loaned_sample_t * cdds_vp_request_loan (struct dds_virtual_interface_pipe *pipe, uint32_t size_requested)
{
  struct cdds_virtual_interface_pipe *cvp = (struct cdds_virtual_interface_pipe *) pipe;
  dds_loaned_sample_t *ls = NULL;
  if (cvp->c.pipe_type == DDS_VIRTUAL_INTERFACE_PIPE_TYPE_SINK)
  {
    uint32_t sz = size_requested + sample_padding;

    void *sample = dds_alloc (sz);
    memset (sample, 0, sz);

    ls = dds_alloc (sizeof (*ls));
    ls->ops = ls_ops;
    ls->loan_origin = (struct dds_virtual_interface_pipe *) cvp;
    ls->metadata = dds_alloc (sizeof (*ls->metadata));
    ls->metadata->sample_state = DDS_LOANED_SAMPLE_STATE_UNITIALIZED;
    ls->metadata->sample_size = size_requested;
    ls->metadata->block_size = sz;
    ls->metadata->data_origin = cvp->c.topic->virtual_interface->interface_id;
    ls->metadata->data_type = cvp->c.topic->data_type;
    ls->sample_ptr = (char *) sample;
    ls->loan_idx = 0;
    ls->refs.v = 0;
  }
  return ls;
}

static dds_return_t cdds_vp_sink_data (struct dds_virtual_interface_pipe *pipe, dds_loaned_sample_t *data)
{
  struct cdds_virtual_interface_pipe *cvp = (struct cdds_virtual_interface_pipe *) pipe;

  struct cdds_virtintf_data sample = {
    .sample_state = (uint32_t) data->metadata->sample_state,
    .data_type = data->metadata->data_type,
    .data_origin = data->metadata->data_origin,
    .sample_size = data->metadata->sample_size,
    .block_size = data->metadata->block_size,
    .timestamp = data->metadata->timestamp,
    .statusinfo = data->metadata->statusinfo,
    .hash = data->metadata->hash,
    .cdr_identifier = data->metadata->cdr_identifier,
    .cdr_options = data->metadata->cdr_options,
    .keysize = data->metadata->keysize
  };
  memcpy (&sample.guid, &data->metadata->guid, sizeof (sample.guid));
  memcpy (&sample.keyhash, data->metadata->keyhash, sizeof (sample.keyhash));
  sample.data._length = sample.data._maximum = data->metadata->sample_size;
  sample.data._release = false;
  sample.data._buffer = data->sample_ptr;
  dds_write (cvp->vi_endpoint, &sample);
  return DDS_RETCODE_OK;
}

static dds_loaned_sample_t * cdds_vp_source_data (struct dds_virtual_interface_pipe *pipe)
{
  (void) pipe;
  return NULL;
}

static dds_loaned_sample_t * incoming_sample_to_loan (struct cdds_virtual_interface_pipe *cvp, const void *sample)
{
  struct cdds_virtintf_data *vi_sample = (struct cdds_virtintf_data *) sample;

  struct dds_virtual_interface_metadata *vmd = dds_alloc (sizeof (*vmd));
  vmd->block_size = vi_sample->block_size;
  vmd->cdr_identifier = vi_sample->cdr_identifier;
  vmd->cdr_options = vi_sample->cdr_options;
  vmd->data_origin = vi_sample->data_origin;
  vmd->data_type = vi_sample->data_type;
  memcpy (&vmd->guid, &vi_sample->guid, sizeof (vi_sample->guid));
  vmd->hash = vi_sample->hash;
  memcpy (vmd->keyhash, &vi_sample->keyhash, sizeof (vmd->keyhash));
  vmd->keysize = (vi_sample->keysize & 0x3fffffff);
  vmd->sample_size = vi_sample->sample_size;
  vmd->sample_state = (enum dds_loaned_sample_state) vi_sample->sample_state;
  vmd->statusinfo = vi_sample->statusinfo;

  dds_loaned_sample_t *ls = dds_alloc (sizeof (*ls));
  ls->ops = ls_ops;
  ls->loan_origin = (struct dds_virtual_interface_pipe *) cvp;
  ls->metadata = vmd;
  ls->sample_ptr = (char *) vi_sample->data._buffer,
  ls->loan_idx = 0;
  ls->refs.v = 0;
  return ls;
}

struct on_data_available_args {
  struct cdds_virtual_interface_pipe *cvp;
};

static uint32_t on_data_available_thread (void *a)
{
  struct on_data_available_args *args = (struct on_data_available_args *) a;
  struct cdds_virtual_interface *cvi = (struct cdds_virtual_interface *) args->cvp->c.topic->virtual_interface;
  dds_return_t ret;

  ddsrt_atomic_inc32 (&args->cvp->on_data_threads_count);

  // attach waitset to virtual interface reader and wait for on_data_available
  dds_entity_t waitset = dds_create_waitset (cvi->participant);
  ret = dds_set_status_mask (args->cvp->vi_endpoint, DDS_DATA_AVAILABLE_STATUS);
  assert (ret == DDS_RETCODE_OK);
  ret = dds_waitset_attach (waitset, args->cvp->vi_endpoint, args->cvp->vi_endpoint);
  assert (ret == DDS_RETCODE_OK);
  while (ddsrt_atomic_ld32 (&args->cvp->on_data_threads_stop) == 0)
  {
    ret = dds_waitset_wait (waitset, NULL, 0, DDS_MSECS (100));
    assert (ret >= 0);

    dds_sample_info_t si;
    void *raw = NULL;
    dds_return_t n = dds_take (args->cvp->vi_endpoint, &raw, &si, 1, 1);
    if (n == 1 && si.valid_data)
    {
      dds_loaned_sample_t *data = incoming_sample_to_loan (args->cvp, raw);
      (void) dds_reader_store_external (args->cvp->cdds_endpoint, data);
    }
  }

  ddsrt_atomic_dec32 (&args->cvp->on_data_threads_count);
  dds_free (args);
  return 0;
}

static dds_return_t cdds_vp_set_on_source (struct dds_virtual_interface_pipe *pipe, dds_entity_t reader)
{
  struct cdds_virtual_interface_pipe *cvp = (struct cdds_virtual_interface_pipe *) pipe;
  cvp->cdds_endpoint = reader;

  struct on_data_available_args *data = dds_alloc (sizeof (*data));
  data->cvp = cvp;

  ddsrt_thread_t tid;
  ddsrt_threadattr_t tattr;
  ddsrt_threadattr_init (&tattr);
  ddsrt_thread_create (&tid, "virtintf_cdds_ondata", &tattr, on_data_available_thread, data);
  return DDS_RETCODE_OK;
}

static void cdds_loaned_sample_free (struct dds_loaned_sample *loaned_sample)
{
  dds_free (loaned_sample->metadata);
  // FIXME: dds_free (loaned_sample->sample_ptr);
  dds_free (loaned_sample);
}

static void cdds_loaned_sample_reset (struct dds_loaned_sample *loaned_sample)
{
  (void) loaned_sample;
}

dds_return_t cdds_create_virtual_interface (dds_virtual_interface_t **virtual_interface, dds_loan_origin_type_t identifier, const char *config)
{
  (void) config;
  assert (virtual_interface);

  struct cdds_virtual_interface *vi = dds_alloc (sizeof (*vi));
  vi->c.interface_name = dds_string_dup ("cdds-virt-intf");
  vi->c.interface_id = identifier;
  vi->c.ops = vi_ops;
  dds_virtual_interface_init_generic (&vi->c);
  vi->domain = -1;

  *virtual_interface = (dds_virtual_interface_t *) vi;
  return DDS_RETCODE_OK;
}

