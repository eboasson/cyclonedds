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

#include <string.h>

#include "dds/ddsrt/heap.h"
#include "dds/ddsrt/dynlib.h"
#include "dds/ddsrt/mh3.h"
#include "dds/ddsi/ddsi_locator.h"
#include "dds/ddsi/ddsi_domaingv.h"
#include "dds__types.h"
#include "dds__virtual_interface.h"

dds_return_t dds_add_vi_topic_to_list (struct dds_virtual_interface_topic *topic, struct dds_virtual_interface_topic_list_elem **list)
{
  if (!topic)
    return DDS_RETCODE_BAD_PARAMETER;

  struct dds_virtual_interface_topic_list_elem *ptr = dds_alloc (sizeof (struct dds_virtual_interface_topic_list_elem));
  if (!ptr)
    return DDS_RETCODE_OUT_OF_RESOURCES;

  ptr->topic = topic;
  ptr->next = NULL;

  if (!*list)
  {
    ptr->prev = NULL;
    *list = ptr;
  }
  else
  {
    struct dds_virtual_interface_topic_list_elem *ptr2 = *list;
    while (ptr2->next)
      ptr2 = ptr2->next;
    ptr2->next = ptr;
    ptr->prev = ptr2;
  }

  return DDS_RETCODE_OK;
}

dds_return_t dds_remove_vi_topic_from_list (struct dds_virtual_interface_topic *topic, struct dds_virtual_interface_topic_list_elem **list)
{
  if (!topic || !list || !*list)
    return DDS_RETCODE_BAD_PARAMETER;

  dds_return_t ret = DDS_RETCODE_OK;
  struct dds_virtual_interface_topic_list_elem *list_entry = *list;

  while (list_entry && list_entry->topic != topic)
    list_entry = list_entry->next;

  if (list_entry != NULL && (ret = list_entry->topic->virtual_interface->ops.topic_destruct (list_entry->topic)) == DDS_RETCODE_OK)
  {
    if (list_entry->prev)
      list_entry->prev->next = list_entry->next;

    if (list_entry->next)
      list_entry->next->prev = list_entry->prev;

    if (list_entry == *list)
      *list = list_entry->next;

    dds_free (list_entry);
  }

  return ret;
}

dds_return_t dds_add_vi_pipe_to_list (struct dds_virtual_interface_pipe *pipe, struct dds_virtual_interface_pipe_list_elem **list)
{
  if (!pipe)
    return DDS_RETCODE_BAD_PARAMETER;

  struct dds_virtual_interface_pipe_list_elem *ptr = dds_alloc (sizeof (struct dds_virtual_interface_pipe_list_elem));
  if (!ptr)
    return DDS_RETCODE_OUT_OF_RESOURCES;

  ptr->pipe = pipe;
  ptr->next = NULL;

  if (!*list)
  {
    ptr->prev = NULL;
    *list = ptr;
  }
  else
  {
    struct dds_virtual_interface_pipe_list_elem *ptr2 = *list;
    while (ptr2->next)
      ptr2 = ptr2->next;
    ptr2->next = ptr;
    ptr->prev = ptr2;
  }

  return DDS_RETCODE_OK;
}

dds_return_t dds_remove_vi_pipe_from_list (struct dds_virtual_interface_pipe *pipe, struct dds_virtual_interface_pipe_list_elem **list)
{
  if (!pipe || !list || !*list)
    return DDS_RETCODE_BAD_PARAMETER;

  dds_return_t ret = DDS_RETCODE_OK;
  struct dds_virtual_interface_pipe_list_elem *list_entry = *list;

  while (list_entry && list_entry->pipe != pipe)
    list_entry = list_entry->next;

  if (list_entry != NULL && (ret = dds_virtual_interface_pipe_close (list_entry->pipe)) == DDS_RETCODE_OK)
  {
    if (list_entry->prev)
      list_entry->prev->next = list_entry->next;

    if (list_entry->next)
      list_entry->next->prev = list_entry->prev;

    if (list_entry == *list)
      *list = list_entry->next;

    dds_free (list_entry);
  }

  return ret;
}

dds_return_t dds_virtual_interface_init_generic (struct dds_virtual_interface * virtual_interface)
{
  struct ddsi_locator *loc = dds_alloc (sizeof (ddsi_locator_t));
  if (loc == NULL)
    return DDS_RETCODE_OUT_OF_RESOURCES;
  memset (loc, 0, sizeof (*loc));

  dds_virtual_interface_node_identifier_t vini = virtual_interface->ops.get_node_id (virtual_interface);

  memcpy (loc->address, &vini, sizeof (vini));
  loc->port = virtual_interface->interface_id;
  loc->kind = DDSI_LOCATOR_KIND_SHEM;

  virtual_interface->locator = loc;

  return DDS_RETCODE_OK;
}

dds_return_t dds_virtual_interface_cleanup_generic (struct dds_virtual_interface *virtual_interface)
{
  dds_return_t ret = DDS_RETCODE_OK;
  dds_free ((void *) virtual_interface->locator);

  while (ret == DDS_RETCODE_OK && virtual_interface->topics)
    ret = dds_remove_vi_topic_from_list (virtual_interface->topics->topic, &virtual_interface->topics);

  return ret;
}

dds_return_t dds_virtual_interface_topic_init_generic (struct dds_virtual_interface_topic *vi_topic, const struct dds_virtual_interface * virtual_interface)
{
  vi_topic->data_type = ddsrt_mh3 (&virtual_interface->interface_id, sizeof (virtual_interface->interface_id), vi_topic->topic_id);
  return DDS_RETCODE_OK;
}

dds_return_t dds_virtual_interface_topic_cleanup_generic (struct dds_virtual_interface_topic *vi_topic)
{
  dds_return_t ret = DDS_RETCODE_OK;
  while (ret == DDS_RETCODE_OK && vi_topic->pipes)
    ret = dds_remove_vi_pipe_from_list (vi_topic->pipes->pipe, &vi_topic->pipes);
  return ret;
}

dds_loaned_sample_t * dds_virtual_interface_pipe_request_loan (struct dds_virtual_interface_pipe *pipe, uint32_t sz)
{
  assert (pipe && pipe->ops.req_loan);
  return pipe->ops.req_loan (pipe, sz);
}

bool dds_virtual_interface_pipe_serialization_required (struct dds_virtual_interface_pipe *pipe)
{
  assert (pipe && pipe->topic);
  return pipe->topic->ops.serialization_required (pipe->topic->data_type_props);
}

dds_virtual_interface_topic_identifier_t dds_calculate_topic_identifier (const struct dds_ktopic * ktopic)
{
  return ddsrt_mh3 (ktopic->name, strlen (ktopic->name), 0x0);
}

static dds_loan_origin_type_t calculate_interface_identifier (const struct ddsi_domaingv * gv, const char *config_name)
{
  uint32_t ext_domainid = gv->config.extDomainId.value;
  uint32_t hashed_id = ddsrt_mh3 (&ext_domainid, sizeof (ext_domainid), 0x0);
  return ddsrt_mh3 (config_name, strlen (config_name), hashed_id);
}

dds_return_t dds_virtual_interface_load (const struct ddsi_domaingv *gv, struct ddsi_config_virtual_interface *config, struct dds_virtual_interface **out)
{
  dds_virtual_interface_create_fn creator = NULL;
  const char *lib_name;
  ddsrt_dynlib_t handle;
  char load_fn[100];
  dds_return_t ret;
  struct dds_virtual_interface *vi = NULL;

  if (!config->library || config->library[0] == '\0')
    lib_name = config->name;
  else
    lib_name = config->library;

  if ((ret = ddsrt_dlopen (lib_name, true, &handle)) != DDS_RETCODE_OK)
  {
    char buf[1024];
    (void) ddsrt_dlerror (buf, sizeof(buf));
    GVERROR ("Failed to load virtual interface library '%s' with error \"%s\".\n", lib_name, buf);
    goto err_dlopen;
  }

  (void) snprintf (load_fn, sizeof (load_fn), "%s_create_virtual_interface", config->name);

  if ((ret = ddsrt_dlsym (handle, load_fn, (void**) &creator)) != DDS_RETCODE_OK)
  {
    GVERROR ("Failed to initialize virtual interface '%s', could not load init function '%s'.\n", config->name, load_fn);
    goto err_dlsym;
  }

  if ((ret = creator (&vi, calculate_interface_identifier (gv, config->name), config->config)) != DDS_RETCODE_OK)
  {
    GVERROR ("Failed to initialize virtual interface '%s'.\n", config->name);
    goto err_init;
  }
  vi->priority = config->priority.value;
  *out = vi;
  return DDS_RETCODE_OK;

err_init:
err_dlsym:
  ddsrt_dlclose (handle);
err_dlopen:
  return ret;
}

static int compare_virtual_interface_prio (const void *va, const void *vb)
{
  const struct dds_virtual_interface *vi1 = va;
  const struct dds_virtual_interface *vi2 = vb;
  return (vi1->priority == vi2->priority) ? 0 : ((vi1->priority < vi2->priority) ? 1 : -1);
}

dds_return_t dds_virtual_interfaces_init (const struct ddsi_domaingv *gv, dds_domain *domain)
{
  dds_return_t ret = DDS_RETCODE_OK;
  if (gv->config.virtual_interfaces != NULL)
  {
    struct ddsi_config_virtual_interface_listelem *iface = gv->config.virtual_interfaces;
    while (iface && domain->virtual_interfaces.length < DDS_MAX_VIRTUAL_INTERFACES)
    {
      GVLOG(DDS_LC_INFO, "Loading virtual interface %s\n", iface->cfg.name);
      struct dds_virtual_interface *vi = NULL;
      if (dds_virtual_interface_load (gv, &iface->cfg, &vi))
        domain->virtual_interfaces.interfaces[domain->virtual_interfaces.length++] = vi;
      else
      {
        GVERROR ("error loading virtual interface \"%s\"\n", iface->cfg.name);
        ret = DDS_RETCODE_ERROR;
        break;
      }
      iface = iface->next;
    }

    qsort (domain->virtual_interfaces.interfaces, domain->virtual_interfaces.length, sizeof (*domain->virtual_interfaces.interfaces), compare_virtual_interface_prio);
  }
  return ret;
}

dds_return_t dds_virtual_interfaces_fini (dds_domain *domain)
{
  dds_return_t ret = DDS_RETCODE_OK;
  for (uint32_t i = 0; ret == DDS_RETCODE_OK && i < domain->virtual_interfaces.length; i++)
  {
    struct dds_virtual_interface *vi = domain->virtual_interfaces.interfaces[i];
    if (!vi->ops.deinit (vi))
      ret = DDS_RETCODE_ERROR;
    else
      domain->virtual_interfaces.interfaces[i] = NULL;
  }
  return ret;
}

struct dds_virtual_interface_pipe * dds_virtual_interface_pipe_open (struct dds_virtual_interface_topic *topic, dds_virtual_interface_pipe_type_t pipe_type)
{
  assert (topic && topic->ops.pipe_open);
  return topic->ops.pipe_open (topic, pipe_type);
}

dds_return_t dds_virtual_interface_pipe_close (struct dds_virtual_interface_pipe *pipe)
{
  assert (pipe && pipe->topic && pipe->topic->ops.pipe_close);
  return pipe->topic->ops.pipe_close (pipe);
}

dds_return_t dds_endpoint_init_virtual_interface (struct dds_endpoint *ep, const dds_qos_t *qos, struct dds_virtual_topics_set *virtual_topics, enum dds_virtual_interface_pipe_type pipe_type)
{
  ep->virtual_pipes.length = 0;
  memset (ep->virtual_pipes.pipes, 0, sizeof (ep->virtual_pipes.pipes));
  for (uint32_t i = 0; virtual_topics != NULL && i < virtual_topics->length; i++)
  {
    struct dds_virtual_interface_topic *vi_topic = virtual_topics->topics[i];
    if (!vi_topic->virtual_interface->ops.qos_supported (qos))
      continue;
    struct dds_virtual_interface_pipe *pipe;
    if ((pipe = dds_virtual_interface_pipe_open (vi_topic, pipe_type)) == NULL)
      goto err;
    ep->virtual_pipes.pipes[ep->virtual_pipes.length++] = pipe;
  }
  return DDS_RETCODE_OK;

err:
  for (uint32_t i = 0; i < ep->virtual_pipes.length; i++)
    (void) dds_virtual_interface_pipe_close (ep->virtual_pipes.pipes[i]);
  return DDS_RETCODE_ERROR;
}
