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

#include "dds/ddsc/dds_virtual_interface.h"
#include "dds__virtual_interface.h"

#include <assert.h>
#include <string.h>

#include "dds/ddsrt/heap.h"

#include "dds/ddsi/ddsi_locator.h"
#include "dds/ddsi/ddsi_domaingv.h"
#include "dds/ddsrt/mh3.h"

dds_return_t dds_add_vi_topic_to_list (ddsi_virtual_interface_topic_t *topic, ddsi_virtual_interface_topic_list_elem_t **list)
{
  if (!topic)
    return DDS_RETCODE_BAD_PARAMETER;

  ddsi_virtual_interface_topic_list_elem_t *ptr = dds_alloc(sizeof(ddsi_virtual_interface_topic_list_elem_t));
  if (!ptr)
    return DDS_RETCODE_OUT_OF_RESOURCES;

  ptr->topic = topic;
  ptr->next = NULL;

  if (!*list) {
    //there is no list yet
    ptr->prev = NULL;
    *list = ptr;
  } else {
    //add to the end of the list
    ddsi_virtual_interface_topic_list_elem_t *ptr2 = *list;
    while (ptr2->next) {
      ptr2 = ptr2->next;
    }
    ptr2->next = ptr;
    ptr->prev = ptr2;
  }

  return DDS_RETCODE_OK;
}

dds_return_t dds_remove_vi_topic_from_list (ddsi_virtual_interface_topic_t *topic, ddsi_virtual_interface_topic_list_elem_t **list)
{
  if (!topic || !list || !*list)
    return DDS_RETCODE_BAD_PARAMETER;

  ddsi_virtual_interface_topic_list_elem_t *list_entry = *list;

  while (list_entry && list_entry->topic != topic) {
    list_entry = list_entry->next;
  }

  if (!list_entry ||  //no entry in the list matching the topic
      !list_entry->topic->virtual_interface->ops.topic_destruct(list_entry->topic)) //destruct failure
    return false;

  if (list_entry->prev)
    list_entry->prev->next = list_entry->next;

  if (list_entry->next)
    list_entry->next->prev = list_entry->prev;

  if (list_entry == *list)
    *list = list_entry->next;

  dds_free(list_entry);

  return DDS_RETCODE_OK;
}

dds_return_t dds_add_vi_pipe_to_list (ddsi_virtual_interface_pipe_t *pipe, ddsi_virtual_interface_pipe_list_elem_t **list)
{
  if (!pipe)
    return DDS_RETCODE_BAD_PARAMETER;

  ddsi_virtual_interface_pipe_list_elem_t *ptr = dds_alloc(sizeof(ddsi_virtual_interface_pipe_list_elem_t));
  if (!ptr)
    return DDS_RETCODE_OUT_OF_RESOURCES;

  ptr->pipe = pipe;
  ptr->next = NULL;

  if (!*list) {
    //there is no list yet
    ptr->prev = NULL;
    *list = ptr;
  } else {
    //add to the end of the list
    ddsi_virtual_interface_pipe_list_elem_t *ptr2 = *list;
    while (ptr2->next) {
      ptr2 = ptr2->next;
    }
    ptr2->next = ptr;
    ptr->prev = ptr2;
  }

  return DDS_RETCODE_OK;
}

dds_return_t dds_remove_vi_pipe_from_list (
  ddsi_virtual_interface_pipe_t *pipe,
  ddsi_virtual_interface_pipe_list_elem_t **list)
{
  if (!pipe || !list || !*list)
    return DDS_RETCODE_BAD_PARAMETER;

  ddsi_virtual_interface_pipe_list_elem_t *list_entry = *list;

  while (list_entry && list_entry->pipe != pipe) {
    list_entry = list_entry->next;
  }

  if (!list_entry ||  //no entry in the list matching the topic
      !ddsi_virtual_interface_pipe_close(list_entry->pipe))   //destruct failure
    return DDS_RETCODE_ERROR;

  if (list_entry->prev)
    list_entry->prev->next = list_entry->next;

  if (list_entry->next)
    list_entry->next->prev = list_entry->prev;

  if (list_entry == *list)
    *list = list_entry->next;

  dds_free(list_entry);

  return DDS_RETCODE_OK;
}

virtual_interface_topic_identifier_t calculate_topic_identifier(const struct dds_ktopic * ktopic)
{
  return ddsrt_mh3(ktopic->name, strlen(ktopic->name), 0x0);
}

dds_loan_origin_type_t calculate_interface_identifier(const struct ddsi_domaingv * cyclone_domain, const char *config_name)
{
  uint32_t val = cyclone_domain->config.extDomainId.value;
  uint32_t mid = ddsrt_mh3(&val, sizeof(val), 0x0);
  return ddsrt_mh3(config_name, strlen(config_name), mid);
}

virtual_interface_data_type_properties_t calculate_data_type_properties(const dds_topic_descriptor_t * t_d)
{
  (void) t_d;

  return DATA_TYPE_CALCULATED; //TODO!!! IMPLEMENT!!!
}

bool ddsi_virtual_interface_init_generic(ddsi_virtual_interface_t * virtual_interface)
{
  struct ddsi_locator * loc = (struct ddsi_locator *)ddsrt_calloc(1,sizeof(ddsi_locator_t));

  if (!loc)
    return false;

  ddsi_virtual_interface_node_identifier_t vini = virtual_interface->ops.get_node_id(virtual_interface);

  memcpy(loc->address, &vini, sizeof(vini));
  loc->port = virtual_interface->interface_id;
  loc->kind = DDSI_LOCATOR_KIND_SHEM;

  virtual_interface->locator = loc;

  return true;
}

bool ddsi_virtual_interface_cleanup_generic(ddsi_virtual_interface_t *virtual_interface)
{
  ddsrt_free((void*)virtual_interface->locator);

  while (virtual_interface->topics) {
    if (!dds_remove_vi_topic_from_list(virtual_interface->topics->topic, &virtual_interface->topics))
      return false;
  }

  return true;
}

bool ddsi_virtual_interface_topic_init_generic(ddsi_virtual_interface_topic_t *topic, const ddsi_virtual_interface_t * virtual_interface)
{
  topic->data_type = ddsrt_mh3(&virtual_interface->interface_id, sizeof(virtual_interface->interface_id), topic->topic_id);

  return true;
}

bool ddsi_virtual_interface_topic_cleanup_generic(ddsi_virtual_interface_topic_t *to_cleanup)
{
  while (to_cleanup->pipes) {
    if (!dds_remove_vi_pipe_from_list(to_cleanup->pipes->pipe, &to_cleanup->pipes))
      return false;
  }

  return true;
}

ddsi_virtual_interface_pipe_t * ddsi_virtual_interface_pipe_open (ddsi_virtual_interface_topic_t * topic, dds_virtual_interface_pipe_type_t pipe_type)
{
  assert (topic && topic->ops.pipe_open);

  return topic->ops.pipe_open(topic, pipe_type);
}

bool ddsi_virtual_interface_pipe_close(ddsi_virtual_interface_pipe_t *pipe)
{
  assert (pipe && pipe->topic && pipe->topic->ops.pipe_close);

  return pipe->topic->ops.pipe_close(pipe);
}

dds_loaned_sample_t* ddsi_virtual_interface_pipe_request_loan(ddsi_virtual_interface_pipe_t *pipe, uint32_t sz)
{
  assert(pipe && pipe->ops.req_loan);

  return pipe->ops.req_loan(pipe, sz);
}

bool ddsi_virtual_interface_pipe_serialization_required(ddsi_virtual_interface_pipe_t *pipe)
{
  assert(pipe && pipe->topic);

  if (pipe->topic)
    return pipe->topic->ops.serialization_required(pipe->topic->data_type_props);
  else
    return true;
}
