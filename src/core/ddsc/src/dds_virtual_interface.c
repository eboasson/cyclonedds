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

#include "dds__alloc.h"
#include "dds/ddsi/ddsi_locator.h"
#include "dds/ddsi/ddsi_domaingv.h"
#include "dds/ddsrt/mh3.h"

bool add_topic_to_list (
  ddsi_virtual_interface_topic_t *toadd,
  ddsi_virtual_interface_topic_list_elem_t **addto)
{
  ddsi_virtual_interface_topic_list_elem_t *ptr = dds_alloc(sizeof(ddsi_virtual_interface_topic_list_elem_t));

  if (!ptr)
    return false;

  ptr->topic = toadd;
  ptr->next = NULL;

  if (!*addto) {
    //there is no list yet
    ptr->prev = NULL;
    *addto = ptr;
  } else {
    //add to the end of the list
    ddsi_virtual_interface_topic_list_elem_t *ptr2 = *addto;
    while (ptr2->next) {
      ptr2 = ptr2->next;
    }
    ptr2->next = ptr;
    ptr->prev = ptr2;
  }

  return true;
}

bool remove_topic_from_list (
  ddsi_virtual_interface_topic_t *to_remove,
  ddsi_virtual_interface_topic_list_elem_t **remove_from)
{
  assert (to_remove);

  if (!remove_from || !*remove_from)
    return false;

  ddsi_virtual_interface_topic_list_elem_t *list_entry = *remove_from;

  while (list_entry && list_entry->topic != to_remove) {
    list_entry = list_entry->next;
  }

  if (!list_entry ||  //no entry in the list matching the topic
      !list_entry->topic->virtual_interface->ops.topic_destruct(list_entry->topic)) //destruct failure
    return false;

  if (list_entry->prev)
    list_entry->prev->next = list_entry->next;

  if (list_entry->next)
    list_entry->next->prev = list_entry->prev;

  if (list_entry == *remove_from)
    *remove_from = list_entry->next;

  dds_free(list_entry);

  return true;
}

bool add_pipe_to_list (
  ddsi_virtual_interface_pipe_t *toadd,
  ddsi_virtual_interface_pipe_list_elem_t **addto)
{
  ddsi_virtual_interface_pipe_list_elem_t *ptr = dds_alloc(sizeof(ddsi_virtual_interface_pipe_list_elem_t));

  if (!ptr)
    return false;

  ptr->pipe = toadd;
  ptr->next = NULL;

  if (!*addto) {
    //there is no list yet
    ptr->prev = NULL;
    *addto = ptr;
  } else {
    //add to the end of the list
    ddsi_virtual_interface_pipe_list_elem_t *ptr2 = *addto;
    while (ptr2->next) {
      ptr2 = ptr2->next;
    }
    ptr2->next = ptr;
    ptr->prev = ptr2;
  }

  return true;
}

bool remove_pipe_from_list (
  ddsi_virtual_interface_pipe_t *to_remove,
  ddsi_virtual_interface_pipe_list_elem_t **remove_from)
{
  assert (to_remove);

  if (!remove_from || !*remove_from)
    return false;

  ddsi_virtual_interface_pipe_list_elem_t *list_entry = *remove_from;

  while (list_entry && list_entry->pipe != to_remove) {
    list_entry = list_entry->next;
  }

  if (!list_entry ||  //no entry in the list matching the topic
      !ddsi_virtual_interface_pipe_close(list_entry->pipe))   //destruct failure
    return false;

  if (list_entry->prev)
    list_entry->prev->next = list_entry->next;

  if (list_entry->next)
    list_entry->next->prev = list_entry->prev;

  if (list_entry == *remove_from)
    *remove_from = list_entry->next;

  dds_free(list_entry);

  return true;
}

virtual_interface_topic_identifier_t calculate_topic_identifier(
  const struct dds_ktopic * ktopic)
{
  return ddsrt_mh3(ktopic->name, strlen(ktopic->name), 0x0);
}

dds_loan_origin_type_t calculate_interface_identifier(
  const struct ddsi_domaingv * cyclone_domain,
  const char *config_name)
{
  uint32_t val = cyclone_domain->config.extDomainId.value;
  uint32_t mid = ddsrt_mh3(&val, sizeof(val), 0x0);
  return ddsrt_mh3(config_name, strlen(config_name), mid);
}

virtual_interface_data_type_properties_t calculate_data_type_properties(
  const dds_topic_descriptor_t * t_d)
{
  (void) t_d;

  return DATA_TYPE_CALCULATED; //TODO!!! IMPLEMENT!!!
}

bool ddsi_virtual_interface_init_generic(
  ddsi_virtual_interface_t * to_init)
{
  struct ddsi_locator * loc = (struct ddsi_locator *)ddsrt_calloc(1,sizeof(ddsi_locator_t));

  if (!loc)
    return false;

  ddsi_virtual_interface_node_identifier_t vini = to_init->ops.get_node_id(to_init);

  memcpy(loc->address, &vini, sizeof(vini));
  loc->port = to_init->interface_id;
  loc->kind = NN_LOCATOR_KIND_SHEM;

  to_init->locator = loc;

  return true;
}

bool ddsi_virtual_interface_cleanup_generic(
  ddsi_virtual_interface_t *to_cleanup)
{
  ddsrt_free((void*)to_cleanup->locator);

  while (to_cleanup->topics) {
    if (!remove_topic_from_list(to_cleanup->topics->topic, &to_cleanup->topics))
      return false;
  }

  return true;
}

bool ddsi_virtual_interface_topic_init_generic(
  ddsi_virtual_interface_topic_t *to_init,
  const ddsi_virtual_interface_t * virtual_interface)
{
  to_init->data_type = ddsrt_mh3(&virtual_interface->interface_id, sizeof(virtual_interface->interface_id), to_init->topic_id);

  return true;
}

bool ddsi_virtual_interface_topic_cleanup_generic(
  ddsi_virtual_interface_topic_t *to_cleanup)
{
  while (to_cleanup->pipes) {
    if (!remove_pipe_from_list(to_cleanup->pipes->pipe, &to_cleanup->pipes))
      return false;
  }

  return true;
}

ddsi_virtual_interface_pipe_t * ddsi_virtual_interface_pipe_open (
    ddsi_virtual_interface_topic_t * topic,
  dds_virtual_interface_pipe_type_t pipe_type)
{
  assert (topic && topic->ops.pipe_open);

  return topic->ops.pipe_open(topic, pipe_type);
}

bool ddsi_virtual_interface_pipe_close(
  ddsi_virtual_interface_pipe_t *pipe)
{
  assert (pipe && pipe->topic && pipe->topic->ops.pipe_close);

  return pipe->topic->ops.pipe_close(pipe);
}

dds_loaned_sample_t* ddsi_virtual_interface_pipe_request_loan(
  ddsi_virtual_interface_pipe_t *pipe,
  uint32_t sz)
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
