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

#ifndef DDS__VIRTUAL_INTERFACE_H
#define DDS__VIRTUAL_INTERFACE_H

#include "dds/ddsi/ddsi_sertype.h"
#include "dds/ddsc/dds_virtual_interface.h"
#include "dds/ddsc/dds_public_impl.h"

struct ddsi_domaingv;
struct dds_domain;
struct dds_ktopic;
struct dds_endpoint;

DDSRT_STATIC_ASSERT (sizeof (dds_virtual_interface_data_type_properties_t) == sizeof (ddsi_data_type_properties_t));

/* linked list describing a number of topics */
struct dds_virtual_interface_topic_list_elem {
  struct dds_virtual_interface_topic * topic; /*the current element in the list*/
  struct dds_virtual_interface_topic_list_elem * prev; /*the previous element in the list*/
  struct dds_virtual_interface_topic_list_elem * next; /*the next element in the list*/
};

/* linked list describing a number of pipes */
struct dds_virtual_interface_pipe_list_elem {
  struct dds_virtual_interface_pipe * pipe; /*the current element in the list*/
  struct dds_virtual_interface_pipe_list_elem * prev; /*the previous element in the list*/
  struct dds_virtual_interface_pipe_list_elem * next; /*the next element in the list*/
};

struct dds_virtual_interface_pipe * dds_virtual_interface_pipe_open (struct dds_virtual_interface_topic *topic, dds_virtual_interface_pipe_type_t pipe_type);

dds_return_t dds_virtual_interface_pipe_close (struct dds_virtual_interface_pipe *pipe);


/*function used to calculate the topic identifier*/
dds_virtual_interface_topic_identifier_t dds_calculate_topic_identifier (const struct dds_ktopic *ktopic);


/**
 * @brief Definition for the function to load a virtual interface.
 *
 * This function is exported from the virtual interface library.
 *
 * @returns a DDS return code
 */
typedef dds_return_t (*dds_virtual_interface_create_fn) (
  struct dds_virtual_interface **virtual_interface, /*output for the virtual interface to be created*/
  dds_loan_origin_type_t identifier, /*the unique identifier for this interface*/
  const char *config /*virtual interface-specific configuration*/
);

dds_return_t dds_virtual_interfaces_init (const struct ddsi_domaingv *gv, struct dds_domain *domain);

dds_return_t dds_virtual_interfaces_fini (struct dds_domain *domain);

dds_return_t dds_endpoint_open_virtual_pipes (struct dds_endpoint *ep, const dds_qos_t *qos, struct dds_virtual_topics_set *virtual_topics, enum dds_virtual_interface_pipe_type pipe_type);
struct ddsi_virtual_locators_set *dds_get_virtual_locators_set (const dds_qos_t *qos, const struct dds_virtual_interfaces_set *vi_set);
void dds_virtual_locators_set_free (struct ddsi_virtual_locators_set *vl_set);

#endif // DDS__VIRTUAL_INTERFACE_H
