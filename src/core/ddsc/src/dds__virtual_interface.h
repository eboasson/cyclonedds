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

#include "dds/ddsc/dds_virtual_interface.h"
#include "dds/ddsc/dds_public_impl.h"

struct ddsi_domaingv;
struct ddsi_sertype;
struct dds_ktopic;

/*function used to calculate the topic identifier*/
virtual_interface_topic_identifier_t calculate_topic_identifier(const struct dds_ktopic * ktopic);

/*function used to calculate the interface identifier*/
dds_loan_origin_type_t calculate_interface_identifier(const struct ddsi_domaingv * cyclone_domain, const char *config_name);

/*function used to parse the properties of a data type*/
virtual_interface_data_type_properties_t calculate_data_type_properties(const dds_topic_descriptor_t * t_d);

#endif // DDS__VIRTUAL_INTERFACE_H
