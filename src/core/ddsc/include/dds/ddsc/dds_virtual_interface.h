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
#ifndef DDS_VIRTUAL_INTERFACE_H
#define DDS_VIRTUAL_INTERFACE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "dds/export.h"
#include "dds/ddsc/dds_basic_types.h"
#include "dds/ddsc/dds_loan.h"
#include "dds/ddsi/ddsi_guid.h"
#include "dds/ddsi/ddsi_keyhash.h"
#include "dds/ddsrt/time.h"

/*forward declarations of used data types*/
struct dds_qos;
struct ddsi_locator;  //is private header
struct ddsi_domaingv; //is private header

/*forward declarations of virtual interfaces data types*/
typedef struct ddsi_virtual_interface ddsi_virtual_interface_t;
typedef struct ddsi_virtual_interface_topic ddsi_virtual_interface_topic_t;
typedef struct ddsi_virtual_interface_pipe ddsi_virtual_interface_pipe_t;

#define MAX_VIRTUAL_INTERFACES 8

/* linked list describing a number of topics
*/
typedef struct ddsi_virtual_interface_topic_list_elem ddsi_virtual_interface_topic_list_elem_t;
struct ddsi_virtual_interface_topic_list_elem {
  ddsi_virtual_interface_topic_t * topic; /*the current element in the list*/
  ddsi_virtual_interface_topic_list_elem_t * prev; /*the previous element in the list*/
  ddsi_virtual_interface_topic_list_elem_t * next; /*the next element in the list*/
};

/* adds a topic to the list, will create the first list entry if it does not yet exist
*/
DDS_EXPORT bool add_topic_to_list (
  ddsi_virtual_interface_topic_t * toadd,
  ddsi_virtual_interface_topic_list_elem_t ** addto);

/* removes a topic from the list, will set the pointer to the list to null if the last entry is removed
*/
DDS_EXPORT bool remove_topic_from_list (
  ddsi_virtual_interface_topic_t * to_remove,
  ddsi_virtual_interface_topic_list_elem_t ** remove_from);

/* linked list describing a number of pipes
*/
typedef struct ddsi_virtual_interface_pipe_list_elem ddsi_virtual_interface_pipe_list_elem_t;
struct ddsi_virtual_interface_pipe_list_elem {
  ddsi_virtual_interface_pipe_t * pipe; /*the current element in the list*/
  ddsi_virtual_interface_pipe_list_elem_t * prev; /*the previous element in the list*/
  ddsi_virtual_interface_pipe_list_elem_t * next; /*the next element in the list*/
};

/* adds a pipe to the list, will create the first list entry if it does not yet exist
*/
DDS_EXPORT bool add_pipe_to_list (
  ddsi_virtual_interface_pipe_t * toadd,
  ddsi_virtual_interface_pipe_list_elem_t ** addto);

/* removes a pipe from the list, will set the pointer to the list to null if the last entry is removed
*/
DDS_EXPORT bool remove_pipe_from_list (
  ddsi_virtual_interface_pipe_t * to_remove,
  ddsi_virtual_interface_pipe_list_elem_t ** remove_from);

/*identifier used to uniquely identify a topic across different processes*/
typedef uint32_t virtual_interface_topic_identifier_t;

/*identifier used to communicate the properties of the data being communicated*/
typedef uint64_t virtual_interface_data_type_properties_t;

/*identifier used to distinguish between interfaces on nodes*/
typedef uint64_t ddsi_virtual_interface_node_identifier_t;

#define DATA_TYPE_FINAL_MODIFIER_OFFSET       0
#define DATA_TYPE_APPENDABLE_MODIFIER_OFFSET  DATA_TYPE_FINAL_MODIFIER_OFFSET+1
#define DATA_TYPE_MUTABLE_MODIFIER_OFFSET     DATA_TYPE_APPENDABLE_MODIFIER_OFFSET+1
#define DATA_TYPE_FINAL_MODIFIER              0x1ull << DATA_TYPE_FINAL_MODIFIER_OFFSET
#define DATA_TYPE_APPENDABLE_MODIFIER         0x1ull << DATA_TYPE_APPENDABLE_MODIFIER_OFFSET
#define DATA_TYPE_MUTABLE_MODIFIER            0x1ull << DATA_TYPE_MUTABLE_MODIFIER_OFFSET
#define DATA_TYPE_CONTAINS_UNION              0x1ull
#define DATA_TYPE_CONTAINS_BITMASK            DATA_TYPE_CONTAINS_UNION << (DATA_TYPE_MUTABLE_MODIFIER_OFFSET+1)
#define DATA_TYPE_CONTAINS_ENUM               DATA_TYPE_CONTAINS_BITMASK << (DATA_TYPE_MUTABLE_MODIFIER_OFFSET+1)
#define DATA_TYPE_CONTAINS_STRUCT             DATA_TYPE_CONTAINS_ENUM << (DATA_TYPE_MUTABLE_MODIFIER_OFFSET+1)
#define DATA_TYPE_CONTAINS_STRING             DATA_TYPE_CONTAINS_STRUCT << (DATA_TYPE_MUTABLE_MODIFIER_OFFSET+1)
#define DATA_TYPE_CONTAINS_BSTRING            DATA_TYPE_CONTAINS_STRING << 1
#define DATA_TYPE_CONTAINS_WSTRING            DATA_TYPE_CONTAINS_BSTRING << 1
#define DATA_TYPE_CONTAINS_SEQUENCE           DATA_TYPE_CONTAINS_WSTRING << 1
#define DATA_TYPE_CONTAINS_BSEQUENCE          DATA_TYPE_CONTAINS_SEQUENCE << 1
#define DATA_TYPE_CONTAINS_ARRAY              DATA_TYPE_CONTAINS_BSEQUENCE << 1
#define DATA_TYPE_CONTAINS_OPTIONAL           DATA_TYPE_CONTAINS_ARRAY << 1
#define DATA_TYPE_CONTAINS_EXTERNAL           DATA_TYPE_CONTAINS_OPTIONAL << 1
#define DATA_TYPE_CALCULATED                  0x1ull << 63
#define DATA_TYPE_CONTAINS_INDIRECTIONS       DATA_TYPE_CALCULATED >> 1
#define DATA_TYPE_IS_FIXED_SIZE               DATA_TYPE_CONTAINS_INDIRECTIONS >> 1

/*the type of a pipe*/
typedef enum dds_virtual_interface_pipe_type {
  DDS_VIRTUAL_INTERFACE_PIPE_TYPE_UNSET,
  DDS_VIRTUAL_INTERFACE_PIPE_TYPE_SOURCE,
  DDS_VIRTUAL_INTERFACE_PIPE_TYPE_SINK
} dds_virtual_interface_pipe_type_t;

/*describes the data which is transferred in addition to just the sample*/  //move to dds_loan.h?
typedef struct dds_virtual_interface_metadata {
  dds_loaned_sample_state_t sample_state;
  dds_loan_data_type_t data_type;
  dds_loan_origin_type_t data_origin;
  uint32_t sample_size;
  uint32_t block_size;
  ddsi_guid_t guid;
  dds_time_t timestamp;
  uint32_t statusinfo;
  uint32_t hash;
  uint16_t cdr_identifier;
  uint16_t cdr_options;
  ddsi_keyhash_t keyhash;
  uint32_t keysize : 30;  //to mirror fixed width of ddsi_serdata_default_key.keysize
} dds_virtual_interface_metadata_t;

/*
*/
typedef bool (*ddsi_virtual_interface_match_locator_f) (
  ddsi_virtual_interface_t * vi,
  const struct ddsi_locator * locator
);

/* returns true when a data type is supported
*/
typedef bool (*ddsi_virtual_interface_data_type_supported_f) (
  virtual_interface_data_type_properties_t data_type_props
);

/* returns true when a qos is supported
*/
typedef bool (*ddsi_virtual_interface_qos_supported_f) (
  const struct dds_qos * qos
);

/* creates a virtual interface topic
*/
typedef ddsi_virtual_interface_topic_t* (*ddsi_virtual_interface_topic_create_f) (
  ddsi_virtual_interface_t * vi,
  virtual_interface_topic_identifier_t topic_identifier,
  virtual_interface_data_type_properties_t data_type_props
);

/* destructs a virtual interface topic
*/
typedef bool (*ddsi_virtual_interface_topic_destruct_f) (
  ddsi_virtual_interface_topic_t * vi_topic
);

/* checks whether serialization is required on this
* returns true on success
*/
typedef bool (*ddsi_virtual_interface_serialization_required_f) (
  virtual_interface_data_type_properties_t data_type_props  /*the data type to check whether serialization is required*/
);

/* opens a pipe on a virtual interface
* returns true on success
*/
typedef ddsi_virtual_interface_pipe_t* (*ddsi_virtual_interface_pipe_open_f) (
  ddsi_virtual_interface_topic_t * topic,  /*the topic to create the pipe on*/
  dds_virtual_interface_pipe_type_t pipe_type /*type type of pipe to open*/
);

/* closes a pipe
* returns true on success
*/
typedef bool (*ddsi_virtual_interface_pipe_close_f) (
  ddsi_virtual_interface_pipe_t * pipe  /*the pipe to close*/
);

/* requests a loan from the virtual interface
* returns a pointer to the loaned block on success
*/
typedef dds_loaned_sample_t* (*ddsi_virtual_interface_pipe_request_loan_f) (
  ddsi_virtual_interface_pipe_t * pipe, /*the pipe to loan from*/
  uint32_t size_requested /*the size of the loan requested*/
);

/* sinks data on a pipe
* returns true on success
*/
typedef bool (*ddsi_virtual_interface_pipe_sink_data_f) (
  ddsi_virtual_interface_pipe_t * pipe, /*the pipe to sink the data on*/
  dds_loaned_sample_t * data  /*the data to sink*/
);

/* sources data on a pipe
* used in a poll based implementation
* returns the oldest unsourced received block of memory
*/
typedef dds_loaned_sample_t* (*ddsi_virtual_interface_pipe_source_data_f) (
  ddsi_virtual_interface_pipe_t * pipe /*the pipe to source the data from*/
);

/* callback function setter
* returns true on success
*/
typedef bool (*ddsi_virtual_interface_pipe_enable_on_source_data_f) (
  ddsi_virtual_interface_pipe_t * pipe, /*the pipe to set the callback function on*/
  dds_entity_t reader /*the reader associated with the pipe*/
);

/* virtual interface cleanup function
* returns true on success
*/
typedef bool (*ddsi_virtual_interface_deinit_f) (
  ddsi_virtual_interface_t * vi
);

/* virtual interface locator generation function
* returns a locator which is unique between nodes, but identical for instances on the same node
*/
typedef ddsi_virtual_interface_node_identifier_t (*ddsi_virtual_interface_get_node_identifier_f) (
  const ddsi_virtual_interface_t * vi
);

/* container for all functions which are used on a virtual interface
*/
typedef struct ddsi_virtual_interface_ops {
  ddsi_virtual_interface_match_locator_f        match_locator;
  ddsi_virtual_interface_data_type_supported_f  data_type_supported;
  ddsi_virtual_interface_qos_supported_f        qos_supported;
  ddsi_virtual_interface_topic_create_f         topic_create;
  ddsi_virtual_interface_topic_destruct_f       topic_destruct;
  ddsi_virtual_interface_deinit_f               deinit;
  ddsi_virtual_interface_get_node_identifier_f  get_node_id;
} ddsi_virtual_interface_ops_t;

/* container for all functions which are used on a virtual interface topic
*/
typedef struct ddsi_virtual_interface_topic_ops {
  ddsi_virtual_interface_serialization_required_f serialization_required;
  ddsi_virtual_interface_pipe_open_f              pipe_open;
  ddsi_virtual_interface_pipe_close_f             pipe_close;
} ddsi_virtual_interface_topic_ops_t;

/* container for all functions which are used on a virtual interface pipe
*/
typedef struct ddsi_virtual_interface_pipe_ops {
  ddsi_virtual_interface_pipe_request_loan_f          req_loan;
  ddsi_virtual_interface_pipe_sink_data_f             sink_data;
  ddsi_virtual_interface_pipe_source_data_f           source_data;
  /*if the set_on_source is not set, then there is no event based functionality, you will need to poll for new data*/
  ddsi_virtual_interface_pipe_enable_on_source_data_f set_on_source;
} ddsi_virtual_interface_pipe_ops_t;

/* the top-level entry point on the virtual interface
* is bound to a specific implementation of a virtual interface
*/
struct ddsi_virtual_interface {
  ddsi_virtual_interface_ops_t ops; /*associated functions*/
  const char * interface_name; /*type of interface being used*/
  int32_t priority; /*priority of choosing this interface*/
  const struct ddsi_locator * locator; /*the locator for this virtual interface*/
  dds_loan_origin_type_t interface_id; /*the unique id of this interface*/
  ddsi_virtual_interface_topic_list_elem_t * topics; /*associated topics*/
};

/**
 * initialization function for the C-level administration, should be called from all
 * constructors of class which inherit from ddsi_virtual_interface_t
 */
DDS_EXPORT bool ddsi_virtual_interface_init_generic(
  ddsi_virtual_interface_t * to_init);

/**
 * cleanup function for the C-level administration, should be called from all
 * destructors of classes which inherit from ddsi_virtual_interface_t
 */
DDS_EXPORT bool ddsi_virtual_interface_cleanup_generic(ddsi_virtual_interface_t *to_cleanup);

/* the topic-level virtual interface
* this will exchange data for readers and writers which are matched through discovery
* will only exchange a single type of data!
*/
struct ddsi_virtual_interface_topic {
  ddsi_virtual_interface_topic_ops_t ops; /*associated functions*/
  ddsi_virtual_interface_t * virtual_interface; /*the virtual interface which created this pipe*/
  virtual_interface_topic_identifier_t topic_id; /*unique identifier of topic representation*/
  dds_loan_data_type_t data_type; /*the unique identifier associated with the data type of this topic*/
  ddsi_virtual_interface_pipe_list_elem_t * pipes; /*associated pipes*/
  virtual_interface_data_type_properties_t data_type_props; /*the properties of the datatype associated with this topic*/
};

/**
 * init function for the C-level administration, should be called from all
 * constructors of classes which inherit from ddsi_virtual_interface_topic_t
 */
DDS_EXPORT bool ddsi_virtual_interface_topic_init_generic(ddsi_virtual_interface_topic_t *to_init, const ddsi_virtual_interface_t * virtual_interface);

/**
 * cleanup function for the C-level administration, should be called from all
 * destructors of classes which inherit from ddsi_virtual_interface_topic_t
 */
DDS_EXPORT bool ddsi_virtual_interface_topic_cleanup_generic(ddsi_virtual_interface_topic_t *to_cleanup);

/* the definition of one instance of a dds
* reader/writer using a virtual interface
*/
struct ddsi_virtual_interface_pipe {
  ddsi_virtual_interface_pipe_ops_t ops; /*associated functions*/
  ddsi_virtual_interface_topic_t * topic; /*the topic this pipe belongs to*/
  dds_virtual_interface_pipe_type_t pipe_type; /*type type of pipe*/
};

/**
 * opens a new pipe
 */
ddsi_virtual_interface_pipe_t * ddsi_virtual_interface_pipe_open (
  ddsi_virtual_interface_topic_t * topic,  /*the topic to create the pipe on*/
  dds_virtual_interface_pipe_type_t pipe_type /*type type of pipe to open*/);

/**
 * closes a pipe
 */
DDS_EXPORT bool ddsi_virtual_interface_pipe_close(
  ddsi_virtual_interface_pipe_t *pipe /*the pipe to close*/);

/**
 * requests a loan from pipe
 */
DDS_EXPORT dds_loaned_sample_t* ddsi_virtual_interface_pipe_request_loan(ddsi_virtual_interface_pipe_t *pipe, uint32_t sz);

/**
 * whether the pipe requires the sample to be serialized for transfer
 */
DDS_EXPORT bool ddsi_virtual_interface_pipe_serialization_required(ddsi_virtual_interface_pipe_t *pipe);

/* this is the only function exported from the virtual interface library
* returns true on success
*/
typedef bool (*ddsi_virtual_interface_create_fn) (
  ddsi_virtual_interface_t **virtual_interface, /*output for the virtual interface to be created*/
  dds_loan_origin_type_t identifier, /*the unique identifier for this interface*/
  const char *config /*virtual interface-specific configuration*/
);
#endif // DDS_VIRTUAL_INTERFACE_H
