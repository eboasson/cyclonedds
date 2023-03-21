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

/**
 * @defgroup virtinf (Virtual Interfaces)
 * @ingroup dds
 */
#ifndef DDS_VIRTUAL_INTERFACE_H
#define DDS_VIRTUAL_INTERFACE_H

#include "dds/export.h"
#include "dds/dds.h"

#if defined (__cplusplus)
extern "C" {
#endif

#define DDS_MAX_VIRTUAL_INTERFACES 8


#define DDS_DATA_TYPE_FINAL_MODIFIER              0x1ull << 0
#define DDS_DATA_TYPE_APPENDABLE_MODIFIER         0x1ull << 1
#define DDS_DATA_TYPE_MUTABLE_MODIFIER            0x1ull << 2

#define DDS_DATA_TYPE_CONTAINS_UNION              0x1ull << 3
#define DDS_DATA_TYPE_CONTAINS_BITMASK            0x1ull << 4
#define DDS_DATA_TYPE_CONTAINS_ENUM               0x1ull << 5
#define DDS_DATA_TYPE_CONTAINS_STRUCT             0x1ull << 6
#define DDS_DATA_TYPE_CONTAINS_STRING             0x1ull << 7
#define DDS_DATA_TYPE_CONTAINS_BSTRING            0x1ull << 8
#define DDS_DATA_TYPE_CONTAINS_WSTRING            0x1ull << 9
#define DDS_DATA_TYPE_CONTAINS_SEQUENCE           0x1ull << 10
#define DDS_DATA_TYPE_CONTAINS_BSEQUENCE          0x1ull << 11
#define DDS_DATA_TYPE_CONTAINS_ARRAY              0x1ull << 12
#define DDS_DATA_TYPE_CONTAINS_OPTIONAL           0x1ull << 13
#define DDS_DATA_TYPE_CONTAINS_EXTERNAL           0x1ull << 14

#define DDS_DATA_TYPE_IS_FIXED_SIZE               0x1ull << 61
#define DDS_DATA_TYPE_CONTAINS_INDIRECTIONS       0x1ull << 62
#define DDS_DATA_TYPE_CALCULATED                  0x1ull << 63

struct dds_virtual_interface;
struct dds_virtual_interface_topic;
struct dds_virtual_interface_topic_list_elem;
struct dds_virtual_interface_pipe;
struct dds_virtual_interface_pipe_list_elem;

/**
 * @brief Type of the virtual interface pipe
 */
typedef enum dds_virtual_interface_pipe_type {
  DDS_VIRTUAL_INTERFACE_PIPE_TYPE_UNSET,
  DDS_VIRTUAL_INTERFACE_PIPE_TYPE_SOURCE,
  DDS_VIRTUAL_INTERFACE_PIPE_TYPE_SINK
} dds_virtual_interface_pipe_type_t;

/**
 * @brief identifier used to uniquely identify a topic across different processes
 */
typedef uint32_t dds_virtual_interface_topic_identifier_t;

/**
 * @brief identifier used to communicate the properties of the data being communicated
 */
typedef uint64_t dds_virtual_interface_data_type_properties_t;

/**
 * @brief identifier used to distinguish between interfaces on nodes
 */
typedef uint64_t dds_virtual_interface_node_identifier_t;


typedef bool (*dds_virtual_interface_data_type_supported_f) (dds_virtual_interface_data_type_properties_t data_type_props);
typedef bool (*dds_virtual_interface_qos_supported_f) (const struct dds_qos *qos);
typedef struct dds_virtual_interface_topic * (* dds_virtual_interface_topic_create_f) (
    struct dds_virtual_interface * vi,
    dds_virtual_interface_topic_identifier_t topic_identifier,
    dds_virtual_interface_data_type_properties_t data_type_props);
typedef bool (*dds_virtual_interface_topic_destruct_f) (struct dds_virtual_interface_topic *vi_topic);

/**
 * @brief virtual interface cleanup function
 *
 * @param[in] vi  the virtual interface to de-initialize
 * @returns true on success
 */
typedef bool (*dds_virtual_interface_deinit_f) (struct dds_virtual_interface *vi);

/**
 * @brief virtual interface locator generation function
 *
 * Returns a locator which is unique between nodes, but identical for instances on
 * the same node
 *
 * @param[in] vi a virtual interface
 * @returns a unique locator
 */
typedef dds_virtual_interface_node_identifier_t (* dds_virtual_interface_get_node_identifier_f) (const struct dds_virtual_interface *vi);

/**
 * @brief functions which are used on a virtual interface
 */
typedef struct dds_virtual_interface_ops {
  dds_virtual_interface_data_type_supported_f  data_type_supported;
  dds_virtual_interface_qos_supported_f        qos_supported;
  dds_virtual_interface_topic_create_f         topic_create;
  dds_virtual_interface_topic_destruct_f       topic_destruct;
  dds_virtual_interface_deinit_f               deinit;
  dds_virtual_interface_get_node_identifier_f  get_node_id;
} dds_virtual_interface_ops_t;


typedef bool (* dds_virtual_interface_serialization_required_f) (dds_virtual_interface_data_type_properties_t data_type_props);
typedef struct dds_virtual_interface_pipe * (* dds_virtual_interface_pipe_open_f) (struct dds_virtual_interface_topic *topic, dds_virtual_interface_pipe_type_t pipe_type);
typedef bool (* dds_virtual_interface_pipe_close_f) (struct dds_virtual_interface_pipe *pipe);

/**
 * @brief functions which are used on a virtual interface topic
 */
typedef struct dds_virtual_interface_topic_ops {
  dds_virtual_interface_serialization_required_f serialization_required;
  dds_virtual_interface_pipe_open_f              pipe_open;
  dds_virtual_interface_pipe_close_f             pipe_close;
} dds_virtual_interface_topic_ops_t;


/**
 * @brief requests a loan from the virtual interface
 *
 * @param[in] pipe            the pipe to loan from
 * @param[in] size_requested  the size of the loan requested
 * @returns a pointer to the loaned block on success
 */
typedef dds_loaned_sample_t * (* dds_virtual_interface_pipe_request_loan_f) (struct dds_virtual_interface_pipe *pipe, uint32_t size_requested);

/**
 * @brief Sinks data on a pipe
 *
 * @param[in] pipe    The pipe to sink the data on
 * @param[in] data    The data to sink
 * @returns true on success
 */
typedef bool (* dds_virtual_interface_pipe_sink_data_f) (struct dds_virtual_interface_pipe *pipe, dds_loaned_sample_t *data);

/**
 * @brief Sources data on a pipe, used in a poll based implementation.
 *
 * @param[in] pipe The pipe to source the data from
 * @returns the oldest unsourced received block of memory
 */
typedef dds_loaned_sample_t * (* dds_virtual_interface_pipe_source_data_f) (struct dds_virtual_interface_pipe *pipe);

/**
 * @brief callback function setter
 *
 * @param[in] pipe      the pipe to set the callback function on
 * @param[in] reader    the reader associated with the pipe
 * @returns true on success
 */
typedef bool (* dds_virtual_interface_pipe_enable_on_source_data_f) (struct dds_virtual_interface_pipe *pipe, dds_entity_t reader);

/**
 * @brief Functions that are used on a Virtual Interface Pipe
 *
 * @note if the set_on_source is not set, then there is no event based functionality,
 * you will need to poll for new data
 */
typedef struct dds_virtual_interface_pipe_ops {
  dds_virtual_interface_pipe_request_loan_f          req_loan;
  dds_virtual_interface_pipe_sink_data_f             sink_data;
  dds_virtual_interface_pipe_source_data_f           source_data;
  dds_virtual_interface_pipe_enable_on_source_data_f set_on_source;
} dds_virtual_interface_pipe_ops_t;

// FIXME: move to dds_loan.h?
/**
 * @brief describes the data which is transferred in addition to just the sample
 */
struct dds_virtual_interface_metadata {
  dds_loaned_sample_state_t sample_state;
  dds_loan_data_type_t data_type;
  dds_loan_origin_type_t data_origin;
  uint32_t sample_size;
  uint32_t block_size;
  dds_guid_t guid;
  dds_time_t timestamp;
  uint32_t statusinfo;
  uint32_t hash;
  uint16_t cdr_identifier;
  uint16_t cdr_options;
  ddsi_keyhash_t keyhash;
  uint32_t keysize : 30;  // to mirror fixed width of dds_serdata_default_key.keysize
};

/**
 * @brief the top-level entry point on the virtual interface is bound to a specific implementation of a virtual interface
 */
struct dds_virtual_interface {
  dds_virtual_interface_ops_t ops; /*associated functions*/
  const char *interface_name; /*type of interface being used*/
  int32_t priority; /*priority of choosing this interface*/
  const struct ddsi_locator *locator; /*the locator for this virtual interface*/
  dds_loan_origin_type_t interface_id; /*the unique id of this interface*/
  struct dds_virtual_interface_topic_list_elem *topics; /*associated topics*/
};

/**
 * @brief the topic-level virtual interface
 *
 * this will exchange data for readers and writers which are matched through discovery
 * will only exchange a single type of data
 */
struct dds_virtual_interface_topic {
  dds_virtual_interface_topic_ops_t ops; /*associated functions*/
  struct dds_virtual_interface *virtual_interface; /*the virtual interface which created this pipe*/
  dds_virtual_interface_topic_identifier_t topic_id; /*unique identifier of topic representation*/
  dds_loan_data_type_t data_type; /*the unique identifier associated with the data type of this topic*/
  struct dds_virtual_interface_pipe_list_elem *pipes; /*associated pipes*/
  dds_virtual_interface_data_type_properties_t data_type_props; /*the properties of the datatype associated with this topic*/
};

/**
 * @brief the definition of one instance of a dds reader/writer using a virtual interface
 */
struct dds_virtual_interface_pipe {
  dds_virtual_interface_pipe_ops_t ops; /*associated functions*/
  struct dds_virtual_interface_topic * topic; /*the topic this pipe belongs to*/
  dds_virtual_interface_pipe_type_t pipe_type; /*type type of pipe*/
};


/**
 * @brief adds a topic to the list
 *
 * will create the first list entry if it does not yet exist
 *
 * @param[in] topic     the topic to add
 * @param[in/out] list  list to add the topic to
 * @return DDS_RETCODE_OK on success
 */
DDS_EXPORT dds_return_t dds_add_vi_topic_to_list (struct dds_virtual_interface_topic *topic, struct dds_virtual_interface_topic_list_elem **list);

/**
 * @brief removes a topic from the list
 *
 * will set the pointer to the list to null if the last entry is removed
 *
 * @param[in] topic     the topic to remove
 * @param[in/out] list  list to remove the topic from
 * @return DDS_RETCODE_OK on success
 */
DDS_EXPORT dds_return_t dds_remove_vi_topic_from_list (struct dds_virtual_interface_topic *topic, struct dds_virtual_interface_topic_list_elem **list);

/**
 * @brief adds a pipe to the list
 *
 * will create the first list entry if it does not yet exist
 *
 * @param[in] pipe   the pipe to add
 * @param[in/out] list   list to add the pipe to
 * @return DDS_RETCODE_OK on success
 */
DDS_EXPORT dds_return_t dds_add_vi_pipe_to_list (struct dds_virtual_interface_pipe *pipe, struct dds_virtual_interface_pipe_list_elem **list);

/**
 * @brief removes a pipe from the list
 *
 * will set the pointer to the list to null if the last entry is removed
 *
 * @param[in] pipe  the pipe to remove
 * @param[in/out] list  list to remove the pipe from
 * @return DDS_RETCODE_OK on success
 */
DDS_EXPORT dds_return_t dds_remove_vi_pipe_from_list (struct dds_virtual_interface_pipe *pipe, struct dds_virtual_interface_pipe_list_elem **list);

/**
 * @brief initialization function for virtual interface
 *
 * Should be called from all constructors of class which inherit from dds_virtual_interface_t
 *
 * @param[in] virtual_interface  the virtual interface to initialize
 * @returns true on success
 */
DDS_EXPORT bool dds_virtual_interface_init_generic (struct dds_virtual_interface *virtual_interface);

/**
 * @brief cleanup function for a virtual interface
 *
 * Should be called from all destructors of classes which inherit from dds_virtual_interface_t
 *
 * @param[in] virtual_interface  the virtual interface to cleanup
 * @returns true on success
 */
DDS_EXPORT bool dds_virtual_interface_cleanup_generic (struct dds_virtual_interface *virtual_interface);

/**
 * @brief init function for topic
 *
 * Should be called from all constructors of classes which inherit from struct dds_virtual_interface_topic
 *
 * @param[in] topic             the topic to initialize
 * @param[in] virtual_interface the virtual interface
 * @returns true on success
 */
DDS_EXPORT bool dds_virtual_interface_topic_init_generic (struct dds_virtual_interface_topic *topic, const struct dds_virtual_interface *virtual_interface);

/**
 * @brief cleanup function for a topic
 *
 * Should be called from all destructors of classes which inherit from struct dds_virtual_interface_topic
 *
 * @param[in] topic   the topic to de-initialize
 * @returns true on success
 */
DDS_EXPORT bool dds_virtual_interface_topic_cleanup_generic(struct dds_virtual_interface_topic *topic);

/**
 * @brief Request a loan
 *
 * @param[in] pipe  the pipe to request a loan for
 * @param[in] sz    size of the loan
 * @return a loaned sample
 */
dds_loaned_sample_t * dds_virtual_interface_pipe_request_loan (struct dds_virtual_interface_pipe *pipe, uint32_t sz);

/**
 * @brief Check if serialization is required
 *
 * @param[in] pipe  the pipe
 * @returns true if serialization is required
 */
bool dds_virtual_interface_pipe_serialization_required (struct dds_virtual_interface_pipe *pipe);


#if defined (__cplusplus)
}
#endif

#endif /*DDS_VIRTUAL_INTERFACE_H*/
