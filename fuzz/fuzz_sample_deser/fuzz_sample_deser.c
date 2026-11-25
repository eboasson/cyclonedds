#include <ddsi__serdata_cdr.h>
#include <dds/ddsc/dds_internal_api.h>
#include <dds/ddsrt/heap.h>
#include <dds/ddsrt/string.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../fuzz_common.h"

#include <fuzz_samples.h>

#ifndef FUZZ_SAMPLE_DESER_XCDR_VERSION
#error "FUZZ_SAMPLE_DESER_XCDR_VERSION must be defined"
#endif

static void __attribute__((constructor)) print_idl_types_seed() {
    printf("IDL types seed: %s (XCDR%u)\n", idl_types_seed, idl_types_xcdr_version);
}

static void exercise_sequence_buffer(const struct dds_cdrstream_desc *desc, const void *data, uint32_t size,
                                     char *reference, dds_sequence_t *full, const struct fuzz_sequence_field *field)
{
    const struct dds_cdrstream_allocator *allocator = &dds_cdrstream_default_allocator;
    char *sample = ddsrt_calloc(1, desc->size);
    dds_sequence_t *seq = (dds_sequence_t *)(sample + field->offset);
    uint8_t *buffer = ddsrt_calloc(1, field->element_size);
    seq->_buffer = buffer;
    seq->_maximum = 1;
    seq->_release = false;

    dds_istream_t is;
    dds_istream_init_well_formed(&is, size, data, FUZZ_SAMPLE_DESER_XCDR_VERSION);
    dds_stream_read_sample(&is, sample, allocator, desc);
    if (seq->_buffer != buffer || seq->_maximum != 1 || seq->_length != 1 || seq->_release || is.m_index != size) {
        abort();
    }

    // Compare the retained prefix and all other members using the local type's CDR.
    dds_ostream_t expected, actual;
    dds_ostream_init(&expected, allocator, 0, FUZZ_SAMPLE_DESER_XCDR_VERSION);
    dds_ostream_init(&actual, allocator, 0, FUZZ_SAMPLE_DESER_XCDR_VERSION);
    const uint32_t full_length = full->_length;
    full->_length = 1;
    const bool expected_ok = dds_stream_write_sample(&expected, allocator, reference, desc);
    full->_length = full_length;
    const bool actual_ok = dds_stream_write_sample(&actual, allocator, sample, desc);
    if (expected_ok != actual_ok ||
        (expected_ok && (expected.m_index != actual.m_index || memcmp(expected.m_buffer, actual.m_buffer, expected.m_index) != 0))) {
        abort();
    }
    dds_ostream_fini(&actual, allocator);
    dds_ostream_fini(&expected, allocator);

    // The harness allocated the buffer with the default allocator. Transfer it for cleanup.
    seq->_release = true;
    dds_stream_free_sample(sample, allocator, desc->ops.ops);
    ddsrt_free(sample);
}

static void exercise_trusted_consumers(const struct fuzz_type *type, const struct dds_cdrstream_desc *desc,
                                       const void *data, uint32_t size)
{
    dds_istream_t is;
    char printbuf[65536];

    char *sample = ddsrt_calloc(1, desc->size);
    dds_istream_init_well_formed (&is, size, data, FUZZ_SAMPLE_DESER_XCDR_VERSION);
    dds_stream_read_sample(&is, sample, &dds_cdrstream_default_allocator, desc);
    // Vary the starting field with the input size and do at most one extra decode per type.
    for (size_t i = 0; i < type->count; i++) {
        const struct fuzz_sequence_field *field = &type->fields[((uint64_t)size + i) % type->count];
        dds_sequence_t *full = (dds_sequence_t *)(sample + field->offset);
        if (full->_length >= 2) {
            exercise_sequence_buffer(desc, data, size, sample, full, field);
            break;
        }
    }
    dds_stream_free_sample(sample, &dds_cdrstream_default_allocator, desc->ops.ops);
    ddsrt_free(sample);

    dds_istream_init_well_formed (&is, size, data, FUZZ_SAMPLE_DESER_XCDR_VERSION);
    (void) dds_stream_print_sample(&is, desc, printbuf, sizeof(printbuf));

    if (desc->keys.nkeys > 0) {
        dds_ostream_t key_os;
        dds_ostream_init(&key_os, &dds_cdrstream_default_allocator, 0, FUZZ_SAMPLE_DESER_XCDR_VERSION);

        dds_istream_init_well_formed (&is, size, data, FUZZ_SAMPLE_DESER_XCDR_VERSION);
        if (dds_stream_extract_key_from_data(&is, &key_os, &dds_cdrstream_default_allocator, desc)) {
            dds_istream_t key_is;
            dds_istream_init_well_formed (&key_is, key_os.m_index, key_os.m_buffer, FUZZ_SAMPLE_DESER_XCDR_VERSION);
            (void) dds_stream_print_key(&key_is, desc, printbuf, sizeof(printbuf));
        }

        dds_ostream_fini(&key_os, &dds_cdrstream_default_allocator);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint32_t actual_size;

    if (size == 0 || size > UINT32_MAX) {
        return 0;
    }

    for(size_t i = 0; i < sizeof(fixed_types)/sizeof(fixed_types[0]); i++) {
        const struct fuzz_type *type = &fixed_types[i];
        struct dds_cdrstream_desc desc;
        dds_cdrstream_desc_from_topic_desc(&desc, type->topic);
        void *data_copy = ddsrt_memdup (data, size);
        if (dds_stream_normalize(data_copy, (uint32_t) size, false, FUZZ_SAMPLE_DESER_XCDR_VERSION, &desc, false, &actual_size) == DDS_STREAM_NORMALIZE_SUCCESS) {
            exercise_trusted_consumers(type, &desc, data_copy, actual_size);
        }
        ddsrt_free (data_copy);
        dds_cdrstream_desc_fini(&desc, &dds_cdrstream_default_allocator);
    }
    return 0;
}
