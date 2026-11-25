#!/usr/bin/env python

import argparse
import os
from fuzz_tools.rand_idl.creator import generate_random_types, generate_random_idl
from fuzz_tools.rand_idl.value import generate_random_instance
from fuzz_tools.rand_idl.compile import compile_idl
from fuzz_tools.rand_idl.containers import RStruct, RTypedef, RTypeDiscriminator

MODULE_NAME = "Fuzz"


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--xcdr-version", type=int, choices=(1, 2), required=True)
    parser.add_argument("--corpus-name", required=True)
    parser.add_argument("seed")
    parser.add_argument("target_directory")
    return parser.parse_args()


def inline_sequence_fields(entity):
    if not isinstance(entity, RStruct):
        return
    for field in entity.fields:
        if field.array_bound or "optional" in field.annotations or "external" in field.annotations:
            continue
        rtype = field.type
        while isinstance(rtype.reference, RTypedef) and not rtype.reference.array_bound:
            rtype = rtype.reference.rtype
        if rtype.discriminator in (RTypeDiscriminator.Sequence, RTypeDiscriminator.BoundedSequence):
            yield field.name


def write_type_table(f, entities):
    f.write("struct fuzz_sequence_field { size_t offset; size_t element_size; };\n")
    f.write("struct fuzz_type { const struct dds_topic_descriptor *topic; "
            "const struct fuzz_sequence_field *fields; size_t count; };\n")
    entries = []
    for entity in entities:
        ctype = f"{MODULE_NAME}_{entity.name}"
        fields = list(inline_sequence_fields(entity))
        field_table = "NULL"
        if fields:
            field_table = f"{ctype}_fields"
            f.write(f"static const struct fuzz_sequence_field {field_table}[] = {{\n")
            for field in fields:
                f.write(f"    {{ offsetof({ctype}, {field}), sizeof(*(({ctype} *)0)->{field}._buffer) }},\n")
            f.write("};\n")
        entries.append(f"    {{ &{ctype}_desc, {field_table}, {len(fields)} }},\n")
    f.write("static const struct fuzz_type fixed_types[] = {\n")
    f.writelines(entries)
    f.write("};\n")


if __name__ == '__main__':
    args = parse_args()
    seed = int(args.seed, 16)
    directory = args.target_directory
    os.makedirs(directory, exist_ok=True)

    # Generate random idl
    scope = generate_random_types(MODULE_NAME, xcdr_version=args.xcdr_version, number=25, seed=seed)
    idl_text = generate_random_idl(scope)
    with open(os.path.join(directory, "fuzz_sample.idl"), "w") as f:
        f.write(idl_text)

    # Hacky way to identify top-level types.
    toplvltypes = [e for e in scope.entities if getattr(e, "extensibility", False)]
    # Generate fuzz_samples.h, collecting all generated types
    with open(os.path.join(directory, "fuzz_samples.h"), "w") as f:
        f.write("#include <stddef.h>\n#include <stdint.h>\n")
        f.write("#include \"fuzz_sample.h\"\n")
        f.write("static const char *idl_types_seed = \"{}\";\n".format(args.seed))
        f.write("static const uint32_t idl_types_xcdr_version = {};\n".format(args.xcdr_version))
        write_type_table(f, toplvltypes)

    # Generate initial corpus
    imported, tdir = compile_idl(idl_text, MODULE_NAME)
    corpus = os.path.join(directory, args.corpus_name)
    os.makedirs(corpus, exist_ok=True)
    for fname in os.listdir(corpus):
        if fname.startswith("seed_"):
            os.unlink(os.path.join(corpus, fname))
    for entity in toplvltypes:
        t = getattr(imported.__fuzzytypes, entity.name)
        sample = generate_random_instance(t, seed=seed)
        fname = "seed_{}".format(entity.name)
        with open(os.path.join(corpus, fname), "wb") as f:
            # The normalizer takes a native-endian payload without the DDS encapsulation header.
            f.write(sample.serialize(use_version_2=args.xcdr_version == 2)[4:])
