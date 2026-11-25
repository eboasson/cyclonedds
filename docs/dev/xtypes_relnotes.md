# Cyclone DDS XTypes 1.3 caveats

## Extensibility in IDL

DDS-XTypes 1.3 specifies `appendable` when a type's extensibility is
unspecified and permits a compiler override. For an IDL declaration without
an extensibility annotation, Cyclone's compiler (IDLC) uses the following
rules. [DDS-XTypes 1.3, §7.3.1.2.1.8](https://www.omg.org/spec/DDS-XTypes/1.3/PDF#page=96)

| IDL declaration | Extensibility chosen by IDLC |
| --- | --- |
| Struct without a base, or union | `final` unless changed with `idlc -x`. |
| Derived struct | Its base's extensibility, regardless of `-x`. |
| Enum or bitmask | `appendable` with `-x appendable`, otherwise `final`. |

The XML type library importer defaults to `appendable`. As a result, the
same struct without a base or extensibility annotation gets different
TypeIdentifiers in IDL and XML with the default settings.

## Type definitions and language bindings

- IDLC and the runtime C topic descriptor builder cannot map a type containing
  a map or bitset to a C sample. The IDLC C backend also rejects IDL
  `long double`. IDLC does not accept `const wchar` or `const wstring`
  declarations.
- Union inheritance is unsupported. If a struct key includes a union, Cyclone
  requires its discriminator to be explicitly marked `@key`. This applies
  through typedefs, collections, and nested structs. When a struct used as a
  key has no key members of its own, the check includes all its members.
- IDLC ignores `@external` on collection elements such as
  `sequence<@external T>`. Its C backend ignores explicit member `@default`
  values.
- IDLC ignores annotations written in the alternative `//@` syntax, as well
  as `@verbatim`, `@ignore_literal_names`, and `@non_serialized`. The
  CompleteTypeObjects it generates omit applied user-defined annotations.
- The C binding has no OMG `DynamicData` API for reading or writing individual
  sample members.
- XML type import covers a subset of the XML representation. For example,
  `xmltype` requires an explicit decimal integer value for each enumerator.
  XTypes also permits an expression or an omitted value. XSD type import is
  unsupported. [DDS-XTypes 1.3, §7.3.2.7.1](https://www.omg.org/spec/DDS-XTypes/1.3/PDF#page=118)

## Type discovery

TypeLookup neither requests nor answers `getTypeDependencies`. With an
incomplete advertised dependency list, endpoint matching can use `getTypes`
to fetch dependencies as their IDs become known. A global `dds_find_topic`
or `dds_create_topic_descriptor` can time out if a reply reveals another
dependency and no endpoint triggers the follow-up request.

## Wire representation

With default DataRepresentation QoS, Cyclone chooses the writer's encoding
from the entire type definition. When both versions are allowed, writers
default to XCDR2 for types containing an optional member or an appendable or
mutable aggregate, and to XCDR1 for all other types. Even for a final topic
struct, changing one member can change both the default and the available
encodings.

| Only member of the `@final` struct | Writer default | XCDR1 allowed? |
| --- | --- | --- |
| `long value;` | XCDR1 | Yes |
| `@optional long value;` | XCDR2 | Yes |
| `Inner value;`, where `Inner` is an appendable struct containing one `long` | XCDR2 | No |

XML wire encoding is unsupported.
