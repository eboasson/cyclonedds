# CDR stream trust boundary refresh

This note records the intended direction for the CDR stream reader, printer and
key extraction code.  It is based on the model that validation of untrusted CDR
belongs in the normalization step, while the stream consumers operate on
well-formed, native-endian data.

## Goals

The main goals are:

* keep `read`, `print` and `extract_key` cheap;
* make `normalize` the single place that validates untrusted input;
* document and enforce the distinction between untrusted serialized bytes and a
  trusted `dds_istream_t`;
* make XCDR1 optional-member handling consistent with the XTypes encoding rules;
* keep compatibility with existing users of `dds_istream_init` while making the
  trust contract clearer.

## Current model

The normal receive paths already follow the desired sequence:

1. copy or assemble the serialized payload;
2. call `dds_stream_normalize`;
3. construct a `dds_istream_t` for the normalized native-endian byte range;
4. call `dds_stream_read_sample`, `dds_stream_print_sample` or
   `dds_stream_extract_key_from_data`.

The public documentation for `dds_istream_init` now says the input buffer must
contain well-formed CDR data in native endianness.  The practical consequence is
that a `dds_istream_t` should be treated as trusted.  It is not merely a cursor
over arbitrary bytes.

That trust boundary is not yet expressed by the type system.  Callers can still
construct a `dds_istream_t` directly or by calling `dds_istream_init` on data
that has not been normalized.  The implementation therefore depends on
discipline and documentation, and the name `dds_istream_init` does not make the
precondition obvious.

## Encoding model

Final and appendable encodings are positional.  The order of fields is known
from the local type description.  For an optional member, the consumer only
needs to know whether the optional field is present.  For XCDR1, normalization
must also verify that the member id in the optional parameter header is the one
expected for that position.

Mutable encodings are different.  The member header identifies the field, and
the input may contain unknown members.  Normalization must decide whether a
member is known, whether it is must-understand, whether it should be skipped,
and whether a known member is well-formed within its declared payload length.
This is true for XCDR1 and XCDR2, even though the header encodings differ.

For mutable optional members, absence is represented by omitting the member.
A zero-length mutable member is still a present member with a zero-length
payload.  It is valid only if the member type is well-formed with such a
payload; it is not a generic absent-optional marker.

## Normalization responsibilities

`normalize` is responsible for accepting, rejecting or rewriting untrusted CDR.
After a successful normalization, stream consumers should not need to repeat
identity or bounds checks.

In particular, normalization should:

* validate bounds before reading primitive values, DHEADERs, EMHEADERs and
  XCDR1 parameter headers;
* byte-swap accepted data to native endian;
* reject XCDR1 final/appendable optional members whose parameter header does not
  match the expected member id;
* validate present XCDR1 optional members within the stated parameter payload
  length;
* reject present final/appendable optional members whose payload is not
  well-formed;
* for mutable encodings, skip unknown non-must-understand members using the
  declared member length;
* for mutable encodings, reject unknown must-understand members;
* for mutable encodings, treat a known zero-length member as present and validate
  it against the member type.

One concrete cleanup is to make the XCDR1 final/appendable optional path treat
`NPHR1_NOT_FOUND` as invalid.  In a positional optional slot, there is no
unknown member to skip.  A wrong member id, a reserved member id or a descriptor
that cannot map the expected operation to a member id should cause
normalization to fail.

The XCDR1 mutable parameter-list path should not collapse
`NPHR1_NOT_PRESENT` into "member absent" before member lookup.  It should look up
the member id and then validate a known zero-length payload, or skip/reject an
unknown one according to the must-understand flag.

## Trusted stream consumers

`read`, `print` and `extract_key` should assume their `dds_istream_t` is
well-formed and native-endian.  They should not validate untrusted lengths or
member identities.  Their job is to consume a stream that `normalize` has
already accepted.

For final/appendable optional members, the trusted consumer logic should be:

* in XCDR1, read the optional parameter header and treat the member as present
  when the parameter length is nonzero;
* in XCDR2, read the presence boolean;
* if present in XCDR1, restrict the temporary nested stream to the stated
  payload length so alignment is relative to the parameter value;
* if absent, skip the local member operations and default/omit the local value as
  appropriate for the consumer.

The consumers do not need to check the XCDR1 optional member id.  That is part
of normalization.  Repeating the check makes the hot path more expensive and
causes trouble for APIs that only carry operation metadata, such as
`dds_stream_read`.

The previous hardening idea of checking the member id in all consumers should
therefore be avoided for final/appendable data.  It is acceptable only as a
debug assertion if the required member-id metadata is available and the check has
no impact on release builds.

## API refresh

The desired long-term model is that callers cannot accidentally create a trusted
input stream from untrusted bytes.

A practical incremental API refresh is:

1. add `dds_istream_init_well_formed`;
2. make it the documented constructor for trusted native-endian CDR;
3. keep `dds_istream_init` as a deprecated alias for compatibility;
4. migrate internal call sites to `dds_istream_init_well_formed`;
5. add helper constructors that combine normalization and stream initialization.

The new constructor would have the same implementation as `dds_istream_init`,
but its name documents the precondition:

```c
void dds_istream_init_well_formed (
  dds_istream_t *is,
  uint32_t size,
  const void *input,
  enum dds_cdr_enc_version xcdr_version);
```

The old constructor should remain available for now:

```c
DDS_DEPRECATED_EXPORT
void dds_istream_init (...);
```

`DDS_DEPRECATED_EXPORT` is the existing public-header convention.  It does not
name the replacement in the compiler warning, so the Doxygen `@deprecated` text
should name `dds_istream_init_well_formed`.

## Normalize-to-stream helpers

To make correct use easier, add helpers that validate a buffer and initialize a
trusted stream only on success.  These helpers should not hide ownership: the
input buffer remains owned by the caller and is normalized in place, just as
`dds_stream_normalize` does today.

A complete-sample helper could look like:

```c
enum dds_stream_normalize_result dds_istream_init_from_normalized_sample (
  dds_istream_t *is,
  void *data,
  uint32_t size,
  bool bswap,
  enum dds_cdr_enc_version xcdr_version,
  const struct dds_cdrstream_desc *desc,
  bool just_key,
  uint32_t *actual_size);
```

On success, this would initialize `is` over `actual_size` bytes.  On discard or
error, it would leave `is` uninitialized or reset it to an empty sentinel.

For the TypeInformation and TypeMapping paths that use
`dds_stream_normalize_xcdr2_data`, a fragment-oriented helper is also useful:

```c
enum dds_stream_normalize_result dds_istream_init_from_normalized_xcdr2_data (
  dds_istream_t *is,
  char *data,
  uint32_t *off,
  uint32_t size,
  bool bswap,
  const uint32_t *ops);
```

This helper initializes the stream over the normalized range.  For callers that
normalize from a nonzero offset, `is->m_index` starts at zero and `is->m_buffer`
points at `data + original_off`.  On error or discard, the offset is restored
and the stream is reset to an empty sentinel.

## Deferred trusted skip cleanup

Some trusted read paths currently reuse normalization as a skip primitive.  The
argument is that normalizing already-normalized data is a no-op.  This is valid,
and it saved implementation effort, so it does not need to block the immediate
fixes.

It should still be cleaned up eventually.  A dedicated trusted skip path would
make the separation clearer:

* `normalize` validates untrusted data;
* `read` and trusted skip functions consume already-normalized data;
* metadata requirements do not leak from validation into trusted consumption.

This becomes especially relevant if XCDR1 optional normalization is tightened to
require member-id metadata for final/appendable optional slots.  A skip helper
that calls normalization with incomplete metadata can become subtly wrong even
though the stream is already trusted.

This cleanup should be deferred until after the correctness fixes and API naming
work.

## Progress tracker

This tracker is intended to be updated as the work progresses.  Each numbered
step is scoped so it can be implemented and committed independently.  The
"decisions so far" bullets record choices made during the design discussion or
during implementation.

Status legend:

* `[ ]` not started;
* `[~]` in progress;
* `[x]` complete;
* `[d]` deferred.

### 1. Tighten XCDR1 final/appendable optional normalization

Status: `[x]`

Commit scope:

* update the XCDR1 optional branch in `stream_normalize_adr`;
* treat a missing, reserved or mismatching member id as invalid for
  final/appendable optional slots;
* add focused normalization tests for matching, absent and wrong member ids.

Decisions so far:

* final and appendable encodings are positional, so a member id in an XCDR1
  optional header is a consistency check for the expected field, not a lookup
  key for an arbitrary field;
* `NPHR1_NOT_FOUND` is valid as an outcome from parsing a parameter header, but
  it should be an error in a final/appendable optional slot;
* a zero-length XCDR1 optional parameter in final/appendable encoding represents
  an absent optional member once the member id has been accepted;
* descriptors without XCDR1 optional member-id metadata are invalid for
  normalization of final/appendable optionals, even though trusted consumers may
  still use operation metadata only after normalization has succeeded.

Verification target:

* focused `ddsc_cdrstream` tests;
* sample deserialization fuzzer in both XCDR1 and XCDR2 modes.

### 2. Tighten XCDR1 mutable zero-length member handling

Status: `[x]`

Commit scope:

* update `stream_normalize_xcdr1_pl` so zero-length mutable members are not
  collapsed into optional absence before member lookup;
* for known members, validate the zero-length payload against the member type;
* for unknown members, skip or reject based on must-understand.

Decisions so far:

* in mutable XCDR1, absent optional members are omitted from the parameter list;
* a zero-length mutable member is present and has an empty payload;
* a zero-length mutable member is valid only when its type is well-formed with an
  empty payload;
* unknown zero-length mutable members remain skippable when they are not
  must-understand, but known zero-length members now go through normal member
  validation.

Verification target:

* tests for unknown non-must-understand zero-length members;
* tests for unknown must-understand zero-length members;
* tests for known zero-length members that should be rejected.

### 3. Restore cheap XCDR1 optional handling in `read`

Status: `[x]`

Commit scope:

* remove release-build member-id lookup from final/appendable optional reads;
* use the generic trusted presence helper for XCDR1 and XCDR2;
* ensure `dds_stream_read` remains usable with operation metadata only.

Decisions so far:

* a `dds_istream_t` is trusted, native-endian and well-formed;
* `read` should not repeat the XCDR1 member-id validation done by `normalize`;
* a debug-only assertion may be acceptable if the required metadata is already
  available, but it must not affect the release hot path;
* `dds_stream_read` must remain usable with `static_empty_mid_table`, because
  that API takes operation metadata rather than a full descriptor.

Verification target:

* regression test showing `dds_stream_read` can consume normalized XCDR1
  optional data without a descriptor member-id table;
* existing XCDR1/XCDR2 optional read tests.

### 4. Align `print` with the trusted stream contract

Status: `[x]`

Commit scope:

* keep `dds_stream_print_sample` and `dds_stream_print_key` on the trusted-stream
  model;
* use the same optional presence interpretation as `read`;
* avoid adding required member-id metadata to the print call tree for
  final/appendable optionals.

Decisions so far:

* printing should not validate untrusted CDR;
* XCDR1 optional member ids have already been accepted by `normalize`;
* print support should be fuzzed after normalization so deviations from `read`
  are caught without making print a validator;
* the existing print path already uses the trusted optional-presence
  interpretation, so no release-build member-id lookup was added.

Verification target:

* focused print tests for normalized XCDR1 optional data;
* fuzzer path that calls print after successful normalization.

### 5. Align `extract_key` with the trusted stream contract

Status: `[x]`

Commit scope:

* keep optimized key extraction on trusted data only;
* use the same optional presence interpretation as `read`;
* ensure optional non-key members are skipped consistently in XCDR1 and XCDR2.

Decisions so far:

* optional key members are not supported by the local type system;
* optional non-key members may still have to be skipped while extracting keys;
* key extraction should not repeat member-id validation for final/appendable
  optional members;
* the existing key-extraction path already uses the trusted optional-presence
  interpretation for final/appendable optionals and skips XCDR1 optional
  non-key members by parameter length.

Verification target:

* focused key-extraction tests for normalized samples with optional non-key
  members;
* fuzzer path that calls key extraction for generated keyed types after
  successful normalization.

### 6. Expand the sample deserialization fuzzer consumers

Status: `[x]`

Commit scope:

* after successful normalization, run the same normalized input through `read`,
  `print` and, where applicable, `extract_key`;
* keep XCDR1 and XCDR2 fuzzer targets and seed corpora separate.

Decisions so far:

* the fuzzer should preserve the production contract: normalize first, then
  trusted consumers;
* XCDR1 and XCDR2 need independent corpora because the encodings differ
  substantially;
* consumer fuzzing is useful for consistency, not for redefining consumers as
  untrusted-input validators;
* each consumer gets a fresh `dds_istream_t` over the same normalized byte range
  so consumption by one path cannot hide behavior in another.

Verification target:

* local fuzzer build using `fuzz/local.sh`;
* representative run of both XCDR1 and XCDR2 fuzzer variants.

### 7. Add `dds_istream_init_well_formed`

Status: `[x]`

Commit scope:

* add `dds_istream_init_well_formed` with the same behavior as
  `dds_istream_init`;
* document it as the preferred constructor for trusted native-endian CDR;
* retain `dds_istream_init` as a deprecated compatibility alias.

Decisions so far:

* the new name should make the trust precondition visible at call sites;
* `dds_istream_init` must remain available for external users for now;
* use `DDS_DEPRECATED_EXPORT` for the compatibility alias, because that is the
  existing public-header convention;
* keep the old symbol as a wrapper around `dds_istream_init_well_formed`;
* update the symbol-export probe to reference both the new constructor and the
  deprecated alias.

Verification target:

* build and symbol export tests;
* header documentation review.

### 8. Migrate straightforward internal stream construction

Status: `[x]`

Commit scope:

* replace internal `dds_istream_init` calls with
  `dds_istream_init_well_formed` where the input is clearly normalized or
  locally serialized;
* replace direct `dds_istream_t` struct literals where doing so is mechanical
  and improves the trust boundary.

Decisions so far:

* the migration should be incremental;
* direct struct literals in tests may remain temporarily when they are clearer
  or when the test intentionally constructs a malformed stream;
* no external compatibility break should be introduced;
* migrate production serdata paths that construct streams only after
  normalization or over stored serialized keys;
* migrate the fuzzer trusted-consumer calls because they run only after
  successful normalization;
* migrate internal tests that read, print or extract keys from static,
  normalized or locally serialized CDR;
* keep one `dds_istream_init` call in the symbol-export probe so the deprecated
  compatibility symbol remains covered.

Verification target:

* normal build;
* focused CDR stream and TypeInformation tests.

### 9. Add normalize-to-stream helpers

Status: `[x]`

Commit scope:

* add a helper that wraps `dds_stream_normalize` and initializes a trusted stream
  on success;
* add an XCDR2 fragment-oriented helper for TypeInformation and TypeMapping
  style users;
* define what happens to the stream output on error or discard.

Decisions so far:

* helpers should normalize in place and must not obscure buffer ownership;
* on success, the stream should cover the accepted normalized byte range;
* for nonzero start offsets, the XCDR2 helper initializes the stream with
  `m_index == 0` over `data + original_off`;
* on error or discard, helpers reset the stream to an empty sentinel;
* on error or discard, the complete-sample helper sets `actual_size` to 0;
* on error or discard, the XCDR2 fragment helper restores `off` to its original
  value.

Verification target:

* helper unit tests for success, discard and error outcomes;
* tests for nonzero-offset XCDR2 fragment normalization if such callers are
  supported by the helper.

### 10. Migrate receive and XTypes metadata paths to helpers

Status: `[ ]`

Commit scope:

* migrate default serdata and CDR serdata receive paths where practical;
* migrate TypeInformation and TypeMapping deserialization paths where practical;
* keep behavior and ownership unchanged.

Decisions so far:

* the migration should happen after the helper APIs are stable;
* normal receive paths already normalize before stream construction, so this is
  primarily a clarity and misuse-prevention step;
* TypeInformation and TypeMapping paths need particular care because they use
  `dds_stream_normalize_xcdr2_data`.

Verification target:

* focused ddsc/ddsi tests for receive and type lookup paths;
* full CDR stream tests.

### 11. Replace normalize-as-skip with trusted skip helpers

Status: `[d]`

Commit scope:

* introduce trusted skip helpers that mirror `read` instead of calling
  normalization on already-normalized data;
* migrate read paths that currently reuse normalization for skipping.

Decisions so far:

* reusing normalization as a no-op on already-normalized data is valid and can
  remain for now;
* this cleanup should not block the immediate correctness and API-naming work;
* a dedicated trusted skip path would make the trust boundary cleaner and avoid
  future metadata mismatches.

Verification target:

* sequence trim/use-default tests;
* tests that skip nested complex values in trusted streams;
* fuzzer runs after the trusted skip path is enabled.

## Testing and fuzzing

Tests should cover both the validator and the trusted consumers.

Normalization tests should include:

* XCDR1 final optional with matching member id and nonzero payload;
* XCDR1 final optional with matching member id and zero payload;
* XCDR1 final optional with wrong member id;
* XCDR1 appendable optional with wrong member id inside the appendable payload;
* XCDR1 mutable unknown non-must-understand member with zero payload;
* XCDR1 mutable unknown must-understand member with zero payload;
* XCDR1 mutable known member with zero payload, for a type where zero payload is
  invalid;
* XCDR2 mutable oversized or overflowing member length checks.

Consumer tests should run only on data that has been accepted by normalization:

* `read` for XCDR1 final/appendable optionals;
* `print` for XCDR1 final/appendable optionals;
* `extract_key` for structures where optional non-key members are skipped;
* mutable unknown-field skipping for XCDR1 and XCDR2.

The sample deserialization fuzzer should keep the normalize-first structure and
then exercise all trusted consumers that are expected to work on the normalized
sample:

1. normalize;
2. read;
3. print;
4. extract key when the generated type has keys.

The XCDR1 and XCDR2 fuzzer variants should keep separate corpora because the
encodings differ substantially.

## Non-goals

This plan does not make every exported CDR helper safe for arbitrary untrusted
bytes.  The contract is the opposite: untrusted bytes must be normalized first.

This plan also does not immediately remove every direct `dds_istream_t`
construction.  The migration should be incremental so existing internal and
external users can adapt without a large compatibility break.
