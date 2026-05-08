// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Embedded `cose-tp/v1` JSON Schema. Loaded at compile time via `include_bytes!` so the
//! frontend has no runtime filesystem dependency.

/// Logical resource name used by the cross-port drift assertion.
///
/// Exposed publicly so test crates can reference the on-disk path without re-encoding it.
pub const EMBEDDED_SCHEMA_RESOURCE_NAME: &str =
    "native/rust/validation/trustfrontends/json/schemas/cose-tp/v1.json";

/// Raw bytes of the embedded schema (`include_bytes!` of the on-disk schema file).
const SCHEMA_BYTES: &[u8] = include_bytes!("../schemas/cose-tp/v1.json");

/// Returns the raw bytes of the embedded schema. Used by callers (and tests) that want
/// to detect drift between the on-disk file and the build-time embedded copy.
pub fn embedded_schema_bytes() -> &'static [u8] {
    SCHEMA_BYTES
}
