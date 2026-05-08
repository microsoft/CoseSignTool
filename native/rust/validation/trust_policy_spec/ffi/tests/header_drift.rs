// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Header drift assertion.
//!
//! Asserts that every `#[no_mangle] pub extern "C" fn` exported by this crate has a
//! matching forward declaration in the hand-written C header at
//! `native/c/include/cose/sign1/trust_policy.h`. CI gate against forgetting to keep
//! the header in lockstep with the Rust exports.
//!
//! The check is a literal-name match: the regex extracts every `cose_sign1_trust_policy_*`
//! identifier from `lib.rs` and from the header, takes the union, and asserts neither
//! direction has any orphan symbols.
//!
//! When the diff fires, fix it by EITHER:
//!   * adding the missing `extern "C"` to `lib.rs` (forgot the export), OR
//!   * adding the missing forward declaration to `trust_policy.h` (forgot the header).
//!
//! Never silence the test by editing this file; that would defeat the gate's purpose.

use std::collections::BTreeSet;
use std::path::PathBuf;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn lib_rs_path() -> PathBuf {
    manifest_dir().join("src").join("lib.rs")
}

fn header_path() -> PathBuf {
    // CARGO_MANIFEST_DIR for this crate is .../validation/trust_policy_spec/ffi.
    // The C header lives 6 levels up, then under c/include/cose/sign1.
    let mut p = manifest_dir();
    for _ in 0..4 {
        p.pop();
    }
    p.join("c")
        .join("include")
        .join("cose")
        .join("sign1")
        .join("trust_policy.h")
}

/// Extract every `cose_sign1_trust_policy_*` identifier that appears in a
/// `pub extern "C" fn <name>(` position in the Rust source.
fn rust_exports(src: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    // Walk the source manually rather than depending on a regex crate (the FFI crate
    // already pays for serde_json + libc; pulling in `regex` for one match is gratuitous).
    for line in src.lines() {
        let trimmed = line.trim();
        // Only the `pub extern "C" fn` lines define ABI exports.
        let Some(rest) = trimmed.strip_prefix("pub extern \"C\" fn ") else {
            continue;
        };
        let Some(name_end) = rest.find(['(', '<']) else {
            continue;
        };
        let name = rest[..name_end].trim();
        if name.starts_with("cose_sign1_trust_policy_") {
            out.insert(name.to_string());
        }
    }
    out
}

/// Extract every `cose_sign1_trust_policy_*` identifier that appears as a function
/// declaration in the C header (heuristic: identifier immediately followed by `(`).
fn header_decls(src: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let bytes = src.as_bytes();
    let mut i = 0;
    while i + 24 <= bytes.len() {
        if bytes[i..].starts_with(b"cose_sign1_trust_policy_") {
            let mut j = i;
            while j < bytes.len() {
                let b = bytes[j];
                if b.is_ascii_alphanumeric() || b == b'_' {
                    j += 1;
                } else {
                    break;
                }
            }
            let ident = std::str::from_utf8(&bytes[i..j]).unwrap_or("");
            // Only accept idents followed by `(` (with optional whitespace) — that
            // distinguishes function declarations from typedef/struct mentions and
            // doc-comment cross-references.
            let mut k = j;
            while k < bytes.len() && (bytes[k] == b' ' || bytes[k] == b'\t') {
                k += 1;
            }
            if k < bytes.len() && bytes[k] == b'(' {
                out.insert(ident.to_string());
            }
            i = j;
        } else {
            i += 1;
        }
    }
    out
}

#[test]
fn rust_and_c_header_export_the_same_function_set() {
    let rust_src = std::fs::read_to_string(lib_rs_path())
        .expect("must read lib.rs");
    let header_src = std::fs::read_to_string(header_path())
        .expect("must read native/c/include/cose/sign1/trust_policy.h");

    let rust_exports = rust_exports(&rust_src);
    let header_decls = header_decls(&header_src);

    let in_rust_not_header: Vec<_> = rust_exports.difference(&header_decls).cloned().collect();
    let in_header_not_rust: Vec<_> = header_decls.difference(&rust_exports).cloned().collect();

    assert!(
        in_rust_not_header.is_empty() && in_header_not_rust.is_empty(),
        "C header drift detected.\n\nRust exports missing from header (add a forward declaration to trust_policy.h):\n  {:#?}\n\nHeader declarations missing from Rust (add a #[no_mangle] pub extern \"C\" fn):\n  {:#?}",
        in_rust_not_header,
        in_header_not_rust,
    );

    // Defensive: at least the canonical entrypoint is exported. Catches a header
    // that exists but is empty or lib.rs that lost its #[no_mangle] block.
    assert!(
        rust_exports.contains("cose_sign1_trust_policy_translate_json"),
        "translate_json must be among the Rust exports; got {:?}",
        rust_exports,
    );
    assert!(
        header_decls.contains("cose_sign1_trust_policy_translate_json"),
        "translate_json must be declared in the C header; got {:?}",
        header_decls,
    );
}

#[test]
fn header_extraction_finds_at_least_one_decl() {
    // Sanity: the parser is non-trivial; assert it produces a non-empty set on a
    // known-good header. If the parser regresses (e.g. someone removes parentheses
    // matching), the orphan-check above could pass vacuously.
    let header_src = std::fs::read_to_string(header_path())
        .expect("must read native/c/include/cose/sign1/trust_policy.h");
    let decls = header_decls(&header_src);
    assert!(
        !decls.is_empty(),
        "header_decls extracted nothing — parser regression?",
    );
}
