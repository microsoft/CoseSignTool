//! Transparent MST pack FFI bindings.
//!
//! This crate exposes the Microsoft Secure Transparency (MST) receipt verification pack to C/C++ consumers.

#![deny(unsafe_op_in_unsafe_fn)]

use cose_sign1_validation_ffi::{
    cose_status_t, cose_trust_policy_builder_t, cose_validator_builder_t, with_catch_unwind,
    with_trust_policy_builder_mut,
};
use cose_sign1_validation_transparent_mst::facts::{
    MstReceiptKidFact, MstReceiptPresentFact, MstReceiptSignatureVerifiedFact,
    MstReceiptStatementCoverageFact, MstReceiptStatementSha256Fact, MstReceiptTrustedFact,
};
use cose_sign1_validation_transparent_mst::fluent_ext::{
    MstCounterSignatureScopeRulesExt, MstReceiptStatementCoverageWhereExt,
    MstReceiptStatementSha256WhereExt, MstReceiptTrustedWhereExt, MstReceiptKidWhereExt,
    MstReceiptPresentWhereExt, MstReceiptSignatureVerifiedWhereExt,
};
use cose_sign1_validation_transparent_mst::pack::MstTrustPack;
use std::ffi::{c_char, CStr};
use std::sync::Arc;

fn string_from_ptr(arg_name: &'static str, s: *const c_char) -> Result<String, anyhow::Error> {
    if s.is_null() {
        anyhow::bail!("{arg_name} must not be null");
    }
    let s = unsafe { CStr::from_ptr(s) }
        .to_str()
        .map_err(|_| anyhow::anyhow!("{arg_name} must be valid UTF-8"))?;
    Ok(s.to_string())
}

/// C ABI representation of MST trust options.
#[repr(C)]
pub struct cose_mst_trust_options_t {
    /// If true, allow network fetching of JWKS when offline keys are missing.
    pub allow_network: bool,

    /// Offline JWKS JSON string (NULL means no offline JWKS). Ownership is not transferred.
    pub offline_jwks_json: *const c_char,

    /// Optional api-version for CodeTransparency /jwks endpoint (NULL means no api-version).
    pub jwks_api_version: *const c_char,
}

/// Adds the MST trust pack with default options (online mode).
#[no_mangle]
pub extern "C" fn cose_validator_builder_with_mst_pack(builder: *mut cose_validator_builder_t) -> cose_status_t { with_catch_unwind(|| {
    let builder = unsafe { builder.as_mut() }.ok_or_else(|| anyhow::anyhow!("builder must not be null"))?;
    builder.packs.push(Arc::new(MstTrustPack::online()));
    Ok(cose_status_t::COSE_OK)
}) }

/// Adds the MST trust pack with custom options (offline JWKS, etc.).
#[no_mangle]
pub extern "C" fn cose_validator_builder_with_mst_pack_ex(builder: *mut cose_validator_builder_t, options: *const cose_mst_trust_options_t) -> cose_status_t { with_catch_unwind(|| {
    let builder = unsafe { builder.as_mut() }.ok_or_else(|| anyhow::anyhow!("builder must not be null"))?;

    let pack = if options.is_null() {
        MstTrustPack::online()
    } else {
        let opts_ref = unsafe { &*options };
        let offline_jwks = if opts_ref.offline_jwks_json.is_null() {
            None
        } else {
            Some(
                unsafe { CStr::from_ptr(opts_ref.offline_jwks_json) }
                    .to_str()
                    .map_err(|_| anyhow::anyhow!("invalid UTF-8 in offline_jwks_json"))?
                    .to_string(),
            )
        };
        let api_version = if opts_ref.jwks_api_version.is_null() {
            None
        } else {
            Some(
                unsafe { CStr::from_ptr(opts_ref.jwks_api_version) }
                    .to_str()
                    .map_err(|_| anyhow::anyhow!("invalid UTF-8 in jwks_api_version"))?
                    .to_string(),
            )
        };

        MstTrustPack {
            allow_network: opts_ref.allow_network,
            offline_jwks_json: offline_jwks,
            jwks_api_version: api_version,
        }
    };

    builder.packs.push(Arc::new(pack));
    Ok(cose_status_t::COSE_OK)
}) }

/// Trust-policy helper: require that an MST receipt is present on at least one counter-signature.
///
/// This API is provided by the MST pack FFI library and extends `cose_trust_policy_builder_t`.
#[no_mangle]
pub extern "C" fn cose_mst_trust_policy_builder_require_receipt_present(policy_builder: *mut cose_trust_policy_builder_t) -> cose_status_t { with_catch_unwind(|| {
    with_trust_policy_builder_mut(policy_builder, |b| b.for_counter_signature(|s| s.require_mst_receipt_present()))?;
    Ok(cose_status_t::COSE_OK)
}) }

/// Trust-policy helper: require that an MST receipt is not present on all counter-signatures.
#[no_mangle]
pub extern "C" fn cose_mst_trust_policy_builder_require_receipt_not_present(policy_builder: *mut cose_trust_policy_builder_t) -> cose_status_t { with_catch_unwind(|| {
    with_trust_policy_builder_mut(policy_builder, |b| {
        b.for_counter_signature(|s| s.require::<MstReceiptPresentFact>(|w| w.require_receipt_not_present()))
    })?;
    Ok(cose_status_t::COSE_OK)
}) }

/// Trust-policy helper: require that the MST receipt signature verified.
#[no_mangle]
pub extern "C" fn cose_mst_trust_policy_builder_require_receipt_signature_verified(policy_builder: *mut cose_trust_policy_builder_t) -> cose_status_t { with_catch_unwind(|| {
    with_trust_policy_builder_mut(policy_builder, |b| b.for_counter_signature(|s| s.require_mst_receipt_signature_verified()))?;
    Ok(cose_status_t::COSE_OK)
}) }

/// Trust-policy helper: require that the MST receipt signature did not verify.
#[no_mangle]
pub extern "C" fn cose_mst_trust_policy_builder_require_receipt_signature_not_verified(policy_builder: *mut cose_trust_policy_builder_t) -> cose_status_t { with_catch_unwind(|| {
    with_trust_policy_builder_mut(policy_builder, |b| {
        b.for_counter_signature(|s| s.require::<MstReceiptSignatureVerifiedFact>(|w| w.require_receipt_signature_not_verified()))
    })?;
    Ok(cose_status_t::COSE_OK)
}) }

/// Trust-policy helper: require that the MST receipt issuer contains the provided substring.
#[no_mangle]
pub extern "C" fn cose_mst_trust_policy_builder_require_receipt_issuer_contains(policy_builder: *mut cose_trust_policy_builder_t, needle_utf8: *const c_char) -> cose_status_t { with_catch_unwind(|| {
    let needle = string_from_ptr("needle_utf8", needle_utf8)?;
    with_trust_policy_builder_mut(policy_builder, |b| b.for_counter_signature(|s| s.require_mst_receipt_issuer_contains(needle)))?;
    Ok(cose_status_t::COSE_OK)
}) }

/// Trust-policy helper: require that the MST receipt issuer equals the provided value.
#[no_mangle]
pub extern "C" fn cose_mst_trust_policy_builder_require_receipt_issuer_eq(policy_builder: *mut cose_trust_policy_builder_t, issuer_utf8: *const c_char) -> cose_status_t { with_catch_unwind(|| {
    let issuer = string_from_ptr("issuer_utf8", issuer_utf8)?;
    with_trust_policy_builder_mut(policy_builder, |b| b.for_counter_signature(|s| s.require_mst_receipt_issuer_eq(issuer)))?;
    Ok(cose_status_t::COSE_OK)
}) }

/// Trust-policy helper: require that the MST receipt key id (kid) equals the provided value.
#[no_mangle]
pub extern "C" fn cose_mst_trust_policy_builder_require_receipt_kid_eq(policy_builder: *mut cose_trust_policy_builder_t, kid_utf8: *const c_char) -> cose_status_t { with_catch_unwind(|| {
    let kid = string_from_ptr("kid_utf8", kid_utf8)?;
    with_trust_policy_builder_mut(policy_builder, |b| b.for_counter_signature(|s| s.require_mst_receipt_kid_eq(kid)))?;
    Ok(cose_status_t::COSE_OK)
}) }

/// Trust-policy helper: require that the MST receipt key id (kid) contains the provided substring.
#[no_mangle]
pub extern "C" fn cose_mst_trust_policy_builder_require_receipt_kid_contains(policy_builder: *mut cose_trust_policy_builder_t, needle_utf8: *const c_char) -> cose_status_t { with_catch_unwind(|| {
    let needle = string_from_ptr("needle_utf8", needle_utf8)?;
    with_trust_policy_builder_mut(policy_builder, |b| {
        b.for_counter_signature(|s| s.require::<MstReceiptKidFact>(|w| w.require_receipt_kid_contains(needle)))
    })?;
    Ok(cose_status_t::COSE_OK)
}) }

/// Trust-policy helper: require that the MST receipt is trusted.
#[no_mangle]
pub extern "C" fn cose_mst_trust_policy_builder_require_receipt_trusted(policy_builder: *mut cose_trust_policy_builder_t) -> cose_status_t { with_catch_unwind(|| {
    with_trust_policy_builder_mut(policy_builder, |b| {
        b.for_counter_signature(|s| s.require::<MstReceiptTrustedFact>(|w| w.require_receipt_trusted()))
    })?;
    Ok(cose_status_t::COSE_OK)
}) }

/// Trust-policy helper: require that the MST receipt is not trusted.
#[no_mangle]
pub extern "C" fn cose_mst_trust_policy_builder_require_receipt_not_trusted(policy_builder: *mut cose_trust_policy_builder_t) -> cose_status_t { with_catch_unwind(|| {
    with_trust_policy_builder_mut(policy_builder, |b| {
        b.for_counter_signature(|s| s.require::<MstReceiptTrustedFact>(|w| w.require_receipt_not_trusted()))
    })?;
    Ok(cose_status_t::COSE_OK)
}) }

/// Trust-policy helper: convenience = require (receipt trusted) AND (issuer contains substring).
#[no_mangle]
pub extern "C" fn cose_mst_trust_policy_builder_require_receipt_trusted_from_issuer_contains(policy_builder: *mut cose_trust_policy_builder_t, needle_utf8: *const c_char) -> cose_status_t { with_catch_unwind(|| {
    let needle = string_from_ptr("needle_utf8", needle_utf8)?;
    with_trust_policy_builder_mut(policy_builder, |b| b.for_counter_signature(|s| s.require_mst_receipt_trusted_from_issuer(needle)))?;
    Ok(cose_status_t::COSE_OK)
}) }

/// Trust-policy helper: require that the MST receipt statement SHA-256 digest equals the provided hex string.
#[no_mangle]
pub extern "C" fn cose_mst_trust_policy_builder_require_receipt_statement_sha256_eq(policy_builder: *mut cose_trust_policy_builder_t, sha256_hex_utf8: *const c_char) -> cose_status_t { with_catch_unwind(|| {
    let sha256_hex = string_from_ptr("sha256_hex_utf8", sha256_hex_utf8)?;
    with_trust_policy_builder_mut(policy_builder, |b| {
        b.for_counter_signature(|s| {
            s.require::<MstReceiptStatementSha256Fact>(|w| w.require_receipt_statement_sha256_eq(sha256_hex))
        })
    })?;
    Ok(cose_status_t::COSE_OK)
}) }

/// Trust-policy helper: require that the MST receipt statement coverage equals the provided value.
#[no_mangle]
pub extern "C" fn cose_mst_trust_policy_builder_require_receipt_statement_coverage_eq(policy_builder: *mut cose_trust_policy_builder_t, coverage_utf8: *const c_char) -> cose_status_t { with_catch_unwind(|| {
    let coverage = string_from_ptr("coverage_utf8", coverage_utf8)?;
    with_trust_policy_builder_mut(policy_builder, |b| {
        b.for_counter_signature(|s| {
            s.require::<MstReceiptStatementCoverageFact>(|w| w.require_receipt_statement_coverage_eq(coverage))
        })
    })?;
    Ok(cose_status_t::COSE_OK)
}) }

/// Trust-policy helper: require that the MST receipt statement coverage contains the provided substring.
#[no_mangle]
pub extern "C" fn cose_mst_trust_policy_builder_require_receipt_statement_coverage_contains(policy_builder: *mut cose_trust_policy_builder_t, needle_utf8: *const c_char) -> cose_status_t { with_catch_unwind(|| {
    let needle = string_from_ptr("needle_utf8", needle_utf8)?;
    with_trust_policy_builder_mut(policy_builder, |b| {
        b.for_counter_signature(|s| {
            s.require::<MstReceiptStatementCoverageFact>(|w| w.require_receipt_statement_coverage_contains(needle))
        })
    })?;
    Ok(cose_status_t::COSE_OK)
}) }
