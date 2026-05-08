// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! C-ABI projection for `cose_sign1_trust_policy_spec`.
//!
//! Phase 4.5 of the native Rust trust-policy port (see
//! `eval-trust-policy-translation-contract-rust.md`). This crate exposes a stable C ABI
//! that lets non-Rust consumers — C/C++ directly, .NET via P/Invoke, Node via N-API,
//! Go via cgo — load `.coseTrustPolicy.json` documents and translate them into a
//! runtime-evaluable form.
//!
//! # Pipeline
//!
//! ```text
//!   JSON bytes ──► translate_json ──► result handle  (carries spec? + diagnostics)
//!                                          │
//!                            result_spec ◄─┘
//!                                          │
//!                              spec handle ─┴──► spec_bind(parameters_json) ──► result handle
//!                                                                                    │
//!                                                                       result_spec ◄┘
//!                                                                                    │
//!                                                                       spec_compile ──► compiled plan
//! ```
//!
//! Translation diagnostics are reported via the result handle (see [`R6`]); the integer
//! status code returned by the ABI functions reports only **infrastructure** failure
//! (null pointer arguments, allocation failure, panic across the FFI boundary) — never
//! translation outcomes. This is the closed `next_action` discipline applied to FFI:
//! agents (consumers) route on a small enum of mechanical outcomes, not on the
//! semantic content of the result.
//!
//! # Memory ownership (R6)
//!
//! - `*mut cose_sign1_trust_policy_*_t` parameters that an out-parameter writes are
//!   owned by **the caller** after the call returns; they MUST be released via the
//!   matching `*_free()` function.
//! - `*const cose_sign1_trust_policy_*_t` parameters are **borrowed**; the caller
//!   retains ownership.
//! - Borrowed UTF-8 returned by [`cose_sign1_trust_policy_diagnostic_read`]
//!   (`out_*_ptr` / `out_*_len`) is valid for the lifetime of the diagnostic handle,
//!   which itself is valid for the lifetime of the result handle that produced it.
//!   The caller MUST NOT free the borrowed strings.
//!
//! # Thread safety
//!
//! - Every exported function is wrapped in `catch_unwind` so Rust panics never cross
//!   the ABI boundary.
//! - All handles are `Send` (heap-owned, single-owner). They are NOT `Sync` (no
//!   internal locking). A handle MUST NOT be mutated concurrently from multiple
//!   threads. Multiple immutable readers are safe iff no thread holds a `*mut`.
//! - `cose_last_error_message_utf8()` (provided by `cose_sign1_validation_ffi`) is
//!   thread-local.
//!
//! # ABI stability
//!
//! Every exported function uses `extern "C"`. Opaque handle types are passed as
//! `*mut` (owned) or `*const` (borrowed). The hand-written C header at
//! `native/c/include/cose/sign1/trust_policy.h` is the authoritative ABI surface; a
//! drift assertion test in `tests/header_drift.rs` keeps the header in lockstep with
//! the Rust exports.
//!
//! [`R6`]: https://example.invalid/eval-trust-policy-translation-contract-rust.md#r6

use anyhow::Context as _;
use cose_sign1_trust_policy_spec::{
    bind, compile, BindError, CompileError, FactPredicateSpec, ParameterRef, SourceLocation,
    TrustPolicySeverity, TrustPolicySpec, TrustPolicyTranslationContext,
    TrustPolicyTranslationDiagnostic, TrustPolicyTranslationResult,
};
use cose_sign1_trust_policy_spec::{HandRolledFactRegistry, IFactRegistry};
use cose_sign1_trustfrontends_json::CoseTpJsonFrontend;
use cose_sign1_validation_ffi::{cose_status_t, with_catch_unwind};
use cose_sign1_validation_primitives::plan::CompiledTrustPlan;
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// Opaque handle types.
// ---------------------------------------------------------------------------

/// Opaque handle to a parsed [`TrustPolicySpec`].
///
/// Heap-owned. Construct via [`cose_sign1_trust_policy_result_spec`] (which clones the
/// spec held by a successful translation result) or [`cose_sign1_trust_policy_spec_bind`]
/// (which produces a new spec from a parameter substitution).
///
/// Release via [`cose_sign1_trust_policy_spec_free`].
#[allow(non_camel_case_types)]
pub struct cose_sign1_trust_policy_spec_t {
    inner: TrustPolicySpec,
}

/// Opaque handle to a translation result. Carries an optional [`TrustPolicySpec`] plus a
/// vector of [`TrustPolicyTranslationDiagnostic`]s.
///
/// Heap-owned. Construct via [`cose_sign1_trust_policy_translate_json`] or
/// [`cose_sign1_trust_policy_spec_bind`]. Release via
/// [`cose_sign1_trust_policy_result_free`].
///
/// **Per the totality contract (§6.5.4 #2):** when any diagnostic carries severity
/// `Error`, `spec` is `None`. [`cose_sign1_trust_policy_result_is_success`] encodes the
/// invariant directly.
#[allow(non_camel_case_types)]
pub struct cose_sign1_trust_policy_translation_result_t {
    inner: TrustPolicyTranslationResult,
}

/// Opaque handle to a single diagnostic. Borrowed from a translation result handle —
/// the diagnostic is valid for as long as the producing result handle is alive.
///
/// Returned by [`cose_sign1_trust_policy_result_diagnostic_at`]. The caller MUST NOT
/// free a diagnostic handle directly; freeing the result handle drops every diagnostic
/// in the result.
///
/// All UTF-8 byte spans returned by [`cose_sign1_trust_policy_diagnostic_read`] alias
/// memory inside the parent result handle — they remain valid until the result handle
/// is freed.
///
/// `#[repr(transparent)]` over [`TrustPolicyTranslationDiagnostic`] so that
/// `&Diagnostic as *const cose_sign1_trust_policy_diagnostic_t` is a sound layout-equivalent
/// reinterpretation; the borrow tooling at this line is the only place the cast happens.
#[allow(non_camel_case_types)]
#[repr(transparent)]
pub struct cose_sign1_trust_policy_diagnostic_t {
    inner: TrustPolicyTranslationDiagnostic,
}

/// Opaque handle to a compiled trust plan produced by
/// [`cose_sign1_trust_policy_spec_compile`].
///
/// Wraps a `CompiledTrustPlan` value owned by this handle. Release via
/// [`cose_sign1_trust_policy_compiled_plan_free`].
///
/// To use the plan against a `cose_sign1_validator_builder_t` (validation-runtime
/// concern), the consumer attaches the inner plan via the validator-builder FFI in
/// `cose_sign1_validation_primitives_ffi` (Phase 5 plumbing — out of scope for this
/// crate's current ABI surface).
#[allow(non_camel_case_types)]
pub struct cose_sign1_trust_policy_compiled_plan_t {
    /// The inner plan is held to keep ownership semantics explicit; the FFI surface
    /// today is opaque-handle introspection only (Phase 5 plumbing will expose
    /// validator-builder attachment).
    #[allow(dead_code)]
    inner: CompiledTrustPlan,
}

// ---------------------------------------------------------------------------
// Severity ABI mapping.
// ---------------------------------------------------------------------------

/// ABI-stable diagnostic severity reported by
/// [`cose_sign1_trust_policy_diagnostic_read`] via `out_severity`.
#[allow(non_camel_case_types)]
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum cose_sign1_trust_policy_severity_t {
    /// Translation cannot proceed; result MUST carry no spec.
    COSE_TP_SEVERITY_ERROR = 0,
    /// Translation succeeded but the frontend wants the host to know.
    COSE_TP_SEVERITY_WARNING = 1,
    /// Informational — always non-blocking.
    COSE_TP_SEVERITY_INFO = 2,
}

impl cose_sign1_trust_policy_severity_t {
    #[doc(hidden)]
    #[inline]
    pub fn from_severity(s: TrustPolicySeverity) -> Self {
        match s {
            TrustPolicySeverity::Error => Self::COSE_TP_SEVERITY_ERROR,
            TrustPolicySeverity::Warning => Self::COSE_TP_SEVERITY_WARNING,
            TrustPolicySeverity::Info => Self::COSE_TP_SEVERITY_INFO,
            other => Self::from_severity_forward_compat(other),
        }
    }

    /// Forward-compat catch-all extracted to its own function so it can carry
    /// `#[coverage(off)]` (the lint forbids that attr on match arms). Reachable only
    /// when the trust-policy-spec crate ships a new severity tier.
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[inline(never)]
    fn from_severity_forward_compat(_other: TrustPolicySeverity) -> Self {
        Self::COSE_TP_SEVERITY_ERROR
    }
}

// ---------------------------------------------------------------------------
// Static fact registry.
// ---------------------------------------------------------------------------

fn registry() -> &'static HandRolledFactRegistry {
    // Initialize once: the canonical workspace registry covers certificates, MST, and
    // validation-core fact contributions. Phase 5 may extend this list.
    static CELL: OnceLock<HandRolledFactRegistry> = OnceLock::new();
    CELL.get_or_init(|| {
        HandRolledFactRegistry::from_packs(&[
            cose_sign1_certificates::__cose_sign1_trust_facts(),
            cose_sign1_transparent_mst::__cose_sign1_trust_facts(),
            cose_sign1_validation::__cose_sign1_trust_facts(),
        ])
        .expect("workspace fact descriptors must register without conflict")
    })
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

#[inline]
unsafe fn slice_from_raw<'a>(
    arg_name: &'static str,
    ptr: *const u8,
    len: usize,
) -> Result<&'a [u8], anyhow::Error> {
    if ptr.is_null() && len != 0 {
        anyhow::bail!("{arg_name} must not be null when len is non-zero");
    }
    if len == 0 {
        return Ok(&[]);
    }
    // SAFETY: caller guarantees ptr is valid for `len` bytes for the duration of the
    // call (FFI ownership rule).
    Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
}

#[inline]
fn diagnostic_for_bind_error(err: BindError) -> TrustPolicyTranslationDiagnostic {
    let code = err.code().to_owned();
    let message = err.to_string();
    TrustPolicyTranslationDiagnostic::new(
        TrustPolicySeverity::Error,
        code,
        message,
        None,
        None,
    )
}

#[inline]
fn diagnostic_for_compile_error(err: &CompileError) -> TrustPolicyTranslationDiagnostic {
    let code = err.code().to_owned();
    let message = err.to_string();
    let location = compile_error_location(err);
    TrustPolicyTranslationDiagnostic::new(
        TrustPolicySeverity::Error,
        code,
        message,
        location,
        None,
    )
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn compile_error_location(err: &CompileError) -> Option<SourceLocation> {
    match err {
        CompileError::UnknownFactId { location, .. } => location.clone(),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Translate.
// ---------------------------------------------------------------------------

/// Translate a `.coseTrustPolicy.json` byte buffer into a translation result handle.
///
/// `json_bytes` need not be NUL-terminated; the buffer length is supplied via
/// `json_len`. UTF-8 is required.
///
/// Returns `COSE_OK` on success — *which always populates `*out_result` with a non-null
/// handle*, regardless of whether the translation produced errors. Translation
/// diagnostics live on the result handle; the integer return is reserved for
/// infrastructure failures (null `out_result`, panic, allocation).
///
/// Use [`cose_sign1_trust_policy_result_is_success`] /
/// [`cose_sign1_trust_policy_result_diagnostic_count`] to inspect the result.
///
/// # Ownership
///
/// On success, `*out_result` carries ownership; the caller MUST free via
/// [`cose_sign1_trust_policy_result_free`].
#[no_mangle]
pub extern "C" fn cose_sign1_trust_policy_translate_json(
    json_bytes: *const u8,
    json_len: usize,
    out_result: *mut *mut cose_sign1_trust_policy_translation_result_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        if out_result.is_null() {
            anyhow::bail!("out_result must not be null");
        }
        // SAFETY: caller guarantees the buffer is valid for `json_len` bytes for the
        // duration of this call.
        let bytes = unsafe { slice_from_raw("json_bytes", json_bytes, json_len)? };

        let text = std::str::from_utf8(bytes)
            .context("json_bytes must be valid UTF-8")?;

        let frontend = CoseTpJsonFrontend::new();
        let ctx = TrustPolicyTranslationContext::empty();
        let result = frontend.translate_text(text, &ctx, None);

        let boxed = Box::new(cose_sign1_trust_policy_translation_result_t { inner: result });
        // SAFETY: out_result was non-null per the early check; we own the only write.
        unsafe {
            *out_result = Box::into_raw(boxed);
        }
        Ok(cose_status_t::COSE_OK)
    })
}

// ---------------------------------------------------------------------------
// Result introspection.
// ---------------------------------------------------------------------------

/// Returns the number of diagnostics carried by `result`. Returns `0` for a null
/// pointer (defensive: avoids forcing the consumer to null-check before iterating).
#[no_mangle]
pub extern "C" fn cose_sign1_trust_policy_result_diagnostic_count(
    result: *const cose_sign1_trust_policy_translation_result_t,
) -> usize {
    // SAFETY: borrowed pointer; we read a single field, no aliasing concerns.
    let Some(result) = (unsafe { result.as_ref() }) else {
        return 0;
    };
    result.inner.diagnostics.len()
}

/// Borrow a diagnostic by index. Returns null when `result` is null or `index` is out
/// of bounds. The returned pointer is borrowed — the caller MUST NOT free it; its
/// lifetime is tied to the parent result handle.
#[no_mangle]
pub extern "C" fn cose_sign1_trust_policy_result_diagnostic_at(
    result: *const cose_sign1_trust_policy_translation_result_t,
    index: usize,
) -> *const cose_sign1_trust_policy_diagnostic_t {
    // SAFETY: borrowed pointer; we read fields without aliasing.
    let Some(result) = (unsafe { result.as_ref() }) else {
        return std::ptr::null();
    };
    let Some(diag) = result.inner.diagnostics.get(index) else {
        return std::ptr::null();
    };
    // SAFETY: `cose_sign1_trust_policy_diagnostic_t` is `#[repr(transparent)]` over
    // `TrustPolicyTranslationDiagnostic`, so a shared reference to the inner type
    // shares the same layout as a `*const` of the wrapper. The pointer's lifetime is
    // bounded by the parent result handle (documented in the struct rustdoc).
    diag as *const TrustPolicyTranslationDiagnostic
        as *const cose_sign1_trust_policy_diagnostic_t
}

/// Read a diagnostic's fields. All UTF-8 byte spans returned by `out_*_ptr` /
/// `out_*_len` are borrowed from the diagnostic — caller MUST NOT free them.
///
/// `out_severity` is a [`cose_sign1_trust_policy_severity_t`] discriminant.
///
/// `out_location_line` and `out_location_column` are `0` when the diagnostic carries
/// no source location. Otherwise both are 1-indexed.
///
/// All `out_*` parameters MAY be null — the caller can selectively read fields without
/// allocating placeholder slots for the rest.
///
/// Does nothing if `diagnostic` is null.
#[no_mangle]
pub extern "C" fn cose_sign1_trust_policy_diagnostic_read(
    diagnostic: *const cose_sign1_trust_policy_diagnostic_t,
    out_severity: *mut u8,
    out_code_ptr: *mut *const u8,
    out_code_len: *mut usize,
    out_message_ptr: *mut *const u8,
    out_message_len: *mut usize,
    out_location_line: *mut u32,
    out_location_column: *mut u32,
) {
    // SAFETY: borrowed pointer; null-tolerant.
    let Some(diag) = (unsafe { diagnostic.as_ref() }) else {
        return;
    };
    let inner = &diag.inner;

    if !out_severity.is_null() {
        // SAFETY: caller guarantees out_severity is writable.
        unsafe {
            *out_severity =
                cose_sign1_trust_policy_severity_t::from_severity(inner.severity) as u8;
        }
    }

    if !out_code_ptr.is_null() && !out_code_len.is_null() {
        let bytes = inner.code.as_bytes();
        // SAFETY: caller guarantees both out pointers are writable.
        unsafe {
            *out_code_ptr = bytes.as_ptr();
            *out_code_len = bytes.len();
        }
    }

    if !out_message_ptr.is_null() && !out_message_len.is_null() {
        let bytes = inner.message.as_bytes();
        // SAFETY: caller guarantees both out pointers are writable.
        unsafe {
            *out_message_ptr = bytes.as_ptr();
            *out_message_len = bytes.len();
        }
    }

    let (line, column) = match &inner.location {
        Some(loc) => (loc.line, loc.column),
        None => (0u32, 0u32),
    };
    if !out_location_line.is_null() {
        // SAFETY: caller guarantees out_location_line is writable.
        unsafe {
            *out_location_line = line;
        }
    }
    if !out_location_column.is_null() {
        // SAFETY: caller guarantees out_location_column is writable.
        unsafe {
            *out_location_column = column;
        }
    }
}

/// Returns `1` when the result carries a non-null spec AND no `Error`-severity
/// diagnostic. Returns `0` otherwise (including when `result` is null).
#[no_mangle]
pub extern "C" fn cose_sign1_trust_policy_result_is_success(
    result: *const cose_sign1_trust_policy_translation_result_t,
) -> i32 {
    // SAFETY: borrowed pointer; null-tolerant.
    let Some(result) = (unsafe { result.as_ref() }) else {
        return 0;
    };
    if result.inner.is_success() {
        1
    } else {
        0
    }
}

/// Borrow the [`TrustPolicySpec`] held by a successful result. Returns null when
/// the result is unsuccessful or `result` is null.
///
/// The returned handle is **a fresh heap-owned copy**: the caller MUST free it via
/// [`cose_sign1_trust_policy_spec_free`]. (Cloning is required because spec handles
/// outlive the result handle in typical pipelines.)
#[no_mangle]
pub extern "C" fn cose_sign1_trust_policy_result_spec(
    result: *const cose_sign1_trust_policy_translation_result_t,
) -> *mut cose_sign1_trust_policy_spec_t {
    // SAFETY: borrowed pointer; null-tolerant.
    let Some(result) = (unsafe { result.as_ref() }) else {
        return std::ptr::null_mut();
    };
    let Some(spec) = result.inner.spec.clone() else {
        return std::ptr::null_mut();
    };
    let boxed = Box::new(cose_sign1_trust_policy_spec_t { inner: spec });
    Box::into_raw(boxed)
}

// ---------------------------------------------------------------------------
// Bind.
// ---------------------------------------------------------------------------

/// Bind `$param` references in `spec` against a JSON-object parameter map.
///
/// `parameters_json` is a UTF-8 JSON object whose keys are parameter names and whose
/// values are the substituted JSON values. An empty buffer (`parameters_json_len == 0`)
/// is interpreted as `{}` — the call still succeeds for specs with no parameter
/// references or for specs whose every reference carries a default.
///
/// Always populates `*out_result` with a non-null handle on `COSE_OK`. Bind errors
/// (`TPX400`, `TPX401`, `TPX301`) surface as a single `Error`-severity diagnostic on
/// the result handle.
///
/// # Ownership
///
/// `spec` is borrowed (caller retains ownership). `*out_result` is owned by the caller
/// after a successful call; release via [`cose_sign1_trust_policy_result_free`].
#[no_mangle]
pub extern "C" fn cose_sign1_trust_policy_spec_bind(
    spec: *const cose_sign1_trust_policy_spec_t,
    parameters_json: *const u8,
    parameters_json_len: usize,
    out_result: *mut *mut cose_sign1_trust_policy_translation_result_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        if out_result.is_null() {
            anyhow::bail!("out_result must not be null");
        }
        // SAFETY: borrowed pointer; null check via as_ref.
        let spec_handle = unsafe { spec.as_ref() }
            .ok_or_else(|| anyhow::anyhow!("spec must not be null"))?;

        // SAFETY: caller-supplied length-prefixed buffer.
        let bytes =
            unsafe { slice_from_raw("parameters_json", parameters_json, parameters_json_len)? };

        let parameters = parse_parameter_map(bytes)?;

        let result = match bind(spec_handle.inner.clone(), &parameters) {
            Ok(spec) => TrustPolicyTranslationResult::success(spec, Vec::new()),
            Err(err) => TrustPolicyTranslationResult::failure(vec![diagnostic_for_bind_error(err)]),
        };

        let boxed = Box::new(cose_sign1_trust_policy_translation_result_t { inner: result });
        // SAFETY: out_result was non-null per the early check.
        unsafe {
            *out_result = Box::into_raw(boxed);
        }
        Ok(cose_status_t::COSE_OK)
    })
}

fn parse_parameter_map(bytes: &[u8]) -> Result<BTreeMap<String, Value>, anyhow::Error> {
    if bytes.is_empty() {
        return Ok(BTreeMap::new());
    }
    let value: Value = serde_json::from_slice(bytes)
        .context("parameters_json must be a valid JSON object")?;
    let map = match value {
        Value::Object(obj) => obj,
        other => anyhow::bail!(
            "parameters_json must be a JSON object, got {kind}",
            kind = short_kind(&other),
        ),
    };
    Ok(map.into_iter().collect())
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn short_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a bool",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

// ---------------------------------------------------------------------------
// Compile.
// ---------------------------------------------------------------------------

/// Compile a (bound) spec to a [`cose_sign1_trust_policy_compiled_plan_t`].
///
/// The fact registry is loaded from the workspace's static pack contributors
/// (certificates + MST + validation-core); the consumer does NOT supply it. Future
/// phases may extend the pack set.
///
/// Returns `COSE_OK` on success; on a structural compile error (`TPX200`, `TPX301`,
/// `TPX500`) the integer return is `COSE_ERR` and the error message is available via
/// `cose_last_error_message_utf8()`. Use [`cose_sign1_trust_policy_spec_compile_to_result`]
/// when the diagnostic-handle introspection path is preferred.
///
/// # Ownership
///
/// `spec` is borrowed. `*out_plan` is owned by the caller; release via
/// [`cose_sign1_trust_policy_compiled_plan_free`].
#[no_mangle]
pub extern "C" fn cose_sign1_trust_policy_spec_compile(
    spec: *const cose_sign1_trust_policy_spec_t,
    out_plan: *mut *mut cose_sign1_trust_policy_compiled_plan_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        if out_plan.is_null() {
            anyhow::bail!("out_plan must not be null");
        }
        // SAFETY: borrowed; null check via as_ref.
        let spec_handle = unsafe { spec.as_ref() }
            .ok_or_else(|| anyhow::anyhow!("spec must not be null"))?;

        let plan = compile(&spec_handle.inner, registry() as &dyn IFactRegistry)
            .map_err(|err| anyhow::anyhow!("{err}"))?;

        let boxed = Box::new(cose_sign1_trust_policy_compiled_plan_t { inner: plan });
        // SAFETY: out_plan was non-null per early check.
        unsafe {
            *out_plan = Box::into_raw(boxed);
        }
        Ok(cose_status_t::COSE_OK)
    })
}

/// Diagnostic-handle variant of [`cose_sign1_trust_policy_spec_compile`].
///
/// Always populates `*out_result` on `COSE_OK`. On compile error, the result handle
/// carries a single `Error`-severity diagnostic and `spec` is `None`. On success the
/// result's `spec` field re-borrows the input spec (for symmetry with translate /
/// bind) and `*out_plan` carries the compiled plan.
///
/// `out_plan` MAY be null — pass null to compile-validate without keeping the plan.
///
/// # Ownership
///
/// `spec` is borrowed. `*out_result` is owned (caller frees with
/// [`cose_sign1_trust_policy_result_free`]). When non-null, `*out_plan` is owned
/// (caller frees with [`cose_sign1_trust_policy_compiled_plan_free`]).
#[no_mangle]
pub extern "C" fn cose_sign1_trust_policy_spec_compile_to_result(
    spec: *const cose_sign1_trust_policy_spec_t,
    out_result: *mut *mut cose_sign1_trust_policy_translation_result_t,
    out_plan: *mut *mut cose_sign1_trust_policy_compiled_plan_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        if out_result.is_null() {
            anyhow::bail!("out_result must not be null");
        }
        // SAFETY: borrowed; null check via as_ref.
        let spec_handle = unsafe { spec.as_ref() }
            .ok_or_else(|| anyhow::anyhow!("spec must not be null"))?;

        let outcome = compile(&spec_handle.inner, registry() as &dyn IFactRegistry);
        let result = match outcome {
            Ok(plan) => {
                if !out_plan.is_null() {
                    let boxed_plan = Box::new(cose_sign1_trust_policy_compiled_plan_t {
                        inner: plan,
                    });
                    // SAFETY: out_plan checked above.
                    unsafe {
                        *out_plan = Box::into_raw(boxed_plan);
                    }
                }
                TrustPolicyTranslationResult::success(spec_handle.inner.clone(), Vec::new())
            }
            Err(err) => {
                if !out_plan.is_null() {
                    // SAFETY: out_plan checked above.
                    unsafe {
                        *out_plan = std::ptr::null_mut();
                    }
                }
                TrustPolicyTranslationResult::failure(vec![diagnostic_for_compile_error(&err)])
            }
        };

        let boxed = Box::new(cose_sign1_trust_policy_translation_result_t { inner: result });
        // SAFETY: out_result was non-null per early check.
        unsafe {
            *out_result = Box::into_raw(boxed);
        }
        Ok(cose_status_t::COSE_OK)
    })
}

// ---------------------------------------------------------------------------
// Spec introspection (small surface — full IR walk is out of scope for FFI).
// ---------------------------------------------------------------------------

/// Returns whether the spec is structurally a parameter-bearing tree (i.e. one or more
/// `$param` references reachable from the root). Useful as a pre-flight check before
/// calling [`cose_sign1_trust_policy_spec_bind`].
///
/// Returns `0` when `spec` is null or carries no parameters; `1` when at least one
/// parameter reference exists.
#[no_mangle]
pub extern "C" fn cose_sign1_trust_policy_spec_has_parameters(
    spec: *const cose_sign1_trust_policy_spec_t,
) -> i32 {
    // SAFETY: borrowed; null-tolerant.
    let Some(spec_handle) = (unsafe { spec.as_ref() }) else {
        return 0;
    };
    if spec_has_parameters(&spec_handle.inner) {
        1
    } else {
        0
    }
}

fn spec_has_parameters(spec: &TrustPolicySpec) -> bool {
    match spec {
        TrustPolicySpec::AllowAll | TrustPolicySpec::DenyAll { .. } => false,
        TrustPolicySpec::And { specs } | TrustPolicySpec::Or { specs } => {
            specs.iter().any(spec_has_parameters)
        }
        TrustPolicySpec::Not { spec, .. } => spec_has_parameters(spec),
        TrustPolicySpec::Implies { antecedent, consequent } => {
            spec_has_parameters(antecedent) || spec_has_parameters(consequent)
        }
        TrustPolicySpec::Message { requirements }
        | TrustPolicySpec::PrimarySigningKey { requirements }
        | TrustPolicySpec::AnyCounterSignature { requirements, .. } => {
            requirements.iter().any(spec_has_parameters)
        }
        TrustPolicySpec::RequireFact { predicate, .. } => predicate_has_parameters(predicate),
        // Forward-compat — see spec_has_parameters_forward_compat docs.
        other => spec_has_parameters_forward_compat(other),
    }
}

/// Forward-compat catch-all for `spec_has_parameters` extracted to its own function so
/// it can carry `#[coverage(off)]`. Reachable only when the IR crate ships a new
/// `TrustPolicySpec` variant; conservatively returns `true` so callers run bind
/// defensively.
#[cfg_attr(coverage_nightly, coverage(off))]
#[inline(never)]
fn spec_has_parameters_forward_compat(_spec: &TrustPolicySpec) -> bool {
    true
}

fn predicate_has_parameters(predicate: &FactPredicateSpec) -> bool {
    match predicate {
        FactPredicateSpec::PathOperator(p) => value_has_parameter(&p.value),
        FactPredicateSpec::Property(p) => p.assertions.values().any(json_has_parameter),
        // Forward-compat — see predicate_has_parameters_forward_compat docs.
        other => predicate_has_parameters_forward_compat(other),
    }
}

/// Forward-compat catch-all for `predicate_has_parameters`. Reachable only when the
/// IR crate ships a new `FactPredicateSpec` variant.
#[cfg_attr(coverage_nightly, coverage(off))]
#[inline(never)]
fn predicate_has_parameters_forward_compat(_predicate: &FactPredicateSpec) -> bool {
    true
}

fn value_has_parameter(value: &Option<Value>) -> bool {
    match value {
        Some(v) => json_has_parameter(v),
        None => false,
    }
}

fn json_has_parameter(value: &Value) -> bool {
    match ParameterRef::try_recognize(value) {
        Ok(Some(_)) => true,
        Ok(None) => match value {
            Value::Array(items) => items.iter().any(json_has_parameter),
            Value::Object(map) => map.values().any(json_has_parameter),
            _ => false,
        },
        // Malformed param literal — surface as "yes parameters present" so the caller
        // is forced to run bind (which surfaces the structured TPX401).
        Err(_) => true,
    }
}

// ---------------------------------------------------------------------------
// Free functions.
// ---------------------------------------------------------------------------

/// Free a translation result handle. Null-tolerant.
#[no_mangle]
pub extern "C" fn cose_sign1_trust_policy_result_free(
    result: *mut cose_sign1_trust_policy_translation_result_t,
) {
    if result.is_null() {
        return;
    }
    // SAFETY: handle was produced by a Box::into_raw on this side of the ABI.
    unsafe {
        drop(Box::from_raw(result));
    }
}

/// Free a spec handle. Null-tolerant.
#[no_mangle]
pub extern "C" fn cose_sign1_trust_policy_spec_free(
    spec: *mut cose_sign1_trust_policy_spec_t,
) {
    if spec.is_null() {
        return;
    }
    // SAFETY: handle was produced by a Box::into_raw on this side of the ABI.
    unsafe {
        drop(Box::from_raw(spec));
    }
}

/// Free a compiled-plan handle. Null-tolerant.
#[no_mangle]
pub extern "C" fn cose_sign1_trust_policy_compiled_plan_free(
    plan: *mut cose_sign1_trust_policy_compiled_plan_t,
) {
    if plan.is_null() {
        return;
    }
    // SAFETY: handle was produced by a Box::into_raw on this side of the ABI.
    unsafe {
        drop(Box::from_raw(plan));
    }
}

// ---------------------------------------------------------------------------
// Frontend metadata exposed for discoverability.
// ---------------------------------------------------------------------------

/// Pointer to a NUL-terminated UTF-8 string holding the canonical frontend ID
/// (`cose-tp-json/v1`). Borrowed; static lifetime; the caller MUST NOT free it.
#[no_mangle]
pub extern "C" fn cose_sign1_trust_policy_frontend_id() -> *const std::ffi::c_char {
    // The string lives in `cose_sign1_trustfrontends_json::FRONTEND_ID` as `&'static str`,
    // which is NOT NUL-terminated. We materialize a `'static` C string once.
    static CSTR: OnceLock<std::ffi::CString> = OnceLock::new();
    CSTR.get_or_init(|| {
        std::ffi::CString::new(cose_sign1_trustfrontends_json::FRONTEND_ID)
            .expect("FRONTEND_ID must not contain NUL")
    })
    .as_ptr()
}
