// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COSE_SIGN1_TRUST_POLICY_H
#define COSE_SIGN1_TRUST_POLICY_H

/**
 * @file trust_policy.h
 * @brief C API for translating, binding, and compiling .coseTrustPolicy.json documents.
 *
 * This is the C-ABI projection of the Rust crate
 * `cose_sign1_trust_policy_spec_ffi` (Phase 4.5 of the native trust-policy port).
 *
 * The translation pipeline is:
 *
 *     JSON bytes
 *         |
 *         v
 *     cose_sign1_trust_policy_translate_json --> result handle (spec? + diagnostics)
 *                                                  |
 *                                cose_sign1_trust_policy_result_spec
 *                                                  |
 *                                                  v
 *                                              spec handle
 *                                                  |
 *                                cose_sign1_trust_policy_spec_bind (parameters_json)
 *                                                  |
 *                                                  v
 *                                              spec handle
 *                                                  |
 *                                cose_sign1_trust_policy_spec_compile
 *                                                  |
 *                                                  v
 *                                          compiled-plan handle
 *
 * # Memory ownership
 *
 *  - `_t*` written via an `out_*` parameter is OWNED by the caller; release it
 *    via the matching `*_free()` function. Free functions are null-tolerant.
 *  - `const _t*` parameters are BORROWED; the callee does not retain the pointer.
 *  - UTF-8 byte spans returned by cose_sign1_trust_policy_diagnostic_read alias
 *    memory inside the parent result handle and are valid until that handle is freed.
 *    The caller MUST NOT free those spans.
 *
 * # Status codes
 *
 * Every entrypoint returns cose_status_t (0 = COSE_OK). Translation diagnostics
 * are surfaced via the result handle, NOT via the return value: COSE_OK can mean
 * "translation produced errors but the result handle is non-null and inspectable".
 * Use cose_sign1_trust_policy_result_is_success / _diagnostic_count to inspect
 * the outcome. The non-zero status codes are reserved for infrastructure failures
 * (null pointer arguments, allocation failure, panic).
 *
 * # Thread safety
 *
 * Every entrypoint catches Rust panics so they never cross the ABI boundary.
 * Handles are NOT internally synchronized: a single handle MUST NOT be mutated
 * from multiple threads concurrently. Multiple immutable readers are safe iff no
 * thread holds a non-const pointer.
 *
 * cose_last_error_message_utf8() (provided by cose_sign1_validation_ffi via
 * <cose/sign1/validation.h>) is thread-local.
 */

#include <cose/sign1/validation.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------------------
// Opaque handle types.
// ---------------------------------------------------------------------------

/** Heap-owned handle to a parsed TrustPolicySpec. Free with cose_sign1_trust_policy_spec_free. */
typedef struct cose_sign1_trust_policy_spec_t cose_sign1_trust_policy_spec_t;

/** Heap-owned handle to a translation result. Free with cose_sign1_trust_policy_result_free. */
typedef struct cose_sign1_trust_policy_translation_result_t
    cose_sign1_trust_policy_translation_result_t;

/**
 * Borrowed handle to a single diagnostic. Returned by
 * cose_sign1_trust_policy_result_diagnostic_at; valid for the lifetime of the
 * parent result handle. The caller MUST NOT free it.
 */
typedef struct cose_sign1_trust_policy_diagnostic_t cose_sign1_trust_policy_diagnostic_t;

/** Heap-owned handle to a compiled trust plan. Free with cose_sign1_trust_policy_compiled_plan_free. */
typedef struct cose_sign1_trust_policy_compiled_plan_t
    cose_sign1_trust_policy_compiled_plan_t;

// ---------------------------------------------------------------------------
// Diagnostic severity ABI.
// ---------------------------------------------------------------------------

/** ABI-stable diagnostic severity discriminant written by *_diagnostic_read. */
typedef enum cose_sign1_trust_policy_severity_t {
    /** Translation cannot proceed; result MUST carry no spec. */
    COSE_TP_SEVERITY_ERROR = 0,
    /** Translation succeeded but the frontend wants the host to know. */
    COSE_TP_SEVERITY_WARNING = 1,
    /** Informational — always non-blocking. */
    COSE_TP_SEVERITY_INFO = 2
} cose_sign1_trust_policy_severity_t;

// ---------------------------------------------------------------------------
// Translate.
// ---------------------------------------------------------------------------

/**
 * @brief Translate a `.coseTrustPolicy.json` byte buffer into a translation result handle.
 *
 * @param json_bytes  UTF-8 buffer; need not be NUL-terminated.
 * @param json_len    Buffer length in bytes; may be 0 (returns a result with a parse error).
 * @param out_result  Out parameter; on COSE_OK, *out_result is non-null and owned by the caller.
 *                    Caller MUST free via cose_sign1_trust_policy_result_free.
 *
 * @return COSE_OK when the result handle was produced (regardless of whether
 *         translation succeeded or produced diagnostics).
 *         COSE_ERR / COSE_PANIC / COSE_INVALID_ARG for infrastructure failures
 *         (null out_result, non-UTF-8 input, panic, allocation failure). On non-OK,
 *         *out_result is left untouched.
 */
cose_status_t cose_sign1_trust_policy_translate_json(
    const uint8_t* json_bytes,
    size_t json_len,
    cose_sign1_trust_policy_translation_result_t** out_result);

// ---------------------------------------------------------------------------
// Result introspection.
// ---------------------------------------------------------------------------

/** Returns the diagnostic count carried by `result`. Returns 0 when `result` is null. */
size_t cose_sign1_trust_policy_result_diagnostic_count(
    const cose_sign1_trust_policy_translation_result_t* result);

/**
 * Borrow a diagnostic by index. Returns null when `result` is null or `index` is
 * out of bounds. The returned pointer is borrowed; caller MUST NOT free it.
 */
const cose_sign1_trust_policy_diagnostic_t* cose_sign1_trust_policy_result_diagnostic_at(
    const cose_sign1_trust_policy_translation_result_t* result,
    size_t index);

/**
 * Read a diagnostic's fields.
 *
 * `out_severity` writes a cose_sign1_trust_policy_severity_t discriminant.
 * `out_*_ptr` / `out_*_len` write borrowed UTF-8 spans valid for the diagnostic's
 * lifetime — caller MUST NOT free them.
 * `out_location_*` writes 0 when the diagnostic carries no source location;
 * otherwise both line and column are 1-indexed.
 *
 * Any out parameter MAY be null. Does nothing when `diagnostic` is null.
 */
void cose_sign1_trust_policy_diagnostic_read(
    const cose_sign1_trust_policy_diagnostic_t* diagnostic,
    uint8_t* out_severity,
    const uint8_t** out_code_ptr,
    size_t* out_code_len,
    const uint8_t** out_message_ptr,
    size_t* out_message_len,
    uint32_t* out_location_line,
    uint32_t* out_location_column);

/**
 * Returns 1 when the result carries a non-null spec AND no Error-severity
 * diagnostic; returns 0 otherwise (including when `result` is null).
 */
int32_t cose_sign1_trust_policy_result_is_success(
    const cose_sign1_trust_policy_translation_result_t* result);

/**
 * Borrow the spec held by a successful result; clones into a NEW heap-owned spec
 * handle. Returns null when the result is unsuccessful or `result` is null.
 *
 * Caller MUST free via cose_sign1_trust_policy_spec_free.
 */
cose_sign1_trust_policy_spec_t* cose_sign1_trust_policy_result_spec(
    const cose_sign1_trust_policy_translation_result_t* result);

// ---------------------------------------------------------------------------
// Bind.
// ---------------------------------------------------------------------------

/**
 * @brief Bind `$param` references in `spec` against a JSON-object parameter map.
 *
 * @param spec                  Borrowed spec handle.
 * @param parameters_json       UTF-8 JSON object; may be empty (treated as `{}`).
 * @param parameters_json_len   Buffer length in bytes.
 * @param out_result            Out parameter; on COSE_OK, *out_result is non-null and owned.
 *
 * Bind errors (TPX400 / TPX401 / TPX301) surface as a single Error-severity
 * diagnostic on the result handle.
 *
 * @return COSE_OK on result-produced. Non-OK only on infrastructure failure.
 */
cose_status_t cose_sign1_trust_policy_spec_bind(
    const cose_sign1_trust_policy_spec_t* spec,
    const uint8_t* parameters_json,
    size_t parameters_json_len,
    cose_sign1_trust_policy_translation_result_t** out_result);

/**
 * Returns 1 when `spec` reachably contains at least one `$param` reference;
 * returns 0 when null or parameter-free. Useful as a pre-flight check.
 */
int32_t cose_sign1_trust_policy_spec_has_parameters(
    const cose_sign1_trust_policy_spec_t* spec);

// ---------------------------------------------------------------------------
// Compile.
// ---------------------------------------------------------------------------

/**
 * @brief Compile a (bound) spec to a compiled trust plan.
 *
 * The fact registry is loaded from the workspace's static pack contributors
 * (certificates + MST + validation core).
 *
 * @param spec     Borrowed spec handle.
 * @param out_plan Out parameter; on COSE_OK, *out_plan is non-null and owned.
 *
 * @return COSE_OK on success.
 *         COSE_ERR on compile error (TPX200 / TPX301 / TPX500); call
 *         cose_last_error_message_utf8() for the detail message.
 *
 * For diagnostic-handle introspection of compile errors, use
 * cose_sign1_trust_policy_spec_compile_to_result.
 */
cose_status_t cose_sign1_trust_policy_spec_compile(
    const cose_sign1_trust_policy_spec_t* spec,
    cose_sign1_trust_policy_compiled_plan_t** out_plan);

/**
 * Diagnostic-handle variant of cose_sign1_trust_policy_spec_compile.
 *
 * Always populates *out_result on COSE_OK. On compile error, the result handle
 * carries a single Error-severity diagnostic and *out_plan (when non-null) is
 * set to null. On success the result's spec field re-borrows the input spec
 * and (when non-null) *out_plan carries the compiled plan.
 *
 * `out_plan` MAY be null — pass null to compile-validate without keeping the plan.
 */
cose_status_t cose_sign1_trust_policy_spec_compile_to_result(
    const cose_sign1_trust_policy_spec_t* spec,
    cose_sign1_trust_policy_translation_result_t** out_result,
    cose_sign1_trust_policy_compiled_plan_t** out_plan);

// ---------------------------------------------------------------------------
// Frontend metadata.
// ---------------------------------------------------------------------------

/**
 * Returns a borrowed NUL-terminated UTF-8 string holding the canonical frontend
 * ID ("cose-tp-json/v1"). Static lifetime; caller MUST NOT free it.
 */
const char* cose_sign1_trust_policy_frontend_id(void);

// ---------------------------------------------------------------------------
// Free functions (null-tolerant).
// ---------------------------------------------------------------------------

/** Free a translation result handle. */
void cose_sign1_trust_policy_result_free(
    cose_sign1_trust_policy_translation_result_t* result);

/** Free a spec handle. */
void cose_sign1_trust_policy_spec_free(
    cose_sign1_trust_policy_spec_t* spec);

/** Free a compiled-plan handle. */
void cose_sign1_trust_policy_compiled_plan_free(
    cose_sign1_trust_policy_compiled_plan_t* plan);

#ifdef __cplusplus
}
#endif

#endif // COSE_SIGN1_TRUST_POLICY_H
