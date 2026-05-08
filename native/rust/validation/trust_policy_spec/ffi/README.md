# cose_sign1_trust_policy_spec_ffi

C-ABI projection for [`cose_sign1_trust_policy_spec`](../README.md). Phase 4.5
of the native Rust trust-policy port.

This crate is the differentiator vs. the .NET implementation: a stable C ABI
that lets non-Rust consumers — C/C++ directly, .NET via P/Invoke, Node via
N-API, Go via cgo — load `.coseTrustPolicy.json` documents and translate them
into a runtime-evaluable form. "Policy as document, runs anywhere."

## Frontend

The single supported frontend in v1 is **`cose-tp-json/v1`** (canonical
reference) — exposed both directly via
[`cose_sign1_trust_policy_translate_json`](../../../c/include/cose/sign1/trust_policy.h)
and via the metadata accessor
[`cose_sign1_trust_policy_frontend_id`](../../../c/include/cose/sign1/trust_policy.h).
A future Phase 5a Rego frontend will land beside it.

## Pipeline

```text
   JSON bytes ──► translate_json ──► result handle  (spec? + diagnostics)
                                          │
                            result_spec ◄─┘                                          │
                              spec handle ─┴──► spec_bind(parameters_json) ──► result handle
                                                                                    │
                                                                       result_spec ◄┘
                                                                                    │
                                                                       spec_compile ──► compiled plan
```

## Memory ownership (R6)

| Pointer kind | Ownership | Free with |
|---|---|---|
| `cose_sign1_trust_policy_spec_t*` (out-param) | caller | `cose_sign1_trust_policy_spec_free` |
| `cose_sign1_trust_policy_translation_result_t*` (out-param) | caller | `cose_sign1_trust_policy_result_free` |
| `cose_sign1_trust_policy_compiled_plan_t*` (out-param) | caller | `cose_sign1_trust_policy_compiled_plan_free` |
| `const cose_sign1_trust_policy_diagnostic_t*` (return value) | borrowed from parent result | DO NOT free |
| `const uint8_t*` UTF-8 spans from `*_diagnostic_read` | borrowed from parent diagnostic | DO NOT free |
| `const char*` from `*_frontend_id` | static lifetime | DO NOT free |

Every `*_free` function is null-tolerant.

## Diagnostic discipline

Translation diagnostics live on the result handle, **not** on the integer
return code. A `cose_status_t COSE_OK` plus a non-null result handle is
guaranteed even when translation produced errors — the caller MUST inspect
the result handle via `cose_sign1_trust_policy_result_is_success` /
`cose_sign1_trust_policy_result_diagnostic_count`. The integer return code is
reserved for **infrastructure** failure: null pointer arguments, invalid UTF-8,
allocation failure, or a Rust panic caught at the FFI boundary.

This matches the closed-`next_action` discipline applied throughout the
workspace: consumers route on a small enum of mechanical outcomes, not on the
semantic content of the result.

Diagnostic codes are stable: see
`cose_sign1_trust_policy_spec::diagnostic_codes` for the full `TPXxxx` table.

## Threading

- Every entrypoint catches Rust panics so they never cross the ABI boundary.
- Handles are NOT internally synchronized. A single handle MUST NOT be mutated
  from multiple threads concurrently. Multiple immutable readers are safe iff
  no thread holds a non-`const` pointer to the same handle.
- `cose_last_error_message_utf8()` (provided by `cose_sign1_validation_ffi`)
  is thread-local.

## Sample C code (~30 lines)

```c
#include <cose/sign1/trust_policy.h>
#include <cose/sign1/validation.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    const char* doc =
        "{\n"
        "  \"frontend\": \"cose-tp-json/v1\",\n"
        "  \"primary_signing_key\": {\n"
        "    \"fact\": \"x509-cert-identity/v1\",\n"
        "    \"predicate\": { \"thumbprint\":\n"
        "        {\"$param\": \"tp\", \"default\": \"abc\"} }\n"
        "  }\n"
        "}";

    cose_sign1_trust_policy_translation_result_t* result = NULL;
    if (cose_sign1_trust_policy_translate_json(
            (const uint8_t*)doc, strlen(doc), &result) != COSE_OK) return 1;

    if (cose_sign1_trust_policy_result_is_success(result) == 0) {
        size_t n = cose_sign1_trust_policy_result_diagnostic_count(result);
        for (size_t i = 0; i < n; ++i) {
            const cose_sign1_trust_policy_diagnostic_t* d =
                cose_sign1_trust_policy_result_diagnostic_at(result, i);
            const uint8_t* code = NULL; size_t code_len = 0;
            cose_sign1_trust_policy_diagnostic_read(
                d, NULL, &code, &code_len, NULL, NULL, NULL, NULL);
            fprintf(stderr, "[%.*s]\n", (int)code_len, (const char*)code);
        }
        cose_sign1_trust_policy_result_free(result);
        return 1;
    }

    cose_sign1_trust_policy_spec_t* spec =
        cose_sign1_trust_policy_result_spec(result);
    cose_sign1_trust_policy_compiled_plan_t* plan = NULL;
    cose_sign1_trust_policy_spec_compile(spec, &plan);

    cose_sign1_trust_policy_compiled_plan_free(plan);
    cose_sign1_trust_policy_spec_free(spec);
    cose_sign1_trust_policy_result_free(result);
    return 0;
}
```

## Sample C++ code (~30 lines)

```cpp
#include <cose/sign1/trust_policy.h>
#include <cose/sign1/validation.h>
#include <memory>
#include <string>

namespace cose {
struct ResultDeleter { void operator()(cose_sign1_trust_policy_translation_result_t* p) const { cose_sign1_trust_policy_result_free(p); } };
struct SpecDeleter   { void operator()(cose_sign1_trust_policy_spec_t* p) const { cose_sign1_trust_policy_spec_free(p); } };
struct PlanDeleter   { void operator()(cose_sign1_trust_policy_compiled_plan_t* p) const { cose_sign1_trust_policy_compiled_plan_free(p); } };
using Result = std::unique_ptr<cose_sign1_trust_policy_translation_result_t, ResultDeleter>;
using Spec   = std::unique_ptr<cose_sign1_trust_policy_spec_t, SpecDeleter>;
using Plan   = std::unique_ptr<cose_sign1_trust_policy_compiled_plan_t, PlanDeleter>;
}

int main() {
    const std::string doc = R"({"frontend":"cose-tp-json/v1","message":{"allow_all":true}})";
    cose_sign1_trust_policy_translation_result_t* raw = nullptr;
    if (cose_sign1_trust_policy_translate_json(
            reinterpret_cast<const uint8_t*>(doc.data()), doc.size(), &raw) != COSE_OK) return 1;
    cose::Result result(raw);

    if (cose_sign1_trust_policy_result_is_success(result.get()) == 0) return 1;
    cose::Spec spec(cose_sign1_trust_policy_result_spec(result.get()));

    cose_sign1_trust_policy_compiled_plan_t* plan_raw = nullptr;
    if (cose_sign1_trust_policy_spec_compile(spec.get(), &plan_raw) != COSE_OK) return 1;
    cose::Plan plan(plan_raw);
    return 0;
}
```

## Test surface

| Test | Coverage |
|---|---|
| `tests/header_drift.rs` | Asserts every `pub extern "C" fn cose_sign1_trust_policy_*` export has a matching declaration in `native/c/include/cose/sign1/trust_policy.h`, and vice versa. |
| `tests/ffi_smoke.rs` | 23 Rust-level integration tests covering happy-path, error-path, every nullable accessor, partial out-pointer reads, and the end-to-end translate + bind + compile lifecycle. |
| `native/c/tests/trust_policy_translate_test.c` | Plain-C consumer; exits 0 on success, prints `[ok]` per check. |
| `native/c/tests/trust_policy_translate_gtest.cpp` | C++ / GoogleTest consumer with RAII handle wrappers, verifying the header is `extern "C"`-clean and integrates with C++ ownership patterns. |

## Coverage gate

Per-crate coverage threshold is 90% (the workspace standard). To run:

```powershell
cd native/rust
.\collect-coverage.ps1 -Package cose_sign1_trust_policy_spec_ffi -FailUnderLines 90
```

## Phase boundary

Phase 4.5 ships **translate + bind + compile** end-to-end. Attaching a
compiled plan to a `cose_sign1_validator_builder_t` for actual validation is
deferred to **Phase 5** plumbing in
`cose_sign1_validation_primitives_ffi`; the compiled-plan handle in this
crate is the bridge.

## Decisions

- **R6** — opaque error handles via the result handle, not via stringly-typed
  return values.
- **R7** — hand-written C header (matches the rest of the workspace's existing
  pattern; no `cbindgen` infrastructure exists). Drift is gated by the
  `tests/header_drift.rs` literal-name assertion.
- **R1** — registry construction uses the workspace's hand-rolled
  `register_facts!` aggregation; no `inventory`/`linkme`.

See [`eval-trust-policy-translation-contract-rust.md`](https://github.com/microsoft/CoseSignTool/issues)
for the full R-decision table.
