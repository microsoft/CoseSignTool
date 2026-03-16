---
applyTo: "native/rust/**/ffi/**,native/c/**/cose_*.h,native/c_pp/**/cose_*.hpp"
---
# Native FFI Standards — CoseSignTool

> Applies to all Rust FFI crates (`<pkg>/ffi/`) and their C/C++ projections.

## FFI Crate Structure

Every library crate that exposes functionality to C/C++ MUST have a corresponding `ffi/` subdirectory:
```
cose_sign1_validation/      ← Rust library (Cargo.toml + src/)
cose_sign1_validation/ffi/  ← C-ABI projection (Cargo.toml + src/)
```

### FFI Crate Rules

1. **One FFI crate per library crate** — never merge FFI for multiple libraries.
2. **`[lib] crate-type = ["staticlib", "cdylib"]`** — produce both static and dynamic libraries.
3. **`test = false`** — FFI crates do not have Rust tests (tests are in C/C++).
4. **`#![deny(unsafe_op_in_unsafe_fn)]`** — enforce explicit unsafe blocks.

## Exported Function Pattern

```rust
/// Brief description of what this function does.
///
/// # Safety
/// - `out_ptr` must be a valid, non-null, aligned pointer.
/// - Caller must free the result with `cose_*_free()`.
#[no_mangle]
pub extern "C" fn cose_module_action(
    input: *const SomeHandle,
    param: *const c_char,
    out_ptr: *mut *mut ResultHandle,
) -> cose_status_t {
    with_catch_unwind(|| {
        // Null checks FIRST
        if out_ptr.is_null() {
            anyhow::bail!("out_ptr must not be null");
        }
        let input = unsafe { input.as_ref() }
            .context("input handle must not be null")?;
        
        // Business logic
        let result = do_something(input)?;
        
        // Transfer ownership to caller
        unsafe { *out_ptr = Box::into_raw(Box::new(result)) };
        Ok(COSE_OK)
    })
}
```

### Mandatory Elements

| Element | Requirement |
|---------|-------------|
| `#[no_mangle]` | Required on all exported functions |
| `pub extern "C"` | C calling convention |
| Return type | Always `cose_status_t` (or `u32`/`i32` for primitives) |
| Null checks | On ALL pointer parameters, fail with descriptive message |
| Panic safety | ALL logic wrapped in `with_catch_unwind()` |
| Memory ownership | Documented: who frees, which `*_free` function to use |
| ABI version | Every FFI crate exports `cose_*_abi_version() -> u32` |

## Handle Types — Opaque Pointers

```rust
/// Opaque handle for the validator builder.
/// Freed with `cose_validator_builder_free()`.
pub struct ValidatorBuilderHandle(ValidatorBuilder);
```

- Handles are `Box::into_raw()` to give to C, `Box::from_raw()` to reclaim.
- **NEVER** expose Rust struct layout to C — handles are always opaque.
- Every handle type needs a corresponding `*_free()` function.

## Status Codes

```rust
pub type cose_status_t = u32;
pub const COSE_OK: cose_status_t = 0;
pub const COSE_ERR: cose_status_t = 1;
pub const COSE_PANIC: cose_status_t = 2;
pub const COSE_INVALID_ARG: cose_status_t = 3;
```

## Error Reporting

Thread-local last-error pattern:
```rust
thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = RefCell::new(None);
}

// Set error (called inside with_catch_unwind on failure)
fn set_last_error(msg: impl AsRef<str>) { ... }

// Retrieve error (called by C: cose_last_error_message_utf8())
fn take_last_error_ptr() -> *mut c_char { ... }
```

## String Ownership

- Strings returned to C are `*mut c_char` allocated via `CString::into_raw()`.
- Caller frees with `cose_string_free(s)` which calls `CString::from_raw()`.
- **NEVER** return `&str` or `String` across FFI — always `CString`.
- Input strings from C: use `CStr::from_ptr(s).to_str()` with null checks.

## Memory Convention Summary

| Allocation | Free Function | Notes |
|-----------|---------------|-------|
| String (`*mut c_char`) | `cose_string_free(s)` | UTF-8 null-terminated |
| Handle (`*mut HandleT`) | `cose_*_free(h)` | Per-type free function |
| Byte buffer (`*mut u8`, `len`) | `cose_*_bytes_free(ptr, len)` | Caller-must-free |

## ABI Parity Gate

The `Assert-FluentHelpersProjectedToFfi` gate in `collect-coverage.ps1` ensures every `require_*` fluent helper in Rust validation code has a corresponding FFI export. 

**Excluded** (Rust-only, require closures): `require_cwt_claim`, `require_kid_allowed`, `require_trusted`.

When adding a new fluent helper: add its FFI projection or add it to the exclusion list with justification.

## Naming Conventions

### Two-Tier Prefix System
- **`cose_`** prefix — generic COSE operations not specific to Sign1:
  `cose_status_t`, `cose_string_free`, `cose_last_error_message_utf8`,
  `cose_headermap_*`, `cose_key_*`, `cose_crypto_*`, `cose_cwt_*`,
  `cose_certificates_key_from_cert_der`, `cose_cert_local_*`,
  `cose_akv_key_client_*`, `cose_mst_client_*`, `cose_mst_bytes_free`
- **`cose_sign1_`** prefix — Sign1-specific operations:
  `cose_sign1_message_*`, `cose_sign1_builder_*`, `cose_sign1_factory_*`,
  `cose_sign1_validator_*`, `cose_sign1_trust_*`,
  `cose_sign1_certificates_trust_policy_builder_require_*`,
  `cose_sign1_mst_trust_policy_builder_require_*`,
  `cose_sign1_akv_trust_policy_builder_require_*`
- **`did_x509_`** prefix — DID:x509 utilities (separate RFC domain)

### C Header Mapping
Each Rust FFI crate maps to one C header and one C++ header:

| Rust FFI Crate | C Header | C++ Header |
|----------------|----------|------------|
| `cose_sign1_primitives_ffi` | `<cose/sign1.h>` | `<cose/sign1.hpp>` |
| `cose_sign1_crypto_openssl_ffi` | `<cose/crypto/openssl.h>` | `<cose/crypto/openssl.hpp>` |
| `cose_sign1_signing_ffi` | `<cose/sign1/signing.h>` | `<cose/sign1/signing.hpp>` |
| `cose_sign1_factories_ffi` | `<cose/sign1/factories.h>` | `<cose/sign1/factories.hpp>` |
| `cose_sign1_headers_ffi` | `<cose/sign1/cwt.h>` | `<cose/sign1/cwt.hpp>` |
| `cose_sign1_validation_ffi` | `<cose/sign1/validation.h>` | `<cose/sign1/validation.hpp>` |
| `cose_sign1_validation_primitives_ffi` | `<cose/sign1/trust.h>` | `<cose/sign1/trust.hpp>` |
| `cose_sign1_certificates_ffi` | `<cose/sign1/extension_packs/certificates.h>` | `<cose/sign1/extension_packs/certificates.hpp>` |
| `cose_sign1_akv_ffi` | `<cose/sign1/extension_packs/azure_key_vault.h>` | `<cose/sign1/extension_packs/azure_key_vault.hpp>` |
| `cose_sign1_mst_ffi` | `<cose/sign1/extension_packs/mst.h>` | `<cose/sign1/extension_packs/mst.hpp>` |
| `did_x509_ffi` | `<cose/did/x509.h>` | `<cose/did/x509.hpp>` |

### Handle Type Names
- C: `typedef struct cose_*_t cose_*_t;`
- Rust: `pub struct *Handle(*Inner);`
