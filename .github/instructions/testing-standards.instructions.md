---
applyTo: "native/**"
---
# Native Testing Standards — CoseSignTool

> Testing conventions for all native Rust, C, and C++ code.

## Test Organization

| Test Type | Location | Purpose |
|-----------|----------|---------|
| Rust unit tests | `src/**/*.rs` (`#[cfg(test)]` mods) | Internal function logic |
| Rust integration tests | `tests/*.rs` | Public API roundtrips |
| FFI smoke tests | `ffi/tests/*.rs` | C-ABI lifecycle + null safety |
| C tests | `native/c/tests/` | C header API correctness |
| C++ tests | `native/c_pp/tests/` | RAII wrapper correctness |

## Rust Test Conventions

### Naming
Test functions should clearly describe the scenario and expected outcome:
```rust
#[test]
fn sign_with_default_headers_produces_valid_tagged_message() { ... }

#[test]
fn parse_null_bytes_returns_error() { ... }
```

### Structure — Arrange, Act, Assert
```rust
#[test]
fn validate_signed_message_succeeds() {
    // Arrange
    let key_pair = TestKeyPair::generate_p256();
    let payload = b"test payload";
    let message = sign_test_message(&key_pair, payload);

    // Act
    let result = validator.validate(&message, &raw_bytes);

    // Assert
    assert!(result.is_ok());
    assert_eq!(result.unwrap().validation_status(), ValidationStatus::Valid);
}
```

### Parallelism Safety
Tests MUST be safe to run in parallel. This means:
```rust
// ❌ BAD: Shared temp file path
let path = std::env::temp_dir().join("test_payload.txt");

// ✅ GOOD: Unique temp file per test invocation
let path = std::env::temp_dir().join(format!(
    "test_payload_{:?}_{}.txt",
    std::thread::current().id(),
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
));
```

Rules:
- **No shared mutable files** — use unique names with thread ID + timestamp
- **No shared global state** — each test creates its own instances
- **No port conflicts** — avoid binding to well-known ports in tests
- **No test ordering dependencies** — each test is self-contained

## FFI Test Patterns

### Lifecycle Test (Create → Use → Free)
```rust
#[test]
fn builder_create_use_free_lifecycle() {
    // Create
    let mut builder: *mut BuilderHandle = std::ptr::null_mut();
    let status = cose_sign1_builder_new(&mut builder);
    assert_eq!(status, COSE_OK);
    assert!(!builder.is_null());

    // Use
    let status = cose_sign1_builder_set_tagged(builder, true);
    assert_eq!(status, COSE_OK);

    // Free
    cose_sign1_builder_free(builder);
}
```

### Null Pointer Safety Tests
Every FFI function must have null-safety tests for each pointer parameter:
```rust
#[test]
fn set_protected_null_builder_returns_error() {
    let mut headers: *mut HeaderMapHandle = std::ptr::null_mut();
    let _ = cose_header_map_new(&mut headers);
    let status = cose_sign1_builder_set_protected(std::ptr::null_mut(), headers);
    assert_eq!(status, COSE_ERR);
    cose_header_map_free(headers);
}

#[test]
fn set_protected_null_headers_returns_error() {
    let mut builder: *mut BuilderHandle = std::ptr::null_mut();
    let _ = cose_sign1_builder_new(&mut builder);
    let status = cose_sign1_builder_set_protected(builder, std::ptr::null());
    assert_eq!(status, COSE_ERR);
    cose_sign1_builder_free(builder);
}
```

### Consume Function Tests
For consume variants, verify that the handle is invalidated after consumption:
```rust
#[test]
fn consume_protected_moves_ownership() {
    let mut builder = create_test_builder();
    let mut headers = create_test_headers();

    let status = cose_sign1_builder_consume_protected(builder, headers);
    assert_eq!(status, COSE_OK);
    // headers is now consumed — do NOT free it

    cose_sign1_builder_free(builder);
}
```

### Roundtrip Tests
Critical for verifying the full pipeline works end-to-end:
```rust
#[test]
fn sign_parse_validate_roundtrip() {
    // Sign
    let signed_bytes = sign_with_test_key(b"payload");

    // Parse
    let message = CoseSign1Message::parse(&signed_bytes).unwrap();
    assert_eq!(message.payload().unwrap(), b"payload");

    // Validate
    let result = validator.validate(&message, &Arc::from(signed_bytes));
    assert!(result.is_ok());
}
```

## Coverage Requirements

### Targets
- **Library crates**: ≥ 90% line coverage
- **Integration tests**: Cover all public API paths
- **FFI crates**: Business logic coverage via library crate tests (FFI stubs excluded)

### Coverage Exclusions

Only these categories may use `#[cfg_attr(coverage_nightly, coverage(off))]`:

| Category | Example | Why Excluded |
|----------|---------|--------------|
| FFI panic handlers | `handle_panic()` | Genuinely unreachable without process crash |
| FFI write stubs | `write_signed_bytes()` | Unreachable due to mandatory post-sign verification |
| ABI version functions | `cose_*_abi_version()` | Compile-time constants |
| Free functions | `cose_*_free()` | Simple pointer dealloc, tested via lifecycle tests |
| Error accessors | `cose_last_error_*()` | Thread-local accessor stubs |

**Never exclude** from coverage:
- Business logic
- Validation / parsing
- Error handling branches
- Crypto operations
- Builder methods

Every `coverage(off)` annotation should include a comment justifying the exclusion:
```rust
/// Writes signed bytes to output buffer.
///
/// This path is unreachable because `SimpleSigningService::verify_signature`
/// always returns `Err`, causing the mandatory post-sign verification to fail
/// before reaching this function.
#[cfg_attr(coverage_nightly, coverage(off))]
unsafe fn write_signed_bytes(...) { ... }
```

### Running Coverage
```powershell
# Full workspace coverage
cd native/rust
$env:OPENSSL_DIR = "c:\vcpkg\installed\x64-windows"
$env:PATH = "$env:OPENSSL_DIR\bin;$env:PATH"
.\collect-coverage.ps1

# Per-crate coverage
cargo +nightly llvm-cov --json -p cose_sign1_signing
```

Note: 5 FFI-only crates (no tests) will report FAIL — this is expected.

## C/C++ Test Conventions

### GTest Structure
```cpp
TEST(CoseSign1BuilderTest, CreateAndFreeLifecycle) {
    CoseSign1Builder builder = CoseSign1Builder::New();
    // Builder is RAII — destructor calls cose_sign1_builder_free()
    // If we get here without crash, the lifecycle works
    ASSERT_TRUE(builder);
}

TEST(CoseSign1BuilderTest, SetProtectedHeaders) {
    auto builder = CoseSign1Builder::New();
    auto headers = HeaderMap::New();
    headers.SetInt(1, -7);  // alg: ES256

    builder.SetProtected(headers);
    // Verify via inspection or roundtrip
}
```

### Feature Guard Tests
Extension pack tests must be guarded by feature defines:
```cpp
#ifdef COSE_HAS_CERTIFICATES
TEST(CertificatesTest, CreateTrustPack) { ... }
#endif
```

## Test Data

- Use `TestKeyPair::generate_p256()` or `generate_p384()` for ephemeral keys
- Never hardcode private keys in test files
- Use `b"test payload"` or descriptive byte literals for test payloads
- For certificate tests, use `certificates_local` crate for ephemeral cert chains
