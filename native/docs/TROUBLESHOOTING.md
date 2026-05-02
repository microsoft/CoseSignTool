<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# Troubleshooting Guide

Common issues when building, linking, or using the native COSE Sign1 SDK.

> See also: [07-troubleshooting.md](07-troubleshooting.md) for vcpkg-specific issues.

---

## Runtime Errors

### COSE_PANIC (status code 2)

A Rust panic was caught at the FFI boundary. This indicates a bug in the library.

**What to do:**

1. Call `cose_last_error_message_utf8()` immediately — the error message describes
   what panicked.
2. Free the returned string with `cose_string_free()`.
3. File a bug report with the error message and reproduction steps.

**Common causes:**

- Malformed CBOR data that triggers an unexpected code path.
- Internal invariant violation (rare).

### COSE_ERR (status code 1)

A recoverable error occurred in the validation / extension-pack layer.

**What to do:**

1. Call `cose_last_error_message_utf8()` for details.
2. Check the error message for guidance (e.g., `"input handle must not be null"`).
3. Fix the calling code accordingly.

### COSE_INVALID_ARG (status code 3)

An invalid argument was passed to a validation or extension-pack FFI function.

**Common causes:**

- `NULL` pointer passed where non-null is required.
- Zero-length buffer with non-null pointer.
- Invalid handle (previously freed or never created).

### Primitives / Signing Layer: Negative Error Codes

The primitives (`<cose/sign1.h>`) and signing (`<cose/sign1/signing.h>`) layers
use negative `int32_t` codes instead of `cose_status_t`. Common ones:

| Code | Meaning |
|------|---------|
| `0`   | Success |
| `-1`  | Null pointer |
| `-2`  | Parse failed (primitives) / Sign failed (signing) |
| `-99` | Rust panic caught |

See [ERROR-CODES.md](ERROR-CODES.md) for the complete reference.

### Thread-Local Error Lost

**Symptoms:** `cose_last_error_message_utf8()` returns `NULL` after a failure.

**Cause:** Error messages are stored in thread-local storage. If you call an FFI
function on thread A and read the error on thread B, you get thread B's last
error (which may be empty).

**Fix:** Always read the error message on the **same thread** that made the
failing call.

### Validation Returns False But No Error

**Symptoms:** `cose_sign1_validation_result_is_success()` returns `false` but
`cose_last_error_message_utf8()` is empty.

**Explanation:** Validation failures are not FFI errors — they are expected
results. The failure reason lives in the validation result itself.

**Fix (C):**

```c
bool success = false;
cose_sign1_validation_result_is_success(result, &success);
if (!success) {
    /* Use the validation result's own message — not the thread-local error */
    char* msg = cose_sign1_validation_result_failure_message_utf8(result);
    fprintf(stderr, "Validation failed: %s\n", msg ? msg : "(no message)");
    cose_string_free(msg);
}
```

**Fix (C++):**

```cpp
auto result = validator.Validate(cose_bytes);
if (!result.IsSuccess()) {
    std::cerr << "Validation failed: " << result.FailureMessage() << std::endl;
}
```

---

## Build Errors

### OpenSSL Not Found

**Symptoms:** Build fails with `"Could not find directory of OpenSSL installation"`.

**Fix (Windows with vcpkg):**

```powershell
vcpkg install openssl:x64-windows
$env:OPENSSL_DIR = "c:\vcpkg\installed\x64-windows"
$env:PATH = "$env:OPENSSL_DIR\bin;$env:PATH"
cargo build --workspace
```

**Fix (Ubuntu / Debian):**

```bash
sudo apt-get install libssl-dev pkg-config
cargo build --workspace
```

**Fix (RHEL / CentOS / Fedora):**

```bash
sudo yum install openssl-devel
cargo build --workspace
```

### CMake Cannot Find Rust Libraries

**Symptoms:** CMake error like `"Could not find cose_sign1_primitives_ffi"`.

**Fix:** Build the Rust workspace first, then re-run CMake:

```bash
cd native/rust && cargo build --release --workspace
cd ../c
cmake -B build -DBUILD_TESTING=ON
cmake --build build --config Release
```

The C/C++ CMake projects discover Rust libraries from `native/rust/target/release/`.

### vcpkg Can't Find the Port

The overlay port ships in this repo. Always pass `--overlay-ports`:

```powershell
vcpkg install cosesign1-validation-native --overlay-ports=<repo>/native/vcpkg_ports
```

### Linker Errors About CRT Mismatch

The vcpkg port enforces static linkage. Ensure your consuming project uses a
compatible runtime library selection (e.g., `/MT` on MSVC).

### OpenCppCoverage Not Found

The coverage scripts look for `OpenCppCoverage.exe` in these locations:

1. `$env:OPENCPPCOVERAGE_PATH`
2. `OpenCppCoverage.exe` on `PATH`
3. Common install locations

Install via Chocolatey:

```powershell
choco install opencppcoverage
```

---

## Common Mistakes

### Using a Handle After Free

Handles are invalidated by their `*_free()` function. Using a freed handle is
undefined behavior.

```c
/* ❌ BAD: use-after-free */
cose_sign1_message_free(msg);
cose_sign1_message_payload(msg, &payload, &len);  /* UB! */

/* ✅ GOOD: use before free */
cose_sign1_message_payload(msg, &payload, &len);
/* ... process payload ... */
cose_sign1_message_free(msg);
```

### Forgetting to Free Strings

Every string returned by the library (`char*`) must be freed by the caller:

```c
char* msg = cose_last_error_message_utf8();
fprintf(stderr, "%s\n", msg ? msg : "(null)");
cose_string_free(msg);  /* Don't forget this! */
```

In C++ this is handled automatically by the RAII wrappers.

### Mixing Up Status Code Layers

The SDK has **two status code conventions**:

| Layer | Type | Success | Error range |
|-------|------|---------|-------------|
| Validation / Extension packs | `cose_status_t` (enum) | `COSE_OK` (0) | 1–3 |
| Primitives / Signing | `int32_t` | `0` | Negative values |

Don't compare a primitives `int32_t` return with `COSE_OK` (they happen to be
the same value, but the semantics differ for error codes).
