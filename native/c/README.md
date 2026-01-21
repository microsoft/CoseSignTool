# COSE Sign1 C API

C projection for the COSE Sign1 validation library.

## Prerequisites

- CMake 3.20 or later
- C11-capable compiler (MSVC, GCC, Clang)
- Rust toolchain (to build the underlying FFI libraries)

## Building

### 1. Build the Rust FFI libraries

```bash
cd ../rust
cargo build --release --workspace
```

This will produce the FFI libraries in `../rust/target/release/`.

### 2. Configure and build the C projection

```bash
mkdir build
cd build
cmake .. -DBUILD_TESTING=ON
cmake --build . --config Release
```

### 3. Run tests

```bash
ctest -C Release
```

## Coverage (Windows)

Coverage for the C projection is collected with OpenCppCoverage.

```powershell
./collect-coverage.ps1 -Configuration RelWithDebInfo
```

Outputs HTML to `native/c/coverage/index.html`.

## Usage Example

## Compilable example programs

This repo ships a real, buildable C example you can use as a starting point:

- `native/c/examples/trust_policy_example.c`

Build it (after building the Rust FFI libs):

```bash
cd native/c
cmake -S . -B build -DBUILD_TESTING=ON
cmake --build build --config Release --target cose_trust_policy_example
```

Run it:

```bash
native/c/build/examples/Release/cose_trust_policy_example.exe path/to/message.cose [path/to/detached_payload.bin]
```

### Detailed end-to-end example (custom trust policy + feedback)

This example shows how to:
- Configure a validator builder (optionally adding packs)
- Author a custom trust policy with message-scope and pack-specific helpers
- Compile the policy into a bundled trust plan and attach it to the validator
- Validate bytes and print user-friendly feedback

If you build via this repo’s CMake, the optional packs are exposed via `COSE_HAS_<PACK>_PACK`.

```c
#include <cose/cose_sign1.h>
#include <cose/cose_trust.h>
#include <cose/cose_certificates.h>
#include <cose/cose_mst.h>
#include <cose/cose_azure_key_vault.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

static void print_last_error_and_free(void) {
    char* err = cose_last_error_message_utf8();
    fprintf(stderr, "%s\n", err ? err : "(no error message)");
    if (err) cose_string_free(err);
}

#define COSE_CHECK(call) \
    do { \
        cose_status_t _st = (call); \
        if (_st != COSE_OK) { \
            fprintf(stderr, "FAILED: %s\n", #call); \
            print_last_error_and_free(); \
            goto cleanup; \
        } \
    } while (0)

int main(void) {
    cose_validator_builder_t* builder = NULL;
    cose_trust_policy_builder_t* policy = NULL;
    cose_compiled_trust_plan_t* plan = NULL;
    cose_validator_t* validator = NULL;
    cose_validation_result_t* result = NULL;

    // 1) Create builder
    COSE_CHECK(cose_validator_builder_new(&builder));

    // 2) Add packs you intend to rely on in policy.
#ifdef COSE_HAS_CERTIFICATES_PACK
    COSE_CHECK(cose_validator_builder_with_certificates_pack(builder));
#endif
#ifdef COSE_HAS_MST_PACK
    COSE_CHECK(cose_validator_builder_with_mst_pack(builder));
#endif
#ifdef COSE_HAS_AKV_PACK
    COSE_CHECK(cose_validator_builder_with_akv_pack(builder));
#endif

    // 3) Build a custom trust policy (starts empty)
    COSE_CHECK(cose_trust_policy_builder_new_from_validator_builder(builder, &policy));

    // Message-scope rules
    COSE_CHECK(cose_trust_policy_builder_require_content_type_non_empty(policy));
    COSE_CHECK(cose_trust_policy_builder_require_detached_payload_absent(policy));
    COSE_CHECK(cose_trust_policy_builder_require_cwt_claims_present(policy));

    // Pack-specific trust-policy helpers
#ifdef COSE_HAS_CERTIFICATES_PACK
    COSE_CHECK(cose_certificates_trust_policy_builder_require_x509_chain_trusted(policy));
    COSE_CHECK(cose_certificates_trust_policy_builder_require_signing_certificate_present(policy));
    COSE_CHECK(cose_certificates_trust_policy_builder_require_signing_certificate_thumbprint_present(policy));
#endif

#ifdef COSE_HAS_MST_PACK
    // Require at least one MST receipt on counter-signatures.
    COSE_CHECK(cose_mst_trust_policy_builder_require_receipt_present(policy));
#endif

#ifdef COSE_HAS_AKV_PACK
    COSE_CHECK(cose_akv_trust_policy_builder_require_azure_key_vault_kid_allowed(policy));
#endif

    // 4) Compile the policy into a bundled plan and attach it
    COSE_CHECK(cose_trust_policy_builder_compile(policy, &plan));
    COSE_CHECK(cose_validator_builder_with_compiled_trust_plan(builder, plan));

    // 5) Build validator
    COSE_CHECK(cose_validator_builder_build(builder, &validator));

    // 6) Validate bytes
    // NOTE: Replace these with your actual bytes.
    const uint8_t* cose_bytes = NULL;
    size_t cose_bytes_len = 0;

    if (cose_bytes == NULL || cose_bytes_len == 0) {
        fprintf(stderr, "Provide COSE_Sign1 bytes before calling validate.\n");
        goto cleanup;
    }

    COSE_CHECK(cose_validator_validate_bytes(
        validator,
        cose_bytes,
        cose_bytes_len,
        NULL,
        0,
        &result
    ));

    {
        bool ok = false;
        COSE_CHECK(cose_validation_result_is_success(result, &ok));
        if (ok) {
            printf("Validation successful\n");
        } else {
            char* msg = cose_validation_result_failure_message_utf8(result);
            printf("Validation failed: %s\n", msg ? msg : "(no message)");
            if (msg) cose_string_free(msg);
        }
    }

cleanup:
    if (result) cose_validation_result_free(result);
    if (validator) cose_validator_free(validator);
    if (plan) cose_compiled_trust_plan_free(plan);
    if (policy) cose_trust_policy_builder_free(policy);
    if (builder) cose_validator_builder_free(builder);

    return 0;
}
```

## Available Pack Headers

- `<cose/cose_sign1.h>` - Base validation API (required)
- `<cose/cose_certificates.h>` - X.509 certificate validation pack
- `<cose/cose_mst.h>` - Microsoft Secure Transparency receipt verification pack
- `<cose/cose_azure_key_vault.h>` - Azure Key Vault KID validation pack

## Pack Options

Each pack supports two functions:
- `cose_validator_builder_with_<pack>_pack()` - Use default (secure) options
- `cose_validator_builder_with_<pack>_pack_ex()` - Use custom options

### Certificates Pack Options

```c
cose_certificate_trust_options_t opts = {
    .trust_embedded_chain_as_trusted = true,  // For testing/pinned roots
    .identity_pinning_enabled = true,
    .allowed_thumbprints = (const char*[]){
        "ABCD1234...",
        NULL  // NULL-terminated
    },
    .pqc_algorithm_oids = NULL  // No custom PQC OIDs
};
cose_validator_builder_with_certificates_pack_ex(builder, &opts);
```

### MST Pack Options

```c
cose_mst_trust_options_t opts = {
    .allow_network = false,
    .offline_jwks_json = "{...}",  // JWKS JSON string
    .jwks_api_version = NULL
};
cose_validator_builder_with_mst_pack_ex(builder, &opts);
```

### Azure Key Vault Pack Options

```c
cose_akv_trust_options_t opts = {
    .require_azure_key_vault_kid = true,
    .allowed_kid_patterns = (const char*[]){
        "https://*.vault.azure.net/keys/*",
        "https://*.managedhsm.azure.net/keys/*",
        NULL
    }
};
cose_validator_builder_with_akv_pack_ex(builder, &opts);
```

## Error Handling

All functions return `cose_status_t`:
- `COSE_OK` - Success
- `COSE_ERR` - Error (retrieve message with `cose_last_error_message_utf8()`)
- `COSE_PANIC` - Rust panic (should not occur in normal usage)
- `COSE_INVALID_ARG` - Invalid argument (e.g., null pointer)

Error messages are thread-local. Always call `cose_string_free()` on strings returned by the library.

## Memory Management

- All `*_new()` functions allocate handles that must be freed with corresponding `*_free()` functions
- `*_free()` functions accept NULL pointers (no-op)
- Strings returned by the library must be freed with `cose_string_free()`
- String arrays in option structs are NOT owned by the library (caller retains ownership)
