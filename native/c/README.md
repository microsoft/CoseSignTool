# COSE Sign1 C API

C projection for the COSE Sign1 SDK. Every header maps 1:1 to a Rust FFI crate
and is feature-gated by CMake so you link only what you need.

## Prerequisites

| Tool | Version |
|------|---------|
| CMake | 3.20+ |
| C compiler | C11 (MSVC, GCC, Clang) |
| Rust toolchain | stable (builds the FFI libraries) |

## Building

### 1. Build the Rust FFI libraries

```bash
cd native/rust
cargo build --release --workspace
```

### 2. Configure and build the C projection

```bash
cd native/c
mkdir build && cd build
cmake .. -DBUILD_TESTING=ON
cmake --build . --config Release
```

### 3. Run tests

```bash
ctest -C Release
```

## Header Reference

| Header | Purpose |
|--------|---------|
| `<cose/cose.h>` | Shared COSE types, status codes, IANA constants |
| `<cose/sign1.h>` | COSE_Sign1 message primitives (includes `cose.h`) |
| `<cose/sign1/validation.h>` | Validator builder / runner |
| `<cose/sign1/trust.h>` | Trust plan / policy authoring |
| `<cose/sign1/signing.h>` | Sign1 builder, signing service, factory |
| `<cose/sign1/factories.h>` | Multi-factory wrapper |
| `<cose/sign1/cwt.h>` | CWT claims builder / serializer |
| `<cose/sign1/extension_packs/certificates.h>` | X.509 certificate trust pack |
| `<cose/sign1/extension_packs/certificates_local.h>` | Ephemeral certificate generation |
| `<cose/sign1/extension_packs/azure_key_vault.h>` | Azure Key Vault trust pack |
| `<cose/sign1/extension_packs/mst.h>` | Microsoft Transparency trust pack |
| `<cose/crypto/openssl.h>` | OpenSSL crypto provider |
| `<cose/did/x509.h>` | DID:x509 utilities |

## Validation Example

```c
#include <cose/sign1/validation.h>
#include <cose/sign1/trust.h>
#include <cose/sign1/extension_packs/certificates.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

static void print_last_error(void) {
    char* err = cose_last_error_message_utf8();
    fprintf(stderr, "%s\n", err ? err : "(no error message)");
    if (err) cose_string_free(err);
}

#define COSE_CHECK(call) \
    do { \
        cose_status_t _st = (call); \
        if (_st != COSE_OK) { \
            fprintf(stderr, "FAILED: %s\n", #call); \
            print_last_error(); \
            goto cleanup; \
        } \
    } while (0)

int main(void) {
    cose_sign1_validator_builder_t* builder = NULL;
    cose_sign1_trust_policy_builder_t* policy = NULL;
    cose_sign1_compiled_trust_plan_t* plan = NULL;
    cose_sign1_validator_t* validator = NULL;
    cose_sign1_validation_result_t* result = NULL;

    /* 1 — Create the validator builder */
    COSE_CHECK(cose_sign1_validator_builder_new(&builder));

    /* 2 — Register the certificates extension pack */
    COSE_CHECK(cose_sign1_validator_builder_with_certificates_pack(builder));

    /* 3 — Author a trust policy */
    COSE_CHECK(cose_sign1_trust_policy_builder_new_from_validator_builder(
                   builder, &policy));

    /* Message-scope rules */
    COSE_CHECK(cose_sign1_trust_policy_builder_require_content_type_non_empty(policy));
    COSE_CHECK(cose_sign1_trust_policy_builder_require_detached_payload_absent(policy));
    COSE_CHECK(cose_sign1_trust_policy_builder_require_cwt_claims_present(policy));

    /* Pack-specific rules */
    COSE_CHECK(cose_sign1_certificates_trust_policy_builder_require_x509_chain_trusted(policy));
    COSE_CHECK(cose_sign1_certificates_trust_policy_builder_require_signing_certificate_present(policy));
    COSE_CHECK(cose_sign1_certificates_trust_policy_builder_require_signing_certificate_thumbprint_present(policy));

    /* 4 — Compile the policy and attach it */
    COSE_CHECK(cose_sign1_trust_policy_builder_compile(policy, &plan));
    COSE_CHECK(cose_sign1_validator_builder_with_compiled_trust_plan(builder, plan));

    /* 5 — Build the validator */
    COSE_CHECK(cose_sign1_validator_builder_build(builder, &validator));

    /* 6 — Validate COSE_Sign1 bytes */
    const uint8_t* cose_bytes = /* ... */ NULL;
    size_t cose_bytes_len = 0;

    COSE_CHECK(cose_sign1_validator_validate_bytes(
        validator, cose_bytes, cose_bytes_len,
        NULL, 0, &result));

    {
        bool ok = false;
        COSE_CHECK(cose_sign1_validation_result_is_success(result, &ok));
        if (ok) {
            printf("Validation successful\n");
        } else {
            char* msg = cose_sign1_validation_result_failure_message_utf8(result);
            printf("Validation failed: %s\n", msg ? msg : "(no message)");
            if (msg) cose_string_free(msg);
        }
    }

cleanup:
    if (result)   cose_sign1_validation_result_free(result);
    if (validator) cose_sign1_validator_free(validator);
    if (plan)      cose_sign1_compiled_trust_plan_free(plan);
    if (policy)    cose_sign1_trust_policy_builder_free(policy);
    if (builder)   cose_sign1_validator_builder_free(builder);
    return 0;
}
```

## Signing Example

```c
#include <cose/sign1/signing.h>
#include <cose/crypto/openssl.h>

#include <stdint.h>
#include <stdio.h>

int main(void) {
    cose_crypto_signer_t* signer = NULL;
    cose_sign1_factory_t* factory = NULL;
    uint8_t* signed_bytes = NULL;
    uint32_t signed_len = 0;

    /* Create a signer from a DER-encoded private key */
    COSE_CHECK(cose_crypto_openssl_signer_from_der(
        private_key_der, private_key_len, &signer));

    /* Create a factory wired to the signer */
    COSE_CHECK(cose_sign1_factory_from_crypto_signer(signer, &factory));

    /* Sign a payload directly */
    COSE_CHECK(cose_sign1_factory_sign_direct(
        factory,
        payload, payload_len,
        "application/example",
        &signed_bytes, &signed_len));

    printf("Signed %u bytes\n", signed_len);

cleanup:
    if (signed_bytes) cose_sign1_factory_bytes_free(signed_bytes, signed_len);
    if (factory)      cose_sign1_factory_free(factory);
    if (signer)       cose_crypto_signer_free(signer);
    return 0;
}
```

## CWT Claims Example

```c
#include <cose/sign1/cwt.h>

#include <stdint.h>
#include <stdio.h>

int main(void) {
    cose_cwt_claims_t* claims = NULL;
    uint8_t* cbor = NULL;
    uint32_t cbor_len = 0;

    COSE_CHECK(cose_cwt_claims_create(&claims));
    COSE_CHECK(cose_cwt_claims_set_issuer(claims, "did:x509:abc123"));
    COSE_CHECK(cose_cwt_claims_set_subject(claims, "my-artifact"));

    /* Serialize to CBOR for use as a protected header */
    COSE_CHECK(cose_cwt_claims_to_cbor(claims, &cbor, &cbor_len));
    printf("CWT claims: %u bytes of CBOR\n", cbor_len);

cleanup:
    if (cbor)   cose_cwt_claims_bytes_free(cbor, cbor_len);
    if (claims) cose_cwt_claims_free(claims);
    return 0;
}
```

## Error Handling

All functions return `cose_status_t`:

| Code | Meaning |
|------|---------|
| `COSE_OK` (0) | Success |
| `COSE_ERR` (1) | Error — call `cose_last_error_message_utf8()` for details |
| `COSE_PANIC` (2) | Rust panic (should not occur in normal usage) |
| `COSE_INVALID_ARG` (3) | Invalid argument (null pointer, bad length, etc.) |

Error messages are **thread-local**. Always free the returned string with
`cose_string_free()`.

## Memory Management

| Resource | Acquire | Release |
|----------|---------|---------|
| Handle (`cose_*_t*`) | `cose_*_new()` / `cose_*_build()` | `cose_*_free()` |
| String (`char*`) | `cose_*_utf8()` | `cose_string_free()` |
| Byte buffer (`uint8_t*`, len) | `cose_*_bytes()` | `cose_*_bytes_free()` |

- `*_free()` functions accept `NULL` (no-op).
- Option structs are **not** owned by the library — callers retain ownership of
  any string arrays passed in.

## Feature Defines

CMake sets these automatically when the corresponding FFI library is found:

| Define | Set When |
|--------|----------|
| `COSE_HAS_CERTIFICATES_PACK` | certificates FFI lib found |
| `COSE_HAS_MST_PACK` | MST FFI lib found |
| `COSE_HAS_AKV_PACK` | AKV FFI lib found |
| `COSE_HAS_TRUST_PACK` | trust FFI lib found |
| `COSE_HAS_PRIMITIVES` | primitives FFI lib found |
| `COSE_HAS_SIGNING` | signing FFI lib found |
| `COSE_HAS_FACTORIES` | factories FFI lib found |
| `COSE_HAS_CWT_HEADERS` | headers FFI lib found |
| `COSE_HAS_DID_X509` | DID:x509 FFI lib found |
| `COSE_CRYPTO_OPENSSL` | OpenSSL crypto provider selected |
| `COSE_CBOR_EVERPARSE` | EverParse CBOR provider selected |

Guard optional code with `#ifdef COSE_HAS_*` so builds succeed regardless of
which packs are linked.

## Coverage (Windows)

```powershell
./collect-coverage.ps1 -Configuration Debug -MinimumLineCoveragePercent 95
```

Outputs HTML to [native/c/coverage/index.html](coverage/index.html).
