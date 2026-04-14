<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# FFI Error Code Reference

Complete reference for all status/error codes across the native COSE Sign1 SDK.

---

## Two Status Code Conventions

The SDK uses two different status code schemes depending on the layer:

| Layer | C Type | Header | Values |
|-------|--------|--------|--------|
| Validation & extension packs | `cose_status_t` (enum) | `<cose/cose.h>` | 0–3 (non-negative) |
| Primitives & signing | `int32_t` | `<cose/sign1.h>`, `<cose/sign1/signing.h>`, etc. | 0 and negative |

---

## Validation / Extension-Pack Status Codes (`cose_status_t`)

Defined in `<cose/cose.h>`. Used by validation, trust-plan, and extension-pack
functions (certificates, MST, Azure Key Vault).

| Value | Name | Meaning |
|-------|------|---------|
| 0 | `COSE_OK` | Success |
| 1 | `COSE_ERR` | Recoverable error — call `cose_last_error_message_utf8()` for details |
| 2 | `COSE_PANIC` | Rust panic caught at FFI boundary (this is a library bug — file a report) |
| 3 | `COSE_INVALID_ARG` | Invalid argument (null pointer, bad size, invalid handle) |

### Reading Errors

```c
#include <cose/cose.h>

cose_status_t status = cose_sign1_validator_validate_bytes(validator, data, len, &result);
if (status != COSE_OK) {
    char* msg = cose_last_error_message_utf8();
    fprintf(stderr, "Error (status %d): %s\n", status, msg ? msg : "unknown");
    cose_string_free(msg);
}
```

---

## Sign1 Primitives Status Codes (`int32_t`)

Defined in `<cose/sign1.h>`. Used by message parsing, inspection, and
verification functions.

| Value | C Macro | Meaning |
|-------|---------|---------|
| 0 | `COSE_SIGN1_OK` | Success |
| −1 | `COSE_SIGN1_ERR_NULL_POINTER` | A required pointer argument was NULL |
| −2 | `COSE_SIGN1_ERR_INVALID_ARGUMENT` | Invalid argument value |
| −3 | `COSE_SIGN1_ERR_PANIC` | Rust panic caught (library bug) |
| −4 | `COSE_SIGN1_ERR_PARSE_FAILED` | CBOR/COSE parsing failed |
| −5 | `COSE_SIGN1_ERR_VERIFY_FAILED` | Signature verification failed |
| −6 | `COSE_SIGN1_ERR_PAYLOAD_MISSING` | Payload is detached (not embedded in message) |
| −7 | `COSE_SIGN1_ERR_PAYLOAD_ERROR` | Error reading payload |
| −8 | `COSE_SIGN1_ERR_HEADER_NOT_FOUND` | Requested header label not found in map |

### Reading Errors

```c
#include <cose/sign1.h>

CoseSign1MessageHandle* msg = NULL;
CoseSign1ErrorHandle* error = NULL;

int32_t status = cose_sign1_message_parse(data, len, &msg, &error);
if (status != COSE_SIGN1_OK) {
    char* err_msg = cose_sign1_error_message(error);
    fprintf(stderr, "Parse failed (code %d): %s\n", status, err_msg ? err_msg : "unknown");
    cose_sign1_string_free(err_msg);
    cose_sign1_error_free(error);
}
```

---

## Signing Status Codes (`int32_t`)

Defined in `<cose/sign1/signing.h>`. Used by the Sign1 builder and signing
service functions.

| Value | C Macro | Meaning |
|-------|---------|---------|
| 0 | `COSE_SIGN1_SIGNING_OK` | Success |
| −1 | `COSE_SIGN1_SIGNING_ERR_NULL_POINTER` | A required pointer argument was NULL |
| −2 | `COSE_SIGN1_SIGNING_ERR_SIGN_FAILED` | Signing operation failed |
| −5 | `COSE_SIGN1_SIGNING_ERR_INVALID_ARG` | Invalid argument value |
| −12 | `COSE_SIGN1_SIGNING_ERR_FACTORY_FAILED` | Signature factory operation failed |
| −99 | `COSE_SIGN1_SIGNING_ERR_PANIC` | Rust panic caught (library bug) |

---

## Factories Status Codes (`int32_t`)

Defined in `<cose/sign1/factories.h>`. Used by the multi-factory wrapper.

| Value | C Macro | Meaning |
|-------|---------|---------|
| 0 | `COSE_SIGN1_FACTORIES_OK` | Success |
| −1 | `COSE_SIGN1_FACTORIES_ERR_NULL_POINTER` | A required pointer argument was NULL |
| −5 | `COSE_SIGN1_FACTORIES_ERR_INVALID_ARG` | Invalid argument value |
| −12 | `COSE_SIGN1_FACTORIES_ERR_FACTORY_FAILED` | Factory operation failed |
| −99 | `COSE_SIGN1_FACTORIES_ERR_PANIC` | Rust panic caught (library bug) |

---

## CWT / Headers Status Codes (`int32_t`)

Defined in `<cose/sign1/cwt.h>`. Used by CWT claims builder and header
serialization functions.

| Value | C Macro | Meaning |
|-------|---------|---------|
| 0 | `COSE_CWT_OK` | Success |
| −1 | `COSE_CWT_ERR_NULL_POINTER` | A required pointer argument was NULL |
| −2 | `COSE_CWT_ERR_CBOR_ENCODE` | CBOR encoding failed |
| −3 | `COSE_CWT_ERR_CBOR_DECODE` | CBOR decoding failed |
| −5 | `COSE_CWT_ERR_INVALID_ARGUMENT` | Invalid argument value |
| −99 | `COSE_CWT_ERR_PANIC` | Rust panic caught (library bug) |

---

## DID:x509 Status Codes (`int32_t`)

Defined in `<cose/did/x509.h>`. Used by DID:x509 parsing, building, and
resolution functions.

| Value | C Macro | Meaning |
|-------|---------|---------|
| 0 | `DID_X509_OK` | Success |
| −1 | `DID_X509_ERR_NULL_POINTER` | A required pointer argument was NULL |
| −2 | `DID_X509_ERR_PARSE_FAILED` | DID string parsing failed |
| −3 | `DID_X509_ERR_BUILD_FAILED` | DID string construction failed |
| −4 | `DID_X509_ERR_VALIDATE_FAILED` | DID validation failed |
| −5 | `DID_X509_ERR_RESOLVE_FAILED` | DID resolution failed |
| −6 | `DID_X509_ERR_INVALID_ARGUMENT` | Invalid argument value |
| −99 | `DID_X509_ERR_PANIC` | Rust panic caught (library bug) |

---

## Crypto Provider Status Codes (`cose_status_t`)

Defined in `<cose/crypto/openssl.h>`. The OpenSSL crypto provider reuses the
same `cose_status_t` enum as validation:

| Value | Name | Meaning |
|-------|------|---------|
| 0 | `COSE_OK` | Success |
| 1 | `COSE_ERR` | Crypto operation failed — call `cose_last_error_message_utf8()` |
| 2 | `COSE_PANIC` | Rust panic caught (library bug) |
| 3 | `COSE_INVALID_ARG` | Invalid argument (null pointer, bad key format) |

---

## Quick Reference: All Layers at a Glance

| Layer | Header | Status Type | OK Value | Panic Value |
|-------|--------|-------------|----------|-------------|
| Validation / Trust | `cose.h` | `cose_status_t` | 0 | 2 |
| Crypto (OpenSSL) | `crypto/openssl.h` | `cose_status_t` | 0 | 2 |
| Sign1 Primitives | `sign1.h` | `int32_t` | 0 | −3 |
| Signing | `sign1/signing.h` | `int32_t` | 0 | −99 |
| Factories | `sign1/factories.h` | `int32_t` | 0 | −99 |
| CWT / Headers | `sign1/cwt.h` | `int32_t` | 0 | −99 |
| DID:x509 | `did/x509.h` | `int32_t` | 0 | −99 |

---

## C++ Exception Mapping

In C++, all error codes are translated into exceptions by the RAII wrappers:

| C++ Exception | Thrown By | Wraps |
|---------------|-----------|-------|
| `cose::sign1::primitives_error` | `CoseSign1Message`, `CoseHeaderMap` | Sign1 primitives `int32_t` codes |
| `cose::validation_error` | `ValidatorBuilder`, `Validator` | `cose_status_t` codes |
| `cose::signing_error` | `CoseSign1Builder`, `SignatureFactory` | Signing `int32_t` codes |

All exceptions inherit from `std::runtime_error` and include the error message
from the Rust layer via `.what()`.
