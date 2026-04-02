# cose_sign1_factories_ffi

C/C++ FFI bindings for the COSE_Sign1 message factory.

## Overview

This crate provides C-compatible FFI exports for creating COSE_Sign1 messages using the factory pattern. It supports:

- Direct signatures (embedded or detached payload)
- Indirect signatures (hash envelope)
- Streaming and file-based payloads
- Transparency provider integration

## Architecture

Maps the Rust `CoseSign1MessageFactory` to C-compatible functions:

- `cose_factories_create_*` — Factory creation with signing service or crypto signer
- `cose_factories_sign_direct*` — Direct signature variants (embedded, detached, file, streaming)
- `cose_factories_sign_indirect*` — Indirect signature variants (memory, file, streaming)
- `cose_factories_*_free` — Memory management functions

## Error Handling

All functions return `i32` status codes:
- `0` = success (`COSE_FACTORIES_OK`)
- Negative values = error codes
- Error details available via `cose_factories_error_message()`

## Memory Management

Caller is responsible for freeing:
- Factory handles: `cose_factories_free()`
- COSE bytes: `cose_factories_bytes_free()`
- Error handles: `cose_factories_error_free()`
- String pointers: `cose_factories_string_free()`

## Safety

All functions use panic safety (`catch_unwind`) and null pointer checks. Undefined behavior is prevented via `#![deny(unsafe_op_in_unsafe_fn)]`.

## Example

```c
#include <cose_factories.h>

// Create factory from crypto signer
CoseFactoriesHandle* factory = NULL;
CoseFactoriesErrorHandle* error = NULL;
if (cose_factories_create_from_crypto_signer(signer, &factory, &error) != 0) {
    // Handle error
    cose_factories_error_free(error);
    return -1;
}

// Sign payload
uint8_t* cose_bytes = NULL;
uint32_t cose_len = 0;
if (cose_factories_sign_direct(factory, payload, payload_len, "application/octet-stream", 
                                 &cose_bytes, &cose_len, &error) != 0) {
    // Handle error
    cose_factories_error_free(error);
    cose_factories_free(factory);
    return -1;
}

// Use COSE message...

// Cleanup
cose_factories_bytes_free(cose_bytes, cose_len);
cose_factories_free(factory);
```

## Dependencies

- `cose_sign1_factories` — Core factory implementation
- `cose_sign1_signing` — Signing service traits
- `cose_sign1_primitives` — COSE types and traits
- `crypto_primitives` — Crypto signer traits
- `cbor_primitives_everparse` — CBOR encoding (via feature flag)
