<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# cose_sign1_headers_ffi

C/C++ FFI projection for CWT (CBOR Web Token) Claims operations.

## Overview

This crate provides C-compatible FFI exports for creating and managing CWT Claims from
C and C++ code. It supports building claims with standard fields (issuer, subject, audience,
issued-at, not-before, expiration), serializing to/from CBOR, and extracting individual fields.

## Exported Functions

| Function | Description |
|----------|-------------|
| `cose_cwt_claims_abi_version` | ABI version check |
| `cose_cwt_claims_create` | Create a new empty CWT claims set |
| `cose_cwt_claims_set_issuer` | Set the `iss` claim |
| `cose_cwt_claims_set_subject` | Set the `sub` claim |
| `cose_cwt_claims_set_audience` | Set the `aud` claim |
| `cose_cwt_claims_set_issued_at` | Set the `iat` claim |
| `cose_cwt_claims_set_not_before` | Set the `nbf` claim |
| `cose_cwt_claims_set_expiration` | Set the `exp` claim |
| `cose_cwt_claims_to_cbor` | Serialize claims to CBOR bytes |
| `cose_cwt_claims_from_cbor` | Deserialize claims from CBOR bytes |
| `cose_cwt_claims_get_issuer` | Get the `iss` claim value |
| `cose_cwt_claims_get_subject` | Get the `sub` claim value |
| `cose_cwt_claims_free` | Free a CWT claims handle |
| `cose_cwt_error_message` | Get error description string |
| `cose_cwt_error_code` | Get error code |
| `cose_cwt_error_free` | Free an error handle |
| `cose_cwt_string_free` | Free a string returned by this library |
| `cose_cwt_bytes_free` | Free a byte buffer returned by this library |

## Handle Types

| Type | Description |
|------|-------------|
| `CoseCwtClaimsHandle` | Opaque CWT claims builder/container |
| `CoseCwtErrorHandle` | Opaque error handle |

## C Header

`<cose/sign1/cwt.h>`

## Parent Library

[`cose_sign1_headers`](../../headers/) — CWT Claims implementation.

## Build

```bash
cargo build --release -p cose_sign1_headers_ffi
```
