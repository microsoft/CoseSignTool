<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# did_x509_ffi

C/C++ FFI projection for DID:x509 identifier operations.

## Overview

This crate provides C-compatible FFI exports for parsing, building, validating, and resolving
DID:x509 identifiers against X.509 certificate chains. It wraps the `did_x509` crate for
core functionality.

## Exported Functions

### ABI & Error Handling

| Function | Description |
|----------|-------------|
| `did_x509_abi_version` | ABI version check |
| `did_x509_error_message` | Get error description string |
| `did_x509_error_code` | Get error code |
| `did_x509_error_free` | Free an error handle |
| `did_x509_string_free` | Free a string returned by this library |

### Parsing

| Function | Description |
|----------|-------------|
| `did_x509_parse` | Parse a DID:x509 identifier string |
| `did_x509_parsed_get_fingerprint` | Get the certificate fingerprint |
| `did_x509_parsed_get_hash_algorithm` | Get the hash algorithm used |
| `did_x509_parsed_get_policy_count` | Get the number of policies |
| `did_x509_parsed_free` | Free a parsed DID handle |

### Building

| Function | Description |
|----------|-------------|
| `did_x509_build_with_eku` | Build a DID:x509 with EKU policy |
| `did_x509_build_from_chain` | Build a DID:x509 from a certificate chain |

### Validation & Resolution

| Function | Description |
|----------|-------------|
| `did_x509_validate` | Validate a DID:x509 against a certificate chain |
| `did_x509_resolve` | Resolve a DID:x509 to a public key |

## Handle Types

| Type | Description |
|------|-------------|
| `DidX509ParsedHandle` | Opaque parsed DID:x509 identifier |
| `DidX509ErrorHandle` | Opaque error handle |

## C Header

`<cose/did/x509.h>`

## Parent Library

[`did_x509`](../../x509/) — DID:x509 implementation.

## Build

```bash
cargo build --release -p did_x509_ffi
```
