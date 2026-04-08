<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# cose_sign1_certificates_local_ffi

C/C++ FFI projection for local certificate creation and loading.

## Overview

This crate provides C-compatible FFI exports for creating ephemeral certificates,
building certificate chains, and loading certificates from PEM or DER encoded files.
It is primarily used for testing and development scenarios where real CA-issued
certificates are not available.

## Exported Functions

### ABI & Error Handling

| Function | Description |
|----------|-------------|
| `cose_cert_local_ffi_abi_version` | ABI version check |
| `cose_cert_local_last_error_message_utf8` | Get thread-local error message |
| `cose_cert_local_last_error_clear` | Clear thread-local error state |
| `cose_cert_local_string_free` | Free a string returned by this library |

### Certificate Factory

| Function | Description |
|----------|-------------|
| `cose_cert_local_factory_new` | Create a new certificate factory |
| `cose_cert_local_factory_free` | Free a certificate factory |
| `cose_cert_local_factory_create_cert` | Create a certificate signed by an issuer |
| `cose_cert_local_factory_create_self_signed` | Create a self-signed certificate |

### Certificate Chain

| Function | Description |
|----------|-------------|
| `cose_cert_local_chain_new` | Create a new certificate chain factory |
| `cose_cert_local_chain_free` | Free a chain factory |
| `cose_cert_local_chain_create` | Create a complete certificate chain |

### Certificate Loading

| Function | Description |
|----------|-------------|
| `cose_cert_local_load_pem` | Load certificate from PEM-encoded data |
| `cose_cert_local_load_der` | Load certificate from DER-encoded data |

### Memory Management

| Function | Description |
|----------|-------------|
| `cose_cert_local_bytes_free` | Free a byte buffer |
| `cose_cert_local_array_free` | Free an array of byte buffer pointers |
| `cose_cert_local_lengths_array_free` | Free an array of lengths |

## Handle Types

| Type | Description |
|------|-------------|
| `cose_cert_local_factory_t` | Opaque ephemeral certificate factory |
| `cose_cert_local_chain_t` | Opaque certificate chain factory |

## C Header

`<cose/sign1/extension_packs/certificates_local.h>`

## Parent Library

[`cose_sign1_certificates_local`](../../local/) — Local certificate creation utilities.

## Build

```bash
cargo build --release -p cose_sign1_certificates_local_ffi
```
