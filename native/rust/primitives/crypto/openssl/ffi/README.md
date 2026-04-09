<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# cose_sign1_crypto_openssl_ffi

C/C++ FFI projection for the OpenSSL crypto provider.

## Overview

This crate provides C-compatible FFI exports for creating cryptographic signers and verifiers
backed by OpenSSL. It supports DER- and PEM-encoded keys, JWK-based EC and RSA verifiers, and
provides the core signing and verification primitives used by the COSE_Sign1 signing pipeline.

## Exported Functions

| Function | Description |
|----------|-------------|
| `cose_crypto_openssl_abi_version` | ABI version check |
| `cose_last_error_message_utf8` | Get thread-local error message |
| `cose_last_error_clear` | Clear thread-local error state |
| `cose_string_free` | Free a string returned by this library |
| `cose_crypto_openssl_provider_new` | Create a new OpenSSL provider |
| `cose_crypto_openssl_provider_free` | Free an OpenSSL provider |
| `cose_crypto_openssl_signer_from_der` | Create signer from DER-encoded private key |
| `cose_crypto_openssl_signer_from_pem` | Create signer from PEM-encoded private key |
| `cose_crypto_signer_sign` | Sign data with a signer |
| `cose_crypto_signer_algorithm` | Get the algorithm of a signer |
| `cose_crypto_signer_free` | Free a signer handle |
| `cose_crypto_openssl_verifier_from_pem` | Create verifier from PEM-encoded public key |
| `cose_crypto_openssl_verifier_from_der` | Create verifier from DER-encoded public key |
| `cose_crypto_verifier_verify` | Verify a signature |
| `cose_crypto_verifier_free` | Free a verifier handle |
| `cose_crypto_openssl_jwk_verifier_from_ec` | Create verifier from JWK EC key |
| `cose_crypto_openssl_jwk_verifier_from_rsa` | Create verifier from JWK RSA key |
| `cose_crypto_bytes_free` | Free a byte buffer returned by this library |

## Handle Types

| Type | Description |
|------|-------------|
| `cose_crypto_provider_t` | Opaque OpenSSL crypto provider |
| `cose_crypto_signer_t` | Opaque cryptographic signer |
| `cose_crypto_verifier_t` | Opaque cryptographic verifier |

## C Header

`<cose/crypto/openssl.h>`

## Parent Library

[`cose_sign1_crypto_openssl`](../../../primitives/crypto/openssl/) — OpenSSL crypto provider implementation.

## Build

```bash
cargo build --release -p cose_sign1_crypto_openssl_ffi
```
