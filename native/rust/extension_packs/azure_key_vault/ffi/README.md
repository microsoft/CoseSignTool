<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# cose_sign1_azure_key_vault_ffi

C/C++ FFI projection for the Azure Key Vault extension pack.

## Overview

This crate provides C-compatible FFI exports for the Azure Key Vault trust pack.
It enables C/C++ consumers to register the AKV trust pack with a validator builder,
author trust policies that constrain Key Vault KID properties, and create signing
keys and signing services backed by Azure Key Vault.

## Exported Functions

### Pack Registration

| Function | Description |
|----------|-------------|
| `cose_sign1_validator_builder_with_akv_pack` | Add AKV pack (default options) |
| `cose_sign1_validator_builder_with_akv_pack_ex` | Add AKV pack (custom options) |

### KID Trust Policies

| Function | Description |
|----------|-------------|
| `..._require_azure_key_vault_kid` | Require AKV KID detected |
| `..._require_not_azure_key_vault_kid` | Require AKV KID not detected |
| `..._require_azure_key_vault_kid_allowed` | Require KID is in allowed list |
| `..._require_azure_key_vault_kid_not_allowed` | Require KID is not in allowed list |

### Key Client Lifecycle

| Function | Description |
|----------|-------------|
| `cose_akv_key_client_new_dev` | Create key client (dev credentials) |
| `cose_akv_key_client_new_client_secret` | Create key client (client secret) |
| `cose_akv_key_client_free` | Free a key client handle |

### Signing Operations

| Function | Description |
|----------|-------------|
| `cose_sign1_akv_create_signing_key` | Create a signing key from AKV |
| `cose_sign1_akv_create_signing_service` | Create a signing service from AKV |
| `cose_sign1_akv_signing_service_free` | Free a signing service handle |

## Handle Types

| Type | Description |
|------|-------------|
| `cose_akv_trust_options_t` | C ABI options struct for AKV trust configuration |
| `AkvKeyClientHandle` | Opaque Azure Key Vault key client |
| `AkvSigningServiceHandle` | Opaque AKV-backed signing service |

## C Header

`<cose/sign1/extension_packs/azure_key_vault.h>`

## Parent Library

[`cose_sign1_azure_key_vault`](../../azure_key_vault/) — Azure Key Vault trust pack implementation.

## Build

```bash
cargo build --release -p cose_sign1_azure_key_vault_ffi
```
