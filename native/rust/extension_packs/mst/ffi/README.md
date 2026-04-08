<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# cose_sign1_transparent_mst_ffi

C/C++ FFI projection for the Microsoft Secure Transparency (MST) extension pack.

## Overview

This crate provides C-compatible FFI exports for the MST receipt verification trust pack.
It enables C/C++ consumers to register the MST trust pack with a validator builder, author
trust policies that constrain MST receipt properties, and interact with the MST transparency
service for creating and retrieving entries.

## Exported Functions

### Pack Registration

| Function | Description |
|----------|-------------|
| `cose_sign1_validator_builder_with_mst_pack` | Add MST pack (default options) |
| `cose_sign1_validator_builder_with_mst_pack_ex` | Add MST pack (custom options) |

### Receipt Trust Policies

| Function | Description |
|----------|-------------|
| `..._require_receipt_present` | Require receipt is present |
| `..._require_receipt_not_present` | Require receipt is not present |
| `..._require_receipt_signature_verified` | Require receipt signature verified |
| `..._require_receipt_signature_not_verified` | Require receipt signature not verified |
| `..._require_receipt_issuer_contains` | Require receipt issuer contains substring |
| `..._require_receipt_issuer_eq` | Require receipt issuer equals value |
| `..._require_receipt_kid_eq` | Require receipt KID equals value |
| `..._require_receipt_kid_contains` | Require receipt KID contains substring |
| `..._require_receipt_trusted` | Require receipt is trusted |
| `..._require_receipt_not_trusted` | Require receipt is not trusted |
| `..._require_receipt_trusted_from_issuer_contains` | Require trusted receipt from issuer |
| `..._require_receipt_statement_sha256_eq` | Require receipt statement SHA-256 hash |
| `..._require_receipt_statement_coverage_eq` | Require receipt statement coverage equals |
| `..._require_receipt_statement_coverage_contains` | Require receipt statement coverage contains |

### MST Service Operations

| Function | Description |
|----------|-------------|
| `cose_mst_client_new` | Create a new MST service client |
| `cose_sign1_mst_make_transparent` | Make a COSE message transparent via MST |
| `cose_sign1_mst_create_entry` | Create an MST transparency entry |
| `cose_sign1_mst_get_entry_statement` | Retrieve an MST entry statement |

## Handle Types

| Type | Description |
|------|-------------|
| `cose_mst_trust_options_t` | C ABI options struct for MST trust configuration |
| `MstClientHandle` | Opaque MST service client |

## C Header

`<cose/sign1/extension_packs/mst.h>`

## Parent Library

[`cose_sign1_transparent_mst`](../../mst/) — Microsoft Secure Transparency trust pack implementation.

## Build

```bash
cargo build --release -p cose_sign1_transparent_mst_ffi
```
