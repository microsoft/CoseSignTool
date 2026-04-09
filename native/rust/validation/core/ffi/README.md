<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# cose_sign1_validation_ffi

C/C++ FFI projection for COSE_Sign1 message validation.

## Overview

This is the base validation FFI crate that exposes the core validator builder, validator runner,
and validation result types. Pack-specific functionality (X.509 certificates, MST, Azure Key Vault,
trust policy authoring) lives in separate FFI crates that extend the validator builder exposed here.

This crate also exports shared infrastructure used by extension pack FFI crates: `cose_status_t`,
`with_catch_unwind`, thread-local error state, and the opaque validator builder/policy builder types.

## Exported Functions

| Function | Description |
|----------|-------------|
| `cose_sign1_validation_abi_version` | ABI version check |
| `cose_last_error_message_utf8` | Get thread-local error message |
| `cose_last_error_clear` | Clear thread-local error state |
| `cose_string_free` | Free a string returned by this library |
| `cose_sign1_validator_builder_new` | Create a new validator builder |
| `cose_sign1_validator_builder_free` | Free a validator builder |
| `cose_sign1_validator_builder_build` | Build a validator from the builder |
| `cose_sign1_validator_free` | Free a validator |
| `cose_sign1_validator_validate_bytes` | Validate a COSE_Sign1 message from bytes |
| `cose_sign1_validation_result_is_success` | Check if validation succeeded |
| `cose_sign1_validation_result_failure_message_utf8` | Get validation failure message |
| `cose_sign1_validation_result_free` | Free a validation result |

## Handle Types

| Type | Description |
|------|-------------|
| `cose_sign1_validator_builder_t` | Opaque validator builder (extended by pack FFI crates) |
| `cose_sign1_validator_t` | Opaque compiled validator |
| `cose_sign1_validation_result_t` | Opaque validation result |
| `cose_trust_policy_builder_t` | Opaque trust policy builder (used by pack FFI crates) |

## C Header

`<cose/sign1/validation.h>`

## Parent Library

[`cose_sign1_validation`](../../core/) — COSE_Sign1 validation implementation.

## Build

```bash
cargo build --release -p cose_sign1_validation_ffi
```
