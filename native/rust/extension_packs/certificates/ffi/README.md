<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# cose_sign1_certificates_ffi

C/C++ FFI projection for the X.509 certificate validation extension pack.

## Overview

This crate provides C-compatible FFI exports for registering the X.509 certificate trust pack
with a validator builder and authoring trust policies that constrain X.509 chain properties.
Supported constraints include chain trust status, chain element identity and validity, public key
algorithms, and signing certificate identity.

## Exported Functions

### Pack Registration

| Function | Description |
|----------|-------------|
| `cose_sign1_validator_builder_with_certificates_pack` | Add certificate pack (default options) |
| `cose_sign1_validator_builder_with_certificates_pack_ex` | Add certificate pack (custom options) |

### Chain Trust Policies

| Function | Description |
|----------|-------------|
| `..._require_x509_chain_trusted` | Require chain is trusted |
| `..._require_x509_chain_not_trusted` | Require chain is not trusted |
| `..._require_x509_chain_built` | Require chain was successfully built |
| `..._require_x509_chain_not_built` | Require chain was not built |
| `..._require_x509_chain_element_count_eq` | Require specific chain length |
| `..._require_x509_chain_status_flags_eq` | Require specific chain status flags |
| `..._require_leaf_chain_thumbprint_present` | Require leaf thumbprint present |
| `..._require_leaf_subject_eq` | Require leaf subject matches |
| `..._require_issuer_subject_eq` | Require issuer subject matches |
| `..._require_leaf_issuer_is_next_chain_subject_optional` | Require leaf-to-chain issuer linkage |

### Signing Certificate Policies

| Function | Description |
|----------|-------------|
| `..._require_signing_certificate_present` | Require signing cert present |
| `..._require_signing_certificate_subject_issuer_matches_*` | Require subject-issuer match |
| `..._require_signing_certificate_thumbprint_eq` | Require specific thumbprint |
| `..._require_signing_certificate_thumbprint_present` | Require thumbprint present |
| `..._require_signing_certificate_subject_eq` | Require specific subject |
| `..._require_signing_certificate_issuer_eq` | Require specific issuer |
| `..._require_signing_certificate_serial_number_eq` | Require specific serial number |
| `..._require_signing_certificate_*` (validity) | Time-based validity constraints |

### Chain Element Policies

| Function | Description |
|----------|-------------|
| `..._require_chain_element_subject_eq` | Require element subject matches |
| `..._require_chain_element_issuer_eq` | Require element issuer matches |
| `..._require_chain_element_thumbprint_eq` | Require element thumbprint matches |
| `..._require_chain_element_thumbprint_present` | Require element thumbprint present |
| `..._require_chain_element_*` (validity) | Element time-based validity constraints |

### Public Key Algorithm Policies

| Function | Description |
|----------|-------------|
| `..._require_not_pqc_algorithm_or_missing` | Require non-PQC algorithm |
| `..._require_x509_public_key_algorithm_thumbprint_eq` | Require specific algorithm thumbprint |
| `..._require_x509_public_key_algorithm_oid_eq` | Require specific algorithm OID |
| `..._require_x509_public_key_algorithm_is_pqc` | Require PQC algorithm |
| `..._require_x509_public_key_algorithm_is_not_pqc` | Require non-PQC algorithm |

### Key Utilities

| Function | Description |
|----------|-------------|
| `cose_sign1_certificates_key_from_cert_der` | Create key handle from DER certificate |

## Handle Types

| Type | Description |
|------|-------------|
| `cose_certificate_trust_options_t` | C ABI options struct for certificate trust configuration |

## C Header

`<cose/sign1/extension_packs/certificates.h>`

## Parent Library

[`cose_sign1_certificates`](../../certificates/) — X.509 certificate trust pack implementation.

## Build

```bash
cargo build --release -p cose_sign1_certificates_ffi
```
