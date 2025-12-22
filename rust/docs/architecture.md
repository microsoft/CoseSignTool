<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# Rust verifier architecture

This repo contains a Rust port of the COSE_Sign1 verification stack and related verifiers.

## Crates and responsibilities

- `cosesign1-abstractions`
  - Shared datatypes and plugin interfaces (signing key providers + message validators).
  - Exists to prevent circular dependencies between the facade and plugins.

- `cosesign1-x509`
  - Registers an `x5c` signing key provider (extract public key for signature verification).
  - Registers an X.509 trust validator (chain policy / revocation) as a message validator.

- `cosesign1-mst`
  - Registers MST receipt verification as a message validator.
  - Also exposes MST helper APIs (offline keystore, optional JWKS fetching).

- `cosesign1`
  - High-level facade that parses COSE_Sign1, verifies signatures, and runs message validators.
  - Owns the signature verification implementation (`cosesign1::validation`).
  - Uses link-time registration (`inventory`) to discover providers/validators when their crates are linked.

## Data flow (high level)

1. **Parse**: `cosesign1::CoseSign1::from_bytes` parses CBOR and header maps.
2. **Signature**: `cosesign1` verifies the COSE signature (optional).
3. **Trust**: additional trust checks (X.509 chain, MST receipts, etc.) run as message validators.

## Error model

All verifiers return `cosesign1::ValidationResult`.

- `is_valid` indicates overall success.
- `failures` is a list of `ValidationFailure` entries, each having:
  - `message` (human-readable)
  - `error_code` (stable-ish string for tests/telemetry)

This pattern keeps callers from needing to match on Rust error types and makes it easy to aggregate multiple failures.

## Extension points

- Algorithms: extend `cosesign1::validation` algorithm dispatch (and tests).
- New key sources: implement `cosesign1_abstractions::SigningKeyProvider` in a plugin crate.
- New trust policies: implement `cosesign1_abstractions::MessageValidator` in a plugin crate.
- MST key sources:
  - Offline: provision keys into `OfflineEcKeyStore`.
  - Online: implement `JwksFetcher` in your application (this repo intentionally does not pick an HTTP client).
