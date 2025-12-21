<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# Rust verifier architecture

This repo contains a Rust port of the COSE_Sign1 verification stack and related verifiers.

## Crates and responsibilities

- `cosesign1-common`
  - Parses COSE_Sign1 (tagged or untagged) into a structured view (`ParsedCoseSign1`).
  - Decodes protected/unprotected header maps into a typed `CoseHeaderMap`.
  - Encodes the COSE Sig_structure (`Signature1`) for verification.

- `cosesign1-validation`
  - Verifies signatures over the Sig_structure via `verify_cose_sign1`.
  - Supports ES256/384/512, RS256, PS256, and ML-DSA-44/65/87.
  - Produces a `ValidationResult` containing `is_valid`, `failures`, and optional metadata.

- `cosesign1-x509`
  - Extracts `x5c` (certificate chain) from COSE headers and verifies using the leaf certificate.
  - Bridges “certificate inputs” (DER cert / SPKI) into the `public_key_bytes` expected by `cosesign1-validation`.

- `cosesign1-mst`
  - Verifies Microsoft Transparent Statement (MST) receipts embedded in the statement.
  - Supports offline verification using caller-provided keys (`OfflineEcKeyStore`).
  - Supports optional online JWKS fetching via the `JwksFetcher` trait.

## Data flow (high level)

1. **Parse**: `cosesign1-common::parse_cose_sign1` parses CBOR and header maps.
2. **Sig_structure**: `cosesign1-common` encodes the verification bytes.
3. **Verify**: `cosesign1-validation::verify_cose_sign1` selects algorithm + verifies.
4. **Compose**: Higher-level verifiers (x5c / MST) are thin orchestration layers on top of (1–3).

## Error model

All verifiers return `cosesign1-validation::ValidationResult`.

- `is_valid` indicates overall success.
- `failures` is a list of `ValidationFailure` entries, each having:
  - `message` (human-readable)
  - `error_code` (stable-ish string for tests/telemetry)

This pattern keeps callers from needing to match on Rust error types and makes it easy to aggregate multiple failures.

## Extension points

- Algorithms: add to `cosesign1-validation` algorithm dispatch (and tests).
- Certificate handling: extend `cosesign1-x509` for additional chain policies.
- MST key sources:
  - Offline: implement key provisioning into `OfflineEcKeyStore`.
  - Online: implement `JwksFetcher` in your application (this repo intentionally does not pick an HTTP client).
