<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# Extending the Rust verifiers

This guide focuses on the most common extension tasks: adding algorithms, adding verifiers, and extending MST key acquisition.

## Add a new signature algorithm

Typical steps:

1. Add the algorithm identifier (if needed) to the algorithm enum/model used by `cosesign1-validation`.
2. Extend algorithm dispatch in `cosesign1-validation` to:
   - Validate key encoding expectations.
   - Validate signature format expectations.
   - Perform the cryptographic verification.
3. Add tests that cover:
   - Success path
   - Wrong key
   - Wrong signature length/format
   - Unsupported/mismatched `alg`
4. Ensure the workspace coverage gate still passes.

The repo’s pattern is: keep `cosesign1-common` purely structural (CBOR/COSE parsing) and keep cryptography isolated in `cosesign1-validation`.

## Add a new verifier crate

A “verifier crate” in this repo usually:

- Uses `cosesign1-common` to parse COSE.
- Uses `cosesign1-validation` to verify signatures.
- Returns `ValidationResult` and stable-ish error codes.

Recommended structure:

- A single `verify_*` entrypoint per public verification mode.
- Small, private helpers for parsing and normalization.
- Avoid introducing an HTTP dependency. Prefer a trait boundary like `JwksFetcher`.

## Extend MST key sources

### Offline key provisioning

`cosesign1-mst` expects keys in `OfflineEcKeyStore`, indexed by `(issuer_host, kid)`.

Common approaches:

- Load a JSON/YAML config of issuer->kid->SPKI and insert at startup.
- Derive SPKI from certificates (leaf SPKI) and insert.

### Online JWKS fetching

To support online mode, implement:

- `cosesign1_mst::JwksFetcher::fetch_jwks(issuer_host, jwks_path, timeout_ms)`

Notes:

- The MST crate expects raw bytes and parses JWKS as JSON.
- Only EC keys are accepted (`kty == "EC"`).
- `crv` is mapped to expected COSE alg (P-256->ES256, P-384->ES384, P-521->ES512).

## Add / update tests

- Unit tests: prefer integration tests under `cosesign1-*/tests/` when exercising public APIs.
- For MST receipts, tests frequently construct synthetic CBOR using `minicbor::Encoder`.

## Coverage gate

The Rust workspace enforces a line coverage threshold.

From `rust/`:

- Run tests: `cargo test --workspace`
- Run coverage gate: `cargo llvm-cov --workspace --tests --fail-under-lines 95`

If you need “what lines are missing”, add `--show-missing-lines`.
