<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# Rust docs

This folder contains end-user documentation and a minimal example CLI that consumes the Rust verifier crates.

## Architecture and extending

- Architecture overview: `architecture.md`
- MST verifier details: `mst-verifier.md`
- Sequence diagrams (Mermaid): `sequence-diagrams.md`
- Extending guide: `extending.md`
- Testing and coverage: `testing-and-coverage.md`

## Quick start

From `rust/`:

- Run tests: `cargo test --workspace`
- Run coverage gate (95% lines): `./collect-coverage.ps1`

## Example CLI ("hello world")

A small, standalone Rust binary crate lives in `rust/docs/hello-world/`.

Build (Windows PowerShell):

- `pwsh -NoProfile -Command "Set-Location rust/docs/hello-world; ./build.ps1"`

Run:

- `rust/docs/hello-world/target/release/hello-world.exe <cose_sign1_file> <public_key_file> [external_payload_file]`

Notes:

- `public_key_file` can be one of:
  - raw public key bytes (for ML-DSA this is the encoded verifying key bytes)
  - DER SubjectPublicKeyInfo
  - DER X.509 certificate (the leaf SPKI is extracted)
- For detached payload COSE_Sign1, pass `external_payload_file`.

See `verification.md` for library usage examples.
