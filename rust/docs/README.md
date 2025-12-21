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

## Using the libraries

- Verification guide: `verification.md`
- Copy/paste snippets: `examples.md`

## Quick start

From `rust/`:

- Run tests: `cargo test --workspace`
- Run coverage gate (95% lines): `./collect-coverage.ps1`

## Example CLI (consumer app)

A small, standalone Rust binary crate lives in `rust/docs/hello-world/`.

Build (Windows PowerShell):

- `pwsh -NoProfile -Command "Set-Location rust/docs/hello-world; ./build.ps1"`

Run:
- `rust/docs/hello-world/target/release/cosesign1_hello_world.exe <mode> [args...]`

Notes:

- `public_key_file` can be one of:
  - raw public key bytes (ML-DSA only; these are the encoded verifying key bytes)
  - DER SubjectPublicKeyInfo
  - DER X.509 certificate (the leaf SPKI is extracted)
- See `rust/docs/hello-world/README.md` for the supported modes and flags.

See `verification.md` for library usage examples.
