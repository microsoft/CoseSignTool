<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# cosesign1-hello-world (consumer example)

This is a small, buildable Rust console app showing how to consume the Rust verifier crates.

It mirrors the native example app in `native/examples/cosesign1-hello-world`.

## Build

From this folder:

- `cargo build --release`

Or from repo root:

- `pwsh -NoProfile -Command "Set-Location rust/docs/hello-world; ./build.ps1"`

## Run

`target/release/cosesign1_hello_world.exe <mode> [args...]`

Modes:

- `key` — verify a COSE_Sign1 using a known public key or certificate
	- `key --cose <file> --public-key <der> [--payload <file>] [--expected-alg <ES256|ES384|ES512|PS256|RS256|MLDsa44|MLDsa65|MLDsa87>]`

- `x5c` — verify a COSE_Sign1 using embedded `x5c`
	- `x5c --cose <file> [--payload <file>] [--expected-alg <...>] --trust <system|custom> [--root <der>] [--revocation <online|offline|none>] [--allow-untrusted]`
	- Notes: the Rust port currently verifies the signature using the leaf certificate but does not implement chain trust evaluation.

- `mst` — verify an MST transparent statement using an offline JWKS file
	- `mst --statement <file> --issuer-host <host> --jwks <file>`

- For `key`, `--public-key` should be DER SPKI or DER X.509 cert (ML-DSA also supports raw verifying key bytes).
