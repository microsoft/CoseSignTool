<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# cosesign1-hello-world (consumer example)

This is a small, buildable Rust console app showing how to consume the Rust verifier crates.

It mirrors the native C ABI surface documented under `native/`.

## Build

From this folder:

- `cargo build --release`

Or from repo root:

- `pwsh -NoProfile -Command "Set-Location rust/docs/hello-world; ./build.ps1"`

## Run

`target/release/cosesign1_hello_world.exe <mode> [args...]`

Modes:

- `key` — verify a COSE_Sign1 using a known public key or certificate
	- `key --cose <file> --public-key <der> [--payload <file>]`

- `x5c` — verify a COSE_Sign1 using embedded `x5c`
	- `x5c --cose <file> [--payload <file>] --trust <system|custom> [--root <der>] [--revocation <online|offline|none>] [--allow-untrusted]`
	- Notes: this mode verifies the COSE signature and then enforces X.509 chain trust via the `x5c_chain` message validator.

- `mst` — verify an MST transparent statement using an offline JWKS file
	- `mst --statement <file> --issuer-host <host> --jwks <file>`

- For `key`, `--public-key` should be DER SPKI or DER X.509 cert (ML-DSA also supports raw verifying key bytes).
