<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# hello-world (consumer example)

This is a minimal consumer of `cosesign1-validation`.

## Build

From this folder:

- `cargo build --release`

Or from repo root:

- `pwsh -NoProfile -Command "Set-Location rust/docs/hello-world; ./build.ps1"`

## Run

`target/release/hello-world.exe <cose_sign1_file> <public_key_file> [external_payload_file]`

- `public_key_file` can be raw key bytes, SPKI DER, or cert DER.
