<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# Rust (parity with `native/`)

This folder hosts Rust equivalents of the native (C++/vcpkg) validator libraries:

- `cosesign1-common`: CBOR + COSE_Sign1 parsing primitives
- `cosesign1-validation`: signature verification + validation result types
- `cosesign1-x509`: x5c / X.509 helpers
- `cosesign1-mst`: Microsoft Signing Transparency (MST) receipt verification

## Build + Test

- `cargo test --workspace`

## Coverage (95% gate)

This repo targets **95% line coverage** for the Rust workspace.

Prereqs (one-time):

- `rustup component add llvm-tools-preview`
- Install `cargo-llvm-cov`: `cargo install cargo-llvm-cov`

Run:

- `cargo llvm-cov --workspace --fail-under-lines 95`

## Docs and consumer example

See `rust/docs/README.md` for:

- library usage docs
- a minimal consumer CLI (`rust/docs/hello-world/`) that builds `hello-world.exe`

