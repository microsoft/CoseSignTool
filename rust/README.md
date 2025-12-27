<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# Rust (parity with `native/`)

This folder hosts the Rust COSE_Sign1 verification stack.

Crates:

- `cosesign1-abstractions`: shared types + plugin interfaces (key providers, message validators)
- `cosesign1`: high-level verification facade (parsing + signature verification + validator pipeline)
- `cosesign1-x509`: `x5c` key provider + X.509 chain trust validator
- `cosesign1-mst`: Microsoft Signing Transparency (MST) receipt validator (+ MST helper APIs)

## Build + Test

- `cargo test --workspace`

## Coverage (95% gate)

This repo targets **95% line coverage** for the Rust workspace.

Prereqs (one-time):

- `rustup component add llvm-tools-preview`
- Install `cargo-llvm-cov`: `cargo install cargo-llvm-cov`

Run:

- `cargo llvm-cov --workspace --tests --fail-under-lines 95`

## Docs and consumer example

See `rust/docs/README.md` for:

- library usage docs
- a minimal consumer CLI (`rust/docs/hello-world/`) that builds `cosesign1_hello_world.exe`

