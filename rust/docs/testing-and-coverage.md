<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# Testing and coverage

## Running tests

From `rust/`:

- `cargo test --workspace`

To run a single crate’s tests:

- `cargo test -p cosesign1-mst`

## Coverage gate

The workspace uses `cargo-llvm-cov` with a minimum line coverage threshold.

From `rust/`:

 `cargo llvm-cov --workspace --tests --fail-under-lines 95`
 `cargo llvm-cov --workspace --tests --show-missing-lines`
To list uncovered lines:

- `cargo llvm-cov --workspace --tests --show-missing-lines --exclude cosesign1-ffi-abstractions --exclude cosesign1-ffi --exclude cosesign1-ffi-x509 --exclude cosesign1-ffi-mst`

## Interpreting common llvm-cov warnings

You may see output like:

- `warning: N functions have mismatched data`

This is emitted by llvm-cov when function coverage mapping doesn’t perfectly match (often due to inlining / compiler details). In this repo it has been observed without impacting the line-coverage gate. Treat it as a signal to re-check results if coverage seems “off”, but it is not necessarily a failure by itself.
