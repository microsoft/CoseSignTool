# Rust COSE_Sign1 Validation + Trust (V2 Port)

This folder documents the Rust workspace under `native/rust/`.

## What you get

- A staged COSE_Sign1 validation pipeline (resolution > trust > signature > post-signature)
- A V2-style trust engine (facts + rule graph + audit + stable subject IDs)
- Pluggable CBOR via `cbor_primitives` traits -- compile-time provider selection for FFI
- Optional trust packs (X.509 x5chain, Transparent MST receipts, Azure Key Vault KID)
- Detached payload support (bytes or provider) + streaming-friendly signature verification
- C and C++ FFI projections with per-pack modularity

## Table of contents

- [Getting Started](getting-started.md)
- [CBOR Provider Selection](cbor-providers.md)
- [Validator Architecture](validator-architecture.md)
- [Extension Points](extension-points.md)
- [Detached Payloads + Streaming](detached-payloads.md)
- [Trust Model (Facts/Rules/Plans)](trust-model.md)
- [Trust Subjects + Stable IDs](trust-subjects.md)
- [Certificate Pack (x5chain)](certificate-pack.md)
- [Transparent MST Pack](transparent-mst-pack.md)
- [Azure Key Vault Pack](azure-key-vault-pack.md)
- [Demo Executable](demo-exe.md)
- [Troubleshooting](troubleshooting.md)

## See also

- [Native FFI Architecture](../../ARCHITECTURE.md) -- Mermaid diagrams, crate dependency graph, C/C++ layer details
- [C Projection](../../c/README.md)
- [C++ Projection](../../c_pp/README.md)
