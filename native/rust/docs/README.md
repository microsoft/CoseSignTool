# Rust COSE_Sign1 Validation + Trust (V2 Port)

This folder documents the Rust workspace under `native/rust/`.

## What you get

- A staged COSE_Sign1 validation pipeline (resolution → trust → signature → post-signature)
- A V2-style trust engine (facts + rule graph + audit + stable subject IDs)
- Optional trust “packs” that can contribute facts (X.509 x5chain parsing, Transparent MST receipts, Azure Key Vault KID checks)
- Detached payload support (bytes or provider) + streaming-friendly signature verification for large payloads

## Table of contents

- [Getting Started](getting-started.md)
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
