# Getting Started

## Prereqs

- Rust toolchain (workspace is edition 2021)

## Build + test

From `native/rust/`:

- Run tests: `cargo test --workspace`
- Check compilation only: `cargo check --workspace`

## Crates

- `cose_sign1_validation_trust`
  - The trust engine (facts, producers, rules, policies, compiled plans, audit)
  - Stable `TrustSubject` IDs (V2-style SHA-256 semantics)

- `cose_sign1_validation`
  - COSE_Sign1-oriented validator facade (parsing + staged orchestration)
  - Extension traits: signing key resolver, counter-signature resolver, post-signature validators
  - Detached payload support (bytes/provider)

- Optional fact producers (“packs”)
  - `cose_sign1_validation_certificates`: parses `x5chain` (COSE header label `33`) and emits X.509 identity facts
  - `cose_sign1_validation_transparent_mst`: reads MST receipt headers and emits MST facts
  - `cose_sign1_validation_azure_key_vault`: inspects KID header label `4` and matches allowed AKV patterns

## Quick start: validate a message

The validator requires:

- A `SigningKeyResolver` (how to resolve a key for the message)
- A trust plan + fact producers (how to decide whether the signing key is trusted)
- Optionally, post-signature validators

A minimal “smoke” setup (bypass trust, accept-any-signature key) is shown in:

- `cose_sign1_validation/examples/validate_smoke.rs`

For a runnable CLI-style demo, see:

- `cose_sign1_validation_demo` (documented in `demo-exe.md`)
