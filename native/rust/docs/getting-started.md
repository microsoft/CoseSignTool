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

The recommended integration style is **trust-pack driven**:

- You pass one or more `CoseSign1TrustPack`s to the validator.
- Packs can contribute signing key resolvers, fact producers, and default trust plans.
- You can optionally provide an explicit trust plan when you need a custom policy.

Two common ways to wire the validator:

1) **Default behavior (packs provide resolvers + default plans)**

  - `CoseSign1Validator::new(trust_packs)`

2) **Custom policy (compile an explicit plan)**

  - `TrustPlanBuilder::new(trust_packs)...compile()`
  - `CoseSign1Validator::new(compiled_plan)`

If you want to focus on cryptographic signature verification while prototyping a policy, you can
temporarily bypass trust evaluation while keeping signature verification enabled via:

- `CoseSign1ValidationOptions.trust_evaluation_options.bypass_trust = true`

## Examples

A minimal “smoke” setup (real signature verification using embedded X.509 `x5chain`, with trust bypassed) is shown in:

- `cose_sign1_validation/examples/validate_smoke.rs`

For a runnable CLI-style demo, see:

- `cose_sign1_validation_demo` (documented in `demo-exe.md`)
