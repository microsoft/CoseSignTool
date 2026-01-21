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

### Detailed end-to-end example (custom trust plan + feedback)

This example also exists as a compilable `cargo` example:

- `native/rust/cose_sign1_validation/examples/validate_custom_policy.rs`

Run it:

- From `native/rust/`: `cargo run -p cose_sign1_validation --example validate_custom_policy`

This example shows how to:

- Configure trust packs (certificates pack shown)
- Compile an explicit trust plan (message-scope + signing-key scope)
- Validate a COSE_Sign1 message with a detached payload
- Print user-friendly feedback when validation fails

```rust
use std::sync::Arc;

use cose_sign1_validation::fluent::*;
use cose_sign1_validation_certificates::pack::{
  CertificateTrustOptions, X509CertificateTrustPack,
};
use cose_sign1_validation_trust::CoseHeaderLocation;

fn main() {
  // Replace these with your own data sources.
  let cose_bytes: Vec<u8> = /* ... */ Vec::new();
  let payload_bytes: Vec<u8> = /* ... */ Vec::new();

  if cose_bytes.is_empty() {
    eprintln!("Provide COSE_Sign1 bytes before validating.");
    return;
  }

  // 1) Configure packs
  let cert_pack = Arc::new(X509CertificateTrustPack::new(CertificateTrustOptions {
    // Deterministic for local examples/tests: treat embedded x5chain as trusted.
    // In production, configure roots/CRLs/OCSP rather than enabling this.
    trust_embedded_chain_as_trusted: true,
    ..Default::default()
  }));

  let trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![cert_pack];

  // 2) Compile an explicit plan
  let plan = TrustPlanBuilder::new(trust_packs)
    .for_message(|msg| {
      msg.require_content_type_non_empty()
        .and()
        .require_detached_payload_present()
        .and()
        .require_cwt_claims_present()
    })
    .and()
    .for_primary_signing_key(|key| {
      key.require_x509_chain_trusted()
        .and()
        .require_signing_certificate_present()
        .and()
        .require_signing_certificate_thumbprint_present()
    })
    .compile()
    .expect("plan compile");

  // 3) Create validator and configure detached payload
  let validator = CoseSign1Validator::new(plan).with_options(|o| {
    o.detached_payload = Some(DetachedPayload::bytes(Arc::from(
      payload_bytes.into_boxed_slice(),
    )));
    o.certificate_header_location = CoseHeaderLocation::Any;
  });

  // 4) Validate
  let result = validator
    .validate_bytes(Arc::from(cose_bytes.into_boxed_slice()))
    .expect("validation pipeline error");

  if result.overall.is_valid() {
    println!("Validation successful");
    return;
  }

  // Feedback: print stage outcome + failure messages
  eprintln!("overall: {:?}", result.overall.kind);
  for failure in &result.overall.failures {
    eprintln!("- {}", failure.message);
  }
}
```
