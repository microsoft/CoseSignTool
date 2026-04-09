<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# cose_sign1_validation_test_utils

Test-only utilities for composing COSE_Sign1 validation scenarios.

## Overview

This crate provides lightweight helper types for assembling trust packs and
validation pipelines in tests **without** pulling in a full extension pack.
It exists to keep the production `cose_sign1_validation` API surface focused
while enabling concise, flexible test composition.

Key capabilities:

- **`SimpleTrustPack`** — Builder-pattern trust pack that implements
  `CoseSign1TrustPack`, composable from any combination of fact producers,
  key resolvers, post-signature validators, and default trust plans
- **`NoopTrustFactProducer`** — A no-op `TrustFactProducer` that produces
  zero facts, useful as a placeholder when fact production is irrelevant to
  the test

## Architecture

```
┌────────────────────────────────────────────┐
│      cose_sign1_validation_test_utils      │
│                                            │
│  ┌──────────────────┐  ┌────────────────┐  │
│  │ SimpleTrustPack  │  │ NoopTrustFact  │  │
│  │                  │  │   Producer     │  │
│  │ • fact_producer  │  │ (produces ∅)   │  │
│  │ • key_resolvers  │  └────────────────┘  │
│  │ • post_sig_vals  │                      │
│  │ • default_plan   │                      │
│  └──────────────────┘                      │
└────────────────────────────────────────────┘
        │                    │
        ▼                    ▼
  cose_sign1_validation   cose_sign1_validation_primitives
  (CoseSign1TrustPack,   (TrustFactProducer, FactKey,
   CoseKeyResolver,       CompiledTrustPlan)
   PostSignatureValidator)
```

## Key Types

### SimpleTrustPack

A convenience `CoseSign1TrustPack` implementation for tests. Start with
`no_facts()` and layer on only the components the test requires:

```rust
use cose_sign1_validation_test_utils::SimpleTrustPack;
use std::sync::Arc;

// Minimal pack — no facts, no resolvers, no plan
let pack = SimpleTrustPack::no_facts("test-pack");

// Composed pack — custom producer + resolver + plan
let pack = SimpleTrustPack::no_facts("cert-test")
    .with_fact_producer(Arc::new(my_producer))
    .with_cose_key_resolver(Arc::new(my_resolver))
    .with_default_trust_plan(my_compiled_plan);
```

### NoopTrustFactProducer

A `TrustFactProducer` that does nothing — useful when a test needs a trust
pack but does not care about fact production:

```rust
use cose_sign1_validation_test_utils::NoopTrustFactProducer;

let producer = NoopTrustFactProducer::default();
assert_eq!(producer.name(), "noop");
assert!(producer.provides().is_empty());
```

## Usage in Tests

Typical pattern for building a validator with a custom trust plan:

```rust
use cose_sign1_validation::fluent::*;
use cose_sign1_validation_test_utils::SimpleTrustPack;
use std::sync::Arc;

// Build a trust pack with a custom key resolver
let pack = Arc::new(
    SimpleTrustPack::no_facts("roundtrip")
        .with_cose_key_resolver(Arc::new(my_key_resolver))
        .with_default_trust_plan(compiled_plan),
);

// Use the pack in a validator
let validator = ValidatorBuilder::new()
    .with_trust_pack(pack)
    .build()?;

let result = validator.validate(&cose_bytes, None)?;
```

## Memory Design

- **`Arc`-based composition**: All components (producers, resolvers, validators)
  are held as `Arc<dyn Trait>`, matching the ownership model of the production
  `CoseSign1TrustPack` trait.
- **Clone-friendly**: `SimpleTrustPack` derives `Clone` so the same pack can be
  shared across multiple validators in a test without rebuilding.
- **No heap overhead beyond `Arc` bumps**: Calling `.clone()` on a
  `SimpleTrustPack` increments reference counts — it does not deep-copy
  producers or resolvers.

## Dependencies

- `cose_sign1_validation` — `CoseSign1TrustPack`, `CoseKeyResolver`, `PostSignatureValidator`
- `cose_sign1_validation_primitives` — `TrustFactProducer`, `FactKey`, `CompiledTrustPlan`

## Note

This crate is **test-only**. It is compiled with `test = false` in its own
`Cargo.toml` (no self-tests) and is intended to be a `[dev-dependencies]`
entry in consumer crates.

## See Also

- [validation/core/](../core/) — Production validation framework
- [validation/primitives/](../primitives/) — Trust fact and plan types
- [extension_packs/certificates/](../../extension_packs/certificates/) — Real-world trust pack example

## License

Licensed under the [MIT License](../../../../LICENSE).