<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# cose_sign1_validation_primitives_ffi

C/C++ FFI projection for trust plan and trust policy authoring.

## Overview

This crate exposes a C ABI for composing compiled trust plans and trust policies, then
attaching them to a validator builder. It enables per-pack modularity: packs (certificates,
MST, AKV) remain separate crates, and trust-plan authoring is exposed as a reusable layer
that works across all packs.

### Trust Plan Builder

Compiles a bundled trust plan by composing the default plans provided by configured trust packs.
Supports OR/AND composition, allow-all, and deny-all strategies.

### Trust Policy Builder

Provides declarative rule authoring for CWT claims constraints, content type requirements,
detached payload presence, and counter-signature envelope integrity.

## Exported Functions

### Trust Plan Builder

| Function | Description |
|----------|-------------|
| `cose_sign1_trust_plan_builder_new_from_validator_builder` | Create plan builder from validator builder |
| `cose_sign1_trust_plan_builder_free` | Free a trust plan builder |
| `cose_sign1_trust_plan_builder_add_all_pack_default_plans` | Add all pack default plans |
| `cose_sign1_trust_plan_builder_add_pack_default_plan_by_name` | Add a specific pack's default plan |
| `cose_sign1_trust_plan_builder_pack_count` | Get number of registered packs |
| `cose_sign1_trust_plan_builder_pack_name_utf8` | Get pack name by index |
| `cose_sign1_trust_plan_builder_pack_has_default_plan` | Check if pack has default plan |
| `cose_sign1_trust_plan_builder_clear_selected_plans` | Clear selected plans |
| `cose_sign1_trust_plan_builder_compile_or` | Compile with OR composition |
| `cose_sign1_trust_plan_builder_compile_and` | Compile with AND composition |
| `cose_sign1_trust_plan_builder_compile_allow_all` | Compile allow-all plan |
| `cose_sign1_trust_plan_builder_compile_deny_all` | Compile deny-all plan |
| `cose_sign1_compiled_trust_plan_free` | Free a compiled trust plan |
| `cose_sign1_validator_builder_with_compiled_trust_plan` | Attach compiled plan to validator builder |

### Trust Policy Builder

| Function | Description |
|----------|-------------|
| `cose_sign1_trust_policy_builder_new_from_validator_builder` | Create policy builder from validator builder |
| `cose_sign1_trust_policy_builder_free` | Free a trust policy builder |
| `cose_sign1_trust_policy_builder_and` | Combine policies with AND |
| `cose_sign1_trust_policy_builder_or` | Combine policies with OR |
| `cose_sign1_trust_policy_builder_compile` | Compile the policy |
| `cose_sign1_trust_policy_builder_require_content_type_*` | Content type constraints |
| `cose_sign1_trust_policy_builder_require_detached_payload_*` | Detached payload constraints |
| `cose_sign1_trust_policy_builder_require_counter_signature_*` | Counter-signature constraints |
| `cose_sign1_trust_policy_builder_require_cwt_*` | CWT claims constraints (~25 functions) |

## Handle Types

| Type | Description |
|------|-------------|
| `cose_sign1_trust_plan_builder_t` | Opaque trust plan builder |
| `cose_sign1_compiled_trust_plan_t` | Opaque compiled trust plan |

## C Header

`<cose/sign1/trust.h>`

## Parent Library

[`cose_sign1_validation_primitives`](../../primitives/) — Trust policy and plan primitives.

## Build

```bash
cargo build --release -p cose_sign1_validation_primitives_ffi
```
