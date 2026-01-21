# Trust plans and policies (C)

The trust authoring surface is in `<cose/cose_trust.h>`.

There are two related concepts:

- **Trust policy**: a minimal fluent surface for message-scope requirements, compiled into a bundled plan.
- **Trust plan builder**: selects pack default plans and composes them (OR/AND), also able to compile allow-all/deny-all.

## Attach a compiled plan to a validator

A compiled plan can be attached to the validator builder, overriding the default behavior.

High level:

1) Start with `cose_validator_builder_t*`
2) Create a plan/policy builder from it
3) Compile into `cose_compiled_trust_plan_t*`
4) Attach with `cose_validator_builder_with_compiled_trust_plan`

Key APIs:

- Policies:
  - `cose_trust_policy_builder_new_from_validator_builder`
  - `cose_trust_policy_builder_require_*`
  - `cose_trust_policy_builder_compile`

- Plan builder:
  - `cose_trust_plan_builder_new_from_validator_builder`
  - `cose_trust_plan_builder_add_all_pack_default_plans`
  - `cose_trust_plan_builder_compile_or` / `..._compile_and`
  - `cose_trust_plan_builder_compile_allow_all` / `..._compile_deny_all`

- Attach:
  - `cose_validator_builder_with_compiled_trust_plan`
