# Trust Model (Facts / Rules / Plans)

The trust engine is a small rule system:

- **Facts**: typed observations produced for a subject (e.g., “x5chain leaf thumbprint is …”)
- **Producers**: code that can observe facts (`TrustFactProducer`)
- **Rules**: evaluate to a `TrustDecision` (`Trusted` / `Denied` + reasons)
- **Plan**: combines required facts + constraints + trust sources + vetoes

## Typical flow

1. Validator constructs a `TrustFactEngine` with the configured producers.
2. The trust plan evaluates against a `TrustSubject`.
3. Rules call into the engine to fetch facts.
4. Producers run on-demand to produce missing facts.

## Policy builder

For validator integrations, prefer the fluent trust-plan builder:

- `cose_sign1_validation::fluent::TrustPlanBuilder`

This keeps policy authoring aligned with pack wiring and the validator result model.

At the lower level, the trust engine also exposes `TrustPolicyBuilder` (in `cose_sign1_validation_trust`) which can be useful for standalone trust-plan evaluation.

Both approaches compile to a `CompiledTrustPlan` with the same semantics:

- required facts (always ensure these are attempted)
- constraints (must all be satisfied)
- trust sources (at least one must be satisfied)
- vetoes (if any are satisfied, deny)

Important: if **no trust sources** are configured, the compiled plan denies by default (V2 parity).

## Audit

You can request an audit trail during evaluation. The validator can include audit data in stage metadata.

## Example

A runnable trust engine example is in:

- [cose_sign1_validation_trust/examples/trust_plan_minimal.rs](../cose_sign1_validation_trust/examples/trust_plan_minimal.rs)
