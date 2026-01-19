# cose_sign1_validation_trust

Trust engine used by the staged validator.

## Concepts

- `TrustSubject`: stable identity being evaluated
- `TrustFactProducer`: produces typed facts for a subject
- `CompiledTrustPlan`: combines constraints + trust sources + vetoes
- `TrustFactEngine`: stores facts + runs producers on demand

## Example

- `cargo run -p cose_sign1_validation_trust --example trust_plan_minimal`

Docs: `native/rust/docs/trust-model.md` and `native/rust/docs/trust-subjects.md`.
