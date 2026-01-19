# native/rust

Rust port of the V2 trust/validation framework (mirrors `V2/CoseSign1.Validation`).

Docs live in `native/rust/docs/`:
- `native/rust/docs/README.md`

Workspace crates:
- `cose_sign1_validation_trust`: facts/rules/plan/audit/subject IDs.
- `cose_sign1_validation`: COSE_Sign1-centric facade (parsing + validation entrypoints).

Try it:
- `cargo test --workspace`
- `cargo run -p cose_sign1_validation_demo -- --help`
