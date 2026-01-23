# native/rust

Rust port of the V2 trust/validation framework (mirrors `V2/CoseSign1.Validation`).

Docs live in [native/rust/docs/](docs/):
- [native/rust/docs/README.md](docs/README.md)

Workspace crates:
- `cose_sign1_validation_trust`: trust engine (facts/rules/compiled plans/audit/subject IDs).
- `cose_sign1_validation`: fluent-first validator facade (trust pack wiring + validation pipeline).
- `cose_sign1_validation_certificates`: X.509 `x5chain` parsing + signature verification via leaf cert public key.
- `cose_sign1_validation_transparent_mst`: Transparent MST receipt parsing + verification.
- `cose_sign1_validation_azure_key_vault`: Azure Key Vault `kid` pattern detection/allow-listing.
- `cose_sign1_validation_demo`: runnable demo (`selftest` + `validate`).

Try it:
- `cargo test --workspace`
- `cargo run -p cose_sign1_validation_demo -- --help`
