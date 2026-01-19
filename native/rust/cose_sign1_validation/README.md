# cose_sign1_validation

COSE_Sign1-focused staged validator.

## What it does

- Parses COSE_Sign1 CBOR and orchestrates validation stages:
  - key material resolution
  - trust evaluation
  - signature verification
  - post-signature policy
- Supports detached payload verification (bytes or provider)
- Provides extension traits for:
  - signing key resolution (`SigningKeyResolver` / `SigningKey`)
  - counter-signature discovery (`CounterSignatureResolver` / `CounterSignature`)
  - post-signature validation (`PostSignatureValidator`)

## Examples

Run:

- `cargo run -p cose_sign1_validation --example validate_smoke`
- `cargo run -p cose_sign1_validation --example detached_payload_provider`

For the bigger picture docs, see `native/rust/docs/README.md`.
