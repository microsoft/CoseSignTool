# cose_sign1_validation_certificates

Trust pack that parses X.509 certificates from COSE `x5chain` (header label `33`).

## PQC / ML-DSA

ML-DSA (FIPS 204) signature verification support is available behind the `pqc-mldsa` feature flag.

## Example

- `cargo run -p cose_sign1_validation_certificates --example x5chain_identity`

Docs: `native/rust/docs/certificate-pack.md`.
