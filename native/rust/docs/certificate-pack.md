# Certificate Pack (x5chain)

Crate: `cose_sign1_validation_certificates`

This pack parses X.509 certificates from the COSE `x5chain` header (label `33`).

## What it produces

For signing key subjects (`PrimarySigningKey` and `CounterSignatureSigningKey`), it can emit:

- `X509SigningCertificateIdentityFact`
- `X509SigningCertificateIdentityAllowedFact` (optional pinning)
- `X509X5ChainCertificateIdentityFact` (one per chain element)
- `X509ChainElementIdentityFact`
- `X509ChainTrustedFact` (chain trust decision; can be made deterministic via options)
- plus additional key usage / EKU / basic constraints / algorithm facts

In addition, the pack provides the primary signing key resolver for `x5chain`:

- It resolves the leaf public key material from the leaf certificate.
- Signature verification is conservative:
	- ES256 is supported when the leaf key matches `id-ecPublicKey` and is a P-256 uncompressed SEC1 point.
	- ML-DSA verification is available behind the `pqc-mldsa` feature flag (FIPS 204).

## Header location

Parsing honors `CoseHeaderLocation`:

- `Protected` (default)
- `Any` (protected + unprotected)

## Counter-signature support

For counter-signatures, the pack can parse `x5chain` out of the raw COSE_Signature bytes for a `CounterSignatureSigningKey` subject.

This requires that some producer provides the countersignature raw bytes (the core `CoseSign1MessageFactProducer` does this via resolver-driven discovery).

## Example

A runnable example that generates a self-signed certificate and embeds it as `x5chain`:

- `cose_sign1_validation_certificates/examples/x5chain_identity.rs`

## Deterministic trust (for tests / demos)

If you need OS-agnostic behavior (no platform trust store dependency), you can enable:

- `CertificateTrustOptions.trust_embedded_chain_as_trusted = true`

This makes `X509ChainTrustedFact` pass when an embedded chain is present, which is useful for
tests and demos that only aim to demonstrate signature verification + policy wiring.
