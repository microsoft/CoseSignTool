# Certificate Pack (x5chain)

Crate: `cose_sign1_validation_certificates`

This pack parses X.509 certificates from the COSE `x5chain` header (label `33`).

## What it produces

For signing key subjects (`PrimarySigningKey` and `CounterSignatureSigningKey`), it can emit:

- `X509SigningCertificateIdentityFact`
- `X509SigningCertificateIdentityAllowedFact` (optional pinning)
- `X509X5ChainCertificateIdentityFact` (one per chain element)
- `X509ChainElementIdentityFact`
- `X509ChainTrustedFact` (placeholder trust evaluation for now)
- plus additional key usage / EKU / basic constraints / algorithm facts

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
