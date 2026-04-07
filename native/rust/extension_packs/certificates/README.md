<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# cose_sign1_certificates

X.509 certificate trust pack for COSE_Sign1 signing and validation.

## Overview

This crate provides both signing and validation capabilities for X.509
certificate-based COSE signatures. It implements the **CoseSign1TrustPack**
trait for certificate chain validation, and the **SigningService** trait for
signing with X.509 certificate-backed keys.

Key capabilities:

- **Certificate-based signing** with automatic x5t/x5chain header injection
- **Certificate chain validation** with configurable trust anchors
- **SCITT compliance** with CWT claims and DID:X509 issuer generation
- **Thumbprint computation** (SHA-256, SHA-384, SHA-512)
- **Fluent trust policy DSL** for declarative certificate validation rules

## Architecture

```
┌─────────────────────────────────────────────────────┐
│              cose_sign1_certificates                 │
├──────────────────────┬──────────────────────────────┤
│  signing/            │  validation/                  │
│  ├ CertificateSigning│  ├ X509CertificateTrustPack   │
│  │   Service         │  ├ X509CertificateCoseKey     │
│  ├ CertificateHeader │  │   Resolver                 │
│  │   Contributor     │  ├ Trust facts (11 types)     │
│  ├ CertificateSource │  └ Fluent DSL extensions      │
│  ├ SigningKeyProvider │                               │
│  └ SCITT compliance  │                               │
├──────────────────────┴──────────────────────────────┤
│  Shared: chain_builder, thumbprint, extensions,      │
│          cose_key_factory, error, chain_sort_order    │
└─────────────────────────────────────────────────────┘
         │                        │
         ▼                        ▼
  cose_sign1_signing      cose_sign1_validation
  cose_sign1_primitives   cose_sign1_validation_primitives
```

## Modules

| Module | Description |
|--------|-------------|
| `signing` | Certificate signing service, header contributors, key providers, SCITT support |
| `validation` | Trust pack, signing key resolver, trust facts, fluent DSL extensions |
| `chain_builder` | `CertificateChainBuilder` trait and `ExplicitCertificateChainBuilder` |
| `thumbprint` | `CoseX509Thumbprint` computation (SHA-256/384/512) |
| `extensions` | x5chain (label 33) and x5t (label 34) header extraction utilities |
| `cose_key_factory` | Create `CryptoVerifier` from X.509 certificate public keys |
| `chain_sort_order` | `X509ChainSortOrder` enum (LeafFirst, RootFirst) |
| `error` | `CertificateError` error type |

## Key Types

### Signing

- **`CertificateSigningService`** — Implements `SigningService` for X.509 certificate-backed signing. Composes a `CertificateSource`, `SigningKeyProvider`, and `CertificateSigningOptions`.
- **`CertificateHeaderContributor`** — Implements `HeaderContributor` to inject x5t (label 34) and x5chain (label 33) into protected headers.
- **`CertificateSigningOptions`** — Configuration for SCITT compliance and custom CWT claims.
- **`CertificateSource`** (trait) — Abstracts certificate sources (local files, remote vaults).
- **`SigningKeyProvider`** (trait) — Extends `CryptoSigner` with `is_remote()` for local vs. remote signing.
- **`CertificateSigningKey`** (trait) — Extends `SigningServiceKey` + `CryptoSigner` with certificate chain access.

### Validation

- **`X509CertificateTrustPack`** — Implements `CoseSign1TrustPack`. Produces 11 certificate-related trust facts, resolves signing keys from x5chain, and provides a secure-by-default trust plan.
- **`X509CertificateCoseKeyResolver`** — Implements `CoseKeyResolver`. Extracts the leaf certificate public key from the x5chain header.
- **`CertificateTrustOptions`** — Configuration for identity pinning, embedded chain trust, and PQC algorithm OIDs.

### Shared

- **`ExplicitCertificateChainBuilder`** — Pre-built certificate chain (stored via `Arc` for zero-copy cloning).
- **`CoseX509Thumbprint`** — CBOR-serializable thumbprint with algorithm ID and hash bytes.
- **`X509CertificateCoseKeyFactory`** — Creates `CryptoVerifier` instances from DER-encoded certificate public keys.

## Usage

### Signing with X.509 Certificates

```rust
use cose_sign1_certificates::signing::{
    CertificateSigningService, CertificateSigningOptions,
    CertificateSource, SigningKeyProvider,
};
use cose_sign1_signing::{SigningService, SigningContext};

// Create a certificate signing service from a source and key provider
let service = CertificateSigningService::new(
    certificate_source,           // impl CertificateSource
    signing_key_provider.into(),  // Arc<dyn SigningKeyProvider>
    CertificateSigningOptions::default(), // SCITT enabled by default
);

// Get a signer for a signing context
let context = SigningContext::new(payload);
let signer = service.get_cose_signer(&context)?;
// signer automatically includes x5t + x5chain in protected headers
```

### Configuring Signing Options

```rust
use cose_sign1_certificates::signing::CertificateSigningOptions;

// Default: SCITT compliance enabled
let options = CertificateSigningOptions::default();

// Custom: disable SCITT, add custom CWT claims
let options = CertificateSigningOptions {
    enable_scitt_compliance: false,
    custom_cwt_claims: Some(my_cwt_claims),
};
```

### Building Certificate Chains

```rust
use cose_sign1_certificates::chain_builder::{
    CertificateChainBuilder, ExplicitCertificateChainBuilder,
};

// Provide a pre-built chain of DER-encoded certificates
let chain_builder = ExplicitCertificateChainBuilder::new(vec![
    leaf_cert_der.to_vec(),
    intermediate_cert_der.to_vec(),
    root_cert_der.to_vec(),
]);

// Build chain from a signing certificate
let chain = chain_builder.build_chain(&signing_cert_der)?;
```

### Computing Thumbprints

```rust
use cose_sign1_certificates::thumbprint::{
    CoseX509Thumbprint, ThumbprintAlgorithm, compute_thumbprint,
};

// Compute a SHA-256 thumbprint (default)
let thumbprint = CoseX509Thumbprint::from_cert(&cert_der);

// Compute with a specific algorithm
let thumbprint = CoseX509Thumbprint::new(&cert_der, ThumbprintAlgorithm::Sha384);

// Serialize/deserialize for CBOR headers
let bytes = thumbprint.serialize()?;
let restored = CoseX509Thumbprint::deserialize(&bytes)?;

// Check if a thumbprint matches a certificate
let matches = thumbprint.matches(&other_cert_der)?;
```

### Validating with the Certificate Trust Pack

```rust
use cose_sign1_certificates::validation::{
    X509CertificateTrustPack, CertificateTrustOptions,
};
use cose_sign1_validation::fluent::*;
use std::sync::Arc;

// Create trust pack with default options
let pack = X509CertificateTrustPack::new(CertificateTrustOptions::default());

// Or trust embedded chains (deterministic, no OS trust store)
let pack = X509CertificateTrustPack::trust_embedded_chain_as_trusted();

// Use the default trust plan (chain trusted + cert valid at now)
let validator = ValidatorBuilder::new()
    .with_trust_pack(Arc::new(pack))
    .build()?;

let result = validator.validate(&cose_bytes, None)?;
```

### Custom Trust Policies with the Fluent DSL

```rust
use cose_sign1_certificates::validation::{
    X509CertificateTrustPack, CertificateTrustOptions,
};
use cose_sign1_certificates::validation::fluent_ext::*;
use cose_sign1_certificates::validation::facts::*;
use cose_sign1_validation::fluent::*;
use std::sync::Arc;

let pack = Arc::new(X509CertificateTrustPack::new(
    CertificateTrustOptions::default(),
));

let plan = TrustPlanBuilder::new(vec![pack.clone()])
    .for_primary_signing_key(|key| {
        key.require_x509_chain_trusted()
           .require_signing_certificate_present()
           .require::<X509SigningCertificateIdentityFact>(|w| {
               w.issuer_eq("CN=My Issuer")
                .cert_valid_at(now_unix_seconds)
           })
    })
    .compile()?;
```

### Extracting x5chain and x5t from Headers

```rust
use cose_sign1_certificates::extensions::{
    extract_x5chain, extract_x5t, verify_x5t_matches_chain,
    X5CHAIN_LABEL, X5T_LABEL,
};

// Extract certificate chain from headers (label 33)
let chain: Vec<ArcSlice> = extract_x5chain(&message.protected)?;

// Extract thumbprint from headers (label 34)
let thumbprint: Option<CoseX509Thumbprint> = extract_x5t(&message.protected)?;

// Verify x5t matches the leaf certificate in x5chain
let valid: bool = verify_x5t_matches_chain(&message.protected)?;
```

## Trust Facts Produced

The `X509CertificateTrustPack` produces the following facts during validation:

| Fact Type | Scope | Description |
|-----------|-------|-------------|
| `X509SigningCertificateIdentityFact` | Signing key | Leaf cert thumbprint, subject, issuer, serial, validity |
| `X509SigningCertificateIdentityAllowedFact` | Signing key | Whether the cert thumbprint is in the allowed list |
| `X509SigningCertificateEkuFact` | Signing key | Extended Key Usage OIDs |
| `X509SigningCertificateKeyUsageFact` | Signing key | Key Usage flags |
| `X509SigningCertificateBasicConstraintsFact` | Signing key | Basic Constraints (CA, path length) |
| `X509ChainElementIdentityFact` | Per-element | Thumbprint, subject, issuer for each chain element |
| `X509ChainElementValidityFact` | Per-element | Validity period for each chain element |
| `X509ChainTrustedFact` | Chain | Whether the chain is trusted, built, status flags |
| `X509PublicKeyAlgorithmFact` | Signing key | Algorithm OID, name, PQC indicator |
| `X509X5ChainCertificateIdentityFact` | Chain | Full x5chain identity details |
| `CertificateSigningKeyTrustFact` | Signing key | Consolidated trust summary |

## Configuration

### CertificateTrustOptions

```rust
pub struct CertificateTrustOptions {
    /// Certificate thumbprints allowed for identity pinning.
    pub allowed_thumbprints: Vec<String>,
    /// Enable identity pinning (restrict to allowed thumbprints).
    pub identity_pinning_enabled: bool,
    /// Custom OIDs treated as post-quantum cryptography algorithms.
    pub pqc_algorithm_oids: Vec<String>,
    /// Trust embedded x5chain without OS trust store validation.
    /// Deterministic across platforms.
    pub trust_embedded_chain_as_trusted: bool,
}
```

## Error Handling

All operations return `CertificateError`:

```rust
pub enum CertificateError {
    NotFound,
    InvalidCertificate(String),
    ChainBuildFailed(String),
    NoPrivateKey,
    SigningError(String),
}
```

Signing operations return `SigningError` (from `cose_sign1_signing`) which wraps
certificate-specific errors. Validation errors are reported through the
`TrustError` type from `cose_sign1_validation_primitives`.

## Dependencies

- `cose_sign1_primitives` — Core COSE types
- `cose_sign1_signing` — Signing service traits
- `cose_sign1_validation` — Validation framework
- `cose_sign1_validation_primitives` — Trust fact types
- `cose_sign1_crypto_openssl` — OpenSSL crypto provider
- `cbor_primitives` — CBOR serialization
- `did_x509` — DID:X509 issuer generation for SCITT
- `x509-parser` — Certificate parsing
- `openssl` — Cryptographic operations
- `sha2` — Hash algorithms

## See Also

- [Certificate Pack documentation](../../docs/certificate-pack.md)
- [cose_sign1_signing](../../signing/core/) — Signing traits
- [cose_sign1_validation](../../validation/core/) — Validation framework
- [cose_sign1_certificates_local](local/) — Ephemeral cert generation for testing
