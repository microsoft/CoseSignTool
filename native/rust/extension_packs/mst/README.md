<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# cose_sign1_transparent_mst

Microsoft Supply Chain Transparency (MST) extension pack for COSE_Sign1.

## Overview

This crate provides validation support for transparent signing receipts emitted
by Microsoft's transparent signing infrastructure, and a transparency provider
that wraps the `code_transparency_client` crate for submitting statements and
retrieving receipts.

Key capabilities:

- **Receipt verification** — Verify MST counter-signature receipts embedded in COSE_Sign1 unprotected headers
- **Transparency provider** — Submit signed COSE messages for transparency logging and retrieve receipts
- **Trust pack** — Implements `CoseSign1TrustPack` for receipt-based trust decisions
- **Fluent trust policy DSL** — Declarative receipt validation rules (issuer allowlisting, receipt trust)
- **JWKS key resolution** — Online and offline receipt signing key discovery

## Architecture

```
┌─────────────────────────────────────────────────────┐
│            cose_sign1_transparent_mst                │
├──────────────────────┬──────────────────────────────┤
│  signing/            │  validation/                  │
│  └ MstTransparency   │  ├ MstTrustPack               │
│      Provider        │  ├ Receipt verification        │
│                      │  ├ JWKS cache                  │
│                      │  ├ Trust facts (7 types)       │
│                      │  ├ Verification options         │
│                      │  └ Fluent DSL extensions        │
├──────────────────────┴──────────────────────────────┤
│  code_transparency_client (Azure SDK)                │
└─────────────────────────────────────────────────────┘
         │                        │
         ▼                        ▼
  cose_sign1_signing      cose_sign1_validation
  (TransparencyProvider)  (CoseSign1TrustPack)
```

MST receipts are stored in the COSE_Sign1 unprotected header at **label 394**
as an array of CBOR byte strings. Each receipt is a COSE_Sign1 counter-signature
that binds a statement digest to a transparency service.

## Modules

| Module | Description |
|--------|-------------|
| `signing` | `MstTransparencyProvider` — submits statements and verifies receipts via Azure SDK |
| `validation::pack` | `MstTrustPack` — trust pack producing receipt-related facts |
| `validation::facts` | Trust fact types: receipt presence, trust, issuer, kid, coverage |
| `validation::fluent_ext` | Fluent DSL extensions for receipt trust policies |
| `validation::receipt_verify` | Core receipt verification logic (COSE signature + claims) |
| `validation::verification_options` | `CodeTransparencyVerificationOptions` with JWKS cache config |
| `validation::jwks_cache` | JWKS key cache with TTL and persistence |
| `validation::verify` | Static verification entry-point functions |

## Key Types

### Signing

- **`MstTransparencyProvider`** — Implements `TransparencyProvider`. Wraps a `CodeTransparencyClient` to submit COSE_Sign1 bytes for transparency logging and verify returned receipts.

### Validation

- **`MstTrustPack`** — Implements `CoseSign1TrustPack` and `TrustFactProducer`. Discovers MST receipts from header label 394, projects each receipt as a counter-signature subject, verifies receipt signatures using JWKS, and emits trust facts.
- **`CodeTransparencyVerificationOptions`** — Controls authorized/unauthorized domain behavior, network JWKS fetching, and offline key pre-seeding.
- **`AuthorizedReceiptBehavior`** — `VerifyAnyMatching`, `VerifyAllMatching`, or `RequireAll` (default).
- **`UnauthorizedReceiptBehavior`** — `VerifyAll` (default), `IgnoreAll`, or `FailIfPresent`.

## Usage

### Signing with Transparency

```rust
use cose_sign1_transparent_mst::signing::MstTransparencyProvider;
use code_transparency_client::{CodeTransparencyClient, CodeTransparencyClientOptions};
use cose_sign1_signing::transparency::TransparencyProvider;

// Create a Code Transparency client for the service endpoint
let options = CodeTransparencyClientOptions::default();
let client = CodeTransparencyClient::new("https://myservice.codetrsp.azure.net", options);

// Create the transparency provider
let provider = MstTransparencyProvider::new(client);

// Submit a signed COSE message and get back the message with embedded receipts
let transparent_bytes = provider.add_transparency_proof(&signed_cose_bytes)?;

// Verify that the receipt is valid
let result = provider.verify_transparency_proof(&transparent_bytes)?;
assert!(result.is_success());
```

### Validating with the MST Trust Pack

```rust
use cose_sign1_transparent_mst::validation::MstTrustPack;
use cose_sign1_validation::fluent::*;
use std::sync::Arc;

// Online mode: fetches JWKS signing keys from receipt issuers
let pack = MstTrustPack::online();

// Use the default trust plan (requires a trusted receipt)
let validator = ValidatorBuilder::new()
    .with_trust_pack(Arc::new(pack))
    .build()?;

let result = validator.validate(&cose_bytes_with_receipts, None)?;
```

### Offline Verification (No Network)

```rust
use cose_sign1_transparent_mst::validation::MstTrustPack;
use cose_sign1_validation::fluent::*;
use std::sync::Arc;

// Pre-seed JWKS signing keys for offline verification
let jwks_json = r#"{"keys":[...]}"#;
let pack = MstTrustPack::offline_with_jwks(jwks_json);

let validator = ValidatorBuilder::new()
    .with_trust_pack(Arc::new(pack))
    .build()?;

let result = validator.validate(&cose_bytes, None)?;
```

### Custom Trust Policies with the Fluent DSL

```rust
use cose_sign1_transparent_mst::validation::MstTrustPack;
use cose_sign1_transparent_mst::validation::pack::fluent_ext::*;
use cose_sign1_transparent_mst::validation::facts::*;
use cose_sign1_validation::fluent::*;
use std::sync::Arc;

let pack = Arc::new(MstTrustPack::online());

let plan = TrustPlanBuilder::new(vec![pack.clone()])
    .for_counter_signature(|cs| {
        cs.require_mst_receipt_trusted_from_issuer("myservice.codetrsp.azure.net")
    })
    .compile()?;
```

### Issuer Allowlisting

```rust
use cose_sign1_transparent_mst::validation::pack::fluent_ext::*;
use cose_sign1_transparent_mst::validation::facts::*;
use cose_sign1_validation::fluent::*;

// Require a specific issuer domain
let plan = TrustPlanBuilder::new(vec![pack.clone()])
    .for_counter_signature(|cs| {
        cs.require::<MstReceiptTrustedFact>(|w| w.require_receipt_trusted())
          .and()
          .require::<MstReceiptIssuerFact>(|w| {
              w.require_receipt_issuer_eq("myservice.codetrsp.azure.net")
          })
    })
    .compile()?;
```

### Advanced Verification Options

```rust
use cose_sign1_transparent_mst::validation::verification_options::{
    CodeTransparencyVerificationOptions,
    AuthorizedReceiptBehavior,
    UnauthorizedReceiptBehavior,
};
use std::collections::HashMap;

let options = CodeTransparencyVerificationOptions {
    // Only trust receipts from these domains
    authorized_domains: vec!["myservice.codetrsp.azure.net".into()],
    // All authorized domains must have valid receipts
    authorized_receipt_behavior: AuthorizedReceiptBehavior::RequireAll,
    // Fail if unauthorized receipts are present
    unauthorized_receipt_behavior: UnauthorizedReceiptBehavior::FailIfPresent,
    // Allow fetching JWKS from the network
    allow_network_fetch: true,
    jwks_cache: None,
    client_factory: None,
};

// Pre-seed offline keys into the options
let options = options.with_offline_keys(HashMap::from([
    ("issuer.example.com".into(), jwks_document),
]));
```

## Trust Facts Produced

The `MstTrustPack` produces the following facts during validation:

| Fact Type | Scope | Description |
|-----------|-------|-------------|
| `MstReceiptPresentFact` | Counter-signature | Whether an MST receipt is present |
| `MstReceiptTrustedFact` | Counter-signature | Whether the receipt verified successfully |
| `MstReceiptIssuerFact` | Counter-signature | The `iss` claim from the receipt |
| `MstReceiptKidFact` | Counter-signature | The `kid` used to resolve the signing key |
| `MstReceiptStatementSha256Fact` | Counter-signature | SHA-256 digest of the bound statement |
| `MstReceiptStatementCoverageFact` | Counter-signature | Description of what bytes are covered |
| `MstReceiptSignatureVerifiedFact` | Counter-signature | Whether the COSE signature on the receipt verified |

Additionally, standard counter-signature projection facts are emitted at the message scope:

| Fact Type | Scope | Description |
|-----------|-------|-------------|
| `CounterSignatureSubjectFact` | Message | Projects each receipt as a counter-signature subject |
| `CounterSignatureSigningKeySubjectFact` | Message | Counter-signature signing key subject |
| `UnknownCounterSignatureBytesFact` | Message | Raw receipt bytes for downstream consumers |
| `CounterSignatureEnvelopeIntegrityFact` | Counter-signature | Envelope integrity check result |

## Configuration

### MstTrustPack

```rust
pub struct MstTrustPack {
    /// Allow network JWKS fetching when offline keys are missing.
    pub allow_network: bool,
    /// Offline JWKS JSON for deterministic verification.
    pub offline_jwks_json: Option<String>,
    /// Optional api-version for the CodeTransparency /jwks endpoint.
    pub jwks_api_version: Option<String>,
}
```

**Constructors:**

| Method | Network | Offline Keys | Use Case |
|--------|---------|-------------|----------|
| `MstTrustPack::online()` | ✅ | None | Production with network access |
| `MstTrustPack::offline_with_jwks(json)` | ❌ | Provided | Air-gapped or test environments |
| `MstTrustPack::new(allow, jwks, api_ver)` | Custom | Custom | Full control |

## Error Handling

Receipt verification errors are reported through `ReceiptVerifyError`:

```rust
pub enum ReceiptVerifyError {
    ReceiptDecode(String),
    MissingAlg,
    UnsupportedVds(String),
    // ... additional variants for JWKS, signature, and claims errors
}
```

Non-MST receipts (e.g., different VDS types) produce `UnsupportedVds` errors,
which are treated as non-fatal — allowing other trust packs to process their
own receipt types alongside MST receipts.

## Dependencies

- `cose_sign1_primitives` — Core COSE types
- `cose_sign1_signing` — `TransparencyProvider` trait
- `cose_sign1_validation` — Validation framework
- `cose_sign1_validation_primitives` — Trust fact types
- `cose_sign1_crypto_openssl` — JWK verification via OpenSSL
- `code_transparency_client` — Azure Code Transparency SDK client
- `sha2` — Statement digest computation
- `serde` / `serde_json` — JWKS document parsing

## See Also

- [Transparent MST Pack documentation](../../docs/transparent-mst-pack.md)
- [cose_sign1_signing](../../signing/core/) — TransparencyProvider trait
- [cose_sign1_validation](../../validation/core/) — Validation framework
- [cose_sign1_certificates](../certificates/) — Certificate trust pack (often combined with MST)
