<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# cose_sign1_headers

CWT (CBOR Web Token) claims and header management for COSE_Sign1 messages.

## Overview

This crate provides CWT Claims support as defined in
[RFC 8392](https://www.rfc-editor.org/rfc/rfc8392) with
[SCITT](https://datatracker.ietf.org/wg/scitt/about/) compliance. It is a
port of the V2 `CoseSign1.Headers` package and supplies the types needed to
attach structured claims to COSE_Sign1 protected headers.

Key capabilities:

- **CWT Claims builder** — Fluent construction of standard and custom claims
  (issuer, subject, audience, expiration, etc.)
- **SCITT-compliant defaults** — Default subject `"unknown.intent"` per the
  SCITT specification
- **Header contributor** — `CwtClaimsHeaderContributor` implements the
  `HeaderContributor` trait to inject claims into protected headers at label 15
- **Multi-value claim types** — `CwtClaimValue` supports text, integers, byte
  strings, booleans, and floats
- **FFI projection** — Companion `cose_sign1_headers_ffi` crate exposes the
  full API over C-ABI

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                 cose_sign1_headers                    │
├──────────────┬──────────────┬────────────────────────┤
│ cwt_claims   │ cwt_claims_  │ cwt_claims_header_     │
│              │ labels       │ contributor             │
│ ┌──────────┐ │ ┌──────────┐ │ ┌────────────────────┐ │
│ │CwtClaims │ │ │ISSUER    │ │ │CwtClaimsHeader     │ │
│ │CwtClaim  │ │ │SUBJECT   │ │ │  Contributor        │ │
│ │  Value   │ │ │AUDIENCE  │ │ │ (HeaderContributor) │ │
│ └──────────┘ │ │EXP / NBF │ │ └────────────────────┘ │
│              │ │IAT / CID │ │                        │
│              │ └──────────┘ │                        │
├──────────────┴──────────────┴────────────────────────┤
│  error (HeaderError)                                  │
└──────────────────────────────────────────────────────┘
        │                    │
        ▼                    ▼
  cose_sign1_signing   cose_sign1_primitives
  (HeaderContributor)  (CoseHeaderMap)
        │
        ▼
  cbor_primitives
  (CBOR encode/decode)
```

## Modules

| Module | Description |
|--------|-------------|
| `cwt_claims` | `CwtClaims` builder and `CwtClaimValue` enum — fluent claim construction with CBOR serialization |
| `cwt_claims_labels` | Constants for standard CWT claim labels per RFC 8392 (issuer = 1, subject = 2, etc.) |
| `cwt_claims_header_contributor` | `CwtClaimsHeaderContributor` — injects CWT claims into protected headers at label 15 |
| `cwt_claims_contributor` | Lower-level claim contributor utilities |
| `error` | `HeaderError` — CBOR encoding/decoding and claim validation errors |

## Key Types

### CwtClaims

Structured CBOR Web Token claims with builder methods:

```rust
use cose_sign1_headers::CwtClaims;

let claims = CwtClaims::new()
    .with_issuer("did:x509:0:sha256:abc123::subject:CN:My Issuer")
    .with_subject("my.artifact.intent")
    .with_issued_at(1700000000)
    .with_expiration_time(1700086400);

// Serialize to CBOR bytes for embedding in COSE headers
let cbor_bytes = claims.to_cbor_bytes()?;
```

### CwtClaimValue

Multi-type claim values for standard and custom claims:

```rust
use cose_sign1_headers::CwtClaimValue;

let text_val  = CwtClaimValue::Text("example".into());
let int_val   = CwtClaimValue::Int(42);
let bytes_val = CwtClaimValue::Bytes(vec![0xDE, 0xAD]);
let bool_val  = CwtClaimValue::Bool(true);
let float_val = CwtClaimValue::Float(3.14);
```

### CwtClaimsHeaderContributor

Implements `HeaderContributor` to inject CWT claims into COSE protected
headers:

```rust
use cose_sign1_headers::CwtClaimsHeaderContributor;
use cose_sign1_signing::HeaderContributor;

let claims = CwtClaims::new()
    .with_issuer("did:x509:...")
    .with_subject("my.intent");

let contributor = CwtClaimsHeaderContributor::new(claims);

// Used by the signing pipeline — injects claims at protected header label 15
// with a Replace merge strategy
contributor.contribute_protected_headers(&mut headers, &context);
```

### Standard Claim Labels

```rust
use cose_sign1_headers::cwt_claims_labels::*;

assert_eq!(ISSUER, 1);
assert_eq!(SUBJECT, 2);
assert_eq!(AUDIENCE, 3);
assert_eq!(EXPIRATION_TIME, 4);
assert_eq!(NOT_BEFORE, 5);
assert_eq!(ISSUED_AT, 6);
assert_eq!(CWT_ID, 7);
```

## Memory Design

- **Owned claim values**: `CwtClaims` owns its claim data as `String` / `Vec<u8>`
  / primitive types. Claims are typically small and constructed once per signing
  operation.
- **CBOR serialization**: Claims serialize to a compact CBOR map. The serialized
  bytes are embedded directly into the protected header at label 15 — no
  intermediate copies.
- **Header contributor pattern**: The contributor borrows the `CwtClaims` via
  `Arc` so multiple signers can share the same claims without cloning.

## Dependencies

- `cose_sign1_primitives` — Core COSE header types
- `cose_sign1_signing` — `HeaderContributor` trait
- `cbor_primitives` — CBOR encoding/decoding
- `did_x509` — DID:X509 issuer generation for SCITT compliance

## FFI

The companion [`cose_sign1_headers_ffi`](ffi/) crate exposes this
functionality over C-ABI with opaque handle types and thread-local error
reporting. See the FFI crate for C/C++ integration details.

## See Also

- [signing/core/](../core/) — `HeaderContributor` trait and signing pipeline
- [extension_packs/certificates/](../../extension_packs/certificates/) — Certificate trust pack that uses CWT claims for SCITT
- [did/x509/](../../did/x509/) — DID:X509 identifier utilities

## License

Licensed under the [MIT License](../../../../LICENSE).