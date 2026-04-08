<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# did_x509

DID:x509 identifier parsing, building, validation, and resolution.

## Overview

This crate implements the [DID:x509 method specification](https://github.com/nicosResworworking-group/did-x509),
which creates Decentralized Identifiers (DIDs) from X.509 certificate chains.
A DID:x509 identifier binds a trust anchor (CA certificate fingerprint) to one
or more policy constraints (EKU, subject, SAN, Fulcio issuer) that must be
satisfied by the leaf certificate in a presented chain.

Key capabilities:

- **Parsing** — zero-copy-friendly DID:x509 string parsing with full validation
- **Building** — fluent construction of DID:x509 identifiers from certificate chains
- **Validation** — validate DID:x509 identifiers against certificate chains
- **Resolution** — resolve DID:x509 identifiers to W3C DID Documents with JWK public keys
- **Policy validators** — EKU, Subject DN, SAN (email/dns/uri/dn), and Fulcio issuer
- **FFI** — complete C/C++ projection via the companion `did_x509_ffi` crate

## DID:x509 Format

```
did:x509:0:sha256:<base64url_CA_fingerprint>::eku:<oid1>:<oid2>::subject:CN:<value>
│        │ │      │                            │                  │
│        │ │      │                            │                  └─ Subject policy
│        │ │      │                            └─ EKU policy
│        │ │      └─ Base64url-encoded CA certificate fingerprint
│        │ └─ Hash algorithm (sha256, sha384, sha512)
│        └─ Version (always 0)
└─ DID method prefix
```

Multiple policies are separated by `::` (double colon). Within a policy, values
are separated by `:` (single colon). Special characters are percent-encoded.

## Architecture

```
┌─────────────────────────────────────────────────┐
│                   did_x509                       │
├─────────────┬───────────────┬───────────────────┤
│  parsing/   │  builder      │  validator        │
│  ├ Parser   │  ├ build()    │  ├ validate()     │
│  ├ Percent  │  ├ build_     │  └ policy match   │
│  │  encode  │  │  sha256()  │                   │
│  └ Percent  │  ├ build_     ├───────────────────┤
│     decode  │  │  from_     │  resolver         │
│             │  │  chain()   │  ├ resolve()      │
│             │  └ build_     │  ├ RSA→JWK        │
│             │     from_     │  └ EC→JWK         │
│             │     chain_    │                   │
│             │     with_eku()│                   │
├─────────────┴───────────────┴───────────────────┤
│  models/                                         │
│  ├ DidX509ParsedIdentifier                       │
│  ├ DidX509Policy (Eku, Subject, San, Fulcio)     │
│  ├ DidX509ValidationResult                       │
│  ├ SanType (Email, Dns, Uri, Dn)                 │
│  ├ CertificateInfo, X509Name                     │
│  └ SubjectAlternativeName                        │
├─────────────────────────────────────────────────┤
│  policy_validators   │  x509_extensions          │
│  ├ validate_eku()    │  ├ extract_eku_oids()     │
│  ├ validate_subject()│  ├ extract_extended_      │
│  ├ validate_san()    │  │   key_usage()          │
│  └ validate_fulcio() │  ├ extract_fulcio_issuer()│
│                      │  └ extract_san()          │
├──────────────────────┴──────────────────────────┤
│  did_document        │  constants                │
│  ├ DidDocument       │  ├ OID constants          │
│  ├ Verification      │  ├ Attribute labels       │
│  │   Method          │  └ oid_to_attribute_      │
│  └ to_json()         │      label()              │
└─────────────────────────────────────────────────┘
         │
         ▼
  x509-parser (DER parsing)
  sha2 (fingerprint hashing)
  serde/serde_json (DID Document serialization)
```

## Modules

| Module | Description |
|--------|-------------|
| `parsing` | `DidX509Parser::parse()` — parses DID:x509 strings into structured identifiers |
| `builder` | `DidX509Builder` — constructs DID:x509 strings from certificates and policies |
| `validator` | `DidX509Validator::validate()` — validates DIDs against certificate chains |
| `resolver` | `DidX509Resolver::resolve()` — resolves DIDs to W3C DID Documents |
| `models` | Core types: `DidX509ParsedIdentifier`, `DidX509Policy`, `DidX509ValidationResult` |
| `policy_validators` | Per-policy validation: EKU, Subject DN, SAN, Fulcio issuer |
| `x509_extensions` | X.509 extension extraction utilities (EKU, SAN, Fulcio) |
| `san_parser` | Subject Alternative Name parsing from certificates |
| `did_document` | W3C DID Document model with JWK-based verification methods |
| `constants` | DID:x509 format constants, well-known OIDs, attribute labels |
| `error` | `DidX509Error` with 24 descriptive variants |

## Key Types

### `DidX509Parser`

Parses a DID:x509 string into its structured components with full validation
of version, hash algorithm, fingerprint length, and policy syntax.

```rust
use did_x509::DidX509Parser;

let did = "did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkExample::eku:1.3.6.1.5.5.7.3.3";
let parsed = DidX509Parser::parse(did).unwrap();

assert_eq!(parsed.hash_algorithm, "sha256");
assert!(parsed.has_eku_policy());
assert_eq!(parsed.policies.len(), 1);
```

### `DidX509Builder`

Constructs DID:x509 identifier strings from CA certificates and policy constraints.

```rust
use did_x509::{DidX509Builder, DidX509Policy};

// Build from a CA certificate with EKU policy
let did = DidX509Builder::build_sha256(
    ca_cert_der,
    &[DidX509Policy::Eku(vec!["1.3.6.1.5.5.7.3.3".into()])],
).unwrap();

// Build from a certificate chain (automatically uses root as CA)
let did = DidX509Builder::build_from_chain(
    &[leaf_der, intermediate_der, root_der],
    &[DidX509Policy::Eku(vec!["1.3.6.1.5.5.7.3.3".into()])],
).unwrap();

// Build with EKU extracted from the leaf certificate
let did = DidX509Builder::build_from_chain_with_eku(
    &[leaf_der, intermediate_der, root_der],
).unwrap();
```

### `DidX509Validator`

Validates a DID:x509 identifier against a certificate chain by verifying the
CA fingerprint matches a certificate in the chain and all policy constraints
are satisfied by the leaf certificate.

```rust
use did_x509::DidX509Validator;

let result = DidX509Validator::validate(did_string, &[leaf_der, root_der]).unwrap();

if result.is_valid {
    println!("CA matched at chain index: {}", result.matched_ca_index.unwrap());
} else {
    for error in &result.errors {
        eprintln!("Validation error: {}", error);
    }
}
```

### `DidX509Resolver`

Resolves a DID:x509 identifier to a W3C DID Document containing the leaf
certificate's public key in JWK format. Performs full validation first.

```rust
use did_x509::DidX509Resolver;

let doc = DidX509Resolver::resolve(did_string, &[leaf_der, root_der]).unwrap();

// DID Document contains the public key as a JsonWebKey2020 verification method
assert_eq!(doc.id, did_string);
assert_eq!(doc.verification_method[0].type_, "JsonWebKey2020");

// Serialize to JSON
let json = doc.to_json(true).unwrap();
```

### `DidX509Policy`

Policy constraints that can be included in a DID:x509 identifier:

```rust
use did_x509::{DidX509Policy, SanType};

// Extended Key Usage — OID list
let eku = DidX509Policy::Eku(vec!["1.3.6.1.5.5.7.3.3".into()]);

// Subject Distinguished Name — key-value pairs
let subject = DidX509Policy::Subject(vec![
    ("CN".to_string(), "example.com".to_string()),
    ("O".to_string(), "Example Corp".to_string()),
]);

// Subject Alternative Name — typed value
let san = DidX509Policy::San(SanType::Email, "user@example.com".to_string());

// Fulcio issuer — OIDC issuer URL
let fulcio = DidX509Policy::FulcioIssuer("https://accounts.google.com".to_string());
```

### `DidX509Error`

Comprehensive error type with 24 variants covering every failure mode:

| Category | Variants |
|----------|----------|
| Format | `EmptyDid`, `InvalidPrefix`, `InvalidFormat`, `MissingPolicies` |
| Version | `UnsupportedVersion` |
| Hash | `UnsupportedHashAlgorithm`, `EmptyFingerprint`, `FingerprintLengthMismatch`, `InvalidFingerprintChars` |
| Policy syntax | `EmptyPolicy`, `InvalidPolicyFormat`, `EmptyPolicyName`, `EmptyPolicyValue` |
| EKU | `InvalidEkuOid` |
| Subject | `InvalidSubjectPolicyComponents`, `EmptySubjectPolicyKey`, `DuplicateSubjectPolicyKey` |
| SAN | `InvalidSanPolicyFormat`, `InvalidSanType` |
| Fulcio | `EmptyFulcioIssuer` |
| Chain | `InvalidChain`, `CertificateParseError`, `NoCaMatch` |
| Validation | `PolicyValidationFailed`, `ValidationFailed` |
| Encoding | `PercentDecodingError`, `InvalidHexCharacter` |

## Supported Hash Algorithms

| Algorithm | Fingerprint Length | Constant |
|-----------|--------------------|----------|
| SHA-256 | 32 bytes (43 base64url chars) | `HASH_ALGORITHM_SHA256` |
| SHA-384 | 48 bytes (64 base64url chars) | `HASH_ALGORITHM_SHA384` |
| SHA-512 | 64 bytes (86 base64url chars) | `HASH_ALGORITHM_SHA512` |

## Supported Policies

| Policy | DID Syntax | Description |
|--------|-----------|-------------|
| EKU | `eku:<oid1>:<oid2>` | Extended Key Usage OIDs must all be present on the leaf cert |
| Subject | `subject:<attr>:<val>` | Subject DN attributes must match (CN, O, OU, L, ST, C, STREET) |
| SAN | `san:<type>:<value>` | Subject Alternative Name must match (email, dns, uri, dn) |
| Fulcio Issuer | `fulcio-issuer:<url>` | Fulcio OIDC issuer extension must match |

## FFI Support

The companion `did_x509_ffi` crate exposes the full API through C-compatible functions:

| FFI Function | Purpose |
|-------------|---------|
| `did_x509_parse` | Parse a DID:x509 string into a handle |
| `did_x509_parsed_get_fingerprint` | Get the CA fingerprint bytes |
| `did_x509_parsed_get_hash_algorithm` | Get the hash algorithm string |
| `did_x509_parsed_get_policy_count` | Get the number of policies |
| `did_x509_parsed_free` | Free a parsed handle |
| `did_x509_build_with_eku` | Build a DID:x509 string with EKU policy |
| `did_x509_build_from_chain` | Build from a certificate chain |
| `did_x509_validate` | Validate a DID against a certificate chain |
| `did_x509_resolve` | Resolve a DID to a JSON DID Document |
| `did_x509_error_message` | Get last error message |
| `did_x509_error_code` | Get last error code |
| `did_x509_error_free` | Free an error handle |
| `did_x509_string_free` | Free a Rust-allocated string |

C and C++ headers are available at:
- **C**: `native/c/include/cose/did/x509.h`
- **C++**: `native/c_pp/include/cose/did/x509.hpp`

## Usage Example: SCITT Compliance

A common pattern for SCITT (Supply Chain Integrity, Transparency, and Trust)
compliance is to build a DID:x509 identifier from a signing certificate chain
and embed it as the `iss` (issuer) claim in CWT protected headers:

```rust
use did_x509::{DidX509Builder, DidX509Policy, DidX509Validator};

// 1. Build the DID from the signing chain (leaf-first order)
let did = DidX509Builder::build_from_chain_with_eku(
    &[leaf_der, intermediate_der, root_der],
).expect("Failed to build DID:x509");

// 2. The DID string can be used as the CWT `iss` claim
//    e.g., "did:x509:0:sha256:<fingerprint>::eku:1.3.6.1.5.5.7.3.3"

// 3. During validation, verify the DID against the presented chain
let result = DidX509Validator::validate(&did, &[leaf_der, intermediate_der, root_der])
    .expect("Validation error");
assert!(result.is_valid);
```

## Dependencies

| Crate | Purpose |
|-------|---------|
| `x509-parser` | DER certificate parsing, extension extraction |
| `sha2` | SHA-256/384/512 fingerprint computation |
| `serde` / `serde_json` | DID Document JSON serialization |

## Memory Design

- **Parsing**: `DidX509Parser::parse()` returns owned `DidX509ParsedIdentifier` (allocation required for fingerprint bytes and policy data extracted from the DID string)
- **Policies**: `DidX509Policy::Eku` uses `Vec<Cow<'static, str>>` — static OID strings use `Cow::Borrowed` (zero allocation), dynamic OIDs use `Cow::Owned`
- **DID Documents**: `VerificationMethod` JWK maps use `HashMap<Cow<'static, str>, String>` — all JWK field names (`kty`, `crv`, `x`, `y`, `n`, `e`) are `Cow::Borrowed`
- **Validation**: `DidX509ValidationResult` collects errors as `Vec<String>` — only allocated on validation failure
- **Fingerprinting**: SHA digests use `to_vec()` for cross-algorithm uniform handling (structurally required)
- **Policy validators**: Borrow certificate data (zero-copy) — only allocate on error paths

## Test Coverage

The crate has 23 test files covering:

- Parser tests: format validation, edge cases, percent encoding/decoding
- Builder tests: SHA-256/384/512, chain construction, EKU extraction
- Validator tests: fingerprint matching, policy validation, error cases
- Resolver tests: RSA and EC key conversion, DID Document generation
- Policy validator tests: EKU, Subject DN, SAN, Fulcio issuer
- X.509 extension tests: extraction utilities
- Comprehensive edge case and coverage-targeted tests

## License

Licensed under the MIT License. See [LICENSE](../../../../LICENSE) for details.