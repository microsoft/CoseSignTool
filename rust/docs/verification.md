<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# Verifying COSE_Sign1 in Rust

The Rust port is intentionally small:

- `cosesign1`: high-level verification facade (parse + signature verification + validator pipeline)
- `cosesign1-x509`: `x5c` public-key extraction + X.509 chain trust validation (as a message validator)
- `cosesign1-mst`: MST receipt verification (as a message validator)
- `cosesign1-abstractions`: shared types + plugin interfaces/registries

## Basic signature verification

```rust
use cosesign1::CoseSign1;

let cose_sign1_bytes: Vec<u8> = std::fs::read("message.cose")?;
let public_key_bytes: Vec<u8> = std::fs::read("public_key.der")?; // DER SPKI (or other encodings supported by the selected alg)

let msg = CoseSign1::from_bytes(&cose_sign1_bytes)?;
let res = msg.verify_signature(None, Some(public_key_bytes.as_slice()));
assert!(res.is_valid, "{res:?}");
```

## Detached payload

If the COSE_Sign1 payload is detached (payload is `null`), pass the external payload bytes:

```rust
use cosesign1::CoseSign1;

let cose_sign1_bytes = std::fs::read("detached.cose")?;
let public_key_bytes = std::fs::read("public_key.der")?;
let external_payload = std::fs::read("payload.bin")?;

let msg = CoseSign1::from_bytes(&cose_sign1_bytes)?;
let res = msg.verify_signature(Some(&external_payload), Some(&public_key_bytes));
assert!(res.is_valid, "{res:?}");
```

## Advanced controls (expected algorithm, etc.)

If you need lower-level knobs (e.g., enforce an expected algorithm), use the lower-level API:

```rust
use cosesign1::validation::{verify_cose_sign1, CoseAlgorithm, VerifyOptions};

let cose_sign1_bytes = std::fs::read("message.cose")?;
let public_key_bytes = std::fs::read("public_key.der")?;

let mut opts = VerifyOptions::default();
opts.public_key_bytes = Some(public_key_bytes);
opts.expected_alg = Some(CoseAlgorithm::ES256);

let res = verify_cose_sign1("Verifier", &cose_sign1_bytes, &opts);
assert!(res.is_valid, "{res:?}");
```

## x5c + X.509 chain trust (validator)

If the message includes an `x5c` chain, the `cosesign1-x509` crate registers:

- a signing key provider that can extract the public key from `x5c` for signature verification
- a message validator that can enforce trust (chain building / revocation policy)

```rust
use cosesign1::{CoseSign1, VerificationSettings};
use cosesign1_x509::{X509ChainVerifyOptions, X509RevocationMode, X509TrustMode};

let cose_sign1_bytes = std::fs::read("message_with_x5c.cose")?;
let msg = CoseSign1::from_bytes(&cose_sign1_bytes)?;

let mut chain = X509ChainVerifyOptions::default();
chain.trust_mode = X509TrustMode::System;
chain.revocation_mode = X509RevocationMode::NoCheck;

let settings = VerificationSettings::default()
    .with_validator_options(cosesign1_x509::x5c_chain_validation_options(chain));

// No explicit public key: the `x5c` provider supplies it.
let res = msg.verify(None, None, &settings);
assert!(res.is_valid, "{res:?}");
```

## ML-DSA public key encodings

For ML-DSA (-48/-49/-50), the verifier accepts:

- raw ML-DSA encoded verifying key bytes
- DER SubjectPublicKeyInfo
- DER X.509 certificate (OID is checked when present)

If you pass a certificate/SPKI with a non-matching OID for the selected ML-DSA algorithm, validation fails with `INVALID_PUBLIC_KEY`.

## MST (Signing Transparency) receipt verification

`cosesign1-mst` verifies receipts embedded in the statement’s unprotected header and returns a `ValidationResult`.

For detailed behavior and header-label semantics, see `mst-verifier.md`.

### MST offline verification (keys provided by caller)

You can either call the MST verifier directly, or enable it as a message validator in the `cosesign1` pipeline.

Validator pipeline example:

```rust
use cosesign1::{CoseSign1, VerificationSettings};
use cosesign1_mst::{OfflineEcKeyStore, VerificationOptions};

let cose_sign1_bytes = std::fs::read("statement.cose")?;
let msg = CoseSign1::from_bytes(&cose_sign1_bytes)?;

let store = OfflineEcKeyStore::default();
let opts = VerificationOptions::default();

let settings = VerificationSettings::default()
    .without_cose_signature()
    .with_validator_options(cosesign1_mst::mst_message_validation_options(store, opts));

let res = msg.verify(None, None, &settings);
assert!(res.is_valid, "{res:?}");
```

Notes:

- `public_key_bytes` should be a DER SubjectPublicKeyInfo (SPKI) for the receipt public key.
- The MST verifier also supports `kid` values that are not ASCII by normalizing them to lowercase hex.

### MST online verification (JWKS fallback)

Online mode is a **two-pass** strategy:

1. Attempt offline verification using keys already present in the cache.
2. If invalid and `allow_network_key_fetch == true`, fetch JWKS for authorized issuers, populate the cache, then retry.

The MST crate does not pick an HTTP client. Your application provides a `JwksFetcher` implementation.

```rust
use cosesign1_mst::{
    verify_transparent_statement_online, JwksFetcher, OfflineEcKeyStore, VerificationOptions,
};

struct MyJwksFetcher;

impl JwksFetcher for MyJwksFetcher {
    fn fetch_jwks(&self, issuer_host: &str, jwks_path: &str, timeout_ms: u32) -> Result<Vec<u8>, String> {
        // Implement with your preferred HTTP stack.
        // Expected return: raw JWKS JSON bytes.
        // Example URL shape: https://{issuer_host}{jwks_path}
        let _ = (issuer_host, jwks_path, timeout_ms);
        Err("not implemented".to_string())
    }
}

fn verify_mst_online(statement: &[u8], authorized_issuers: Vec<String>) -> bool {
    let mut cache = OfflineEcKeyStore::default();
    let fetcher = MyJwksFetcher;

    let mut opts = VerificationOptions::default();
    opts.authorized_domains = authorized_issuers;
    opts.allow_network_key_fetch = true;
    opts.jwks_path = "/jwks".to_string();
    opts.jwks_timeout_ms = 5_000;

    verify_transparent_statement_online("MST", statement, &mut cache, &fetcher, &opts).is_valid
}
```

Notes:

- JWKS keys are filtered to EC JWKs and inserted into the cache by `(issuer, kid)`.
- The verifier maps EC curves to expected COSE algorithms:
  - `P-256` → `ES256`
  - `P-384` → `ES384`
  - `P-521` → `ES512`
