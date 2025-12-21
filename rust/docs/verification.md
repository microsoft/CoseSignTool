<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# Verifying COSE_Sign1 in Rust

The Rust port provides a small set of crates:

- `cosesign1-common`: COSE_Sign1 parsing and Sig_structure encoding
- `cosesign1-validation`: signature verification (ES256/384/512, RS256, PS256, and ML-DSA-44/65/87)
- `cosesign1-x509`: x5c extraction and leaf-certificate-based verification helpers
- `cosesign1-mst`: Microsoft Signing Transparency (MST) receipt verification

## Basic verification

`cosesign1-validation` exposes `verify_cose_sign1`:

```rust
use cosesign1_validation::{verify_cose_sign1, VerifyOptions};

let cose_sign1_bytes: Vec<u8> = std::fs::read("message.cose")?;
let public_key_bytes: Vec<u8> = std::fs::read("public_key.der")?; // DER SPKI or DER X.509 cert (ML-DSA also supports raw verifying key bytes)

let opts = VerifyOptions {
    public_key_bytes: Some(public_key_bytes),
    ..Default::default()
};

let res = verify_cose_sign1("Verifier", &cose_sign1_bytes, &opts);
assert!(res.is_valid, "{res:?}");
```

## Detached payload

If the COSE_Sign1 payload is detached (payload is `null`), pass the external payload bytes:

```rust
use cosesign1_validation::{verify_cose_sign1, VerifyOptions};

let cose_sign1_bytes = std::fs::read("detached.cose")?;
let public_key_bytes = std::fs::read("public_key.der")?;
let external_payload = std::fs::read("payload.bin")?;

let opts = VerifyOptions {
    public_key_bytes: Some(public_key_bytes),
    external_payload: Some(external_payload),
    ..Default::default()
};

let res = verify_cose_sign1("Verifier", &cose_sign1_bytes, &opts);
assert!(res.is_valid);
```

## Expected algorithm

If you want to enforce a specific algorithm (instead of trusting the COSE header), set `expected_alg`:

```rust
use cosesign1_validation::{verify_cose_sign1, CoseAlgorithm, VerifyOptions};

let opts = VerifyOptions {
    public_key_bytes: Some(std::fs::read("public_key.der")?),
    expected_alg: Some(CoseAlgorithm::ES256),
    ..Default::default()
};
```

## x5c / certificate-based verification

The x5c helper verifies a COSE_Sign1 signature using the **leaf certificate** embedded in the message.

Note: unlike the native `cosesign1_x509`, the Rust port does not currently implement X.509 chain trust evaluation or revocation checking.

```rust
use cosesign1_validation::VerifyOptions;
use cosesign1_x509::verify_cose_sign1_with_x5c;

let cose_sign1_bytes = std::fs::read("message_with_x5c.cose")?;
let opts = VerifyOptions::default();

// Pass `None` to perform signature verification using the embedded leaf certificate.
let res = verify_cose_sign1_with_x5c("X5c", &cose_sign1_bytes, &opts, None);
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

Use `OfflineEcKeyStore` and insert keys by `(issuer_host, kid)`.

```rust
use cosesign1_mst::{
    verify_transparent_statement, OfflineEcKeyStore, ResolvedKey, VerificationOptions,
};
use cosesign1_validation::CoseAlgorithm;

fn verify_mst_offline(statement: &[u8], issuer: &str, kid: &str, spki_der: Vec<u8>) -> bool {
    let mut key_store = OfflineEcKeyStore::default();
    key_store.insert(
        issuer,
        kid,
        ResolvedKey {
            public_key_bytes: spki_der,
            expected_alg: CoseAlgorithm::ES256,
        },
    );

    let mut opts = VerificationOptions::default();
    opts.authorized_domains = vec![issuer.to_string()];
    // Configure other behaviors if needed:
    // opts.authorized_receipt_behavior = ...;
    // opts.unauthorized_receipt_behavior = ...;

    verify_transparent_statement("MST", statement, &key_store, &opts).is_valid
}
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
