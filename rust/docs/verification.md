<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# Verifying COSE_Sign1 in Rust

The Rust port provides a small set of crates:

- `cosesign1-common`: COSE_Sign1 parsing and Sig_structure encoding
- `cosesign1-validation`: signature verification (ES256/384/512, RS256, PS256, and ML-DSA-44/65/87)
- `cosesign1-x509`: x5c extraction and leaf-certificate-based verification helpers

## Basic verification

`cosesign1-validation` exposes `verify_cose_sign1`:

```rust
use cosesign1_validation::{verify_cose_sign1, VerifyOptions};

let cose_sign1_bytes: Vec<u8> = std::fs::read("message.cose")?;
let public_key_bytes: Vec<u8> = std::fs::read("public_key.der")?; // SPKI DER, cert DER, or raw key bytes

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

The x5c helper verifies a COSE_Sign1 using the leaf certificate embedded in the message.

```rust
use cosesign1_validation::VerifyOptions;
use cosesign1_x509::{verify_cose_sign1_with_x5c, X509ChainVerifyOptions};

let cose_sign1_bytes = std::fs::read("message_with_x5c.cose")?;
let opts = VerifyOptions::default();
let chain = X509ChainVerifyOptions::default();

let res = verify_cose_sign1_with_x5c("X5c", &cose_sign1_bytes, &opts, Some(&chain));
assert!(res.is_valid, "{res:?}");
```

## ML-DSA public key encodings

For ML-DSA (-48/-49/-50), the verifier accepts:

- raw ML-DSA encoded verifying key bytes
- DER SubjectPublicKeyInfo
- DER X.509 certificate (OID is checked when present)

If you pass a certificate/SPKI with a non-matching OID for the selected ML-DSA algorithm, validation fails with `INVALID_PUBLIC_KEY`.
