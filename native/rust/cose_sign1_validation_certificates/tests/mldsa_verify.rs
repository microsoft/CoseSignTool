// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for ML-DSA verification.
//!
//! These tests live under `tests/` (instead of `src/`) to satisfy the repository's
//! `collect-coverage.ps1` gate that prohibits test code under `src/`.

#![cfg(feature = "pqc-mldsa")]

use cose_sign1_validation_certificates::signing_key_resolver::verify_ml_dsa_dispatch;
use pqcrypto_mldsa::mldsa44;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};

const OID_MLDSA_44: &str = "2.16.840.1.101.3.4.3.17";

#[test]
fn mldsa_44_verify_roundtrip_succeeds() {
    let msg = b"sig_structure";
    let (pk, sk) = mldsa44::keypair();
    let sig = mldsa44::detached_sign(msg, &sk);

    let ok = verify_ml_dsa_dispatch(
        OID_MLDSA_44,
        pk.as_bytes(),
        msg,
        sig.as_bytes(),
        OID_MLDSA_44,
    )
        .expect("verify");
    assert!(ok);
}

#[test]
fn mldsa_44_oid_mismatch_is_reported() {
    let msg = b"sig_structure";
    let (pk, sk) = mldsa44::keypair();
    let sig = mldsa44::detached_sign(msg, &sk);

    let err = verify_ml_dsa_dispatch("1.2.3.4", pk.as_bytes(), msg, sig.as_bytes(), OID_MLDSA_44)
        .unwrap_err();
    assert!(err.contains("unexpected public key algorithm OID"));
}
