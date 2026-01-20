// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for ML-DSA verification.
//!
//! These tests live under `tests/` (instead of `src/`) to satisfy the repository's
//! `collect-coverage.ps1` gate that prohibits test code under `src/`.

#![cfg(feature = "pqc-mldsa")]

use cose_sign1_validation_certificates::signing_key_resolver::verify_ml_dsa_dispatch;
use ml_dsa::signature::Signer as _;
use ml_dsa::{KeyGen as _, MlDsa44};

const OID_MLDSA_44: &str = "2.16.840.1.101.3.4.3.17";

#[test]
fn mldsa_44_verify_roundtrip_succeeds() {
    let seed: ml_dsa::B32 = [42u8; 32].into();
    let kp = MlDsa44::key_gen_internal(&seed);

    let msg = b"sig_structure";
    let sig = kp.signing_key().sign(msg);
    let pk = kp.verifying_key().encode();

    let ok = verify_ml_dsa_dispatch(OID_MLDSA_44, pk.as_ref(), msg, sig.encode().as_ref(), OID_MLDSA_44)
        .expect("verify");
    assert!(ok);
}

#[test]
fn mldsa_44_oid_mismatch_is_reported() {
    let seed: ml_dsa::B32 = [42u8; 32].into();
    let kp = MlDsa44::key_gen_internal(&seed);

    let msg = b"sig_structure";
    let sig = kp.signing_key().sign(msg);
    let pk = kp.verifying_key().encode();

    let err = verify_ml_dsa_dispatch("1.2.3.4", pk.as_ref(), msg, sig.encode().as_ref(), OID_MLDSA_44)
        .unwrap_err();
    assert!(err.contains("unexpected public key algorithm OID"));
}
