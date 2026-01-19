// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation_trust::evaluation_options::{CoseHeaderLocation, TrustEvaluationOptions};
use cose_sign1_validation_trust::ids::{
    sha256_domain_separated, sha256_of_bytes, sha256_of_concat, SubjectId,
};
use cose_sign1_validation_trust::subject::TrustSubject;
use cose_sign1_validation_trust::TrustDecision;

#[test]
fn subject_id_to_hex_is_64_chars() {
    let id = SubjectId([0xAB; 32]);
    let hex = id.to_hex();
    assert_eq!(64, hex.len());
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn sha256_helpers_are_deterministic_and_distinct() {
    let a = sha256_of_bytes(b"hello");
    let b = sha256_of_bytes(b"hello");
    let c = sha256_of_bytes(b"world");
    assert_eq!(a, b);
    assert_ne!(a, c);

    let concat1 = sha256_of_concat(&[b"a", b"bc"]);
    let concat2 = sha256_of_concat(&[b"ab", b"c"]);
    // raw concat can collide for ambiguous splits
    assert_eq!(concat1, concat2);

    let dom1 = sha256_domain_separated(b"domain", &[b"a", b"bc"]);
    let dom2 = sha256_domain_separated(b"domain", &[b"ab", b"c"]);
    // length-prefixing prevents ambiguity
    assert_ne!(dom1, dom2);

    let dom3 = sha256_domain_separated(b"other-domain", &[b"a", b"bc"]);
    assert_ne!(dom1, dom3);
}

#[test]
fn trust_subject_ids_are_stable_and_kind_correct() {
    let msg = TrustSubject::message(b"encoded-message-bytes");
    assert_eq!("Message", msg.kind);

    let psk = TrustSubject::primary_signing_key(&msg);
    assert_eq!("PrimarySigningKey", psk.kind);
    assert_ne!(msg.id, psk.id);

    let cs = TrustSubject::counter_signature(&msg, b"raw-countersig");
    assert_eq!("CounterSignature", cs.kind);

    let cssk = TrustSubject::counter_signature_signing_key(&cs);
    assert_eq!("CounterSignatureSigningKey", cssk.kind);
    assert_ne!(cs.id, cssk.id);

    let root_a = TrustSubject::root("X", b"seed");
    let root_b = TrustSubject::root("X", b"seed");
    let root_c = TrustSubject::root("X", b"other-seed");
    assert_eq!(root_a, root_b);
    assert_ne!(root_a, root_c);

    let derived_a = TrustSubject::derived(&root_a, "Y", b"disc");
    let derived_b = TrustSubject::derived(&root_a, "Y", b"disc");
    let derived_c = TrustSubject::derived(&root_a, "Y", b"other-disc");
    assert_eq!(derived_a, derived_b);
    assert_ne!(derived_a, derived_c);
}

#[test]
fn trust_decision_helpers_behave_as_expected() {
    assert!(TrustDecision::trusted().is_trusted);
    assert!(TrustDecision::trusted().reasons.is_empty());

    let empty = TrustDecision::trusted_with(vec![]);
    assert!(empty.is_trusted);
    assert!(empty.reasons.is_empty());

    let one = TrustDecision::trusted_reason("ok");
    assert!(one.is_trusted);
    assert_eq!(vec!["ok".to_string()], one.reasons);

    let denied = TrustDecision::denied(vec!["no".to_string()]);
    assert!(!denied.is_trusted);
    assert_eq!(vec!["no".to_string()], denied.reasons);
}

#[test]
fn trust_evaluation_options_defaults() {
    let opts = TrustEvaluationOptions::default();
    assert!(opts.overall_timeout.is_none());
    assert!(opts.per_fact_timeout.is_none());
    assert!(opts.per_producer_timeout.is_none());
    assert!(!opts.bypass_trust);

    assert_eq!(CoseHeaderLocation::Protected, CoseHeaderLocation::default());
}
