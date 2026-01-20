// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation::fluent::CoseSign1;
use cose_sign1_validation_azure_key_vault::facts::{
    AzureKeyVaultKidAllowedFact, AzureKeyVaultKidDetectedFact,
};
use cose_sign1_validation_azure_key_vault::pack::{
    AzureKeyVaultTrustOptions, AzureKeyVaultTrustPack, KID_HEADER_LABEL,
};
use cose_sign1_validation_trust::facts::{TrustFactEngine, TrustFactProducer, TrustFactSet};
use cose_sign1_validation_trust::subject::TrustSubject;
use std::sync::Arc;
use tinycbor::{Encode, Encoder};

fn build_cose_sign1_with_kid(kid_utf8: Option<&str>) -> Vec<u8> {
    let mut buf = vec![0u8; 2048];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    enc.array(4).unwrap();

    // protected header: bstr(CBOR map {1: -7, 4: kid?})
    let mut hdr_buf = vec![0u8; 256];
    let hdr_len = hdr_buf.len();
    let mut hdr_enc = Encoder(hdr_buf.as_mut_slice());

    let map_len = if kid_utf8.is_some() { 2 } else { 1 };
    hdr_enc.map(map_len).unwrap();
    (1i64).encode(&mut hdr_enc).unwrap();
    (-7i64).encode(&mut hdr_enc).unwrap();

    if let Some(k) = kid_utf8 {
        KID_HEADER_LABEL.encode(&mut hdr_enc).unwrap();
        k.as_bytes().encode(&mut hdr_enc).unwrap();
    }

    let used_hdr = hdr_len - hdr_enc.0.len();
    let protected_bytes = &hdr_buf[..used_hdr];
    protected_bytes.encode(&mut enc).unwrap();

    // unprotected header: empty map
    enc.map(0).unwrap();

    // payload + signature
    b"payload".as_slice().encode(&mut enc).unwrap();
    b"sig".as_slice().encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

fn build_cose_sign1_with_unprotected_kid(kid_utf8: Option<&str>) -> Vec<u8> {
    let mut buf = vec![0u8; 2048];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    enc.array(4).unwrap();

    // protected header: bstr(CBOR map {1: -7})
    let mut hdr_buf = vec![0u8; 64];
    let hdr_len = hdr_buf.len();
    let mut hdr_enc = Encoder(hdr_buf.as_mut_slice());
    hdr_enc.map(1).unwrap();
    (1i64).encode(&mut hdr_enc).unwrap();
    (-7i64).encode(&mut hdr_enc).unwrap();
    let used_hdr = hdr_len - hdr_enc.0.len();
    let protected_bytes = &hdr_buf[..used_hdr];
    protected_bytes.encode(&mut enc).unwrap();

    // unprotected header map
    match kid_utf8 {
        None => enc.map(0).unwrap(),
        Some(k) => {
            enc.map(1).unwrap();
            KID_HEADER_LABEL.encode(&mut enc).unwrap();
            k.as_bytes().encode(&mut enc).unwrap();
        }
    }

    // payload + signature
    b"payload".as_slice().encode(&mut enc).unwrap();
    b"sig".as_slice().encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

fn build_cose_sign1_with_raw_kid(
    protected_kid: Option<&[u8]>,
    unprotected_kid: Option<&[u8]>,
) -> Vec<u8> {
    let mut buf = vec![0u8; 2048];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    enc.array(4).unwrap();

    // protected header: bstr(CBOR map {1: -7, 4: kid?})
    let mut hdr_buf = vec![0u8; 256];
    let hdr_len = hdr_buf.len();
    let mut hdr_enc = Encoder(hdr_buf.as_mut_slice());

    let map_len = if protected_kid.is_some() { 2 } else { 1 };
    hdr_enc.map(map_len).unwrap();
    (1i64).encode(&mut hdr_enc).unwrap();
    (-7i64).encode(&mut hdr_enc).unwrap();

    if let Some(k) = protected_kid {
        KID_HEADER_LABEL.encode(&mut hdr_enc).unwrap();
        k.encode(&mut hdr_enc).unwrap();
    }

    let used_hdr = hdr_len - hdr_enc.0.len();
    let protected_bytes = &hdr_buf[..used_hdr];
    protected_bytes.encode(&mut enc).unwrap();

    // unprotected header map
    match unprotected_kid {
        None => enc.map(0).unwrap(),
        Some(k) => {
            enc.map(1).unwrap();
            KID_HEADER_LABEL.encode(&mut enc).unwrap();
            k.encode(&mut enc).unwrap();
        }
    }

    // payload + signature
    b"payload".as_slice().encode(&mut enc).unwrap();
    b"sig".as_slice().encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

fn build_cose_sign1_with_text_kid_in_protected_and_bytes_in_unprotected(
    protected_kid_text: &str,
    unprotected_kid_bytes: &[u8],
) -> Vec<u8> {
    let mut buf = vec![0u8; 2048];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    enc.array(4).unwrap();

    // protected header: bstr(CBOR map {1: -7, 4: kid(text)})
    let mut hdr_buf = vec![0u8; 256];
    let hdr_len = hdr_buf.len();
    let mut hdr_enc = Encoder(hdr_buf.as_mut_slice());

    hdr_enc.map(2).unwrap();
    (1i64).encode(&mut hdr_enc).unwrap();
    (-7i64).encode(&mut hdr_enc).unwrap();

    KID_HEADER_LABEL.encode(&mut hdr_enc).unwrap();
    protected_kid_text.encode(&mut hdr_enc).unwrap();

    let used_hdr = hdr_len - hdr_enc.0.len();
    let protected_bytes = &hdr_buf[..used_hdr];
    protected_bytes.encode(&mut enc).unwrap();

    // unprotected header: map {4: kid(bstr)}
    enc.map(1).unwrap();
    KID_HEADER_LABEL.encode(&mut enc).unwrap();
    unprotected_kid_bytes.encode(&mut enc).unwrap();

    // payload + signature
    b"payload".as_slice().encode(&mut enc).unwrap();
    b"sig".as_slice().encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

fn build_cose_sign1_with_text_kid_in_unprotected_only(kid_text: &str) -> Vec<u8> {
    let mut buf = vec![0u8; 2048];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    enc.array(4).unwrap();

    // protected header: bstr(CBOR map {1: -7})
    let mut hdr_buf = vec![0u8; 64];
    let hdr_len = hdr_buf.len();
    let mut hdr_enc = Encoder(hdr_buf.as_mut_slice());
    hdr_enc.map(1).unwrap();
    (1i64).encode(&mut hdr_enc).unwrap();
    (-7i64).encode(&mut hdr_enc).unwrap();
    let used_hdr = hdr_len - hdr_enc.0.len();
    let protected_bytes = &hdr_buf[..used_hdr];
    protected_bytes.encode(&mut enc).unwrap();

    // unprotected header: map {4: kid(text)}
    enc.map(1).unwrap();
    KID_HEADER_LABEL.encode(&mut enc).unwrap();
    kid_text.encode(&mut enc).unwrap();

    // payload + signature
    b"payload".as_slice().encode(&mut enc).unwrap();
    b"sig".as_slice().encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

#[test]
fn akv_pack_missing_when_no_kid() {
    let cose = build_cose_sign1_with_kid(None);
    let msg = CoseSign1::from_cbor(&cose).unwrap();
    let parsed = cose_sign1_validation_trust::CoseSign1ParsedMessage::from_parts(
        msg.protected_header,
        msg.unprotected_header.as_ref(),
        msg.payload,
        msg.signature,
    )
    .unwrap();

    let pack = Arc::new(AzureKeyVaultTrustPack::new(AzureKeyVaultTrustOptions {
        allowed_kid_patterns: vec!["https://*.vault.azure.net/keys/*".to_string()],
        require_azure_key_vault_kid: true,
    }));

    let engine = TrustFactEngine::new(vec![pack])
        .with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let subject = TrustSubject::message(b"seed");

    let detected = engine
        .get_fact_set::<AzureKeyVaultKidDetectedFact>(&subject)
        .unwrap();
    assert!(matches!(detected, TrustFactSet::Missing { .. }));

    let allowed = engine
        .get_fact_set::<AzureKeyVaultKidAllowedFact>(&subject)
        .unwrap();
    assert!(matches!(allowed, TrustFactSet::Missing { .. }));
}

#[test]
fn akv_pack_detects_and_allows_matching_kid() {
    let kid = "https://myvault.vault.azure.net/keys/mykey";
    let cose = build_cose_sign1_with_kid(Some(kid));
    let msg = CoseSign1::from_cbor(&cose).unwrap();
    let parsed = cose_sign1_validation_trust::CoseSign1ParsedMessage::from_parts(
        msg.protected_header,
        msg.unprotected_header.as_ref(),
        msg.payload,
        msg.signature,
    )
    .unwrap();

    let pack = Arc::new(AzureKeyVaultTrustPack::new(AzureKeyVaultTrustOptions {
        allowed_kid_patterns: vec!["https://*.vault.azure.net/keys/*".to_string()],
        require_azure_key_vault_kid: true,
    }));

    let engine = TrustFactEngine::new(vec![pack])
        .with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let subject = TrustSubject::message(b"seed");

    let detected = engine
        .get_facts::<AzureKeyVaultKidDetectedFact>(&subject)
        .unwrap();
    assert_eq!(1, detected.len());
    assert!(detected[0].is_azure_key_vault_key);

    let allowed = engine
        .get_facts::<AzureKeyVaultKidAllowedFact>(&subject)
        .unwrap();
    assert_eq!(1, allowed.len());
    assert!(allowed[0].is_allowed);
}

#[test]
fn akv_pack_is_noop_for_non_message_subjects() {
    let kid = "https://myvault.vault.azure.net/keys/mykey";
    let cose = build_cose_sign1_with_kid(Some(kid));
    let msg = CoseSign1::from_cbor(&cose).unwrap();
    let parsed = cose_sign1_validation_trust::CoseSign1ParsedMessage::from_parts(
        msg.protected_header,
        msg.unprotected_header.as_ref(),
        msg.payload,
        msg.signature,
    )
    .unwrap();

    let pack = Arc::new(AzureKeyVaultTrustPack::new(AzureKeyVaultTrustOptions {
        allowed_kid_patterns: vec!["https://*.vault.azure.net/keys/*".to_string()],
        require_azure_key_vault_kid: true,
    }));

    let engine = TrustFactEngine::new(vec![pack])
        .with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let subject = TrustSubject::root("NotMessage", b"seed");
    let detected = engine
        .get_fact_set::<AzureKeyVaultKidDetectedFact>(&subject)
        .unwrap();
    match detected {
        TrustFactSet::Available(v) => assert!(v.is_empty()),
        other => panic!("expected Available(empty), got {other:?}"),
    }
}

#[test]
fn akv_pack_marks_missing_when_message_is_unavailable() {
    let pack = Arc::new(AzureKeyVaultTrustPack::new(AzureKeyVaultTrustOptions {
        allowed_kid_patterns: vec!["https://*.vault.azure.net/keys/*".to_string()],
        require_azure_key_vault_kid: true,
    }));
    let engine = TrustFactEngine::new(vec![pack]);
    let subject = TrustSubject::message(b"seed");

    let detected = engine
        .get_fact_set::<AzureKeyVaultKidDetectedFact>(&subject)
        .unwrap();
    assert!(matches!(detected, TrustFactSet::Missing { .. }));
}

#[test]
fn akv_pack_reads_kid_from_unprotected_header() {
    let kid = "https://myvault.vault.azure.net/keys/mykey";
    let cose = build_cose_sign1_with_unprotected_kid(Some(kid));
    let msg = CoseSign1::from_cbor(&cose).unwrap();
    let parsed = cose_sign1_validation_trust::CoseSign1ParsedMessage::from_parts(
        msg.protected_header,
        msg.unprotected_header.as_ref(),
        msg.payload,
        msg.signature,
    )
    .unwrap();

    let pack = Arc::new(AzureKeyVaultTrustPack::new(AzureKeyVaultTrustOptions {
        allowed_kid_patterns: vec!["https://*.vault.azure.net/keys/*".to_string()],
        require_azure_key_vault_kid: true,
    }));

    let engine = TrustFactEngine::new(vec![pack])
        .with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let subject = TrustSubject::message(b"seed");
    let detected = engine
        .get_facts::<AzureKeyVaultKidDetectedFact>(&subject)
        .unwrap();
    assert_eq!(1, detected.len());
    assert!(detected[0].is_azure_key_vault_key);
}

#[test]
fn akv_pack_prefers_protected_kid_over_unprotected() {
    let protected_kid = "https://myvault.vault.azure.net/keys/protected";
    let unprotected_kid = "https://example.com/keys/not-akv";

    let cose = build_cose_sign1_with_raw_kid(
        Some(protected_kid.as_bytes()),
        Some(unprotected_kid.as_bytes()),
    );
    let msg = CoseSign1::from_cbor(&cose).unwrap();
    let parsed = cose_sign1_validation_trust::CoseSign1ParsedMessage::from_parts(
        msg.protected_header,
        msg.unprotected_header.as_ref(),
        msg.payload,
        msg.signature,
    )
    .unwrap();

    let pack = Arc::new(AzureKeyVaultTrustPack::new(AzureKeyVaultTrustOptions {
        allowed_kid_patterns: vec!["https://*.vault.azure.net/keys/*".to_string()],
        require_azure_key_vault_kid: true,
    }));

    let engine = TrustFactEngine::new(vec![pack])
        .with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let subject = TrustSubject::message(b"seed");

    let detected = engine
        .get_facts::<AzureKeyVaultKidDetectedFact>(&subject)
        .unwrap();
    assert_eq!(1, detected.len());
    assert!(detected[0].is_azure_key_vault_key);

    let allowed = engine
        .get_facts::<AzureKeyVaultKidAllowedFact>(&subject)
        .unwrap();
    assert_eq!(1, allowed.len());
    assert!(allowed[0].is_allowed);
}

#[test]
fn akv_pack_treats_invalid_utf8_kid_as_missing() {
    let cose = build_cose_sign1_with_raw_kid(Some(&[0xff, 0xfe]), None);
    let msg = CoseSign1::from_cbor(&cose).unwrap();
    let parsed = cose_sign1_validation_trust::CoseSign1ParsedMessage::from_parts(
        msg.protected_header,
        msg.unprotected_header.as_ref(),
        msg.payload,
        msg.signature,
    )
    .unwrap();

    let pack = Arc::new(AzureKeyVaultTrustPack::new(AzureKeyVaultTrustOptions {
        allowed_kid_patterns: vec!["https://*.vault.azure.net/keys/*".to_string()],
        require_azure_key_vault_kid: true,
    }));

    let engine = TrustFactEngine::new(vec![pack])
        .with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let subject = TrustSubject::message(b"seed");
    let detected = engine
        .get_fact_set::<AzureKeyVaultKidDetectedFact>(&subject)
        .unwrap();
    assert!(matches!(detected, TrustFactSet::Missing { .. }));
}

#[test]
fn akv_pack_treats_whitespace_only_kid_as_missing() {
    let cose = build_cose_sign1_with_raw_kid(Some(b"   "), None);
    let msg = CoseSign1::from_cbor(&cose).unwrap();
    let parsed = cose_sign1_validation_trust::CoseSign1ParsedMessage::from_parts(
        msg.protected_header,
        msg.unprotected_header.as_ref(),
        msg.payload,
        msg.signature,
    )
    .unwrap();

    let pack = Arc::new(AzureKeyVaultTrustPack::new(AzureKeyVaultTrustOptions {
        allowed_kid_patterns: vec!["https://*.vault.azure.net/keys/*".to_string()],
        require_azure_key_vault_kid: true,
    }));

    let engine = TrustFactEngine::new(vec![pack])
        .with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let subject = TrustSubject::message(b"seed");
    let detected = engine
        .get_fact_set::<AzureKeyVaultKidDetectedFact>(&subject)
        .unwrap();
    assert!(matches!(detected, TrustFactSet::Missing { .. }));
}

#[test]
fn akv_pack_ignores_text_kid_in_protected_and_falls_back_to_unprotected_bytes() {
    let protected_text = "https://myvault.vault.azure.net/keys/should_be_ignored";
    let unprotected = "https://myvault.vault.azure.net/keys/mykey";
    let cose = build_cose_sign1_with_text_kid_in_protected_and_bytes_in_unprotected(
        protected_text,
        unprotected.as_bytes(),
    );
    let msg = CoseSign1::from_cbor(&cose).unwrap();
    let parsed = cose_sign1_validation_trust::CoseSign1ParsedMessage::from_parts(
        msg.protected_header,
        msg.unprotected_header.as_ref(),
        msg.payload,
        msg.signature,
    )
    .unwrap();

    let pack = Arc::new(AzureKeyVaultTrustPack::new(AzureKeyVaultTrustOptions {
        allowed_kid_patterns: vec!["https://*.vault.azure.net/keys/*".to_string()],
        require_azure_key_vault_kid: true,
    }));

    let engine = TrustFactEngine::new(vec![pack])
        .with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let subject = TrustSubject::message(b"seed");
    let allowed = engine.get_facts::<AzureKeyVaultKidAllowedFact>(&subject).unwrap();
    assert_eq!(1, allowed.len());
    assert!(allowed[0].is_allowed);
}

#[test]
fn akv_pack_treats_text_kid_in_unprotected_as_missing() {
    let cose = build_cose_sign1_with_text_kid_in_unprotected_only(
        "https://myvault.vault.azure.net/keys/mykey",
    );
    let msg = CoseSign1::from_cbor(&cose).unwrap();
    let parsed = cose_sign1_validation_trust::CoseSign1ParsedMessage::from_parts(
        msg.protected_header,
        msg.unprotected_header.as_ref(),
        msg.payload,
        msg.signature,
    )
    .unwrap();

    let pack = Arc::new(AzureKeyVaultTrustPack::new(AzureKeyVaultTrustOptions {
        allowed_kid_patterns: vec!["https://*.vault.azure.net/keys/*".to_string()],
        require_azure_key_vault_kid: true,
    }));

    let engine = TrustFactEngine::new(vec![pack])
        .with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let subject = TrustSubject::message(b"seed");
    let detected = engine
        .get_fact_set::<AzureKeyVaultKidDetectedFact>(&subject)
        .unwrap();
    assert!(matches!(detected, TrustFactSet::Missing { .. }));
}

#[test]
fn akv_pack_detects_managedhsm_kid_and_allows_when_pattern_matches() {
    let kid = "https://myhsm.managedhsm.azure.net/keys/mykey";
    let cose = build_cose_sign1_with_kid(Some(kid));
    let msg = CoseSign1::from_cbor(&cose).unwrap();
    let parsed = cose_sign1_validation_trust::CoseSign1ParsedMessage::from_parts(
        msg.protected_header,
        msg.unprotected_header.as_ref(),
        msg.payload,
        msg.signature,
    )
    .unwrap();

    let pack = Arc::new(AzureKeyVaultTrustPack::new(AzureKeyVaultTrustOptions {
        allowed_kid_patterns: vec!["https://*.managedhsm.azure.net/keys/*".to_string()],
        require_azure_key_vault_kid: true,
    }));

    let engine = TrustFactEngine::new(vec![pack])
        .with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let subject = TrustSubject::message(b"seed");

    let detected = engine
        .get_facts::<AzureKeyVaultKidDetectedFact>(&subject)
        .unwrap();
    assert_eq!(1, detected.len());
    assert!(detected[0].is_azure_key_vault_key);

    let allowed = engine
        .get_facts::<AzureKeyVaultKidAllowedFact>(&subject)
        .unwrap();
    assert_eq!(1, allowed.len());
    assert!(allowed[0].is_allowed);
}

#[test]
fn akv_pack_denies_non_akv_kid_when_required() {
    let kid = "https://example.com/keys/not-akv";
    let cose = build_cose_sign1_with_kid(Some(kid));
    let msg = CoseSign1::from_cbor(&cose).unwrap();
    let parsed = cose_sign1_validation_trust::CoseSign1ParsedMessage::from_parts(
        msg.protected_header,
        msg.unprotected_header.as_ref(),
        msg.payload,
        msg.signature,
    )
    .unwrap();

    let pack = Arc::new(AzureKeyVaultTrustPack::new(AzureKeyVaultTrustOptions {
        allowed_kid_patterns: vec!["https://*.vault.azure.net/keys/*".to_string()],
        require_azure_key_vault_kid: true,
    }));

    let engine = TrustFactEngine::new(vec![pack])
        .with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let subject = TrustSubject::message(b"seed");
    let allowed = engine
        .get_facts::<AzureKeyVaultKidAllowedFact>(&subject)
        .unwrap();
    assert_eq!(1, allowed.len());
    assert!(!allowed[0].is_allowed);
    assert_eq!(Some("NoPatternMatch".to_string()), allowed[0].details);
}

#[test]
fn akv_pack_denies_when_no_allowed_patterns_configured() {
    let kid = "https://myvault.vault.azure.net/keys/mykey";
    let cose = build_cose_sign1_with_kid(Some(kid));
    let msg = CoseSign1::from_cbor(&cose).unwrap();
    let parsed = cose_sign1_validation_trust::CoseSign1ParsedMessage::from_parts(
        msg.protected_header,
        msg.unprotected_header.as_ref(),
        msg.payload,
        msg.signature,
    )
    .unwrap();

    let pack = Arc::new(AzureKeyVaultTrustPack::new(AzureKeyVaultTrustOptions {
        // empty/whitespace patterns are ignored
        allowed_kid_patterns: vec!["  ".to_string()],
        require_azure_key_vault_kid: false,
    }));

    let engine = TrustFactEngine::new(vec![pack])
        .with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let subject = TrustSubject::message(b"seed");
    let allowed = engine
        .get_facts::<AzureKeyVaultKidAllowedFact>(&subject)
        .unwrap();
    assert_eq!(1, allowed.len());
    assert!(!allowed[0].is_allowed);
    assert_eq!(Some("NoAllowedPatterns".to_string()), allowed[0].details);
}

#[test]
fn akv_pack_supports_regex_prefix_patterns() {
    let kid = "https://myvault.vault.azure.net/keys/mykey";
    let cose = build_cose_sign1_with_kid(Some(kid));
    let msg = CoseSign1::from_cbor(&cose).unwrap();
    let parsed = cose_sign1_validation_trust::CoseSign1ParsedMessage::from_parts(
        msg.protected_header,
        msg.unprotected_header.as_ref(),
        msg.payload,
        msg.signature,
    )
    .unwrap();

    let pack = Arc::new(AzureKeyVaultTrustPack::new(AzureKeyVaultTrustOptions {
        allowed_kid_patterns: vec!["regex:https://.*\\.vault\\.azure\\.net/keys/.*".to_string()],
        require_azure_key_vault_kid: false,
    }));

    let engine = TrustFactEngine::new(vec![pack])
        .with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let subject = TrustSubject::message(b"seed");
    let allowed = engine
        .get_facts::<AzureKeyVaultKidAllowedFact>(&subject)
        .unwrap();
    assert_eq!(1, allowed.len());
    assert!(allowed[0].is_allowed);
}

#[test]
fn akv_pack_ignores_invalid_regex_patterns_and_treats_as_no_allowed_patterns() {
    let kid = "https://myvault.vault.azure.net/keys/mykey";
    let cose = build_cose_sign1_with_kid(Some(kid));
    let msg = CoseSign1::from_cbor(&cose).unwrap();
    let parsed = cose_sign1_validation_trust::CoseSign1ParsedMessage::from_parts(
        msg.protected_header,
        msg.unprotected_header.as_ref(),
        msg.payload,
        msg.signature,
    )
    .unwrap();

    // Invalid regex should be ignored; leaving no compiled patterns.
    let pack = Arc::new(AzureKeyVaultTrustPack::new(AzureKeyVaultTrustOptions {
        allowed_kid_patterns: vec!["regex:[".to_string()],
        require_azure_key_vault_kid: false,
    }));

    let engine = TrustFactEngine::new(vec![pack])
        .with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let subject = TrustSubject::message(b"seed");
    let allowed = engine
        .get_facts::<AzureKeyVaultKidAllowedFact>(&subject)
        .unwrap();
    assert_eq!(1, allowed.len());
    assert!(!allowed[0].is_allowed);
    assert_eq!(Some("NoAllowedPatterns".to_string()), allowed[0].details);
}

#[test]
fn akv_pack_treats_non_url_kid_as_not_akv() {
    let kid = "not a url";
    let cose = build_cose_sign1_with_kid(Some(kid));
    let msg = CoseSign1::from_cbor(&cose).unwrap();
    let parsed = cose_sign1_validation_trust::CoseSign1ParsedMessage::from_parts(
        msg.protected_header,
        msg.unprotected_header.as_ref(),
        msg.payload,
        msg.signature,
    )
    .unwrap();

    let pack = Arc::new(AzureKeyVaultTrustPack::new(AzureKeyVaultTrustOptions {
        allowed_kid_patterns: vec!["*".to_string()],
        require_azure_key_vault_kid: true,
    }));

    let engine = TrustFactEngine::new(vec![pack])
        .with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let subject = TrustSubject::message(b"seed");
    let detected = engine
        .get_facts::<AzureKeyVaultKidDetectedFact>(&subject)
        .unwrap();
    assert_eq!(1, detected.len());
    assert!(!detected[0].is_azure_key_vault_key);

    let allowed = engine
        .get_facts::<AzureKeyVaultKidAllowedFact>(&subject)
        .unwrap();
    assert_eq!(1, allowed.len());
    assert!(!allowed[0].is_allowed);
    assert_eq!(Some("NoPatternMatch".to_string()), allowed[0].details);
}

#[test]
fn akv_pack_handles_urls_without_host_as_not_akv() {
    let kid = "https:///keys/mykey";
    let cose = build_cose_sign1_with_kid(Some(kid));
    let msg = CoseSign1::from_cbor(&cose).unwrap();
    let parsed = cose_sign1_validation_trust::CoseSign1ParsedMessage::from_parts(
        msg.protected_header,
        msg.unprotected_header.as_ref(),
        msg.payload,
        msg.signature,
    )
    .unwrap();

    let pack = Arc::new(AzureKeyVaultTrustPack::new(AzureKeyVaultTrustOptions {
        allowed_kid_patterns: vec!["https://*.vault.azure.net/keys/*".to_string()],
        require_azure_key_vault_kid: false,
    }));

    let engine = TrustFactEngine::new(vec![pack])
        .with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let subject = TrustSubject::message(b"seed");
    let detected = engine
        .get_facts::<AzureKeyVaultKidDetectedFact>(&subject)
        .unwrap();
    assert_eq!(1, detected.len());
    assert!(!detected[0].is_azure_key_vault_key);
}

#[test]
fn akv_pack_supports_question_mark_wildcard_patterns() {
    let kid = "https://abcvault.vault.azure.net/keys/aa";
    let cose = build_cose_sign1_with_kid(Some(kid));
    let msg = CoseSign1::from_cbor(&cose).unwrap();
    let parsed = cose_sign1_validation_trust::CoseSign1ParsedMessage::from_parts(
        msg.protected_header,
        msg.unprotected_header.as_ref(),
        msg.payload,
        msg.signature,
    )
    .unwrap();

    let pack = Arc::new(AzureKeyVaultTrustPack::new(AzureKeyVaultTrustOptions {
        allowed_kid_patterns: vec!["https://*vault.vault.azure.net/keys/??".to_string()],
        require_azure_key_vault_kid: false,
    }));

    let engine = TrustFactEngine::new(vec![pack])
        .with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let subject = TrustSubject::message(b"seed");
    let allowed = engine
        .get_facts::<AzureKeyVaultKidAllowedFact>(&subject)
        .unwrap();
    assert_eq!(1, allowed.len());
    assert!(allowed[0].is_allowed);
}

#[test]
fn akv_pack_provides_reports_expected_fact_keys() {
    let pack = AzureKeyVaultTrustPack::new(AzureKeyVaultTrustOptions::default());
    let provided = pack.provides();
    assert_eq!(2, provided.len());
}
