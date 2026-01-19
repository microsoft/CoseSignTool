// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation::fluent::*;
use cose_sign1_validation_azure_key_vault::fluent_ext::AzureKeyVaultMessageScopeRulesExt;
use cose_sign1_validation_azure_key_vault::pack::{
    AzureKeyVaultTrustOptions, AzureKeyVaultTrustPack, KID_HEADER_LABEL,
};
use cose_sign1_validation_certificates::facts::{
    X509ChainElementValidityFact, X509ChainTrustedFact, X509SigningCertificateIdentityFact,
};
use cose_sign1_validation_certificates::pack::fluent_ext::{
    PrimarySigningKeyScopeRulesExt,
    X509ChainElementValidityWhereExt,
    X509SigningCertificateIdentityWhereExt,
};
use cose_sign1_validation::fluent::MessageScopeRulesExt;
use cose_sign1_validation_certificates::pack::{CertificateTrustOptions, X509CertificateTrustPack};
use cose_sign1_validation_transparent_mst::fluent_ext::MstCounterSignatureScopeRulesExt;
use cose_sign1_validation_transparent_mst::pack::MstTrustPack;
use cose_sign1_validation_trust::CoseHeaderLocation;
use cose_sign1_validation_trust::facts::{TrustFactEngine, TrustFactSet};
use cose_sign1_validation_trust::subject::TrustSubject;
use cose_sign1_validation_trust::TrustEvaluationOptions;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tinycbor::{Encode, Encoder};
use x509_parser::parse_x509_certificate;

fn v1_testdata_path(file_name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join("v1")
        .join(file_name)
}

fn v1_scitt_testdata_path(file_name: &str) -> PathBuf {
    // Prefer local testdata if present, else fall back to the certificates crate test vectors.
    let local = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join("v1")
        .join(file_name);
    if local.exists() {
        return local;
    }

    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("cose_sign1_validation_certificates")
        .join("testdata")
        .join("v1")
        .join(file_name)
}

fn encode_cbor_value_bytes<T: Encode>(value: T) -> Vec<u8> {
    // tinycbor encoder needs a writable buffer; we allocate a generous slice and then truncate.
    let mut buf = vec![0u8; 1024];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());
    value.encode(&mut enc).expect("encode failed");
    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

const X5CHAIN_HEADER_LABEL: i64 = 33;

fn leaf_and_issuer_subjects_from_embedded_x5chain(
    cose_bytes: &[u8],
    loc: CoseHeaderLocation,
) -> (String, String) {
    fn try_read_x5chain(map_bytes: &[u8]) -> Result<Option<Vec<Vec<u8>>>, String> {
        let mut d = tinycbor::Decoder(map_bytes);
        let mut map = d
            .map_visitor()
            .map_err(|e| format!("header_map_decode_failed: {e}"))?;

        while let Some(entry) = map.visit::<i64, tinycbor::Any>() {
            let (key, value_any) = entry.map_err(|e| format!("map_entry_decode_failed: {e}"))?;
            if key != X5CHAIN_HEADER_LABEL {
                continue;
            }

            // x5chain can be a single bstr or an array of bstr.
            let mut vd = tinycbor::Decoder(value_any.as_ref());

            // Single cert as bstr.
            if let Ok(it) = vd.bytes_iter() {
                let mut one = Vec::new();
                for part in it {
                    let part = part.map_err(|e| format!("x5chain_bytes_iter_failed: {e}"))?;
                    one.extend_from_slice(part);
                }
                return Ok(Some(vec![one]));
            }

            // Array of bstr.
            let mut arr = vd
                .array_visitor()
                .map_err(|e| format!("x5chain_array_decode_failed: {e}"))?;

            let mut certs = Vec::new();
            while let Some(item) = arr.visit::<&[u8]>() {
                let b = item.map_err(|e| format!("x5chain_item_decode_failed: {e}"))?;
                certs.push(b.to_vec());
            }

            return Ok(Some(certs));
        }

        Ok(None)
    }

    let msg = CoseSign1::from_cbor(cose_bytes).expect("expected valid COSE_Sign1");

    let protected_map_bytes = msg.protected_header;
    let unprotected_map_bytes = msg.unprotected_header.as_ref();

    let chain = match loc {
        CoseHeaderLocation::Protected => try_read_x5chain(protected_map_bytes)
            .expect("x5chain parse failed")
            .expect("x5chain not found in protected header"),
        CoseHeaderLocation::Any => {
            if let Some(v) =
                try_read_x5chain(protected_map_bytes).expect("x5chain parse failed")
            {
                v
            } else if let Some(v) =
                try_read_x5chain(unprotected_map_bytes).expect("x5chain parse failed")
            {
                v
            } else {
                panic!("x5chain not found in protected or unprotected header")
            }
        }
    };

    let leaf_der = chain
        .first()
        .expect("expected leaf cert at x5chain index 0")
        .as_slice();
    let issuer_der = chain
        .get(1)
        .expect("expected issuer cert at x5chain index 1")
        .as_slice();

    let (_rem, leaf) = parse_x509_certificate(leaf_der).expect("leaf x509 parse failed");
    let (_rem, issuer) = parse_x509_certificate(issuer_der).expect("issuer x509 parse failed");

    (leaf.subject().to_string(), issuer.subject().to_string())
}

#[test]
fn trust_plan_compile_fails_when_required_pack_missing() {
    let plan = TrustPlanBuilder::new(vec![]).for_primary_signing_key(|key| {
        // This fact type is only available when the X.509 certificates trust pack is included.
        key.require::<X509ChainTrustedFact>(|w| w)
    });

    let err = plan
        .compile()
        .err()
        .expect("expected compile() to fail due to missing trust packs");
    match err {
        TrustPlanCompileError::MissingRequiredTrustPacks { missing } => {
            assert!(missing.contains("X509ChainTrustedFact"));
        }
    }
}

#[test]
fn trust_plan_compile_succeeds_when_required_pack_present() {
    let cert_pack: Arc<dyn CoseSign1TrustPack> = Arc::new(X509CertificateTrustPack::default());
    let trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![cert_pack];

    TrustPlanBuilder::new(trust_packs)
        .for_primary_signing_key(|key| key.require::<X509ChainTrustedFact>(|w| w))
        .compile()
        .expect("expected required facts to be provided by the included trust packs");
}

fn encoder_write_raw(enc: &mut Encoder<&mut [u8]>, raw: &[u8]) -> Result<(), String> {
    if enc.0.len() < raw.len() {
        return Err("encode buffer too small".to_string());
    }
    let remaining = std::mem::take(&mut enc.0);
    let (head, tail) = remaining.split_at_mut(raw.len());
    head.copy_from_slice(raw);
    enc.0 = tail;
    Ok(())
}


fn insert_kid_into_unprotected_map(unprotected_map_bytes: &[u8], kid_utf8: &str) -> Vec<u8> {
    let mut d = tinycbor::Decoder(unprotected_map_bytes);
    let mut map = d.map_visitor().expect("unprotected header must be a map");

    let mut entries: BTreeMap<i64, Vec<u8>> = BTreeMap::new();
    while let Some(entry) = map.visit::<i64, tinycbor::Any<'_>>() {
        let (key, value_any) = entry.expect("map entry decode failed");
        if key == KID_HEADER_LABEL {
            continue;
        }
        entries.insert(key, value_any.as_ref().to_vec());
    }

    // kid header is a bstr.
    let kid_value_bytes = encode_cbor_value_bytes(kid_utf8.as_bytes().to_vec());
    entries.insert(KID_HEADER_LABEL, kid_value_bytes);

    // Encode a new map with the combined entries.
    let mut buf = vec![0u8; unprotected_map_bytes.len() + kid_utf8.len() + 256];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());
    enc.map(entries.len()).expect("map encode failed");

    for (k, v_bytes) in entries {
        k.encode(&mut enc).expect("key encode failed");
        encoder_write_raw(&mut enc, &v_bytes).expect("value raw write failed");
    }

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

const CONTENT_TYPE_HEADER_LABEL: i64 = 3;

fn insert_content_type_into_unprotected_map(
    unprotected_map_bytes: &[u8],
    content_type: &str,
) -> Vec<u8> {
    let mut d = tinycbor::Decoder(unprotected_map_bytes);
    let mut map = d.map_visitor().expect("unprotected header must be a map");

    let mut entries: BTreeMap<i64, Vec<u8>> = BTreeMap::new();
    while let Some(entry) = map.visit::<i64, tinycbor::Any<'_>>() {
        let (key, value_any) = entry.expect("map entry decode failed");
        if key == CONTENT_TYPE_HEADER_LABEL {
            continue;
        }
        entries.insert(key, value_any.as_ref().to_vec());
    }

    // content-type header can be a tstr; use a string for clarity.
    let content_type_value_bytes = encode_cbor_value_bytes(content_type.to_string());
    entries.insert(CONTENT_TYPE_HEADER_LABEL, content_type_value_bytes);

    // Encode a new map with the combined entries.
    let mut buf = vec![0u8; unprotected_map_bytes.len() + content_type.len() + 256];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());
    enc.map(entries.len()).expect("map encode failed");

    for (k, v_bytes) in entries {
        k.encode(&mut enc).expect("key encode failed");
        encoder_write_raw(&mut enc, &v_bytes).expect("value raw write failed");
    }

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

fn with_kid(cose_bytes: &[u8], kid_utf8: &str) -> Vec<u8> {
    let msg = CoseSign1::from_cbor(cose_bytes).expect("expected valid COSE_Sign1");
    let new_unprotected =
        insert_kid_into_unprotected_map(msg.unprotected_header.as_ref(), kid_utf8);

    // Re-encode COSE_Sign1 array without tag(18). Decoder accepts both.
    let mut buf = vec![0u8; cose_bytes.len() + kid_utf8.len() + 512];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());
    enc.array(4).expect("array encode failed");

    // protected: bstr
    msg.protected_header
        .encode(&mut enc)
        .expect("protected encode failed");
    // unprotected: map (already CBOR)
    encoder_write_raw(&mut enc, &new_unprotected).expect("unprotected raw write failed");

    // payload: bstr / nil
    match msg.payload {
        Some(p) => p.encode(&mut enc).expect("payload encode failed"),
        None => encoder_write_raw(&mut enc, &[0xF6]).expect("nil write failed"),
    }

    // signature: bstr
    msg.signature
        .encode(&mut enc)
        .expect("signature encode failed");

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

fn with_content_type_and_detached_payload(cose_bytes: &[u8], content_type: &str) -> Vec<u8> {
    let msg = CoseSign1::from_cbor(cose_bytes).expect("expected valid COSE_Sign1");
    let new_unprotected =
        insert_content_type_into_unprotected_map(msg.unprotected_header.as_ref(), content_type);

    // Re-encode COSE_Sign1 array without tag(18). Decoder accepts both.
    // Force payload to nil to demonstrate detached-payload style requirements.
    let mut buf = vec![0u8; cose_bytes.len() + content_type.len() + 512];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());
    enc.array(4).expect("array encode failed");

    // protected: bstr
    msg.protected_header
        .encode(&mut enc)
        .expect("protected encode failed");
    // unprotected: map (already CBOR)
    encoder_write_raw(&mut enc, &new_unprotected).expect("unprotected raw write failed");

    // payload: nil
    encoder_write_raw(&mut enc, &[0xF6]).expect("nil write failed");

    // signature: bstr
    msg.signature
        .encode(&mut enc)
        .expect("signature encode failed");

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

#[test]
fn real_v1_policy_can_gate_on_certificate_facts() {
    let cose_bytes = fs::read(v1_testdata_path("UnitTestSignatureWithCRL.cose")).unwrap();
    let payload_bytes = fs::read(v1_testdata_path("UnitTestPayload.json")).unwrap();

    let cert_pack = Arc::new(X509CertificateTrustPack::new(CertificateTrustOptions {
        identity_pinning_enabled: false,
        ..CertificateTrustOptions::default()
    }));

    let trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![cert_pack];

    // Fluent plan: certificate must be present, and PQC algorithms are denied.
    let bundled_plan = TrustPlanBuilder::new(trust_packs)
        .for_primary_signing_key(|key| {
            key.require_signing_certificate_present()
                .and()
                .require_not_pqc_algorithm_or_missing()
        })
        .compile()
        .expect("plan compile");

    let validator = CoseSign1Validator::new(bundled_plan).with_options(|o| {
        o.detached_payload = Some(DetachedPayload::bytes(Arc::from(
            payload_bytes.into_boxed_slice(),
        )));
        o.certificate_header_location = CoseHeaderLocation::Any;
    });

    let result = validator
        .validate_bytes(Arc::from(cose_bytes.into_boxed_slice()))
        .unwrap();

    assert!(result.resolution.is_valid());
    assert!(result.trust.is_valid(), "trust invalid: {:#?}", result.trust);
    assert_ne!(ValidationResultKind::NotApplicable, result.signature.kind);
}

const MICROSOFT_CCF_JWKS: &str = include_str!(
    "../../cose_sign1_validation_transparent_mst/testdata/esrp-cts-cp.confidential-ledger.azure.com.jwks.json"
);

#[test]
fn real_v1_policy_can_prefer_mst_but_fall_back_to_certificate() {
    let cose_bytes = fs::read(v1_scitt_testdata_path("2ts-statement.scitt")).unwrap();

    // The SCITT statement includes a real MST receipt in the unprotected header.

    let trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![
        Arc::new(MstTrustPack {
            allow_network: false,
            offline_jwks_json: Some(MICROSOFT_CCF_JWKS.to_string()),
            jwks_api_version: None,
        }),
        Arc::new(X509CertificateTrustPack::trust_embedded_chain_as_trusted()),
    ];

    // Fluent plan:
    // (mst_trusted OR cert_chain_trusted) AND NOT(pqc)
    let bundled_plan = TrustPlanBuilder::new(trust_packs)
        .and_group(|p| {
            p.for_counter_signature(|cs| {
                cs.require_mst_receipt_trusted_from_issuer("confidential-ledger.azure.com")
            })
                .or()
                .for_primary_signing_key(|key| key.require_x509_chain_trusted())
        })
        .and()
        .for_primary_signing_key(|key| key.require_not_pqc_algorithm_or_missing())
        .compile()
        .expect("plan compile");

    let validator = CoseSign1Validator::new(bundled_plan).with_options(|o| {
        o.certificate_header_location = CoseHeaderLocation::Any;
    });

    let result = validator
        .validate_bytes(Arc::from(cose_bytes.into_boxed_slice()))
        .unwrap();

    assert!(result.resolution.is_valid());
    assert!(result.trust.is_valid(), "trust invalid: {:#?}", result.trust);
    assert_ne!(ValidationResultKind::NotApplicable, result.signature.kind);
}

#[test]
fn real_v1_policy_can_validate_with_mst_only_by_bypassing_primary_signature() {
    let cose_bytes = fs::read(v1_scitt_testdata_path("2ts-statement.scitt")).unwrap();

    let trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![Arc::new(MstTrustPack {
        allow_network: false,
        offline_jwks_json: Some(MICROSOFT_CCF_JWKS.to_string()),
        jwks_api_version: None,
    })];

    let bundled_plan = TrustPlanBuilder::new(trust_packs)
        .for_counter_signature(|cs| {
            cs.require_mst_receipt_trusted_from_issuer("confidential-ledger.azure.com")
        })
        .compile()
        .expect("plan compile");

    let validator = CoseSign1Validator::new(bundled_plan).with_options(|o| {
        o.certificate_header_location = CoseHeaderLocation::Any;
    });

    let result = validator
        .validate_bytes(Arc::from(cose_bytes.into_boxed_slice()))
        .unwrap();

    assert!(result.overall.is_valid(), "overall invalid: {:#?}", result.overall);
    assert!(result.trust.is_valid(), "trust invalid: {:#?}", result.trust);
    assert!(result.signature.is_valid(), "signature invalid: {:#?}", result.signature);

    assert_eq!(
        Some("BypassedByCounterSignature"),
        result
            .signature
            .metadata
            .get("SignatureVerificationMode")
            .map(|v| v.as_str())
    );
}

#[test]
fn real_v1_policy_can_require_allowed_akv_kid_and_certificate() {
    let cose_bytes = fs::read(v1_testdata_path("UnitTestSignatureWithCRL.cose")).unwrap();
    let payload_bytes = fs::read(v1_testdata_path("UnitTestPayload.json")).unwrap();

    let cose_with_kid = with_kid(
        &cose_bytes,
        "https://example.vault.azure.net/keys/unit-test-key/00000000000000000000000000000000",
    );

    let cert_pack = Arc::new(X509CertificateTrustPack::new(CertificateTrustOptions {
        trust_embedded_chain_as_trusted: true,
        ..CertificateTrustOptions::default()
    }));
    let akv_pack = Arc::new(AzureKeyVaultTrustPack::new(AzureKeyVaultTrustOptions {
        allowed_kid_patterns: vec!["https://example.vault.azure.net/keys/*".to_string()],
        require_azure_key_vault_kid: true,
    }));

    let akv_pack: Arc<dyn CoseSign1TrustPack> = akv_pack;
    let trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![cert_pack, akv_pack];

    let bundled_plan = TrustPlanBuilder::new(trust_packs)
        .for_primary_signing_key(|key| {
            key.require_signing_certificate_present()
                .and()
                .require_not_pqc_algorithm_or_missing()
        })
        .and()
        .for_message(|msg| msg.require_azure_key_vault_kid_allowed())
        .compile()
        .expect("plan compile");

    let validator = CoseSign1Validator::new(bundled_plan).with_options(|o| {
        o.detached_payload = Some(DetachedPayload::bytes(Arc::from(
            payload_bytes.into_boxed_slice(),
        )));
        o.certificate_header_location = CoseHeaderLocation::Any;
    });

    let result = validator
        .validate_bytes(Arc::from(cose_with_kid.into_boxed_slice()))
        .unwrap();

    assert!(result.resolution.is_valid());
    assert!(result.trust.is_valid());
    assert_ne!(ValidationResultKind::NotApplicable, result.signature.kind);
}

#[test]
fn real_v1_policy_can_require_chain_trusted_and_subject_issuer_match() {
    let cose_bytes = fs::read(v1_testdata_path("UnitTestSignatureWithCRL.cose")).unwrap();
    let payload_bytes = fs::read(v1_testdata_path("UnitTestPayload.json")).unwrap();

    let cert_pack = Arc::new(X509CertificateTrustPack::new(CertificateTrustOptions {
        trust_embedded_chain_as_trusted: true,
        ..CertificateTrustOptions::default()
    }));

    let trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![cert_pack];

    // Subject+Issuer pinning policy:
    // - leaf certificate subject must match a pinned subject
    // - issuer certificate subject must match a pinned issuer subject
    //
    // Derive the pinned values from the embedded chain facts so the test doesn't need hard-coded DNs.
    let (leaf_subject, issuer_subject) =
        leaf_and_issuer_subjects_from_embedded_x5chain(&cose_bytes, CoseHeaderLocation::Any);

    let bundled_plan = TrustPlanBuilder::new(trust_packs)
        .for_primary_signing_key(|key| {
            key.require_x509_chain_trusted()
                .and()
                .require_leaf_subject_eq(leaf_subject)
                .and()
                .require_issuer_subject_eq(issuer_subject)
        })
        .compile()
        .expect("plan compile");

    let validator = CoseSign1Validator::new(bundled_plan).with_options(|o| {
        o.detached_payload = Some(DetachedPayload::bytes(Arc::from(
            payload_bytes.into_boxed_slice(),
        )));
        o.certificate_header_location = CoseHeaderLocation::Any;
    });

    let result = validator
        .validate_bytes(Arc::from(cose_bytes.into_boxed_slice()))
        .unwrap();

    assert!(result.resolution.is_valid());
    assert!(result.trust.is_valid());
    assert_ne!(ValidationResultKind::NotApplicable, result.signature.kind);
}

#[test]
fn real_v1_policy_fluent_dsl_example_reads_like_the_csharp_api() {
    let cose_bytes = fs::read(v1_testdata_path("UnitTestSignatureWithCRL.cose")).unwrap();
    let payload_bytes = fs::read(v1_testdata_path("UnitTestPayload.json")).unwrap();

    // Ensure message facts can demonstrate content-type + detached payload requirements.
    let cose_bytes = with_content_type_and_detached_payload(&cose_bytes, "application/json");

    let cert_pack = Arc::new(X509CertificateTrustPack::new(CertificateTrustOptions {
        trust_embedded_chain_as_trusted: true,
        ..CertificateTrustOptions::default()
    }));

    // Roughly analogous to:
    // Rules.Require<X509ChainTrustedFact>(f => f.IsTrusted)
    //   .And()
    //   .Require<X509ChainElementIdentityFact>(f => f.Position == Root && f.Thumbprint == "...")
    //   .Compile(...)
    let trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![cert_pack.clone()];

    let plan = TrustPlanBuilder::new(trust_packs)
        .for_message(|msg| msg.require_content_type_non_empty().and().require_detached_payload_present())
        .and()
        .for_primary_signing_key(|key| {
            key.require_x509_chain_trusted()
                .and()
                .require_leaf_chain_thumbprint_present()
        })
        .compile()
        .expect("plan compile");

    let validator = CoseSign1Validator::new(plan).with_options(|o| {
        o.detached_payload = Some(DetachedPayload::bytes(Arc::from(
            payload_bytes.into_boxed_slice(),
        )));
        o.certificate_header_location = CoseHeaderLocation::Any;
    });

    let result = validator
        .validate_bytes(Arc::from(cose_bytes.into_boxed_slice()))
        .unwrap();

    assert!(result.resolution.is_valid());
    assert!(result.trust.is_valid());
    assert_ne!(ValidationResultKind::NotApplicable, result.signature.kind);
}

fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64
}

#[test]
fn real_v1_default_certificate_trust_plan_denies_expired_leaf_certificate() {
    let cose_bytes = fs::read(v1_testdata_path("UnitTestSignatureWithCRL.cose")).unwrap();
    let payload_bytes = fs::read(v1_testdata_path("UnitTestPayload.json")).unwrap();

    // Secure-by-default behavior:
    // - Caller provides ONLY trust packs (no explicit SigningKeyResolver, no explicit policy).
    // - Packs contribute their signing key resolver(s) + their default trust plan(s).
    // - Default plans are OR-composed when the caller does not provide a plan.
    //
    // For the certificates pack, default trust requires a trusted chain and a time-valid signing
    // certificate. We set `trust_embedded_chain_as_trusted=true` to keep this deterministic.
    // The real v1 test vector is expected to have an expired leaf cert, so trust should fail.
    let cert_pack = Arc::new(X509CertificateTrustPack::new(CertificateTrustOptions {
        trust_embedded_chain_as_trusted: true,
        ..CertificateTrustOptions::default()
    }));

    let trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![cert_pack];

    let validator = CoseSign1Validator::new(trust_packs).with_options(|o| {
        o.detached_payload = Some(DetachedPayload::bytes(Arc::from(
            payload_bytes.into_boxed_slice(),
        )));
        o.certificate_header_location = CoseHeaderLocation::Any;
    });

    let result = validator
        .validate_bytes(Arc::from(cose_bytes.into_boxed_slice()))
        .unwrap();

    assert!(result.resolution.is_valid());
    assert!(!result.trust.is_valid());
    assert_eq!(ValidationResultKind::NotApplicable, result.signature.kind);
}

#[test]
fn real_v1_policy_can_allow_expired_leaf_but_require_nonexpired_chain_certs() {
    let cose_bytes = fs::read(v1_testdata_path("UnitTestSignatureWithCRL.cose")).unwrap();
    let payload_bytes = fs::read(v1_testdata_path("UnitTestPayload.json")).unwrap();

    let cert_pack = Arc::new(X509CertificateTrustPack::new(CertificateTrustOptions {
        trust_embedded_chain_as_trusted: true,
        ..CertificateTrustOptions::default()
    }));
    let trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![cert_pack];
    let now = now_unix_seconds();

    // Custom policy:
    // - Explicitly allow an expired *leaf* signing certificate (demonstration).
    // - Require any present non-leaf chain certs (index 1/2) to be time-valid.
    //   (If they are missing, this is allowed.)
    let plan = TrustPlanBuilder::new(trust_packs)
        .for_primary_signing_key(|key| {
            key.require::<X509SigningCertificateIdentityFact>(|f| f.cert_expired_at_or_before(now))
            .and()
            .require_optional::<X509ChainElementValidityFact>(|f| {
                f.index_eq(1)
                .cert_valid_at(now)
            })
            .and()
            .require_optional::<X509ChainElementValidityFact>(|f| {
                f.index_eq(2)
                .cert_valid_at(now)
            })
        })
        .compile()
        .expect("plan compile");

    let validator = CoseSign1Validator::new(plan).with_options(|o| {
        o.detached_payload = Some(DetachedPayload::bytes(Arc::from(
            payload_bytes.into_boxed_slice(),
        )));
        o.certificate_header_location = CoseHeaderLocation::Any;
    });

    let result = validator
        .validate_bytes(Arc::from(cose_bytes.into_boxed_slice()))
        .unwrap();

    assert!(result.resolution.is_valid());
    assert!(result.trust.is_valid());
    assert_ne!(ValidationResultKind::NotApplicable, result.signature.kind);
}

#[test]
fn real_scitt_policy_can_require_cwt_claims_and_mst_receipt_trusted_from_issuer() {
    use cose_sign1_validation::fluent::MessageScopeRulesExt;

    let cose_bytes = fs::read(v1_scitt_testdata_path("2ts-statement.scitt")).unwrap();

    let trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![
        Arc::new(MstTrustPack {
            allow_network: false,
            offline_jwks_json: Some(MICROSOFT_CCF_JWKS.to_string()),
            jwks_api_version: None,
        }),
        Arc::new(X509CertificateTrustPack::trust_embedded_chain_as_trusted()),
    ];

    let plan = TrustPlanBuilder::new(trust_packs)
        .for_message(|m| m.require_cwt_claims_present())
        .and()
        .for_counter_signature(|cs| {
            cs.require_mst_receipt_trusted_from_issuer("confidential-ledger.azure.com")
        })
        .compile()
        .expect("plan compile");

    let validator = CoseSign1Validator::new(plan).with_options(|o| {
        o.certificate_header_location = CoseHeaderLocation::Any;
    });

    let result = validator
        .validate_bytes(Arc::from(cose_bytes.into_boxed_slice()))
        .unwrap();

    assert!(result.resolution.is_valid());
    assert!(result.trust.is_valid(), "trust invalid: {:#?}", result.trust);
    assert_ne!(ValidationResultKind::NotApplicable, result.signature.kind);
}

#[test]
fn real_scitt_policy_handles_single_receipt_encoding_when_mst_trusted_from_issuer() {
    // This vector intentionally contains a single receipt.
    // Our MST pack enforces the canonical encoding for the receipts header: array-of-bstr
    // (even when there is exactly one receipt).
    let cose_bytes = fs::read(v1_scitt_testdata_path("1ts-statement.scitt")).unwrap();

    let trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![
        Arc::new(MstTrustPack {
            allow_network: false,
            offline_jwks_json: Some(MICROSOFT_CCF_JWKS.to_string()),
            jwks_api_version: None,
        }),
        Arc::new(X509CertificateTrustPack::trust_embedded_chain_as_trusted()),
    ];

    // Require at least one counter-signature that is an MST receipt and is trusted.
    // (The counter-signature scope uses AnyOf semantics; it will pass if one derived subject passes.)
    let plan = TrustPlanBuilder::new(trust_packs)
        .for_counter_signature(|cs| {
            cs.require_mst_receipt_trusted_from_issuer("confidential-ledger.azure.com")
        })
        .compile()
        .expect("plan compile");

    let validator = CoseSign1Validator::new(plan).with_options(|o| {
        o.certificate_header_location = CoseHeaderLocation::Any;
    });

    let result = validator
        .validate_bytes(Arc::from(cose_bytes.into_boxed_slice()))
        .unwrap();

    assert!(result.resolution.is_valid());
    assert!(result.trust.is_valid(), "trust invalid: {:#?}", result.trust);
    assert_ne!(ValidationResultKind::NotApplicable, result.signature.kind);
}

#[test]
fn real_scitt_message_can_dump_cwt_claim_facts_then_enforce_them_with_policy() {
    use cose_sign1_validation::fluent::CwtClaimsWhereExt;

    // Use a real SCITT statement that includes MST receipts.
    // We focus here on the *message* CWT claims (COSE header parameter label 15).
    let cose_bytes = fs::read(v1_scitt_testdata_path("2ts-statement.scitt")).unwrap();

    // Build a trust fact engine that can produce *message facts* (including CWT claims).
    let producer = Arc::new(CoseSign1MessageFactProducer::new());
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose_bytes.clone().into_boxed_slice()));

    let subject = TrustSubject::message(b"seed");

    // Dump the real extracted claims so you can copy/paste the values into a stricter policy.
    let claims_set = engine.get_fact_set::<CwtClaimsFact>(&subject).unwrap();
    let claims = match claims_set {
        TrustFactSet::Available(v) => v.into_iter().next().expect("expected one CwtClaimsFact"),
        other => panic!("expected Available CwtClaimsFact, got {other:?}"),
    };

    println!("--- Real CWT claim facts (from label 15) ---");
    println!("iss: {:?}", claims.iss);
    println!("sub: {:?}", claims.sub);
    println!("aud: {:?}", claims.aud);
    println!("iat: {:?}", claims.iat);
    println!("nbf: {:?}", claims.nbf);
    println!("exp: {:?}", claims.exp);
    println!("scalar_claims: {:?}", claims.scalar_claims);
    println!("raw_claims(keys): {:?}", claims.raw_claims.keys().collect::<Vec<_>>());
    println!("raw_claims_text(keys): {:?}", claims.raw_claims_text.keys().collect::<Vec<_>>());

    // Now create a policy that requires the *same* extracted values.
    // (This demonstrates the plumbing: facts -> policy predicates -> trust decision.)
    let expected_iss = claims.iss.clone();
    let expected_sub = claims.sub.clone();
    let expected_aud = claims.aud.clone();
    let expected_iat = claims.iat;

    let plan = cose_sign1_validation_trust::fluent::TrustPlanBuilder::new().for_message(|msg| {
        let msg = msg.require_cwt_claims_present();

        // Require standard string claims when present.
        let msg = if let Some(iss) = expected_iss.clone() {
            msg.and().require::<CwtClaimsFact>(|w| w.iss_eq(iss))
        } else {
            msg
        };

        let msg = if let Some(sub) = expected_sub.clone() {
            msg.and().require::<CwtClaimsFact>(|w| w.sub_eq(sub))
        } else {
            msg
        };

        let msg = if let Some(aud) = expected_aud.clone() {
            msg.and().require::<CwtClaimsFact>(|w| w.aud_eq(aud))
        } else {
            msg
        };

        // Require iat (numeric label 6) when present.
        // This uses the generic claim reader so policies can handle profile-specific encodings.
        if let Some(iat) = expected_iat {
            msg.and().require_cwt_claim(6, move |r| r.decode::<i64>() == Some(iat))
        } else {
            msg
        }
    });

    let compiled = plan.compile();
    let decision = compiled
        .evaluate(&engine, &subject, &TrustEvaluationOptions::default())
        .expect("plan evaluate failed");

    assert!(
        decision.is_trusted,
        "expected policy to match extracted CWT claim facts"
    );
}
