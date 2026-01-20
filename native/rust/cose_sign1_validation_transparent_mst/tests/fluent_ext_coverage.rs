// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation::fluent::*;
use cose_sign1_validation_transparent_mst::facts::{
    MstReceiptIssuerFact, MstReceiptKidFact, MstReceiptPresentFact, MstReceiptSignatureVerifiedFact,
    MstReceiptStatementCoverageFact, MstReceiptStatementSha256Fact, MstReceiptTrustedFact,
};
use cose_sign1_validation_transparent_mst::fluent_ext::*;
use cose_sign1_validation_transparent_mst::pack::MstTrustPack;
use cose_sign1_validation_trust::fact_properties::FactProperties;
use std::sync::Arc;

#[test]
fn mst_fluent_extensions_build_and_compile() {
    let pack = MstTrustPack {
        allow_network: false,
        offline_jwks_json: None,
        jwks_api_version: None,
    };

    let _plan = TrustPlanBuilder::new(vec![Arc::new(pack)])
        .for_counter_signature(|s| {
            s.require_mst_receipt_present()
                .and()
                .require_mst_receipt_signature_verified()
                .and()
                .require_mst_receipt_issuer_eq("issuer")
                .and()
                .require_mst_receipt_issuer_contains("needle")
                .and()
                .require_mst_receipt_kid_eq("kid")
                .and()
                .require_mst_receipt_trusted_from_issuer("needle")
                .and()
                .require::<MstReceiptPresentFact>(|w| w.require_receipt_not_present())
                .and()
                .require::<MstReceiptTrustedFact>(|w| w.require_receipt_not_trusted())
                .and()
                .require::<MstReceiptIssuerFact>(|w| w.require_receipt_issuer_contains("needle"))
                .and()
                .require::<MstReceiptKidFact>(|w| w.require_receipt_kid_contains("kid"))
                .and()
                .require::<MstReceiptStatementSha256Fact>(|w| {
                    w.require_receipt_statement_sha256_eq("00")
                })
                .and()
                .require::<MstReceiptStatementCoverageFact>(|w| {
                    w.require_receipt_statement_coverage_eq("coverage")
                        .require_receipt_statement_coverage_contains("cov")
                })
                .and()
                .require::<MstReceiptSignatureVerifiedFact>(|w| w.require_receipt_signature_not_verified())
        })
        .compile()
        .expect("expected plan compile to succeed");
}

#[test]
fn mst_facts_expose_declarative_properties() {
    let present = MstReceiptPresentFact { present: true };
    assert!(present.get_property("present").is_some());
    assert!(present.get_property("no_such_field").is_none());

    let issuer = MstReceiptIssuerFact {
        issuer: "issuer".to_string(),
    };
    assert!(issuer.get_property("issuer").is_some());

    let kid = MstReceiptKidFact { kid: "kid".to_string() };
    assert!(kid.get_property("kid").is_some());

    let sha = MstReceiptStatementSha256Fact {
        sha256_hex: "00".to_string(),
    };
    assert!(sha.get_property("sha256_hex").is_some());

    let coverage = MstReceiptStatementCoverageFact {
        coverage: "coverage".to_string(),
    };
    assert!(coverage.get_property("coverage").is_some());

    let verified = MstReceiptSignatureVerifiedFact { verified: false };
    assert!(verified.get_property("verified").is_some());

    let trusted = MstReceiptTrustedFact {
        trusted: true,
        details: Some("ok".to_string()),
    };
    assert!(trusted.get_property("trusted").is_some());
}
