// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation::fluent::*;
use cose_sign1_validation_certificates::facts::{
    X509ChainElementIdentityFact, X509ChainElementValidityFact, X509ChainTrustedFact,
    X509PublicKeyAlgorithmFact, X509SigningCertificateIdentityFact,
};
use cose_sign1_validation_certificates::fluent_ext::*;
use cose_sign1_validation_certificates::pack::X509CertificateTrustPack;
use std::sync::Arc;

#[test]
fn certificates_fluent_extensions_build_and_compile() {
    let pack = X509CertificateTrustPack::default();

    let _plan = TrustPlanBuilder::new(vec![Arc::new(pack)])
        .for_primary_signing_key(|s| {
            s.require_x509_chain_trusted()
                .and()
                .require_leaf_chain_thumbprint_present()
                .and()
                .require_signing_certificate_present()
                .and()
                .require_leaf_subject_eq("leaf-subject")
                .and()
                .require_issuer_subject_eq("issuer-subject")
                .and()
                .require_signing_certificate_subject_issuer_matches_leaf_chain_element()
                .and()
                .require_leaf_issuer_is_next_chain_subject_optional()
                .and()
                .require_not_pqc_algorithm_or_missing()
                .and()
                .require::<X509SigningCertificateIdentityFact>(|w| {
                    w.thumbprint_eq("thumb")
                        .thumbprint_non_empty()
                        .subject_eq("subject")
                        .issuer_eq("issuer")
                        .serial_number_eq("serial")
                        .not_before_le(123)
                        .not_before_ge(123)
                        .not_after_le(456)
                        .not_after_ge(456)
                        .cert_not_before(123)
                        .cert_not_after(456)
                        .cert_valid_at(234)
                        .cert_expired_at_or_before(456)
                })
                .and()
                .require::<X509ChainElementIdentityFact>(|w| {
                    w.index_eq(0)
                        .thumbprint_eq("thumb")
                        .thumbprint_non_empty()
                        .subject_eq("subject")
                        .issuer_eq("issuer")
                })
                .and()
                .require::<X509ChainElementValidityFact>(|w| {
                    w.index_eq(0)
                        .not_before_le(1)
                        .not_before_ge(1)
                        .not_after_le(2)
                        .not_after_ge(2)
                        .cert_not_before(1)
                        .cert_not_after(2)
                        .cert_valid_at(1)
                })
                .and()
                .require::<X509ChainTrustedFact>(|w| {
                    w.require_trusted()
                        .require_not_trusted()
                        .require_chain_built()
                        .require_chain_not_built()
                        .element_count_eq(1)
                        .status_flags_eq(0)
                })
                .and()
                .require::<X509PublicKeyAlgorithmFact>(|w| {
                    w.thumbprint_eq("thumb")
                        .algorithm_oid_eq("1.2.3.4")
                        .require_pqc()
                        .require_not_pqc()
                })
        })
        .compile()
        .expect("expected plan compile to succeed");
}
