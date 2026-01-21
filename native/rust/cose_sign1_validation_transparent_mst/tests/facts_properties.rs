// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation_transparent_mst::facts::{
    MstReceiptIssuerFact, MstReceiptKidFact, MstReceiptPresentFact,
    MstReceiptSignatureVerifiedFact, MstReceiptStatementCoverageFact,
    MstReceiptStatementSha256Fact, MstReceiptTrustedFact,
};
use cose_sign1_validation_trust::fact_properties::FactProperties;

#[test]
fn mst_fact_properties_unknown_fields_return_none() {
    assert!(MstReceiptPresentFact { present: true }
        .get_property("unknown")
        .is_none());

    assert!(MstReceiptTrustedFact {
        trusted: true,
        details: None,
    }
    .get_property("unknown")
    .is_none());

    assert!(MstReceiptIssuerFact {
        issuer: "example.com".to_string(),
    }
    .get_property("unknown")
    .is_none());

    assert!(MstReceiptKidFact {
        kid: "kid".to_string(),
    }
    .get_property("unknown")
    .is_none());

    assert!(MstReceiptStatementSha256Fact {
        sha256_hex: "00".repeat(32),
    }
    .get_property("unknown")
    .is_none());

    assert!(MstReceiptStatementCoverageFact {
        coverage: "coverage".to_string(),
    }
    .get_property("unknown")
    .is_none());

    assert!(MstReceiptSignatureVerifiedFact { verified: true }
        .get_property("unknown")
        .is_none());
}
