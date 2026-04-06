// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_transparent_mst::validation::facts::{
    MstReceiptIssuerFact, MstReceiptKidFact, MstReceiptPresentFact,
    MstReceiptSignatureVerifiedFact, MstReceiptStatementCoverageFact,
    MstReceiptStatementSha256Fact, MstReceiptTrustedFact,
};
use cose_sign1_validation_primitives::fact_properties::FactProperties;
use std::sync::Arc;

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
        issuer: Arc::from("example.com"),
    }
    .get_property("unknown")
    .is_none());

    assert!(MstReceiptKidFact {
        kid: Arc::from("kid"),
    }
    .get_property("unknown")
    .is_none());

    assert!(MstReceiptStatementSha256Fact {
        sha256_hex: Arc::from("00".repeat(32).as_str()),
    }
    .get_property("unknown")
    .is_none());

    assert!(MstReceiptStatementCoverageFact {
        coverage: "coverage",
    }
    .get_property("unknown")
    .is_none());

    assert!(MstReceiptSignatureVerifiedFact { verified: true }
        .get_property("unknown")
        .is_none());
}
