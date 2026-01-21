// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::sync::Arc;

use cose_sign1_validation::fluent::*;
use cose_sign1_validation_certificates::fluent_ext::PrimarySigningKeyScopeRulesExt;
use cose_sign1_validation_certificates::pack::{CertificateTrustOptions, X509CertificateTrustPack};
use cose_sign1_validation_trust::CoseHeaderLocation;

fn main() {
    // This example demonstrates a "real" integration shape:
    // - choose packs
    // - compile an explicit trust plan (policy)
    // - configure detached payload
    // - validate and print feedback

    let args: Vec<String> = std::env::args().collect();

    // Usage:
    //   validate_custom_policy <message.cose> [detached_payload.bin]
    // If no args are supplied, fall back to an in-repo test vector (may fail depending on algorithms).
    let (cose_bytes, payload_bytes) = if args.len() >= 2 {
        let cose_path = &args[1];
        let payload_path = args.get(2);
        let cose = std::fs::read(cose_path).expect("read cose file");
        let payload = payload_path.map(|p| std::fs::read(p).expect("read payload file"));
        (cose, payload)
    } else {
        let testdata_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("testdata")
            .join("v1");

        let cose = std::fs::read(testdata_dir.join("UnitTestSignatureWithCRL.cose"))
            .expect("read cose testdata");
        let payload =
            std::fs::read(testdata_dir.join("UnitTestPayload.json")).expect("read payload testdata");
        (cose, Some(payload))
    };

    // 1) Packs
    let cert_pack = Arc::new(X509CertificateTrustPack::new(CertificateTrustOptions {
        // Deterministic for examples/tests: treat embedded x5chain as trusted.
        // In production, configure trust roots / revocation rather than enabling this.
        trust_embedded_chain_as_trusted: true,
        ..Default::default()
    }));

    let trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![cert_pack];

    // 2) Custom plan
    let plan = TrustPlanBuilder::new(trust_packs).for_primary_signing_key(|key| {
            key.require_x509_chain_trusted()
                .and()
                .require_signing_certificate_present()
                .and()
                .require_leaf_chain_thumbprint_present()
        })
        .compile()
        .expect("plan compile");

    // 3) Validator + detached payload configuration
    let validator = CoseSign1Validator::new(plan).with_options(|o| {
        if let Some(payload_bytes) = payload_bytes.clone() {
            o.detached_payload = Some(DetachedPayload::bytes(Arc::from(
                payload_bytes.into_boxed_slice(),
            )));
        }
        o.certificate_header_location = CoseHeaderLocation::Any;
    });

    // 4) Validate
    let result = validator
        .validate_bytes(Arc::from(cose_bytes.into_boxed_slice()))
        .expect("validation pipeline error");

    println!("resolution: {:?}", result.resolution.kind);
    println!("trust: {:?}", result.trust.kind);
    println!("signature: {:?}", result.signature.kind);
    println!("post_signature_policy: {:?}", result.post_signature_policy.kind);
    println!("overall: {:?}", result.overall.kind);

    if result.overall.is_valid() {
        println!("Validation successful");
        return;
    }

    let stages = [
        ("resolution", &result.resolution),
        ("trust", &result.trust),
        ("signature", &result.signature),
        ("post_signature_policy", &result.post_signature_policy),
        ("overall", &result.overall),
    ];

    for (name, stage) in stages {
        if stage.failures.is_empty() {
            continue;
        }

        eprintln!("{name} failures:");
        for failure in &stage.failures {
            eprintln!("- {}", failure.message);
        }
    }
}
