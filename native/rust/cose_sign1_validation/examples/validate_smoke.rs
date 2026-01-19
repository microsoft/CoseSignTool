// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation::fluent::*;

fn main() {
    // This example demonstrates the recommended integration pattern:
    // - use the fluent API surface (`cose_sign1_validation::fluent::*`)
    // - wire one or more trust packs (here: the certificates pack)
    // - optionally bypass trust while still verifying the cryptographic signature

    let testdata_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join("v1");

    // Real COSE + payload test vector.
    let cose_bytes = std::fs::read(testdata_dir.join("UnitTestSignatureWithCRL.cose"))
        .expect("read cose testdata");
    let payload_bytes =
        std::fs::read(testdata_dir.join("UnitTestPayload.json")).expect("read payload testdata");

    let cert_pack = std::sync::Arc::new(
        cose_sign1_validation_certificates::pack::X509CertificateTrustPack::new(
            cose_sign1_validation_certificates::pack::CertificateTrustOptions {
                // Deterministic for a local example: treat embedded x5chain as trusted.
                trust_embedded_chain_as_trusted: true,
                ..Default::default()
            },
        ),
    );

    let trust_packs: Vec<std::sync::Arc<dyn CoseSign1TrustPack>> = vec![cert_pack];

    let validator = CoseSign1Validator::new(trust_packs).with_options(|o| {
        o.detached_payload = Some(DetachedPayload::bytes(std::sync::Arc::from(
            payload_bytes.into_boxed_slice(),
        )));
        o.certificate_header_location = cose_sign1_validation_trust::CoseHeaderLocation::Any;

        // Trust is often environment-dependent (roots/CRLs/OCSP). For a smoke example,
        // keep trust bypassed but still verify the signature.
        o.trust_evaluation_options.bypass_trust = true;
    });

    let result = validator
        .validate_bytes(std::sync::Arc::from(cose_bytes.into_boxed_slice()))
        .expect("validation failed");

    println!("resolution: {:?}", result.resolution.kind);
    println!("trust: {:?}", result.trust.kind);
    println!("signature: {:?}", result.signature.kind);
    println!("overall: {:?}", result.overall.kind);
}
