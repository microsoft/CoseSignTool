// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use code_transparency_client::CodeTransparencyClient;
use cose_sign1_crypto_openssl::jwk_verifier::OpenSslJwkVerifierFactory;
use cose_sign1_signing::transparency::{
    TransparencyProvider, TransparencyValidationResult, TransparencyError,
    extract_receipts,
};
use cose_sign1_primitives::CoseSign1Message;
use crate::validation::receipt_verify::{verify_mst_receipt, ReceiptVerifyInput};

/// MST transparency provider.
/// Maps V2 `MstTransparencyProvider` extending `TransparencyProviderBase`.
pub struct MstTransparencyProvider {
    client: CodeTransparencyClient,
}

impl MstTransparencyProvider {
    pub fn new(client: CodeTransparencyClient) -> Self {
        Self { client }
    }
}

impl TransparencyProvider for MstTransparencyProvider {
    fn provider_name(&self) -> &str {
        "Microsoft Signing Transparency"
    }

    fn add_transparency_proof(&self, cose_bytes: &[u8]) -> Result<Vec<u8>, TransparencyError> {
        self.client.make_transparent(cose_bytes)
            .map_err(|e| TransparencyError::SubmissionFailed(e.to_string()))
    }

    fn verify_transparency_proof(&self, cose_bytes: &[u8]) -> Result<TransparencyValidationResult, TransparencyError> {
        let msg = CoseSign1Message::parse(cose_bytes)
            .map_err(|e| TransparencyError::InvalidMessage(e.to_string()))?;
        let receipts = extract_receipts(&msg);
        if receipts.is_empty() {
            return Ok(TransparencyValidationResult::failure(
                self.provider_name(), vec!["No MST receipts found in header 394".into()],
            ));
        }
        for receipt_bytes in &receipts {
            let factory = OpenSslJwkVerifierFactory;
            let input = ReceiptVerifyInput {
                statement_bytes_with_receipts: cose_bytes,
                receipt_bytes: receipt_bytes.as_slice(),
                offline_jwks_json: None,
                allow_network_fetch: true,
                jwks_api_version: None,
                client: Some(&self.client),
                jwk_verifier_factory: &factory,
            };
            if let Ok(result) = verify_mst_receipt(input) {
                if result.trusted {
                    return Ok(TransparencyValidationResult::success(self.provider_name()));
                }
            }
        }
        Ok(TransparencyValidationResult::failure(
            self.provider_name(), vec!["No valid MST receipts found".into()],
        ))
    }
}
