// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use x509_parser::prelude::*;
use sha2::{Sha256, Sha384, Sha512, Digest};
use crate::models::*;
use crate::parsing::DidX509Parser;
use crate::error::DidX509Error;
use crate::policy_validators;

/// Validator for DID:x509 identifiers against certificate chains
pub struct DidX509Validator;

impl DidX509Validator {
    /// Validate a DID:x509 string against a certificate chain.
    /// 
    /// # Arguments
    /// * `did` - The DID:x509 string to validate
    /// * `chain` - DER-encoded certificate chain (leaf-first order)
    ///
    /// # Returns
    /// Validation result indicating success/failure with details
    pub fn validate(did: &str, chain: &[&[u8]]) -> Result<DidX509ValidationResult, DidX509Error> {
        // 1. Parse the DID
        let parsed = DidX509Parser::parse(did)?;
        
        // 2. Validate chain is not empty
        if chain.is_empty() {
            return Err(DidX509Error::InvalidChain("Empty chain".into()));
        }

        // 3. Find the CA cert in chain matching the fingerprint
        let ca_index = Self::find_ca_by_fingerprint(chain, &parsed.hash_algorithm, &parsed.ca_fingerprint)?;
        
        // 4. Parse the leaf certificate
        let leaf_der = chain[0];
        let (_, leaf_cert) = X509Certificate::from_der(leaf_der)
            .map_err(|e| DidX509Error::CertificateParseError(e.to_string()))?;

        // 5. Validate each policy against the leaf cert
        let mut errors = Vec::new();
        for policy in &parsed.policies {
            if let Err(e) = Self::validate_policy(policy, &leaf_cert) {
                errors.push(e.to_string());
            }
        }

        // 6. Return validation result
        if errors.is_empty() {
            Ok(DidX509ValidationResult::valid(ca_index))
        } else {
            Ok(DidX509ValidationResult::invalid_multiple(errors))
        }
    }

    /// Find the CA certificate in the chain that matches the fingerprint
    fn find_ca_by_fingerprint(
        chain: &[&[u8]], 
        hash_alg: &str, 
        expected: &[u8]
    ) -> Result<usize, DidX509Error> {
        for (i, cert_der) in chain.iter().enumerate() {
            let fingerprint = match hash_alg {
                "sha256" => Sha256::digest(cert_der).to_vec(),
                "sha384" => Sha384::digest(cert_der).to_vec(),
                "sha512" => Sha512::digest(cert_der).to_vec(),
                _ => return Err(DidX509Error::UnsupportedHashAlgorithm(hash_alg.into())),
            };
            if fingerprint == expected {
                return Ok(i);
            }
        }
        Err(DidX509Error::NoCaMatch)
    }

    /// Validate a single policy against the certificate
    fn validate_policy(policy: &DidX509Policy, cert: &X509Certificate) -> Result<(), DidX509Error> {
        match policy {
            DidX509Policy::Eku(expected_oids) => {
                policy_validators::validate_eku(cert, expected_oids)
            }
            DidX509Policy::Subject(expected_attrs) => {
                policy_validators::validate_subject(cert, expected_attrs)
            }
            DidX509Policy::San(san_type, expected_value) => {
                policy_validators::validate_san(cert, san_type, expected_value)
            }
            DidX509Policy::FulcioIssuer(expected_issuer) => {
                policy_validators::validate_fulcio_issuer(cert, expected_issuer)
            }
        }
    }
}
