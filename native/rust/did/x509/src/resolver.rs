// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::did_document::{DidDocument, VerificationMethod};
use crate::error::DidX509Error;
use crate::validator::DidX509Validator;
use std::borrow::Cow;
use std::collections::HashMap;
use x509_parser::oid_registry::Oid;
use x509_parser::prelude::*;
use x509_parser::public_key::{ECPoint, PublicKey, RSAPublicKey};

// Inline base64url utilities
const BASE64_URL_SAFE: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64_encode(input: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 2 < input.len() {
        let n = (input[i] as u32) << 16 | (input[i + 1] as u32) << 8 | input[i + 2] as u32;
        out.push(alphabet[((n >> 18) & 0x3F) as usize] as char);
        out.push(alphabet[((n >> 12) & 0x3F) as usize] as char);
        out.push(alphabet[((n >> 6) & 0x3F) as usize] as char);
        out.push(alphabet[(n & 0x3F) as usize] as char);
        i += 3;
    }
    let rem = input.len() - i;
    if rem == 1 {
        let n = (input[i] as u32) << 16;
        out.push(alphabet[((n >> 18) & 0x3F) as usize] as char);
        out.push(alphabet[((n >> 12) & 0x3F) as usize] as char);
        if pad {
            out.push_str("==");
        }
    } else if rem == 2 {
        let n = (input[i] as u32) << 16 | (input[i + 1] as u32) << 8;
        out.push(alphabet[((n >> 18) & 0x3F) as usize] as char);
        out.push(alphabet[((n >> 12) & 0x3F) as usize] as char);
        out.push(alphabet[((n >> 6) & 0x3F) as usize] as char);
        if pad {
            out.push('=');
        }
    }
    out
}

/// Encode bytes as base64url (no padding).
fn base64url_encode(input: &[u8]) -> String {
    base64_encode(input, BASE64_URL_SAFE, false)
}

/// Resolver for DID:x509 identifiers to DID Documents
pub struct DidX509Resolver;

impl DidX509Resolver {
    /// Resolve a DID:x509 identifier to a DID Document.
    ///
    /// This performs the following steps:
    /// 1. Validates the DID against the certificate chain
    /// 2. Extracts the leaf certificate's public key
    /// 3. Converts the public key to JWK format
    /// 4. Builds a DID Document with a verification method
    ///
    /// # Arguments
    /// * `did` - The DID:x509 identifier string
    /// * `chain` - Certificate chain in DER format (leaf-first order)
    ///
    /// # Returns
    /// A DID Document if resolution succeeds
    ///
    /// # Errors
    /// Returns an error if:
    /// - DID validation fails
    /// - Certificate parsing fails
    /// - Public key extraction or conversion fails
    pub fn resolve(did: &str, chain: &[&[u8]]) -> Result<DidDocument, DidX509Error> {
        // Step 1: Validate DID against chain
        let result = DidX509Validator::validate(did, chain)?;
        if !result.is_valid {
            return Err(DidX509Error::PolicyValidationFailed(
                result.errors.join("; "),
            ));
        }

        // Step 2: Parse leaf certificate
        let leaf_der = chain[0];
        let (_, leaf_cert) = X509Certificate::from_der(leaf_der)
            .map_err(|e| DidX509Error::CertificateParseError(e.to_string()))?;

        // Step 3: Extract public key and convert to JWK
        let jwk = Self::public_key_to_jwk(&leaf_cert)?;

        // Step 4: Build DID Document
        let vm_id = format!("{}#key-1", did);
        Ok(DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_string()],
            id: did.to_string(),
            verification_method: vec![VerificationMethod {
                id: vm_id.clone(),
                type_: "JsonWebKey2020".to_string(),
                controller: did.to_string(),
                public_key_jwk: jwk,
            }],
            assertion_method: vec![vm_id],
        })
    }

    /// Convert X.509 certificate public key to JWK format
    fn public_key_to_jwk(
        cert: &X509Certificate,
    ) -> Result<HashMap<Cow<'static, str>, String>, DidX509Error> {
        let public_key = cert.public_key();

        match public_key.parsed() {
            Ok(PublicKey::RSA(rsa_key)) => Self::rsa_to_jwk(&rsa_key),
            Ok(PublicKey::EC(ec_point)) => Self::ec_to_jwk(cert, &ec_point),
            _ => Err(DidX509Error::InvalidChain(format!(
                "Unsupported public key type: {:?}",
                public_key.algorithm
            ))),
        }
    }

    /// Convert RSA public key to JWK
    fn rsa_to_jwk(rsa: &RSAPublicKey) -> Result<HashMap<Cow<'static, str>, String>, DidX509Error> {
        let mut jwk = HashMap::new();
        jwk.insert(Cow::Borrowed("kty"), "RSA".to_string());

        // Encode modulus (n) as base64url
        let n_base64 = base64url_encode(rsa.modulus);
        jwk.insert(Cow::Borrowed("n"), n_base64);

        // Encode exponent (e) as base64url
        let e_base64 = base64url_encode(rsa.exponent);
        jwk.insert(Cow::Borrowed("e"), e_base64);

        Ok(jwk)
    }

    /// Convert EC public key to JWK
    fn ec_to_jwk(
        cert: &X509Certificate,
        ec_point: &ECPoint,
    ) -> Result<HashMap<Cow<'static, str>, String>, DidX509Error> {
        let mut jwk = HashMap::new();
        jwk.insert(Cow::Borrowed("kty"), "EC".to_string());

        // Determine the curve from the algorithm OID
        let alg_oid = &cert.public_key().algorithm.algorithm;
        let curve = Self::determine_ec_curve(alg_oid, ec_point.data())?;
        jwk.insert(Cow::Borrowed("crv"), curve.to_string());

        // Extract x and y coordinates from the EC point
        // EC points are typically encoded as 0x04 || x || y for uncompressed points
        let point_data = ec_point.data();
        if point_data.is_empty() {
            return Err(DidX509Error::InvalidChain(
                "Empty EC point data".to_string(),
            ));
        }

        if point_data[0] == 0x04 {
            // Uncompressed point format
            let coord_len = (point_data.len() - 1) / 2;
            if coord_len * 2 + 1 != point_data.len() {
                return Err(DidX509Error::InvalidChain(
                    "Invalid EC point length".to_string(),
                ));
            }

            let x = &point_data[1..1 + coord_len];
            let y = &point_data[1 + coord_len..];

            jwk.insert(Cow::Borrowed("x"), base64url_encode(x));
            jwk.insert(Cow::Borrowed("y"), base64url_encode(y));
        } else {
            return Err(DidX509Error::InvalidChain(
                "Compressed EC point format not supported".to_string(),
            ));
        }

        Ok(jwk)
    }

    /// Determine EC curve name from algorithm parameters
    fn determine_ec_curve(alg_oid: &Oid, point_data: &[u8]) -> Result<&'static str, DidX509Error> {
        // Common EC curve OIDs
        const P256_OID: &str = "1.2.840.10045.3.1.7"; // secp256r1 / prime256v1
        const P384_OID: &str = "1.3.132.0.34"; // secp384r1
        const P521_OID: &str = "1.3.132.0.35"; // secp521r1

        // Determine curve based on point size if OID doesn't match
        // P-256: 65 bytes (1 + 32 + 32)
        // P-384: 97 bytes (1 + 48 + 48)
        // P-521: 133 bytes (1 + 66 + 66)
        let curve = match point_data.len() {
            65 => "P-256",
            97 => "P-384",
            133 => "P-521",
            _ => {
                // Try to match by OID
                match alg_oid.to_string().as_str() {
                    P256_OID => "P-256",
                    P384_OID => "P-384",
                    P521_OID => "P-521",
                    _ => {
                        return Err(DidX509Error::InvalidChain(format!(
                            "Unsupported EC curve: OID {}, point length {}",
                            alg_oid,
                            point_data.len()
                        )))
                    }
                }
            }
        };

        Ok(curve)
    }
}
