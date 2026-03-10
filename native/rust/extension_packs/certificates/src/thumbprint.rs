// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! COSE X.509 thumbprint support.
//!
//! This module provides thumbprint computation for X.509 certificates
//! compatible with COSE x5t header format (CBOR array [int, bstr]).

use sha2::{Sha256, Sha384, Sha512, Digest};
use cbor_primitives::{CborDecoder, CborEncoder, CborType};
use crate::error::CertificateError;

/// Thumbprint hash algorithms supported by COSE.
///
/// Maps to COSE algorithm identifiers from IANA COSE registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThumbprintAlgorithm {
    /// SHA-256 (COSE algorithm ID: -16)
    Sha256,
    /// SHA-384 (COSE algorithm ID: -43)
    Sha384,
    /// SHA-512 (COSE algorithm ID: -44)
    Sha512,
}

impl ThumbprintAlgorithm {
    /// Returns the COSE algorithm identifier for this hash algorithm.
    pub fn cose_algorithm_id(&self) -> i64 {
        match self {
            Self::Sha256 => -16,
            Self::Sha384 => -43,
            Self::Sha512 => -44,
        }
    }

    /// Creates a ThumbprintAlgorithm from a COSE algorithm ID.
    pub fn from_cose_id(id: i64) -> Option<Self> {
        match id {
            -16 => Some(Self::Sha256),
            -43 => Some(Self::Sha384),
            -44 => Some(Self::Sha512),
            _ => None,
        }
    }
}

/// COSE X.509 thumbprint (maps V2 CoseX509Thumbprint class).
///
/// Represents the x5t header in a COSE signature structure, which is
/// different from a standard X.509 certificate thumbprint (SHA-1 hash).
///
/// The thumbprint is serialized as a CBOR array: [hash_id, thumbprint_bytes]
/// where hash_id is the COSE algorithm identifier.
#[derive(Debug, Clone)]
pub struct CoseX509Thumbprint {
    /// COSE algorithm identifier for the hash algorithm.
    pub hash_id: i64,
    /// Hash bytes of the certificate DER encoding.
    pub thumbprint: Vec<u8>,
}

impl CoseX509Thumbprint {
    /// Creates a thumbprint from DER-encoded certificate bytes with specified algorithm.
    pub fn new(cert_der: &[u8], algorithm: ThumbprintAlgorithm) -> Self {
        let thumbprint = compute_thumbprint(cert_der, algorithm);
        Self {
            hash_id: algorithm.cose_algorithm_id(),
            thumbprint,
        }
    }

    /// Creates a thumbprint with SHA-256 (default, matching V2).
    pub fn from_cert(cert_der: &[u8]) -> Self {
        Self::new(cert_der, ThumbprintAlgorithm::Sha256)
    }

    /// Serializes to CBOR array: [int, bstr].
    ///
    /// Maps V2 `Serialize(CborWriter)`.
    pub fn serialize(&self) -> Result<Vec<u8>, CertificateError> {
        let mut encoder = cose_sign1_primitives::provider::encoder();
        
        encoder.encode_array(2)
            .map_err(|e| CertificateError::InvalidCertificate(format!("Failed to encode array: {}", e)))?;
        encoder.encode_i64(self.hash_id)
            .map_err(|e| CertificateError::InvalidCertificate(format!("Failed to encode hash_id: {}", e)))?;
        encoder.encode_bstr(&self.thumbprint)
            .map_err(|e| CertificateError::InvalidCertificate(format!("Failed to encode thumbprint: {}", e)))?;
        
        Ok(encoder.into_bytes())
    }

    /// Deserializes from CBOR bytes.
    ///
    /// Maps V2 `Deserialize(CborReader)`.
    pub fn deserialize(data: &[u8]) -> Result<Self, CertificateError> {
        let mut decoder = cose_sign1_primitives::provider::decoder(data);
        
        // Check that we have an array
        if decoder.peek_type()
            .map_err(|e| CertificateError::InvalidCertificate(format!("Failed to peek type: {}", e)))? 
            != CborType::Array 
        {
            return Err(CertificateError::InvalidCertificate(
                "x5t first level must be an array".to_string()
            ));
        }

        // Read array length (must be 2)
        let array_len = decoder.decode_array_len()
            .map_err(|e| CertificateError::InvalidCertificate(format!("Failed to decode array length: {}", e)))?;
        
        if array_len != Some(2) {
            return Err(CertificateError::InvalidCertificate(
                "x5t first level must be 2 element array".to_string()
            ));
        }

        // Read hash_id (must be integer)
        let peek_type = decoder.peek_type()
            .map_err(|e| CertificateError::InvalidCertificate(format!("Failed to peek type: {}", e)))?;
        
        if peek_type != CborType::UnsignedInt && peek_type != CborType::NegativeInt {
            return Err(CertificateError::InvalidCertificate(
                "x5t first member must be integer".to_string()
            ));
        }

        let hash_id = decoder.decode_i64()
            .map_err(|e| CertificateError::InvalidCertificate(format!("Failed to decode hash_id: {}", e)))?;

        // Validate hash_id is supported
        if ThumbprintAlgorithm::from_cose_id(hash_id).is_none() {
            return Err(CertificateError::InvalidCertificate(
                format!("Unsupported thumbprint hash algorithm value of {}", hash_id)
            ));
        }

        // Read thumbprint (must be byte string)
        if decoder.peek_type()
            .map_err(|e| CertificateError::InvalidCertificate(format!("Failed to peek type: {}", e)))? 
            != CborType::ByteString 
        {
            return Err(CertificateError::InvalidCertificate(
                "x5t second member must be ByteString".to_string()
            ));
        }

        let thumbprint = decoder.decode_bstr_owned()
            .map_err(|e| CertificateError::InvalidCertificate(format!("Failed to decode thumbprint: {}", e)))?;

        Ok(Self { hash_id, thumbprint })
    }

    /// Checks if a certificate matches this thumbprint.
    ///
    /// Maps V2 `Match(X509Certificate2)`.
    pub fn matches(&self, cert_der: &[u8]) -> Result<bool, CertificateError> {
        let algorithm = ThumbprintAlgorithm::from_cose_id(self.hash_id)
            .ok_or_else(|| CertificateError::InvalidCertificate(
                format!("Unsupported hash ID: {}", self.hash_id)
            ))?;
        let computed = compute_thumbprint(cert_der, algorithm);
        Ok(computed == self.thumbprint)
    }
}

/// Computes a thumbprint for a certificate using the specified hash algorithm.
pub fn compute_thumbprint(cert_der: &[u8], algorithm: ThumbprintAlgorithm) -> Vec<u8> {
    match algorithm {
        ThumbprintAlgorithm::Sha256 => Sha256::digest(cert_der).to_vec(),
        ThumbprintAlgorithm::Sha384 => Sha384::digest(cert_der).to_vec(),
        ThumbprintAlgorithm::Sha512 => Sha512::digest(cert_der).to_vec(),
    }
}


