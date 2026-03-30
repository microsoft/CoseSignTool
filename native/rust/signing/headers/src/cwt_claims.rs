// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CWT (CBOR Web Token) Claims implementation.

use crate::{cwt_claims_labels::CWTClaimsHeaderLabels, error::HeaderError};
use cbor_primitives::{CborDecoder, CborEncoder, CborType};
use std::collections::HashMap;

/// A single CWT claim value.
///
/// Maps V2 custom claim value types in `CwtClaims`.
#[derive(Clone, Debug, PartialEq)]
pub enum CwtClaimValue {
    /// Text string value.
    Text(String),
    /// Integer value.
    Integer(i64),
    /// Byte string value.
    Bytes(Vec<u8>),
    /// Boolean value.
    Bool(bool),
    /// Floating point value.
    Float(f64),
}

/// CWT (CBOR Web Token) Claims.
///
/// Maps V2 `CwtClaims` class in CoseSign1.Headers.
#[derive(Clone, Debug, Default)]
pub struct CwtClaims {
    /// Issuer (iss, label 1).
    pub issuer: Option<String>,

    /// Subject (sub, label 2). Defaults to "unknown.intent".
    pub subject: Option<String>,

    /// Audience (aud, label 3).
    pub audience: Option<String>,

    /// Expiration time (exp, label 4) - Unix timestamp.
    pub expiration_time: Option<i64>,

    /// Not before (nbf, label 5) - Unix timestamp.
    pub not_before: Option<i64>,

    /// Issued at (iat, label 6) - Unix timestamp.
    pub issued_at: Option<i64>,

    /// CWT ID (cti, label 7).
    pub cwt_id: Option<Vec<u8>>,

    /// Custom claims with integer labels.
    pub custom_claims: HashMap<i64, CwtClaimValue>,
}

impl CwtClaims {
    /// Default subject value per SCITT specification.
    pub const DEFAULT_SUBJECT: &'static str = "unknown.intent";

    /// Creates a new empty CwtClaims instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Serializes the claims to CBOR map bytes.
    pub fn to_cbor_bytes(&self) -> Result<Vec<u8>, HeaderError> {
        let mut encoder = cose_sign1_primitives::provider::encoder();

        // Count non-null standard claims
        let mut count = 0;
        if self.issuer.is_some() {
            count += 1;
        }
        if self.subject.is_some() {
            count += 1;
        }
        if self.audience.is_some() {
            count += 1;
        }
        if self.expiration_time.is_some() {
            count += 1;
        }
        if self.not_before.is_some() {
            count += 1;
        }
        if self.issued_at.is_some() {
            count += 1;
        }
        if self.cwt_id.is_some() {
            count += 1;
        }
        count += self.custom_claims.len();

        encoder
            .encode_map(count)
            .map_err(|e| HeaderError::CborEncodingError(e.to_string()))?;

        // Encode standard claims (in label order per CBOR deterministic encoding)
        if let Some(issuer) = &self.issuer {
            encoder
                .encode_i64(CWTClaimsHeaderLabels::ISSUER)
                .map_err(|e| HeaderError::CborEncodingError(e.to_string()))?;
            encoder
                .encode_tstr(issuer)
                .map_err(|e| HeaderError::CborEncodingError(e.to_string()))?;
        }

        if let Some(subject) = &self.subject {
            encoder
                .encode_i64(CWTClaimsHeaderLabels::SUBJECT)
                .map_err(|e| HeaderError::CborEncodingError(e.to_string()))?;
            encoder
                .encode_tstr(subject)
                .map_err(|e| HeaderError::CborEncodingError(e.to_string()))?;
        }

        if let Some(audience) = &self.audience {
            encoder
                .encode_i64(CWTClaimsHeaderLabels::AUDIENCE)
                .map_err(|e| HeaderError::CborEncodingError(e.to_string()))?;
            encoder
                .encode_tstr(audience)
                .map_err(|e| HeaderError::CborEncodingError(e.to_string()))?;
        }

        if let Some(exp) = self.expiration_time {
            encoder
                .encode_i64(CWTClaimsHeaderLabels::EXPIRATION_TIME)
                .map_err(|e| HeaderError::CborEncodingError(e.to_string()))?;
            encoder
                .encode_i64(exp)
                .map_err(|e| HeaderError::CborEncodingError(e.to_string()))?;
        }

        if let Some(nbf) = self.not_before {
            encoder
                .encode_i64(CWTClaimsHeaderLabels::NOT_BEFORE)
                .map_err(|e| HeaderError::CborEncodingError(e.to_string()))?;
            encoder
                .encode_i64(nbf)
                .map_err(|e| HeaderError::CborEncodingError(e.to_string()))?;
        }

        if let Some(iat) = self.issued_at {
            encoder
                .encode_i64(CWTClaimsHeaderLabels::ISSUED_AT)
                .map_err(|e| HeaderError::CborEncodingError(e.to_string()))?;
            encoder
                .encode_i64(iat)
                .map_err(|e| HeaderError::CborEncodingError(e.to_string()))?;
        }

        if let Some(cti) = &self.cwt_id {
            encoder
                .encode_i64(CWTClaimsHeaderLabels::CWT_ID)
                .map_err(|e| HeaderError::CborEncodingError(e.to_string()))?;
            encoder
                .encode_bstr(cti)
                .map_err(|e| HeaderError::CborEncodingError(e.to_string()))?;
        }

        // Encode custom claims (sorted by label for deterministic encoding)
        let mut sorted_labels: Vec<_> = self.custom_claims.keys().copied().collect();
        sorted_labels.sort_unstable();

        for label in sorted_labels {
            if let Some(value) = self.custom_claims.get(&label) {
                encoder
                    .encode_i64(label)
                    .map_err(|e| HeaderError::CborEncodingError(e.to_string()))?;

                match value {
                    CwtClaimValue::Text(s) => {
                        encoder
                            .encode_tstr(s)
                            .map_err(|e| HeaderError::CborEncodingError(e.to_string()))?;
                    }
                    CwtClaimValue::Integer(i) => {
                        encoder
                            .encode_i64(*i)
                            .map_err(|e| HeaderError::CborEncodingError(e.to_string()))?;
                    }
                    CwtClaimValue::Bytes(b) => {
                        encoder
                            .encode_bstr(b)
                            .map_err(|e| HeaderError::CborEncodingError(e.to_string()))?;
                    }
                    CwtClaimValue::Bool(b) => {
                        encoder
                            .encode_bool(*b)
                            .map_err(|e| HeaderError::CborEncodingError(e.to_string()))?;
                    }
                    CwtClaimValue::Float(f) => {
                        encoder
                            .encode_f64(*f)
                            .map_err(|e| HeaderError::CborEncodingError(e.to_string()))?;
                    }
                }
            }
        }

        Ok(encoder.into_bytes())
    }

    /// Deserializes claims from CBOR map bytes.
    pub fn from_cbor_bytes(data: &[u8]) -> Result<Self, HeaderError> {
        let mut decoder = cose_sign1_primitives::provider::decoder(data);

        // Expect a map
        let cbor_type = decoder
            .peek_type()
            .map_err(|e| HeaderError::CborDecodingError(e.to_string()))?;

        if cbor_type != CborType::Map {
            return Err(HeaderError::CborDecodingError(format!(
                "Expected CBOR map, got {:?}",
                cbor_type
            )));
        }

        let map_len = decoder
            .decode_map_len()
            .map_err(|e| HeaderError::CborDecodingError(e.to_string()))?
            .ok_or_else(|| {
                HeaderError::CborDecodingError("Indefinite-length maps not supported".to_string())
            })?;

        let mut claims = CwtClaims::new();

        for _ in 0..map_len {
            // Read the label (must be an integer)
            let label_type = decoder
                .peek_type()
                .map_err(|e| HeaderError::CborDecodingError(e.to_string()))?;

            let label = match label_type {
                CborType::UnsignedInt | CborType::NegativeInt => decoder
                    .decode_i64()
                    .map_err(|e| HeaderError::CborDecodingError(e.to_string()))?,
                _ => {
                    return Err(HeaderError::CborDecodingError(format!(
                        "CWT claim label must be integer, got {:?}",
                        label_type
                    )));
                }
            };

            // Read the value based on the label
            match label {
                CWTClaimsHeaderLabels::ISSUER => {
                    claims.issuer = Some(
                        decoder
                            .decode_tstr_owned()
                            .map_err(|e| HeaderError::CborDecodingError(e.to_string()))?,
                    );
                }
                CWTClaimsHeaderLabels::SUBJECT => {
                    claims.subject = Some(
                        decoder
                            .decode_tstr_owned()
                            .map_err(|e| HeaderError::CborDecodingError(e.to_string()))?,
                    );
                }
                CWTClaimsHeaderLabels::AUDIENCE => {
                    claims.audience = Some(
                        decoder
                            .decode_tstr_owned()
                            .map_err(|e| HeaderError::CborDecodingError(e.to_string()))?,
                    );
                }
                CWTClaimsHeaderLabels::EXPIRATION_TIME => {
                    claims.expiration_time = Some(
                        decoder
                            .decode_i64()
                            .map_err(|e| HeaderError::CborDecodingError(e.to_string()))?,
                    );
                }
                CWTClaimsHeaderLabels::NOT_BEFORE => {
                    claims.not_before = Some(
                        decoder
                            .decode_i64()
                            .map_err(|e| HeaderError::CborDecodingError(e.to_string()))?,
                    );
                }
                CWTClaimsHeaderLabels::ISSUED_AT => {
                    claims.issued_at = Some(
                        decoder
                            .decode_i64()
                            .map_err(|e| HeaderError::CborDecodingError(e.to_string()))?,
                    );
                }
                CWTClaimsHeaderLabels::CWT_ID => {
                    claims.cwt_id = Some(
                        decoder
                            .decode_bstr_owned()
                            .map_err(|e| HeaderError::CborDecodingError(e.to_string()))?,
                    );
                }
                _ => {
                    // Custom claim - peek type and decode appropriately
                    let value_type = decoder
                        .peek_type()
                        .map_err(|e| HeaderError::CborDecodingError(e.to_string()))?;

                    let claim_value = match value_type {
                        CborType::TextString => {
                            let s = decoder
                                .decode_tstr_owned()
                                .map_err(|e| HeaderError::CborDecodingError(e.to_string()))?;
                            CwtClaimValue::Text(s)
                        }
                        CborType::UnsignedInt | CborType::NegativeInt => {
                            let i = decoder
                                .decode_i64()
                                .map_err(|e| HeaderError::CborDecodingError(e.to_string()))?;
                            CwtClaimValue::Integer(i)
                        }
                        CborType::ByteString => {
                            let b = decoder
                                .decode_bstr_owned()
                                .map_err(|e| HeaderError::CborDecodingError(e.to_string()))?;
                            CwtClaimValue::Bytes(b)
                        }
                        CborType::Bool => {
                            let b = decoder
                                .decode_bool()
                                .map_err(|e| HeaderError::CborDecodingError(e.to_string()))?;
                            CwtClaimValue::Bool(b)
                        }
                        CborType::Float64 | CborType::Float32 | CborType::Float16 => {
                            let f = decoder
                                .decode_f64()
                                .map_err(|e| HeaderError::CborDecodingError(e.to_string()))?;
                            CwtClaimValue::Float(f)
                        }
                        _ => {
                            // For complex types (arrays, maps, etc.), we need to skip them
                            // Since we can't add them to our CWT claims, we'll consume them but not store
                            match value_type {
                                CborType::Array => {
                                    // Skip array by reading length and all elements
                                    if let Ok(Some(len)) = decoder.decode_array_len() {
                                        for _ in 0..len {
                                            // Skip each element by trying to decode as a generic CBOR value
                                            // Since we don't have a generic skip method, we'll try to consume as i64
                                            let _ = decoder.decode_i64().or_else(|_| {
                                                decoder.decode_tstr().map(|_| 0i64).or_else(|_| {
                                                    decoder.decode_bstr().map(|_| 0i64).or_else(
                                                        |_| decoder.decode_bool().map(|_| 0i64),
                                                    )
                                                })
                                            });
                                        }
                                    }
                                }
                                CborType::Map => {
                                    // Skip map by reading all key-value pairs
                                    if let Ok(Some(len)) = decoder.decode_map_len() {
                                        for _ in 0..len {
                                            // Skip key and value
                                            let _ = decoder
                                                .decode_i64()
                                                .or_else(|_| decoder.decode_tstr().map(|_| 0i64));
                                            let _ = decoder.decode_i64().or_else(|_| {
                                                decoder.decode_tstr().map(|_| 0i64).or_else(|_| {
                                                    decoder.decode_bstr().map(|_| 0i64).or_else(
                                                        |_| decoder.decode_bool().map(|_| 0i64),
                                                    )
                                                })
                                            });
                                        }
                                    }
                                }
                                _ => {
                                    // Other complex types - just fail for now as we can't handle them properly
                                    return Err(HeaderError::CborDecodingError(format!(
                                        "Unsupported CWT claim value type: {:?}",
                                        value_type
                                    )));
                                }
                            }
                            continue;
                        }
                    };

                    claims.custom_claims.insert(label, claim_value);
                }
            }
        }

        Ok(claims)
    }

    /// Builder method to set the issuer.
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Builder method to set the subject.
    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    /// Builder method to set the audience.
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// Builder method to set the expiration time (Unix timestamp).
    pub fn with_expiration_time(mut self, exp: i64) -> Self {
        self.expiration_time = Some(exp);
        self
    }

    /// Builder method to set the not-before time (Unix timestamp).
    pub fn with_not_before(mut self, nbf: i64) -> Self {
        self.not_before = Some(nbf);
        self
    }

    /// Builder method to set the issued-at time (Unix timestamp).
    pub fn with_issued_at(mut self, iat: i64) -> Self {
        self.issued_at = Some(iat);
        self
    }

    /// Builder method to set the CWT ID.
    pub fn with_cwt_id(mut self, cti: Vec<u8>) -> Self {
        self.cwt_id = Some(cti);
        self
    }

    /// Builder method to add a custom claim.
    pub fn with_custom_claim(mut self, label: i64, value: CwtClaimValue) -> Self {
        self.custom_claims.insert(label, value);
        self
    }
}
