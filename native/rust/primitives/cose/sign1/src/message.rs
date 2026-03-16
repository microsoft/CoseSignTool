// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CoseSign1Message parsing and verification.
//!
//! Provides the `CoseSign1Message` type for parsing and verifying
//! COSE_Sign1 messages per RFC 9052.
//!
//! All CBOR operations use the compile-time-selected provider singleton.
//! which is set once during parsing and reused for all subsequent operations.

use std::sync::Arc;

use cbor_primitives::{CborDecoder, CborEncoder, CborProvider, CborType};
use crypto_primitives::CryptoVerifier;

use crate::algorithms::COSE_SIGN1_TAG;
use crate::error::{CoseKeyError, CoseSign1Error};
use crate::headers::{CoseHeaderLabel, CoseHeaderMap, CoseHeaderValue, ProtectedHeader};
use crate::payload::StreamingPayload;
use crate::provider::{cbor_provider, CborProviderImpl};
use crate::sig_structure::{build_sig_structure, SizedRead, SizedReader};

/// A parsed COSE_Sign1 message.
///
/// COSE_Sign1 structure per RFC 9052:
///
/// ```text
/// COSE_Sign1 = [
///     protected : bstr .cbor protected-header-map,
///     unprotected : unprotected-header-map,
///     payload : bstr / nil,
///     signature : bstr
/// ]
/// ```
///
/// The message may be optionally wrapped in a CBOR tag (18).
///
/// All CBOR operations use the compile-time-selected provider singleton.
/// allowing further CBOR operations without needing to know the concrete provider type.
#[derive(Clone)]
pub struct CoseSign1Message {
    /// Protected headers (integrity protected) with their raw CBOR bytes.
    pub protected: ProtectedHeader,
    /// Unprotected headers (not integrity protected).
    pub unprotected: CoseHeaderMap,
    /// Payload bytes (None if detached).
    pub payload: Option<Vec<u8>>,
    /// Signature bytes.
    pub signature: Vec<u8>,
}

impl std::fmt::Debug for CoseSign1Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoseSign1Message")
            .field("protected", &self.protected)
            .field("unprotected", &self.unprotected)
            .field("payload", &self.payload)
            .field("signature", &self.signature)
            .finish()
    }
}

impl CoseSign1Message {
    /// Parses a COSE_Sign1 message from CBOR bytes.
    ///
    /// Handles both tagged (tag 18) and untagged messages.
    /// Uses the compile-time-selected CBOR provider.
    ///
    /// # Arguments
    ///
    /// * `data` - The CBOR-encoded message bytes
    ///
    /// # Example
    ///
    /// ```ignore
    /// let msg = CoseSign1Message::parse(&bytes)?;
    /// ```
    pub fn parse(data: &[u8]) -> Result<Self, CoseSign1Error> {
        let mut decoder = crate::provider::decoder(data);

        // Check for optional tag
        let typ = decoder
            .peek_type()
            .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;

        if typ == CborType::Tag {
            let tag = decoder
                .decode_tag()
                .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
            if tag != COSE_SIGN1_TAG {
                return Err(CoseSign1Error::InvalidMessage(format!(
                    "unexpected COSE tag: expected {}, got {}",
                    COSE_SIGN1_TAG, tag
                )));
            }
        }

        // Decode the array
        let len = decoder
            .decode_array_len()
            .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;

        match len {
            Some(4) => {}
            Some(n) => {
                return Err(CoseSign1Error::InvalidMessage(format!(
                    "COSE_Sign1 must have 4 elements, got {}",
                    n
                )))
            }
            None => {
                return Err(CoseSign1Error::InvalidMessage(
                    "COSE_Sign1 must be definite-length array".to_string(),
                ))
            }
        }

        // 1. Protected header (bstr containing CBOR map)
        let protected_bytes = decoder
            .decode_bstr_owned()
            .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;

        let protected = ProtectedHeader::decode(protected_bytes)?;

        // 2. Unprotected header (map)
        let unprotected = Self::decode_unprotected_header(&mut decoder)?;

        // 3. Payload (bstr or null)
        let payload = Self::decode_payload(&mut decoder)?;

        // 4. Signature (bstr)
        let signature = decoder
            .decode_bstr_owned()
            .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;

        Ok(Self {
            protected,
            unprotected,
            payload,
            signature,
        })
    }

    /// Returns a reference to the compile-time-selected CBOR provider.
    ///
    /// Convenience method so consumers can access encoding/decoding
    /// without importing cbor_primitives directly.
    #[inline]
    pub fn provider(&self) -> &'static CborProviderImpl {
        cbor_provider()
    }

    /// Parse a nested COSE_Sign1 message.
    pub fn parse_inner(&self, data: &[u8]) -> Result<Self, CoseSign1Error> {
        Self::parse(data)
    }

    /// Returns the raw protected header bytes (for verification).
    pub fn protected_header_bytes(&self) -> &[u8] {
        self.protected.as_bytes()
    }

    /// Returns the algorithm from the protected header.
    pub fn alg(&self) -> Option<i64> {
        self.protected.alg()
    }

    /// Returns a reference to the parsed protected headers.
    pub fn protected_headers(&self) -> &CoseHeaderMap {
        self.protected.headers()
    }

    /// Returns true if the payload is detached.
    pub fn is_detached(&self) -> bool {
        self.payload.is_none()
    }

    /// Verifies the signature on an embedded payload.
    ///
    /// # Arguments
    ///
    /// * `verifier` - The verifier to use
    /// * `external_aad` - Optional external additional authenticated data
    ///
    /// # Returns
    ///
    /// `true` if verification succeeds, `false` otherwise.
    ///
    /// # Errors
    ///
    /// Returns `PayloadMissing` if the payload is detached.
    pub fn verify(
        &self,
        verifier: &dyn CryptoVerifier,
        external_aad: Option<&[u8]>,
    ) -> Result<bool, CoseSign1Error> {
        let payload = self
            .payload
            .as_ref()
            .ok_or(CoseSign1Error::PayloadMissing)?;
        let sig_structure = build_sig_structure(self.protected.as_bytes(), external_aad, payload)?;
        verifier
            .verify(&sig_structure, &self.signature)
            .map_err(CoseKeyError::from)
            .map_err(CoseSign1Error::from)
    }

    /// Verifies the signature with a detached payload.
    ///
    /// # Arguments
    ///
    /// * `verifier` - The verifier to use
    /// * `payload` - The detached payload bytes
    /// * `external_aad` - Optional external additional authenticated data
    pub fn verify_detached(
        &self,
        verifier: &dyn CryptoVerifier,
        payload: &[u8],
        external_aad: Option<&[u8]>,
    ) -> Result<bool, CoseSign1Error> {
        let sig_structure = build_sig_structure(self.protected.as_bytes(), external_aad, payload)?;
        verifier
            .verify(&sig_structure, &self.signature)
            .map_err(CoseKeyError::from)
            .map_err(CoseSign1Error::from)
    }

    /// Verifies the signature with a streaming detached payload.
    ///
    /// # Arguments
    ///
    /// * `verifier` - The verifier to use
    /// * `payload` - A [`SizedRead`] providing the detached payload (reader + known length)
    /// * `external_aad` - Optional external additional authenticated data
    ///
    /// # Example
    ///
    /// ```ignore
    /// // File implements SizedRead directly
    /// let mut file = std::fs::File::open("payload.bin")?;
    /// msg.verify_detached_streaming(&verifier, &mut file, None)?;
    ///
    /// // Or wrap a reader with known length
    /// let mut payload = SizedReader::new(reader, content_length);
    /// msg.verify_detached_streaming(&verifier, &mut payload, None)?;
    /// ```
    pub fn verify_detached_streaming(
        &self,
        verifier: &dyn CryptoVerifier,
        payload: &mut dyn SizedRead,
        external_aad: Option<&[u8]>,
    ) -> Result<bool, CoseSign1Error> {
        // Buffer the payload into memory
        let payload_len = payload
            .len()
            .map_err(|e| CoseSign1Error::IoError(e.to_string()))?;
        let mut buf = Vec::with_capacity(payload_len as usize);
        std::io::Read::read_to_end(payload, &mut buf)
            .map_err(|e| CoseSign1Error::IoError(e.to_string()))?;
        self.verify_detached(verifier, &buf, external_aad)
    }

    /// Verifies the signature with a detached payload from a plain `Read`.
    ///
    /// Use this when you have a reader with unknown length. The entire
    /// payload is read into memory first to determine the length.
    ///
    /// For large payloads with known length, prefer `verify_detached_streaming` with
    /// `SizedReader::new(reader, len)` instead.
    ///
    /// # Arguments
    ///
    /// * `verifier` - The verifier to use
    /// * `payload` - A reader providing the detached payload (will be buffered into memory)
    /// * `external_aad` - Optional external additional authenticated data
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Network stream with unknown length
    /// let mut stream = get_network_stream();
    /// msg.verify_detached_read(&verifier, &mut stream, None)?;
    /// ```
    pub fn verify_detached_read(
        &self,
        verifier: &dyn CryptoVerifier,
        payload: &mut dyn std::io::Read,
        external_aad: Option<&[u8]>,
    ) -> Result<bool, CoseSign1Error> {
        let mut buf = Vec::new();
        std::io::Read::read_to_end(payload, &mut buf)
            .map_err(|e| CoseSign1Error::IoError(e.to_string()))?;
        self.verify_detached(verifier, &buf, external_aad)
    }

    /// Verifies the signature with a streaming payload source.
    ///
    /// # Arguments
    ///
    /// * `verifier` - The verifier to use
    /// * `payload` - A streaming payload source
    /// * `external_aad` - Optional external additional authenticated data
    pub fn verify_streaming(
        &self,
        verifier: &dyn CryptoVerifier,
        payload: Arc<dyn StreamingPayload>,
        external_aad: Option<&[u8]>,
    ) -> Result<bool, CoseSign1Error> {
        let reader = payload.open().map_err(CoseSign1Error::from)?;
        let len = payload.size();
        let mut sized = SizedReader::new(reader, len);
        self.verify_detached_streaming(verifier, &mut sized, external_aad)
    }

    /// Returns the raw CBOR-encoded Sig_structure bytes for this message.
    ///
    /// The Sig_structure is the data that is actually signed/verified:
    ///
    /// ```text
    /// Sig_structure = [
    ///     context: "Signature1",
    ///     body_protected: bstr,  // This message's protected header bytes
    ///     external_aad: bstr,
    ///     payload: bstr
    /// ]
    /// ```
    ///
    /// # When to Use
    ///
    /// For most use cases, prefer the `verify*` methods which handle Sig_structure
    /// construction internally. This method exists for special cases where you need
    /// direct access to the Sig_structure bytes, such as:
    ///
    /// - MST receipt verification where the "payload" is a merkle accumulator
    ///   computed externally rather than the message's actual payload
    /// - Custom verification flows with non-standard key types
    /// - Debugging and testing
    ///
    /// # Arguments
    ///
    /// * `payload` - The payload bytes to include in the Sig_structure
    /// * `external_aad` - Optional external additional authenticated data
    ///
    /// # Example
    ///
    /// ```ignore
    /// // For MST receipt verification with computed accumulator
    /// let accumulator = compute_merkle_accumulator(&proof, &leaf_hash);
    /// let sig_structure = receipt.sig_structure_bytes(&accumulator, None)?;
    /// verify_with_jwk(&sig_structure, &receipt.signature, &jwk)?;
    /// ```
    pub fn sig_structure_bytes(
        &self,
        payload: &[u8],
        external_aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, CoseSign1Error> {
        crate::build_sig_structure(
            self.protected.as_bytes(),
            external_aad,
            payload,
        )
    }

    /// Encodes the message to CBOR bytes using the stored provider.
    ///
    /// # Arguments
    ///
    /// * `tagged` - If true, wraps the message in CBOR tag 18
    pub fn encode(&self, tagged: bool) -> Result<Vec<u8>, CoseSign1Error> {
        let provider = cbor_provider();
        let mut encoder = provider.encoder();

        // Optional tag
        if tagged {
            encoder
                .encode_tag(COSE_SIGN1_TAG)
                .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
        }

        // Array of 4 elements
        encoder
            .encode_array(4)
            .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;

        // 1. Protected header bytes
        encoder
            .encode_bstr(self.protected.as_bytes())
            .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;

        // 2. Unprotected header
        let unprotected_bytes = self.unprotected.encode()?;
        encoder
            .encode_raw(&unprotected_bytes)
            .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;

        // 3. Payload
        match &self.payload {
            Some(p) => encoder
                .encode_bstr(p)
                .map_err(|e| CoseSign1Error::CborError(e.to_string()))?,
            None => encoder
                .encode_null()
                .map_err(|e| CoseSign1Error::CborError(e.to_string()))?,
        }

        // 4. Signature
        encoder
            .encode_bstr(&self.signature)
            .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;

        Ok(encoder.into_bytes())
    }

    fn decode_unprotected_header(
        decoder: &mut crate::provider::Decoder<'_>,
    ) -> Result<CoseHeaderMap, CoseSign1Error> {
        let len = decoder
            .decode_map_len()
            .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;

        if len == Some(0) {
            return Ok(CoseHeaderMap::new());
        }

        let mut headers = CoseHeaderMap::new();

        match len {
            Some(n) => {
                for _ in 0..n {
                    let label = Self::decode_header_label(decoder)?;
                    let value = Self::decode_header_value(decoder)?;
                    headers.insert(label, value);
                }
            }
            None => {
                // Indefinite length
                loop {
                    if decoder
                        .is_break()
                        .map_err(|e| CoseSign1Error::CborError(e.to_string()))?
                    {
                        decoder
                            .decode_break()
                            .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
                        break;
                    }
                    let label = Self::decode_header_label(decoder)?;
                    let value = Self::decode_header_value(decoder)?;
                    headers.insert(label, value);
                }
            }
        }

        Ok(headers)
    }

    fn decode_header_label(
        decoder: &mut crate::provider::Decoder<'_>,
    ) -> Result<CoseHeaderLabel, CoseSign1Error> {
        let typ = decoder
            .peek_type()
            .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;

        match typ {
            CborType::UnsignedInt | CborType::NegativeInt => {
                let v = decoder
                    .decode_i64()
                    .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
                Ok(CoseHeaderLabel::Int(v))
            }
            CborType::TextString => {
                let v = decoder
                    .decode_tstr_owned()
                    .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
                Ok(CoseHeaderLabel::Text(v))
            }
            _ => Err(CoseSign1Error::InvalidMessage(format!(
                "invalid header label type: {:?}",
                typ
            ))),
        }
    }

    fn decode_header_value(
        decoder: &mut crate::provider::Decoder<'_>,
    ) -> Result<CoseHeaderValue, CoseSign1Error> {
        let typ = decoder
            .peek_type()
            .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;

        match typ {
            CborType::UnsignedInt => {
                let v = decoder
                    .decode_u64()
                    .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
                if v <= i64::MAX as u64 {
                    Ok(CoseHeaderValue::Int(v as i64))
                } else {
                    Ok(CoseHeaderValue::Uint(v))
                }
            }
            CborType::NegativeInt => {
                let v = decoder
                    .decode_i64()
                    .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
                Ok(CoseHeaderValue::Int(v))
            }
            CborType::ByteString => {
                let v = decoder
                    .decode_bstr_owned()
                    .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
                Ok(CoseHeaderValue::Bytes(v))
            }
            CborType::TextString => {
                let v = decoder
                    .decode_tstr_owned()
                    .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
                Ok(CoseHeaderValue::Text(v))
            }
            CborType::Array => {
                let len = decoder
                    .decode_array_len()
                    .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;

                let mut arr = Vec::new();
                match len {
                    Some(n) => {
                        for _ in 0..n {
                            arr.push(Self::decode_header_value(decoder)?);
                        }
                    }
                    None => loop {
                        if decoder
                            .is_break()
                            .map_err(|e| CoseSign1Error::CborError(e.to_string()))?
                        {
                            decoder
                                .decode_break()
                                .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
                            break;
                        }
                        arr.push(Self::decode_header_value(decoder)?);
                    },
                }
                Ok(CoseHeaderValue::Array(arr))
            }
            CborType::Map => {
                let len = decoder
                    .decode_map_len()
                    .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;

                let mut pairs = Vec::new();
                match len {
                    Some(n) => {
                        for _ in 0..n {
                            let k = Self::decode_header_label(decoder)?;
                            let v = Self::decode_header_value(decoder)?;
                            pairs.push((k, v));
                        }
                    }
                    None => loop {
                        if decoder
                            .is_break()
                            .map_err(|e| CoseSign1Error::CborError(e.to_string()))?
                        {
                            decoder
                                .decode_break()
                                .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
                            break;
                        }
                        let k = Self::decode_header_label(decoder)?;
                        let v = Self::decode_header_value(decoder)?;
                        pairs.push((k, v));
                    },
                }
                Ok(CoseHeaderValue::Map(pairs))
            }
            CborType::Tag => {
                let tag = decoder
                    .decode_tag()
                    .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
                let inner = Self::decode_header_value(decoder)?;
                Ok(CoseHeaderValue::Tagged(tag, Box::new(inner)))
            }
            CborType::Bool => {
                let v = decoder
                    .decode_bool()
                    .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
                Ok(CoseHeaderValue::Bool(v))
            }
            CborType::Null => {
                decoder
                    .decode_null()
                    .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
                Ok(CoseHeaderValue::Null)
            }
            CborType::Undefined => {
                decoder
                    .decode_undefined()
                    .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
                Ok(CoseHeaderValue::Undefined)
            }
            CborType::Float16 | CborType::Float32 | CborType::Float64 => {
                let v = decoder
                    .decode_f64()
                    .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
                Ok(CoseHeaderValue::Float(v))
            }
            _ => {
                // Skip unknown types
                decoder
                    .skip()
                    .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
                Ok(CoseHeaderValue::Null)
            }
        }
    }

    fn decode_payload(
        decoder: &mut crate::provider::Decoder<'_>,
    ) -> Result<Option<Vec<u8>>, CoseSign1Error> {
        if decoder
            .is_null()
            .map_err(|e| CoseSign1Error::CborError(e.to_string()))?
        {
            decoder
                .decode_null()
                .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
            return Ok(None);
        }

        let payload = decoder
            .decode_bstr_owned()
            .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
        Ok(Some(payload))
    }
}
