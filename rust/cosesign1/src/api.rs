// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::io::Read;

use crate::{cose_sign1, cose_sign1_verifier, CoseAlgorithm, ReadSeek, VerifyOptions};

/// Parse a COSE_Sign1 structure from its CBOR encoding.
pub fn parse_cose_sign1(input: &[u8]) -> Result<cosesign1_abstractions::ParsedCoseSign1, String> {
    cose_sign1::parse_cose_sign1(input)
}

/// Parse a COSE_Sign1 structure from an input stream.
pub fn parse_cose_sign1_from_reader(
    reader: impl Read,
) -> Result<cosesign1_abstractions::ParsedCoseSign1, String> {
    cose_sign1::parse_cose_sign1_from_reader(reader)
}

/// Parse a COSE_Sign1 structure from an input stream, enforcing a maximum size.
pub fn parse_cose_sign1_from_reader_with_max_len(
    reader: impl Read,
    max_len: usize,
) -> Result<cosesign1_abstractions::ParsedCoseSign1, String> {
    cose_sign1::parse_cose_sign1_from_reader_with_max_len(reader, max_len)
}

/// Encode the COSE Sig_structure bytes for COSE_Sign1.
pub fn encode_signature1_sig_structure(
    msg: &cosesign1_abstractions::ParsedCoseSign1,
    external_payload: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
    cose_sign1::encode_signature1_sig_structure(msg, external_payload)
}

/// Verify a COSE_Sign1 signature.
pub fn verify_cose_sign1(
    validator_name: &str,
    cose_sign1: &[u8],
    options: &VerifyOptions,
) -> cosesign1_abstractions::ValidationResult {
    cose_sign1_verifier::verify_cose_sign1(validator_name, cose_sign1, options)
}

pub fn verify_parsed_cose_sign1(
    validator_name: &str,
    parsed: &cosesign1_abstractions::ParsedCoseSign1,
    external_payload: Option<&[u8]>,
    options: &VerifyOptions,
) -> cosesign1_abstractions::ValidationResult {
    cose_sign1_verifier::verify_parsed_cose_sign1(validator_name, parsed, external_payload, options)
}

pub fn verify_parsed_cose_sign1_detached_payload_reader(
    validator_name: &str,
    parsed: &cosesign1_abstractions::ParsedCoseSign1,
    payload_reader: &mut dyn ReadSeek,
    options: &VerifyOptions,
) -> cosesign1_abstractions::ValidationResult {
    cose_sign1_verifier::verify_parsed_cose_sign1_detached_payload_reader(
        validator_name,
        parsed,
        payload_reader,
        options,
    )
}

pub fn verify_sig_structure(
    alg: CoseAlgorithm,
    public_key_bytes: &[u8],
    sig_structure: &[u8],
    signature: &[u8],
) -> Result<(), (String, String)> {
    cose_sign1_verifier::verify_sig_structure(alg, public_key_bytes, sig_structure, signature)
}
