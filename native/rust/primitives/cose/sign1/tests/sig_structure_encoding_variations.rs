// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional sig_structure encoding variation coverage.

use cbor_primitives::{CborProvider, CborDecoder};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_primitives::sig_structure::{
    build_sig_structure, build_sig_structure_prefix, SizedReader
};
use cose_sign1_primitives::SizedRead;

#[test]
fn test_build_sig_structure_with_external_aad() {
    let protected = b"protected_header";
    let external_aad = b"external_additional_authenticated_data";
    let payload = b"test_payload_for_sig_structure";
    
    let result = build_sig_structure(protected, Some(external_aad), payload).unwrap();
    
    // Parse and verify structure
    let provider = EverParseCborProvider;
    let mut decoder = provider.decoder(&result);
    
    let len = decoder.decode_array_len().unwrap();
    assert_eq!(len, Some(4)); // ["Signature1", protected, external_aad, payload]
    
    // Context string
    let context = decoder.decode_tstr().unwrap();
    assert_eq!(context, "Signature1");
    
    // Protected header
    let protected_decoded = decoder.decode_bstr().unwrap();
    assert_eq!(protected_decoded, protected);
    
    // External AAD
    let aad_decoded = decoder.decode_bstr().unwrap();
    assert_eq!(aad_decoded, external_aad);
    
    // Payload
    let payload_decoded = decoder.decode_bstr().unwrap();
    assert_eq!(payload_decoded, payload);
}

#[test]
fn test_build_sig_structure_without_external_aad() {
    let protected = b"protected_header";
    let payload = b"test_payload_no_aad";
    
    let result = build_sig_structure(protected, None, payload).unwrap();
    
    // Parse and verify structure
    let provider = EverParseCborProvider;
    let mut decoder = provider.decoder(&result);
    
    let len = decoder.decode_array_len().unwrap();
    assert_eq!(len, Some(4));
    
    // Context string
    let context = decoder.decode_tstr().unwrap();
    assert_eq!(context, "Signature1");
    
    // Protected header
    let protected_decoded = decoder.decode_bstr().unwrap();
    assert_eq!(protected_decoded, protected);
    
    // External AAD (should be empty bstr)
    let aad_decoded = decoder.decode_bstr().unwrap();
    assert_eq!(aad_decoded, b"");
    
    // Payload
    let payload_decoded = decoder.decode_bstr().unwrap();
    assert_eq!(payload_decoded, payload);
}

#[test]
fn test_build_sig_structure_empty_protected() {
    let protected = b"";
    let payload = b"payload_empty_protected";
    
    let result = build_sig_structure(protected, None, payload).unwrap();
    
    // Should succeed with empty protected header
    assert!(result.len() > 0);
    
    let provider = EverParseCborProvider;
    let mut decoder = provider.decoder(&result);
    
    decoder.decode_array_len().unwrap();
    decoder.decode_tstr().unwrap(); // context
    
    let protected_decoded = decoder.decode_bstr().unwrap();
    assert_eq!(protected_decoded, b"");
}

#[test]
fn test_build_sig_structure_empty_payload() {
    let protected = b"protected_for_empty";
    let payload = b"";
    
    let result = build_sig_structure(protected, None, payload).unwrap();
    
    // Should succeed with empty payload
    assert!(result.len() > 0);
    
    let provider = EverParseCborProvider;
    let mut decoder = provider.decoder(&result);
    
    decoder.decode_array_len().unwrap();
    decoder.decode_tstr().unwrap(); // context
    decoder.decode_bstr().unwrap(); // protected
    decoder.decode_bstr().unwrap(); // aad
    
    let payload_decoded = decoder.decode_bstr().unwrap();
    assert_eq!(payload_decoded, b"");
}

#[test]
fn test_build_sig_structure_prefix() {
    let protected = b"protected_for_prefix";
    let external_aad = b"aad_for_prefix";
    let payload_len = 1234u64;
    
    let prefix = build_sig_structure_prefix(protected, Some(external_aad), payload_len).unwrap();
    
    // Parse the prefix - it should contain everything except the payload
    let provider = EverParseCborProvider;
    let mut decoder = provider.decoder(&prefix);
    
    let len = decoder.decode_array_len().unwrap();
    assert_eq!(len, Some(4));
    
    // Context
    let context = decoder.decode_tstr().unwrap();
    assert_eq!(context, "Signature1");
    
    // Protected
    let protected_decoded = decoder.decode_bstr().unwrap();
    assert_eq!(protected_decoded, protected);
    
    // External AAD
    let aad_decoded = decoder.decode_bstr().unwrap();
    assert_eq!(aad_decoded, external_aad);
    
    // Payload bstr header (but not the payload content)
    // The prefix ends with the bstr header for the payload
    // We can't easily verify this without knowing CBOR encoding details
}

#[test]
fn test_build_sig_structure_prefix_no_aad() {
    let protected = b"protected_no_aad_prefix";
    let payload_len = 5678u64;
    
    let prefix = build_sig_structure_prefix(protected, None, payload_len).unwrap();
    
    assert!(prefix.len() > 0);
    
    // Should contain the array header + context + protected + empty aad + payload bstr header
    let provider = EverParseCborProvider;
    let mut decoder = provider.decoder(&prefix);
    
    let len = decoder.decode_array_len().unwrap();
    assert_eq!(len, Some(4));
    
    let context = decoder.decode_tstr().unwrap();
    assert_eq!(context, "Signature1");
    
    let protected_decoded = decoder.decode_bstr().unwrap();
    assert_eq!(protected_decoded, protected);
    
    let aad_decoded = decoder.decode_bstr().unwrap();
    assert_eq!(aad_decoded, b"");
}

#[test]
fn test_sig_structure_large_payload() {
    let protected = b"protected_large";
    let large_payload = vec![0xAB; 10000]; // 10KB of 0xAB bytes
    
    let result = build_sig_structure(protected, None, &large_payload).unwrap();
    
    // Should handle large payloads correctly
    assert!(result.len() > large_payload.len()); // Should be larger due to CBOR overhead
    
    let provider = EverParseCborProvider;
    let mut decoder = provider.decoder(&result);
    
    decoder.decode_array_len().unwrap();
    decoder.decode_tstr().unwrap(); // context
    decoder.decode_bstr().unwrap(); // protected
    decoder.decode_bstr().unwrap(); // aad
    
    let payload_decoded = decoder.decode_bstr().unwrap();
    assert_eq!(payload_decoded.len(), 10000);
    assert!(payload_decoded.iter().all(|&b| b == 0xAB));
}

#[test]
fn test_sized_reader_basic_usage() {
    use std::io::Cursor;
    
    let data = b"test data for sized reader";
    let cursor = Cursor::new(data);
    let mut sized_reader = SizedReader::new(cursor, data.len() as u64);
    
    // Test length
    assert_eq!(sized_reader.len().unwrap(), data.len() as u64);
    
    // Test reading
    let mut buffer = Vec::new();
    use std::io::Read;
    sized_reader.read_to_end(&mut buffer).unwrap();
    assert_eq!(buffer, data);
}

#[test]
fn test_sized_reader_length_mismatch() {
    use std::io::Cursor;
    
    let data = b"short data";
    let cursor = Cursor::new(data);
    let mut sized_reader = SizedReader::new(cursor, 1000); // Claim it's much larger
    
    // Length should return what we told it
    assert_eq!(sized_reader.len().unwrap(), 1000);
    
    // But reading should only get the actual data
    let mut buffer = Vec::new();
    use std::io::Read;
    let bytes_read = sized_reader.read_to_end(&mut buffer).unwrap();
    assert_eq!(bytes_read, data.len());
    assert_eq!(buffer, data);
}

#[test]
fn test_build_sig_structure_edge_cases() {
    // Test with maximum size values that might cause CBOR encoding issues
    let protected = vec![0xFF; 255]; // Moderately large protected header
    let external_aad = vec![0xEE; 512]; // Larger external AAD
    let payload = vec![0xDD; 1024]; // Larger payload
    
    let result = build_sig_structure(&protected, Some(&external_aad), &payload);
    
    // Should handle reasonably large inputs without issues
    assert!(result.is_ok());
    
    let encoded = result.unwrap();
    assert!(encoded.len() > protected.len() + external_aad.len() + payload.len());
}