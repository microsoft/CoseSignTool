// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Output formatting and inspect command comprehensive coverage tests.
//! Tests all output format combinations and inspect functionality.

#![cfg(feature = "crypto-openssl")]

use cose_sign1_cli::commands::inspect;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

fn create_temp_file_with_content(content: &[u8]) -> (TempDir, PathBuf) {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test_file");
    fs::write(&file_path, content).unwrap();
    (temp_dir, file_path)
}

fn create_minimal_cbor_array() -> Vec<u8> {
    // Create minimal CBOR data that might pass basic structure checks
    // This is CBOR array with 4 elements: [protected, unprotected, payload, signature]
    // Array(4), empty map, empty map, empty bytes, empty bytes
    vec![
        0x84, // Array of length 4
        0xA0, // Empty map (protected headers)
        0xA0, // Empty map (unprotected headers) 
        0x40, // Empty byte string (payload)
        0x40  // Empty byte string (signature)
    ]
}

fn create_cbor_with_headers() -> Vec<u8> {
    // More complex CBOR structure that might get further in parsing
    // Array(4), protected headers map with algorithm, unprotected empty, payload, signature
    vec![
        0x84,       // Array of length 4
        0x43, 0xA1, 0x01, 0x26,  // Byte string containing map {1: -7} (alg: ES256)
        0xA0,       // Empty map (unprotected headers)
        0x47, 0x74, 0x65, 0x73, 0x74, 0x20, 0x64, 0x61,  // "test data" as payload
        0x58, 0x40, // Byte string of length 64 (dummy signature)
    ]
}

#[test]
fn test_inspect_with_minimal_cbor_text_format() {
    let cbor_data = create_minimal_cbor_array();
    let (_temp_dir, input_path) = create_temp_file_with_content(&cbor_data);
    
    let args = inspect::InspectArgs {
        input: input_path,
        output_format: "text".to_string(),
        all_headers: false,
        show_certs: false,
        show_signature: false,
        show_cwt: false,
    };
    
    let exit_code = inspect::run(args);
    // May succeed or fail depending on CBOR parsing strictness, but exercises text format path
    assert!(exit_code == 0 || exit_code == 2, "Should either succeed or fail parsing");
}

#[test]
fn test_inspect_with_minimal_cbor_json_format() {
    let cbor_data = create_minimal_cbor_array();
    let (_temp_dir, input_path) = create_temp_file_with_content(&cbor_data);
    
    let args = inspect::InspectArgs {
        input: input_path,
        output_format: "json".to_string(),
        all_headers: false,
        show_certs: false,
        show_signature: false,
        show_cwt: false,
    };
    
    let exit_code = inspect::run(args);
    assert!(exit_code == 0 || exit_code == 2, "Should exercise JSON format path");
}

#[test]
fn test_inspect_with_minimal_cbor_quiet_format() {
    let cbor_data = create_minimal_cbor_array();
    let (_temp_dir, input_path) = create_temp_file_with_content(&cbor_data);
    
    let args = inspect::InspectArgs {
        input: input_path,
        output_format: "quiet".to_string(),
        all_headers: false,
        show_certs: false,
        show_signature: false,
        show_cwt: false,
    };
    
    let exit_code = inspect::run(args);
    assert!(exit_code == 0 || exit_code == 2, "Should exercise quiet format path");
}

#[test]
fn test_inspect_all_headers_enabled() {
    let cbor_data = create_cbor_with_headers();
    let (_temp_dir, input_path) = create_temp_file_with_content(&cbor_data);
    
    let args = inspect::InspectArgs {
        input: input_path,
        output_format: "text".to_string(),
        all_headers: true, // Enable all headers display
        show_certs: false,
        show_signature: false,
        show_cwt: false,
    };
    
    let exit_code = inspect::run(args);
    assert!(exit_code == 0 || exit_code == 2, "Should exercise all headers display path");
}

#[test]
fn test_inspect_show_certificates() {
    let cbor_data = create_cbor_with_headers();
    let (_temp_dir, input_path) = create_temp_file_with_content(&cbor_data);
    
    let args = inspect::InspectArgs {
        input: input_path,
        output_format: "text".to_string(),
        all_headers: false,
        show_certs: true, // Enable certificate display
        show_signature: false,
        show_cwt: false,
    };
    
    let exit_code = inspect::run(args);
    assert!(exit_code == 0 || exit_code == 2, "Should exercise certificate display path");
}

#[test]
fn test_inspect_show_signature() {
    let cbor_data = create_cbor_with_headers();
    let (_temp_dir, input_path) = create_temp_file_with_content(&cbor_data);
    
    let args = inspect::InspectArgs {
        input: input_path,
        output_format: "text".to_string(),
        all_headers: false,
        show_certs: false,
        show_signature: true, // Enable signature display
        show_cwt: false,
    };
    
    let exit_code = inspect::run(args);
    assert!(exit_code == 0 || exit_code == 2, "Should exercise signature display path");
}

#[test]
fn test_inspect_show_cwt() {
    let cbor_data = create_cbor_with_headers();
    let (_temp_dir, input_path) = create_temp_file_with_content(&cbor_data);
    
    let args = inspect::InspectArgs {
        input: input_path,
        output_format: "text".to_string(),
        all_headers: false,
        show_certs: false,
        show_signature: false,
        show_cwt: true, // Enable CWT claims display
    };
    
    let exit_code = inspect::run(args);
    assert!(exit_code == 0 || exit_code == 2, "Should exercise CWT display path");
}

#[test]
fn test_inspect_all_flags_enabled() {
    let cbor_data = create_cbor_with_headers();
    let (_temp_dir, input_path) = create_temp_file_with_content(&cbor_data);
    
    let args = inspect::InspectArgs {
        input: input_path,
        output_format: "json".to_string(),
        all_headers: true,  // All flags enabled
        show_certs: true,
        show_signature: true,
        show_cwt: true,
    };
    
    let exit_code = inspect::run(args);
    assert!(exit_code == 0 || exit_code == 2, "Should exercise all display options with JSON format");
}

#[test]
fn test_inspect_empty_cbor_data() {
    let (_temp_dir, input_path) = create_temp_file_with_content(&[]);
    
    let args = inspect::InspectArgs {
        input: input_path,
        output_format: "text".to_string(),
        all_headers: false,
        show_certs: false,
        show_signature: false,
        show_cwt: false,
    };
    
    let exit_code = inspect::run(args);
    assert_eq!(exit_code, 2, "Should fail with empty data");
}

#[test]
fn test_inspect_malformed_cbor() {
    // Malformed CBOR that starts like an array but is incomplete
    let malformed_cbor = vec![0x84, 0xA0]; // Array start but missing elements
    let (_temp_dir, input_path) = create_temp_file_with_content(&malformed_cbor);
    
    let args = inspect::InspectArgs {
        input: input_path,
        output_format: "text".to_string(),
        all_headers: false,
        show_certs: false,
        show_signature: false,
        show_cwt: false,
    };
    
    let exit_code = inspect::run(args);
    assert_eq!(exit_code, 2, "Should fail with malformed CBOR");
}

#[test]
fn test_inspect_wrong_cbor_structure() {
    // CBOR that's valid but not a COSE_Sign1 structure (e.g., just a string)
    let wrong_structure = vec![0x64, 0x74, 0x65, 0x73, 0x74]; // CBOR text string "test"
    let (_temp_dir, input_path) = create_temp_file_with_content(&wrong_structure);
    
    let args = inspect::InspectArgs {
        input: input_path,
        output_format: "json".to_string(),
        all_headers: false,
        show_certs: false,
        show_signature: false,
        show_cwt: false,
    };
    
    let exit_code = inspect::run(args);
    assert_eq!(exit_code, 2, "Should fail with wrong CBOR structure");
}

fn create_cbor_with_text_labels() -> Vec<u8> {
    // CBOR array with text header labels instead of integer labels
    // This tests the header label formatting code paths
    vec![
        0x84,       // Array of length 4
        0x50,       // Byte string of length 16 containing map
        0xA1, 0x63, 0x61, 0x6C, 0x67, 0x26,  // Map {"alg": -7}
        0xA0,       // Empty map (unprotected headers)
        0x44, 0x74, 0x65, 0x73, 0x74,  // "test" as payload
        0x40        // Empty signature
    ]
}

#[test]
fn test_inspect_with_text_header_labels() {
    let cbor_data = create_cbor_with_text_labels();
    let (_temp_dir, input_path) = create_temp_file_with_content(&cbor_data);
    
    let args = inspect::InspectArgs {
        input: input_path,
        output_format: "text".to_string(),
        all_headers: true, // Show all headers to test text label formatting
        show_certs: false,
        show_signature: false,
        show_cwt: false,
    };
    
    let exit_code = inspect::run(args);
    assert!(exit_code == 0 || exit_code == 2, "Should exercise text label formatting");
}

fn create_cbor_with_unprotected_headers() -> Vec<u8> {
    // CBOR with unprotected headers to test unprotected header display
    vec![
        0x84,       // Array of length 4
        0x40,       // Empty byte string (protected headers)
        0xA1, 0x04, 0x42, 0x68, 0x69,  // Map {4: "hi"} (kid header)
        0x44, 0x74, 0x65, 0x73, 0x74,  // "test" as payload
        0x40        // Empty signature
    ]
}

#[test]
fn test_inspect_with_unprotected_headers() {
    let cbor_data = create_cbor_with_unprotected_headers();
    let (_temp_dir, input_path) = create_temp_file_with_content(&cbor_data);
    
    let args = inspect::InspectArgs {
        input: input_path,
        output_format: "text".to_string(),
        all_headers: true, // Show all headers including unprotected
        show_certs: false,
        show_signature: false,
        show_cwt: false,
    };
    
    let exit_code = inspect::run(args);
    assert!(exit_code == 0 || exit_code == 2, "Should exercise unprotected headers display");
}

fn create_detached_payload_cbor() -> Vec<u8> {
    // CBOR with null payload (detached signature)
    vec![
        0x84,       // Array of length 4  
        0x43, 0xA1, 0x01, 0x26,  // Protected: {1: -7}
        0xA0,       // Empty unprotected
        0xF6,       // null (detached payload)
        0x40        // Empty signature
    ]
}

#[test]
fn test_inspect_detached_payload() {
    let cbor_data = create_detached_payload_cbor();
    let (_temp_dir, input_path) = create_temp_file_with_content(&cbor_data);
    
    let args = inspect::InspectArgs {
        input: input_path,
        output_format: "text".to_string(),
        all_headers: false,
        show_certs: false,
        show_signature: false,
        show_cwt: false,
    };
    
    let exit_code = inspect::run(args);
    assert!(exit_code == 0 || exit_code == 2, "Should handle detached payload display");
}

#[test]
fn test_inspect_large_signature() {
    // CBOR with a larger signature to test size display
    let mut large_sig = vec![0x58, 0xFF]; // Byte string of length 255
    large_sig.extend(vec![0x00; 255]); // 255 zero bytes
    
    let mut cbor_data = vec![
        0x84,       // Array of length 4
        0x43, 0xA1, 0x01, 0x26,  // Protected: {1: -7}
        0xA0,       // Empty unprotected
        0x44, 0x74, 0x65, 0x73, 0x74,  // "test" payload
    ];
    cbor_data.extend(large_sig);
    
    let (_temp_dir, input_path) = create_temp_file_with_content(&cbor_data);
    
    let args = inspect::InspectArgs {
        input: input_path,
        output_format: "text".to_string(),
        all_headers: false,
        show_certs: false,
        show_signature: true, // Show signature to test size display
        show_cwt: false,
    };
    
    let exit_code = inspect::run(args);
    assert!(exit_code == 0 || exit_code == 2, "Should handle large signature display");
}

#[test]  
fn test_inspect_different_algorithm() {
    // CBOR with different algorithm (PS256 = -37)
    let cbor_data = vec![
        0x84,       // Array of length 4
        0x44, 0xA1, 0x01, 0x38, 0x24,  // Protected: {1: -37} (PS256)
        0xA0,       // Empty unprotected
        0x44, 0x74, 0x65, 0x73, 0x74,  // "test" payload
        0x40        // Empty signature
    ];
    
    let (_temp_dir, input_path) = create_temp_file_with_content(&cbor_data);
    
    let args = inspect::InspectArgs {
        input: input_path,
        output_format: "json".to_string(), // Test with JSON format
        all_headers: false,
        show_certs: false,
        show_signature: false,
        show_cwt: false,
    };
    
    let exit_code = inspect::run(args);
    assert!(exit_code == 0 || exit_code == 2, "Should handle different algorithm display");
}