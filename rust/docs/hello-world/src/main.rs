// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Minimal “hello world” consumer for the Rust COSE_Sign1 verifier.
//!
//! This binary demonstrates how external consumers can call into
//! `cosesign1-validation` using file inputs.
//!
//! Inputs:
//! - COSE_Sign1 bytes (CBOR)
//! - Public key bytes (raw, SPKI DER, or cert DER; depending on algorithm)
//! - Optional external payload bytes (for detached payload COSE_Sign1)

use cosesign1_validation::{verify_cose_sign1, VerifyOptions};

/// Read a file to bytes or exit with a clear error.
fn read(path: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| {
        eprintln!("failed to read {path}: {e}");
        std::process::exit(2);
    })
}

fn main() {
    // Usage:
    //   hello-world.exe <cose_sign1_file> <public_key_file> [external_payload_file]
    //
    // We keep this intentionally small: parse args, call verifier, print result.
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 3 || args.len() > 4 {
        eprintln!(
            "usage: {} <cose_sign1_file> <public_key_file> [external_payload_file]",
            args.get(0).map(|s| s.as_str()).unwrap_or("hello-world")
        );
        eprintln!("\nNotes:");
        eprintln!("- public_key_file may be raw key bytes, SPKI DER, or cert DER");
        eprintln!("- pass external_payload_file for detached payload COSE_Sign1");
        std::process::exit(2);
    }

    let cose_sign1 = read(&args[1]);
    let public_key_bytes = read(&args[2]);
    let external_payload = if args.len() == 4 { Some(read(&args[3])) } else { None };

    let opts = VerifyOptions {
        public_key_bytes: Some(public_key_bytes),
        external_payload,
        ..Default::default()
    };

    let res = verify_cose_sign1("hello-world", &cose_sign1, &opts);
    if res.is_valid {
        println!("OK");
        return;
    }

    eprintln!("FAIL");
    for f in res.failures {
        match f.error_code {
            Some(code) => eprintln!("- {code}: {}", f.message),
            None => eprintln!("- {}", f.message),
        }
    }

    std::process::exit(1);
}
