// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Consumer example for the Rust verifier crates.
//!
//! This binary intentionally mirrors the native example app:
//! `native/examples/cosesign1-hello-world`.

use cosesign1_common::parse_cose_sign1;
use cosesign1_mst::{add_issuer_keys, parse_jwks, verify_transparent_statement, OfflineEcKeyStore, VerificationOptions};
use cosesign1_validation::{verify_cose_sign1, CoseAlgorithm, ValidationResult, VerifyOptions};
use cosesign1_x509::{verify_cose_sign1_with_x5c, X509ChainVerifyOptions, X509RevocationMode, X509TrustMode};

/// Read a file to bytes or exit with a clear error.
fn read(path: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| {
        eprintln!("failed to read {path}: {e}");
        std::process::exit(2);
    })
}

fn print_result(r: &ValidationResult) {
    println!("is_valid: {}", if r.is_valid { "true" } else { "false" });
    println!("validator: {}", r.validator_name);
    if !r.metadata.is_empty() {
        println!("metadata:");
        let mut keys: Vec<_> = r.metadata.keys().collect();
        keys.sort();
        for k in keys {
            if let Some(v) = r.metadata.get(k) {
                println!("  {k}: {v}");
            }
        }
    }
    if !r.failures.is_empty() {
        println!("failures:");
        for f in &r.failures {
            match &f.error_code {
                Some(code) => println!("- {code}: {}", f.message),
                None => println!("- {}", f.message),
            }
        }
    }
}

fn get_arg_value(args: &[String], name: &str) -> Option<String> {
    let mut i = 0usize;
    while i < args.len() {
        if args[i] == name {
            return args.get(i + 1).cloned();
        }
        i += 1;
    }
    None
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn parse_alg(s: &str) -> Option<CoseAlgorithm> {
    match s {
        "" => None,
        "ES256" => Some(CoseAlgorithm::ES256),
        "ES384" => Some(CoseAlgorithm::ES384),
        "ES512" => Some(CoseAlgorithm::ES512),
        "PS256" => Some(CoseAlgorithm::PS256),
        "RS256" => Some(CoseAlgorithm::RS256),
        "MLDsa44" => Some(CoseAlgorithm::MLDsa44),
        "MLDsa65" => Some(CoseAlgorithm::MLDsa65),
        "MLDsa87" => Some(CoseAlgorithm::MLDsa87),
        _ => None,
    }
}

fn usage_and_exit(exe: &str) -> ! {
    eprintln!("Usage:");
    eprintln!(
        "  {exe} key --cose <file> --public-key <der> [--payload <file>] [--expected-alg <ES256|PS256|...>]"
    );
    eprintln!(
        "  {exe} x5c --cose <file> [--payload <file>] [--expected-alg <ES256|...>] --trust <system|custom> [--root <der>] [--revocation <online|offline|none>] [--allow-untrusted]"
    );
    eprintln!("  {exe} mst --statement <file> --issuer-host <host> --jwks <file>");
    std::process::exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let exe = args.get(0).map(|s| s.as_str()).unwrap_or("cosesign1_hello_world");
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("");
    if mode.is_empty() {
        usage_and_exit(exe);
    }

    if mode == "key" {
        let cose_path = get_arg_value(&args, "--cose").unwrap_or_default();
        let key_path = get_arg_value(&args, "--public-key").unwrap_or_default();
        let payload_path = get_arg_value(&args, "--payload").unwrap_or_default();
        let alg_str = get_arg_value(&args, "--expected-alg").unwrap_or_default();

        if cose_path.is_empty() || key_path.is_empty() {
            usage_and_exit(exe);
        }

        let cose = read(&cose_path);
        let parsed = parse_cose_sign1(&cose).unwrap_or_else(|e| {
            eprintln!("COSE parse failed: {e}");
            std::process::exit(1);
        });

        let mut opt = VerifyOptions::default();
        opt.public_key_bytes = Some(read(&key_path));
        if !alg_str.is_empty() {
            opt.expected_alg = parse_alg(&alg_str);
            if opt.expected_alg.is_none() {
                eprintln!("unknown --expected-alg value: {alg_str}");
                std::process::exit(2);
            }
        }

        if parsed.payload.is_none() {
            if payload_path.is_empty() {
                eprintln!("COSE payload is detached (null); provide --payload <file>");
                std::process::exit(1);
            }
            opt.external_payload = Some(read(&payload_path));
        }

        let r = verify_cose_sign1("Signature", &cose, &opt);
        print_result(&r);
        std::process::exit(if r.is_valid { 0 } else { 3 });
    }

    if mode == "x5c" {
        let cose_path = get_arg_value(&args, "--cose").unwrap_or_default();
        let payload_path = get_arg_value(&args, "--payload").unwrap_or_default();
        let alg_str = get_arg_value(&args, "--expected-alg").unwrap_or_default();

        let trust = get_arg_value(&args, "--trust").unwrap_or_default();
        let _root_path = get_arg_value(&args, "--root").unwrap_or_default();
        let revocation = get_arg_value(&args, "--revocation").unwrap_or_default();
        let allow_untrusted = has_flag(&args, "--allow-untrusted");

        if cose_path.is_empty() || trust.is_empty() {
            usage_and_exit(exe);
        }

        if !revocation.is_empty() && revocation != "none" {
            eprintln!("revocation checking not supported in the Rust port; use --revocation none");
            std::process::exit(2);
        }

        let cose = read(&cose_path);
        let parsed = parse_cose_sign1(&cose).unwrap_or_else(|e| {
            eprintln!("COSE parse failed: {e}");
            std::process::exit(1);
        });

        let mut opt = VerifyOptions::default();
        if !alg_str.is_empty() {
            opt.expected_alg = parse_alg(&alg_str);
            if opt.expected_alg.is_none() {
                eprintln!("unknown --expected-alg value: {alg_str}");
                std::process::exit(2);
            }
        }

        if parsed.payload.is_none() {
            if payload_path.is_empty() {
                eprintln!("COSE payload is detached (null); provide --payload <file>");
                std::process::exit(1);
            }
            opt.external_payload = Some(read(&payload_path));
        }

        let trust_mode = match trust.as_str() {
            "system" => X509TrustMode::System,
            "custom" => X509TrustMode::CustomRoots,
            _ => {
                eprintln!("unknown --trust value: {trust}");
                std::process::exit(2);
            }
        };

        let mut chain = X509ChainVerifyOptions::default();
        chain.trust_mode = trust_mode;
        chain.revocation_mode = X509RevocationMode::NoCheck;
        chain.allow_untrusted_roots = allow_untrusted;

        let r = verify_cose_sign1_with_x5c("X5c", &cose, &opt, Some(&chain));
        print_result(&r);
        std::process::exit(if r.is_valid { 0 } else { 3 });
    }

    if mode == "mst" {
        let stmt_path = get_arg_value(&args, "--statement").unwrap_or_default();
        let issuer_host = get_arg_value(&args, "--issuer-host").unwrap_or_default();
        let jwks_path = get_arg_value(&args, "--jwks").unwrap_or_default();
        if stmt_path.is_empty() || issuer_host.is_empty() || jwks_path.is_empty() {
            usage_and_exit(exe);
        }

        let statement = read(&stmt_path);
        let jwks_bytes = read(&jwks_path);

        let doc = match parse_jwks(&jwks_bytes) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("failed to parse JWKS: {e}");
                std::process::exit(2);
            }
        };

        let mut store = OfflineEcKeyStore::default();
        if let Err(e) = add_issuer_keys(&mut store, &issuer_host, &doc) {
            eprintln!("failed to add issuer keys: {e}");
            std::process::exit(2);
        }

        let mut opt = VerificationOptions::default();
        opt.authorized_domains = vec![issuer_host];

        let r = verify_transparent_statement("MST", &statement, &store, &opt);
        print_result(&r);
        std::process::exit(if r.is_valid { 0 } else { 3 });
    }

    usage_and_exit(exe);
}
