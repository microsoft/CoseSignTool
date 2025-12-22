// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Consumer example for the Rust verifier crates.
//!
//! This binary intentionally mirrors the native example app:
//! `native/examples/cosesign1-hello-world`.

use cosesign1::CoseSign1;
use cosesign1_mst::{add_issuer_keys, parse_jwks, OfflineEcKeyStore, VerificationOptions};
use cosesign1::ValidationResult;
use cosesign1_x509::{X509ChainVerifyOptions, X509RevocationMode, X509TrustMode};

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

fn usage_and_exit(exe: &str) -> ! {
    eprintln!("Usage:");
    eprintln!(
        "  {exe} key --cose <file> --public-key <der> [--payload <file>]"
    );
    eprintln!(
        "  {exe} x5c --cose <file> [--payload <file>] --trust <system|custom> [--root <der>] [--revocation <online|offline|none>] [--allow-untrusted]"
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

        if cose_path.is_empty() || key_path.is_empty() {
            usage_and_exit(exe);
        }

        let cose = read(&cose_path);

        let msg = CoseSign1::from_bytes(&cose).unwrap_or_else(|e| {
            eprintln!("COSE parse failed: {e}");
            std::process::exit(1);
        });

        let payload_bytes = if payload_path.is_empty() {
            None
        } else {
            Some(read(&payload_path))
        };

        if msg.parsed.payload.is_none() && payload_bytes.is_none() {
            eprintln!("COSE payload is detached (null); provide --payload <file>");
            std::process::exit(1);
        }

        let public_key = read(&key_path);
        let r = msg.verify_signature(payload_bytes.as_deref(), Some(public_key.as_slice()));
        print_result(&r);
        std::process::exit(if r.is_valid { 0 } else { 3 });
    }

    if mode == "x5c" {
        let cose_path = get_arg_value(&args, "--cose").unwrap_or_default();
        let payload_path = get_arg_value(&args, "--payload").unwrap_or_default();

        let trust = get_arg_value(&args, "--trust").unwrap_or_default();
        let root_path = get_arg_value(&args, "--root").unwrap_or_default();
        let revocation = get_arg_value(&args, "--revocation").unwrap_or_default();
        let allow_untrusted = has_flag(&args, "--allow-untrusted");

        if cose_path.is_empty() || trust.is_empty() {
            usage_and_exit(exe);
        }

        let cose = read(&cose_path);

        let msg = CoseSign1::from_bytes(&cose).unwrap_or_else(|e| {
            eprintln!("COSE parse failed: {e}");
            std::process::exit(1);
        });

        let payload_bytes = if payload_path.is_empty() {
            None
        } else {
            Some(read(&payload_path))
        };

        if msg.parsed.payload.is_none() && payload_bytes.is_none() {
            eprintln!("COSE payload is detached (null); provide --payload <file>");
            std::process::exit(1);
        }

        let trust_mode = match trust.as_str() {
            "system" => X509TrustMode::System,
            "custom" => X509TrustMode::CustomRoots,
            _ => {
                eprintln!("unknown --trust value: {trust}");
                std::process::exit(2);
            }
        };

        let revocation_mode = match revocation.as_str() {
            "" | "none" => X509RevocationMode::NoCheck,
            "online" => X509RevocationMode::Online,
            "offline" => X509RevocationMode::Offline,
            _ => {
                eprintln!("unknown --revocation value: {revocation}");
                std::process::exit(2);
            }
        };

        let mut chain = X509ChainVerifyOptions::default();
        chain.trust_mode = trust_mode;
        chain.revocation_mode = revocation_mode;
        chain.allow_untrusted_roots = allow_untrusted;

        if chain.trust_mode == X509TrustMode::CustomRoots {
            if root_path.is_empty() {
                eprintln!("--trust custom requires --root <der>");
                std::process::exit(2);
            }
            chain.trusted_roots_der = vec![read(&root_path)];
        }

        // Pipeline:
        // - Verify the COSE signature (required by default).
        // - Resolve the public key from `x5c` via the registered provider.
        // - Enforce X.509 trust as a message validator (not in the provider).
        let settings = cosesign1::VerificationSettings::default()
            .with_validator_options(cosesign1_x509::x5c_chain_validation_options(chain));

        let r = msg.verify(payload_bytes.as_deref(), None, &settings);
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

        // Receipt-based verification pipeline:
        // - Do NOT require trusting the COSE signing key.
        // - Validate the MST receipt which binds to the statement.
        let msg = CoseSign1::from_bytes(&statement).unwrap_or_else(|e| {
            eprintln!("COSE parse failed: {e}");
            std::process::exit(1);
        });

        let settings = cosesign1::VerificationSettings::default()
            .without_cose_signature()
            .with_validator_options(cosesign1_mst::mst_message_validation_options(store, opt));

        let r = msg.verify(None, None, &settings);
        print_result(&r);
        std::process::exit(if r.is_valid { 0 } else { 3 });
    }

    usage_and_exit(exe);
}
