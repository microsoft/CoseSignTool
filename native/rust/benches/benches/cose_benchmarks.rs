// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Criterion benchmark suite for the native CoseSign1 Rust stack.
//!
//! Benchmarks the hot paths: parsing, signing, verification, and header decode.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use cose_sign1_crypto_openssl::{EvpSigner, EvpVerifier, ES256};
use cose_sign1_primitives::{CoseHeaderMap, CoseSign1Builder, CoseSign1Message};
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::PKey;

/// Generate an EC P-256 key pair and return (private_der, public_der).
fn setup_ec_key() -> (Vec<u8>, Vec<u8>) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(ec).unwrap();
    let private_der = pkey.private_key_to_der().unwrap();
    let public_der = pkey.public_key_to_der().unwrap();
    (private_der, public_der)
}

/// Build a tagged COSE_Sign1 message with an embedded payload.
fn create_signed_message(private_key_der: &[u8], payload: &[u8]) -> Vec<u8> {
    let signer = EvpSigner::from_der(private_key_der, ES256).unwrap();
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(ES256);
    CoseSign1Builder::new()
        .protected(protected)
        .tagged(true)
        .sign(&signer, payload)
        .unwrap()
}

// ---------------------------------------------------------------------------
// Parsing benchmarks
// ---------------------------------------------------------------------------

fn bench_parse(c: &mut Criterion) {
    let (priv_key, _) = setup_ec_key();

    let sizes: &[(&str, usize)] = &[
        ("256B", 256),
        ("1KB", 1024),
        ("10KB", 10 * 1024),
        ("100KB", 100 * 1024),
    ];

    let mut group = c.benchmark_group("parse");
    for (label, size) in sizes {
        let payload = vec![0x42u8; *size];
        let msg_bytes = create_signed_message(&priv_key, &payload);

        group.throughput(Throughput::Bytes(msg_bytes.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("embedded", label),
            &msg_bytes,
            |b, bytes| {
                b.iter(|| CoseSign1Message::parse(black_box(bytes)).unwrap());
            },
        );
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Signing benchmarks
// ---------------------------------------------------------------------------

fn bench_sign(c: &mut Criterion) {
    let (priv_key, _) = setup_ec_key();
    let signer = EvpSigner::from_der(&priv_key, ES256).unwrap();

    let mut protected = CoseHeaderMap::new();
    protected.set_alg(ES256);

    let sizes: &[(&str, usize)] = &[("1KB", 1024), ("100KB", 100 * 1024)];

    let mut group = c.benchmark_group("sign");
    for (label, size) in sizes {
        let payload = vec![0x42u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_function(BenchmarkId::new("ecdsa_p256", label), |b| {
            b.iter(|| {
                CoseSign1Builder::new()
                    .protected(protected.clone())
                    .tagged(true)
                    .sign(black_box(&signer), black_box(&payload))
                    .unwrap()
            });
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Verification benchmarks
// ---------------------------------------------------------------------------

fn bench_verify(c: &mut Criterion) {
    let (priv_key, pub_key) = setup_ec_key();
    let verifier = EvpVerifier::from_der(&pub_key, ES256).unwrap();

    let sizes: &[(&str, usize)] = &[("1KB", 1024), ("100KB", 100 * 1024)];

    let mut group = c.benchmark_group("verify");
    for (label, size) in sizes {
        let payload = vec![0x42u8; *size];
        let signed_bytes = create_signed_message(&priv_key, &payload);
        let message = CoseSign1Message::parse(&signed_bytes).unwrap();

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_function(BenchmarkId::new("ecdsa_p256", label), |b| {
            b.iter(|| {
                message
                    .verify(black_box(&verifier), None)
                    .unwrap();
            });
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Header decode benchmarks
// ---------------------------------------------------------------------------

fn bench_header_decode(c: &mut Criterion) {
    let (priv_key, _) = setup_ec_key();
    let payload = vec![0x42u8; 1024];
    let signed_bytes = create_signed_message(&priv_key, &payload);

    // Parse once — protected headers are lazily decoded on first access.
    let message = CoseSign1Message::parse(&signed_bytes).unwrap();

    // Force initial parse so we benchmark repeated access, not first-parse.
    let _ = message.protected_headers().alg();

    c.bench_function("header_decode/alg", |b| {
        b.iter(|| {
            black_box(message.protected_headers().alg());
        });
    });
}

// ---------------------------------------------------------------------------
// Roundtrip benchmark (sign → parse → verify)
// ---------------------------------------------------------------------------

fn bench_roundtrip(c: &mut Criterion) {
    let (priv_key, pub_key) = setup_ec_key();
    let signer = EvpSigner::from_der(&priv_key, ES256).unwrap();
    let verifier = EvpVerifier::from_der(&pub_key, ES256).unwrap();

    let mut protected = CoseHeaderMap::new();
    protected.set_alg(ES256);

    let payload = vec![0x42u8; 1024];

    c.bench_function("roundtrip/sign_parse_verify_1KB", |b| {
        b.iter(|| {
            let bytes = CoseSign1Builder::new()
                .protected(protected.clone())
                .tagged(true)
                .sign(black_box(&signer), black_box(&payload))
                .unwrap();
            let msg = CoseSign1Message::parse(black_box(&bytes)).unwrap();
            msg.verify(black_box(&verifier), None).unwrap();
        });
    });
}

// ---------------------------------------------------------------------------
// Allocation-sensitive benchmark (parse only — should be minimal allocs)
// ---------------------------------------------------------------------------

fn bench_allocations(c: &mut Criterion) {
    let (priv_key, _) = setup_ec_key();
    let payload = vec![0x42u8; 1024];
    let signed_bytes = create_signed_message(&priv_key, &payload);

    c.bench_function("alloc/parse_1KB", |b| {
        b.iter(|| {
            let msg = CoseSign1Message::parse(black_box(&signed_bytes)).unwrap();
            black_box(msg);
        });
    });
}

criterion_group!(
    benches,
    bench_parse,
    bench_sign,
    bench_verify,
    bench_header_decode,
    bench_roundtrip,
    bench_allocations,
);
criterion_main!(benches);
