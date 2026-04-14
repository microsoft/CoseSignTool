// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Criterion benchmark suite for the native CoseSign1 Rust stack.
//!
//! Benchmarks the hot paths: parsing, signing, verification, and header decode.

use std::collections::HashMap;
use std::sync::Arc;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use cose_sign1_crypto_openssl::{EvpSigner, EvpVerifier, ES256, ES384, PS256};
use cose_sign1_factories::direct::{DirectSignatureFactory, DirectSignatureOptions};
use cose_sign1_primitives::{CoseHeaderMap, CoseSign1Builder, CoseSign1Message};
use cose_sign1_signing::{
    CoseSigner, SigningContext, SigningError, SigningService, SigningServiceMetadata,
};
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;

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

// ---------------------------------------------------------------------------
// Factory-level signing benchmarks (DirectSignatureFactory)
// ---------------------------------------------------------------------------

/// A real `SigningService` backed by OpenSSL ECDSA for benchmarking the factory pipeline.
struct BenchSigningService {
    private_der: Vec<u8>,
    verifier: EvpVerifier,
    metadata: SigningServiceMetadata,
}

impl BenchSigningService {
    fn new(private_der: &[u8], public_der: &[u8]) -> Self {
        Self {
            private_der: private_der.to_vec(),
            verifier: EvpVerifier::from_der(public_der, ES256).unwrap(),
            metadata: SigningServiceMetadata {
                service_name: "BenchSigningService".to_string(),
                service_description: "Benchmark signing service".to_string(),
                additional_metadata: HashMap::new(),
            },
        }
    }
}

impl SigningService for BenchSigningService {
    fn get_cose_signer(&self, _context: &SigningContext<'_>) -> Result<CoseSigner, SigningError> {
        let signer = EvpSigner::from_der(&self.private_der, ES256).map_err(|e| {
            SigningError::KeyError {
                detail: e.to_string().into(),
            }
        })?;

        let mut protected = CoseHeaderMap::new();
        protected.set_alg(ES256);

        Ok(CoseSigner::new(
            Box::new(signer),
            protected,
            CoseHeaderMap::new(),
        ))
    }

    fn is_remote(&self) -> bool {
        false
    }

    fn service_metadata(&self) -> &SigningServiceMetadata {
        &self.metadata
    }

    fn verify_signature(
        &self,
        message_bytes: &[u8],
        _context: &SigningContext<'_>,
    ) -> Result<bool, SigningError> {
        let message =
            CoseSign1Message::parse(message_bytes).map_err(|e| SigningError::VerificationFailed {
                detail: e.to_string().into(),
            })?;
        message
            .verify(&self.verifier, None)
            .map_err(|e| SigningError::VerificationFailed {
                detail: e.to_string().into(),
            })
    }
}

fn bench_factory_sign(c: &mut Criterion) {
    let (priv_key, pub_key) = setup_ec_key();
    let signing_service: Arc<dyn SigningService> =
        Arc::new(BenchSigningService::new(&priv_key, &pub_key));
    let factory = DirectSignatureFactory::new(signing_service);

    let payload = vec![0x42u8; 1024];

    let mut group = c.benchmark_group("factory_sign");

    // WITH post-sign verification (default, secure)
    group.bench_function("ecdsa_p256_1kb_with_verify", |b| {
        b.iter(|| {
            factory
                .create_bytes(
                    black_box(&payload),
                    "application/octet-stream",
                    Some(DirectSignatureOptions::new().with_verify_after_sign(true)),
                )
                .unwrap()
        })
    });

    // WITHOUT post-sign verification (performance mode)
    group.bench_function("ecdsa_p256_1kb_no_verify", |b| {
        b.iter(|| {
            factory
                .create_bytes(
                    black_box(&payload),
                    "application/octet-stream",
                    Some(DirectSignatureOptions::new().with_verify_after_sign(false)),
                )
                .unwrap()
        })
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// RSA signing / verification benchmarks
// ---------------------------------------------------------------------------

fn setup_rsa_key() -> (Vec<u8>, Vec<u8>) {
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();
    (
        pkey.private_key_to_der().unwrap(),
        pkey.public_key_to_der().unwrap(),
    )
}

fn bench_rsa(c: &mut Criterion) {
    let (priv_key, pub_key) = setup_rsa_key();
    let signer = EvpSigner::from_der(&priv_key, PS256).unwrap();
    let verifier = EvpVerifier::from_der(&pub_key, PS256).unwrap();

    let payload = vec![0x42u8; 1024];
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(PS256);

    let mut group = c.benchmark_group("rsa");

    group.bench_function("sign_ps256_2048_1kb", |b| {
        b.iter(|| {
            CoseSign1Builder::new()
                .protected(protected.clone())
                .tagged(true)
                .sign(black_box(&signer), black_box(&payload))
                .unwrap()
        })
    });

    let signed = CoseSign1Builder::new()
        .protected(protected)
        .tagged(true)
        .sign(&signer, &payload)
        .unwrap();
    let message = CoseSign1Message::parse(&signed).unwrap();

    group.bench_function("verify_ps256_2048_1kb", |b| {
        b.iter(|| message.verify(black_box(&verifier), None).unwrap())
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// EC P-384 benchmarks
// ---------------------------------------------------------------------------

fn setup_p384_key() -> (Vec<u8>, Vec<u8>) {
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let ec = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(ec).unwrap();
    (
        pkey.private_key_to_der().unwrap(),
        pkey.public_key_to_der().unwrap(),
    )
}

fn bench_p384(c: &mut Criterion) {
    let (priv_key, pub_key) = setup_p384_key();
    let signer = EvpSigner::from_der(&priv_key, ES384).unwrap();
    let verifier = EvpVerifier::from_der(&pub_key, ES384).unwrap();

    let payload = vec![0x42u8; 1024];
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(ES384);

    let mut group = c.benchmark_group("p384");

    group.bench_function("sign_es384_1kb", |b| {
        b.iter(|| {
            CoseSign1Builder::new()
                .protected(protected.clone())
                .tagged(true)
                .sign(black_box(&signer), black_box(&payload))
                .unwrap()
        })
    });

    let signed = CoseSign1Builder::new()
        .protected(protected)
        .tagged(true)
        .sign(&signer, &payload)
        .unwrap();
    let message = CoseSign1Message::parse(&signed).unwrap();

    group.bench_function("verify_es384_1kb", |b| {
        b.iter(|| message.verify(black_box(&verifier), None).unwrap())
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Certificate-based key generation benchmarks
// ---------------------------------------------------------------------------

fn bench_cert_keygen(c: &mut Criterion) {
    use cose_sign1_certificates_local::traits::CertificateFactory;
    use cose_sign1_certificates_local::{
        CertificateOptions, EphemeralCertificateFactory, KeyAlgorithm, SoftwareKeyProvider,
    };

    let mut group = c.benchmark_group("cert_keygen");

    group.bench_function("ecdsa_p256", |b| {
        let factory =
            EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()));
        b.iter(|| {
            factory
                .create_certificate(
                    CertificateOptions::new()
                        .with_subject_name("CN=Benchmark")
                        .with_key_algorithm(KeyAlgorithm::Ecdsa)
                        .with_key_size(256),
                )
                .unwrap()
        })
    });

    group.bench_function("rsa_2048", |b| {
        let factory =
            EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()));
        b.iter(|| {
            factory
                .create_certificate(
                    CertificateOptions::new()
                        .with_subject_name("CN=Benchmark")
                        .with_key_algorithm(KeyAlgorithm::Rsa)
                        .with_key_size(2048),
                )
                .unwrap()
        })
    });

    group.bench_function("eddsa_ed25519", |b| {
        let factory =
            EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()));
        b.iter(|| {
            factory
                .create_certificate(
                    CertificateOptions::new()
                        .with_subject_name("CN=Benchmark")
                        .with_key_algorithm(KeyAlgorithm::EdDsa),
                )
                .unwrap()
        })
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// PQC (ML-DSA) benchmarks — feature-gated
// ---------------------------------------------------------------------------

#[cfg(feature = "pqc")]
fn bench_pqc(c: &mut Criterion) {
    use cose_sign1_crypto_openssl::{generate_mldsa_key_der, MlDsaVariant, ML_DSA_44, ML_DSA_65, ML_DSA_87};

    let mut group = c.benchmark_group("pqc");

    // ML-DSA-44 (lightweight PQC)
    {
        let (priv_der, pub_der) = generate_mldsa_key_der(MlDsaVariant::MlDsa44).unwrap();
        let signer = EvpSigner::from_der(&priv_der, ML_DSA_44).unwrap();
        let verifier = EvpVerifier::from_der(&pub_der, ML_DSA_44).unwrap();

        let payload = vec![0x42u8; 1024];
        let mut protected = CoseHeaderMap::new();
        protected.set_alg(ML_DSA_44);

        group.bench_function("sign_mldsa44_1kb", |b| {
            b.iter(|| {
                CoseSign1Builder::new()
                    .protected(protected.clone())
                    .tagged(true)
                    .sign(black_box(&signer), black_box(&payload))
                    .unwrap()
            })
        });

        let signed = CoseSign1Builder::new()
            .protected(protected)
            .tagged(true)
            .sign(&signer, &payload)
            .unwrap();
        let message = CoseSign1Message::parse(&signed).unwrap();

        group.bench_function("verify_mldsa44_1kb", |b| {
            b.iter(|| message.verify(black_box(&verifier), None).unwrap())
        });
    }

    // ML-DSA-65 (standard PQC)
    {
        let (priv_der, pub_der) = generate_mldsa_key_der(MlDsaVariant::MlDsa65).unwrap();
        let signer = EvpSigner::from_der(&priv_der, ML_DSA_65).unwrap();
        let verifier = EvpVerifier::from_der(&pub_der, ML_DSA_65).unwrap();

        let payload = vec![0x42u8; 1024];
        let mut protected = CoseHeaderMap::new();
        protected.set_alg(ML_DSA_65);

        group.bench_function("sign_mldsa65_1kb", |b| {
            b.iter(|| {
                CoseSign1Builder::new()
                    .protected(protected.clone())
                    .tagged(true)
                    .sign(black_box(&signer), black_box(&payload))
                    .unwrap()
            })
        });

        let signed = CoseSign1Builder::new()
            .protected(protected)
            .tagged(true)
            .sign(&signer, &payload)
            .unwrap();
        let message = CoseSign1Message::parse(&signed).unwrap();

        group.bench_function("verify_mldsa65_1kb", |b| {
            b.iter(|| message.verify(black_box(&verifier), None).unwrap())
        });
    }

    // ML-DSA-87 (high-security PQC)
    {
        let (priv_der, pub_der) = generate_mldsa_key_der(MlDsaVariant::MlDsa87).unwrap();
        let signer = EvpSigner::from_der(&priv_der, ML_DSA_87).unwrap();
        let verifier = EvpVerifier::from_der(&pub_der, ML_DSA_87).unwrap();

        let payload = vec![0x42u8; 1024];
        let mut protected = CoseHeaderMap::new();
        protected.set_alg(ML_DSA_87);

        group.bench_function("sign_mldsa87_1kb", |b| {
            b.iter(|| {
                CoseSign1Builder::new()
                    .protected(protected.clone())
                    .tagged(true)
                    .sign(black_box(&signer), black_box(&payload))
                    .unwrap()
            })
        });

        let signed = CoseSign1Builder::new()
            .protected(protected)
            .tagged(true)
            .sign(&signer, &payload)
            .unwrap();
        let message = CoseSign1Message::parse(&signed).unwrap();

        group.bench_function("verify_mldsa87_1kb", |b| {
            b.iter(|| message.verify(black_box(&verifier), None).unwrap())
        });
    }

    group.finish();
}

#[cfg(not(feature = "pqc"))]
criterion_group!(
    benches,
    bench_parse,
    bench_sign,
    bench_verify,
    bench_header_decode,
    bench_roundtrip,
    bench_allocations,
    bench_factory_sign,
    bench_rsa,
    bench_p384,
    bench_cert_keygen,
);

#[cfg(feature = "pqc")]
criterion_group!(
    benches,
    bench_parse,
    bench_sign,
    bench_verify,
    bench_header_decode,
    bench_roundtrip,
    bench_allocations,
    bench_factory_sign,
    bench_rsa,
    bench_p384,
    bench_cert_keygen,
    bench_pqc,
);

criterion_main!(benches);
