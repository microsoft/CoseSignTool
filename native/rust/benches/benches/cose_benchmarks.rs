// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Criterion benchmark suite for the native CoseSign1 Rust stack.
//!
//! Benchmarks the hot paths: parsing, signing, verification, and header decode.

use std::collections::HashMap;
use std::sync::Arc;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use cose_sign1_crypto_openssl::{EvpSigner, EvpVerifier, EDDSA, ES256, ES384, PS256};
#[cfg(feature = "pqc")]
use cose_sign1_crypto_openssl::{generate_mldsa_key_der, MlDsaVariant, ML_DSA_44, ML_DSA_65, ML_DSA_87};
use cose_sign1_factories::direct::{DirectSignatureFactory, DirectSignatureOptions};
use cose_sign1_factories::indirect::IndirectSignatureFactory;
use cose_sign1_primitives::{CoseHeaderMap, CoseSign1Builder, CoseSign1Message};
use cose_sign1_signing::{
    CoseSigner, SigningContext, SigningError, SigningService, SigningServiceMetadata,
};
use cose_sign1_certificates::signing::{
    CertificateSigningOptions, CertificateSigningService, CertificateSource, SigningKeyProvider,
};
use cose_sign1_certificates::{
    CertificateChainBuilder, CertificateError, ExplicitCertificateChainBuilder,
};
use cose_sign1_certificates_local::traits::CertificateFactory;
use cose_sign1_certificates_local::{
    Certificate, CertificateOptions, EphemeralCertificateFactory, KeyAlgorithm,
    SoftwareKeyProvider,
};
use crypto_primitives::{CryptoError, CryptoSigner};
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
// Certificate-based factory signing benchmarks (CertificateSigningService)
//
// These benchmarks mirror V2 C# CertificateSigningService behavior:
// x5chain + x5t + CWT (SCITT) headers are embedded in every COSE_Sign1 message.
// ---------------------------------------------------------------------------

/// Certificate source backed by in-memory DER bytes and an explicit chain.
struct BenchCertificateSource {
    cert_der: Vec<u8>,
    chain_builder: ExplicitCertificateChainBuilder,
}

impl BenchCertificateSource {
    fn new(cert_der: Vec<u8>, chain: Vec<Vec<u8>>) -> Self {
        Self {
            cert_der,
            chain_builder: ExplicitCertificateChainBuilder::new(chain),
        }
    }
}

impl CertificateSource for BenchCertificateSource {
    fn get_signing_certificate(&self) -> Result<&[u8], CertificateError> {
        Ok(&self.cert_der)
    }

    fn has_private_key(&self) -> bool {
        true
    }

    fn get_chain_builder(&self) -> &dyn CertificateChainBuilder {
        &self.chain_builder
    }
}

/// Signing key provider wrapping an EvpSigner for local (non-remote) signing.
struct BenchSigningKeyProvider {
    signer: EvpSigner,
}

impl CryptoSigner for BenchSigningKeyProvider {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.signer.sign(data)
    }

    fn algorithm(&self) -> i64 {
        self.signer.algorithm()
    }

    fn key_id(&self) -> Option<&[u8]> {
        self.signer.key_id()
    }

    fn key_type(&self) -> &str {
        self.signer.key_type()
    }
}

impl SigningKeyProvider for BenchSigningKeyProvider {
    fn is_remote(&self) -> bool {
        false
    }
}

/// Creates a `DirectSignatureFactory` backed by `CertificateSigningService`
/// with x5chain, x5t, and SCITT CWT headers — matching V2 C# behavior.
fn create_cert_signing_factory(cert: &Certificate, cose_algorithm: i64) -> DirectSignatureFactory {
    let private_key_der = cert
        .private_key_der
        .as_ref()
        .expect("cert must have private key");
    let signer = EvpSigner::from_der(private_key_der, cose_algorithm)
        .expect("failed to create EvpSigner from cert private key");

    // Self-signed: chain contains only the signing certificate.
    let source = Box::new(BenchCertificateSource::new(
        cert.cert_der.clone(),
        vec![cert.cert_der.clone()],
    ));
    let provider: Arc<dyn SigningKeyProvider> = Arc::new(BenchSigningKeyProvider { signer });
    let options = CertificateSigningOptions::default(); // SCITT enabled per V2

    let service: Arc<dyn SigningService> =
        Arc::new(CertificateSigningService::new(source, provider, options));
    DirectSignatureFactory::new(service)
}

fn bench_cert_factory_sign(c: &mut Criterion) {
    let cert_factory = EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()));
    let payload = vec![0x42u8; 1024];

    let mut group = c.benchmark_group("cert_factory_sign");

    // ECDSA P-256 with x5chain + x5t + CWT claims
    {
        let cert = cert_factory
            .create_certificate(
                CertificateOptions::new()
                    .with_subject_name("CN=Benchmark ECDSA P-256")
                    .with_key_algorithm(KeyAlgorithm::Ecdsa)
                    .with_key_size(256),
            )
            .unwrap();
        let factory = create_cert_signing_factory(&cert, ES256);

        group.bench_function("ecdsa_p256_1kb_with_x5chain", |b| {
            b.iter(|| {
                factory
                    .create_bytes(
                        black_box(&payload),
                        "application/octet-stream",
                        None,
                    )
                    .unwrap()
            })
        });
    }

    // RSA-PSS 2048 with x5chain + x5t + CWT claims
    {
        let cert = cert_factory
            .create_certificate(
                CertificateOptions::new()
                    .with_subject_name("CN=Benchmark RSA 2048")
                    .with_key_algorithm(KeyAlgorithm::Rsa)
                    .with_key_size(2048),
            )
            .unwrap();
        let factory = create_cert_signing_factory(&cert, PS256);

        group.bench_function("rsa_2048_1kb_with_x5chain", |b| {
            b.iter(|| {
                factory
                    .create_bytes(
                        black_box(&payload),
                        "application/octet-stream",
                        None,
                    )
                    .unwrap()
            })
        });
    }

    // ECDSA P-384 with x5chain + x5t + CWT claims
    {
        let cert = cert_factory
            .create_certificate(
                CertificateOptions::new()
                    .with_subject_name("CN=Benchmark ECDSA P-384")
                    .with_key_algorithm(KeyAlgorithm::Ecdsa)
                    .with_key_size(384),
            )
            .unwrap();
        let factory = create_cert_signing_factory(&cert, ES384);

        group.bench_function("ecdsa_p384_1kb_with_x5chain", |b| {
            b.iter(|| {
                factory
                    .create_bytes(
                        black_box(&payload),
                        "application/octet-stream",
                        None,
                    )
                    .unwrap()
            })
        });
    }

    // ML-DSA-65 with x5chain + x5t + CWT claims (PQC, feature-gated)
    #[cfg(feature = "pqc")]
    {
        let cert = cert_factory
            .create_certificate(
                CertificateOptions::new()
                    .with_subject_name("CN=Benchmark ML-DSA-65")
                    .with_key_algorithm(KeyAlgorithm::MlDsa)
                    .with_key_size(65),
            )
            .unwrap();
        let factory = create_cert_signing_factory(&cert, ML_DSA_65);

        group.bench_function("mldsa65_1kb_with_x5chain", |b| {
            b.iter(|| {
                factory
                    .create_bytes(
                        black_box(&payload),
                        "application/octet-stream",
                        None,
                    )
                    .unwrap()
            })
        });
    }

    group.finish();
}

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
// Message size measurement (informational, runs once)
// ---------------------------------------------------------------------------

/// Prints a table of COSE_Sign1 message sizes for each algorithm.
/// This gives consumers critical sizing data for capacity planning.
fn print_message_sizes() {
    println!("\n\u{2554}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2557}");
    println!("\u{2551}              COSE_Sign1 Message Sizes (1 KB payload)           \u{2551}");
    println!("\u{2560}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2566}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2566}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2563}");
    println!("\u{2551} Algorithm             \u{2551} Message Size   \u{2551} Overhead vs Payload   \u{2551}");
    println!("\u{2560}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{256C}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{256C}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2563}");

    let payload = vec![0x42u8; 1024];

    // ECDSA P-256
    {
        let (priv_key, _) = setup_ec_key();
        let bytes = create_signed_message(&priv_key, &payload);
        let overhead = bytes.len() - 1024;
        println!(
            "\u{2551} ECDSA P-256 (ES256)   \u{2551} {:>10} B   \u{2551} {:>10} B ({:>4.1}%)    \u{2551}",
            bytes.len(),
            overhead,
            (overhead as f64 / 1024.0) * 100.0
        );
    }

    // ECDSA P-384
    {
        let (priv_key, _) = setup_p384_key();
        let signer = EvpSigner::from_der(&priv_key, ES384).unwrap();
        let mut protected = CoseHeaderMap::new();
        protected.set_alg(ES384);
        let bytes = CoseSign1Builder::new()
            .protected(protected)
            .tagged(true)
            .sign(&signer, &payload)
            .unwrap();
        let overhead = bytes.len() - 1024;
        println!(
            "\u{2551} ECDSA P-384 (ES384)   \u{2551} {:>10} B   \u{2551} {:>10} B ({:>4.1}%)    \u{2551}",
            bytes.len(),
            overhead,
            (overhead as f64 / 1024.0) * 100.0
        );
    }

    // RSA-PSS 2048
    {
        let (priv_key, _) = setup_rsa_key();
        let signer = EvpSigner::from_der(&priv_key, PS256).unwrap();
        let mut protected = CoseHeaderMap::new();
        protected.set_alg(PS256);
        let bytes = CoseSign1Builder::new()
            .protected(protected)
            .tagged(true)
            .sign(&signer, &payload)
            .unwrap();
        let overhead = bytes.len() - 1024;
        println!(
            "\u{2551} RSA-PSS 2048 (PS256)  \u{2551} {:>10} B   \u{2551} {:>10} B ({:>4.1}%)    \u{2551}",
            bytes.len(),
            overhead,
            (overhead as f64 / 1024.0) * 100.0
        );
    }

    // EdDSA Ed25519
    {
        let pkey = PKey::generate_ed25519().unwrap();
        let priv_der = pkey.private_key_to_der().unwrap();
        let signer = EvpSigner::from_der(&priv_der, EDDSA).unwrap();
        let mut protected = CoseHeaderMap::new();
        protected.set_alg(EDDSA);
        let bytes = CoseSign1Builder::new()
            .protected(protected)
            .tagged(true)
            .sign(&signer, &payload)
            .unwrap();
        let overhead = bytes.len() - 1024;
        println!(
            "\u{2551} EdDSA Ed25519         \u{2551} {:>10} B   \u{2551} {:>10} B ({:>4.1}%)    \u{2551}",
            bytes.len(),
            overhead,
            (overhead as f64 / 1024.0) * 100.0
        );
    }

    // PQC: ML-DSA-44/65/87
    #[cfg(feature = "pqc")]
    {
        for (name, variant, alg) in [
            ("ML-DSA-44", MlDsaVariant::MlDsa44, ML_DSA_44),
            ("ML-DSA-65", MlDsaVariant::MlDsa65, ML_DSA_65),
            ("ML-DSA-87", MlDsaVariant::MlDsa87, ML_DSA_87),
        ] {
            let (priv_der, _pub_der) = generate_mldsa_key_der(variant).unwrap();
            let signer = EvpSigner::from_der(&priv_der, alg).unwrap();
            let mut protected = CoseHeaderMap::new();
            protected.set_alg(alg);
            let bytes = CoseSign1Builder::new()
                .protected(protected)
                .tagged(true)
                .sign(&signer, &payload)
                .unwrap();
            let overhead = bytes.len() - 1024;
            println!(
                "\u{2551} {:21} \u{2551} {:>10} B   \u{2551} {:>10} B ({:>4.1}%)    \u{2551}",
                name,
                bytes.len(),
                overhead,
                (overhead as f64 / 1024.0) * 100.0
            );
        }
    }

    // Indirect signature sizes (hash of payload, not payload itself)
    println!("\u{2560}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{256C}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{256C}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2563}");
    println!("\u{2551} Indirect Signatures   \u{2551}                \u{2551} (payload = hash only) \u{2551}");
    println!("\u{2560}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{256C}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{256C}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2563}");
    {
        let (priv_key, pub_key) = setup_ec_key();
        let service: Arc<dyn SigningService> =
            Arc::new(BenchSigningService::new(&priv_key, &pub_key));
        let direct = DirectSignatureFactory::new(service);
        let indirect = IndirectSignatureFactory::new(direct);

        let indirect_bytes = indirect
            .create_bytes(&payload, "application/octet-stream", None)
            .unwrap();
        println!(
            "\u{2551} ES256 Indirect SHA256 \u{2551} {:>10} B   \u{2551} (original: 1024 B)    \u{2551}",
            indirect_bytes.len()
        );
    }

    // Certificate-based message sizes (x5chain + x5t + CWT embedded)
    println!("\u{2560}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{256C}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{256C}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2563}");
    println!("\u{2551} Cert-Based (x5chain)  \u{2551}                \u{2551} (includes SCITT CWT)  \u{2551}");
    println!("\u{2560}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{256C}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{256C}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2563}");
    {
        let cert_factory = EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()));

        // ES256 + x5chain
        let cert = cert_factory
            .create_certificate(
                CertificateOptions::new()
                    .with_subject_name("CN=Size Test ECDSA P-256")
                    .with_key_algorithm(KeyAlgorithm::Ecdsa)
                    .with_key_size(256),
            )
            .unwrap();
        let factory = create_cert_signing_factory(&cert, ES256);
        let bytes = factory
            .create_bytes(&payload, "application/octet-stream", None)
            .unwrap();
        let overhead = bytes.len() - 1024;
        println!(
            "\u{2551} ES256 + x5chain       \u{2551} {:>10} B   \u{2551} {:>10} B ({:>4.1}%)    \u{2551}",
            bytes.len(),
            overhead,
            (overhead as f64 / 1024.0) * 100.0
        );

        // PS256 + x5chain
        let cert = cert_factory
            .create_certificate(
                CertificateOptions::new()
                    .with_subject_name("CN=Size Test RSA 2048")
                    .with_key_algorithm(KeyAlgorithm::Rsa)
                    .with_key_size(2048),
            )
            .unwrap();
        let factory = create_cert_signing_factory(&cert, PS256);
        let bytes = factory
            .create_bytes(&payload, "application/octet-stream", None)
            .unwrap();
        let overhead = bytes.len() - 1024;
        println!(
            "\u{2551} PS256 + x5chain       \u{2551} {:>10} B   \u{2551} {:>10} B ({:>4.1}%)    \u{2551}",
            bytes.len(),
            overhead,
            (overhead as f64 / 1024.0) * 100.0
        );

        // ES384 + x5chain
        let cert = cert_factory
            .create_certificate(
                CertificateOptions::new()
                    .with_subject_name("CN=Size Test ECDSA P-384")
                    .with_key_algorithm(KeyAlgorithm::Ecdsa)
                    .with_key_size(384),
            )
            .unwrap();
        let factory = create_cert_signing_factory(&cert, ES384);
        let bytes = factory
            .create_bytes(&payload, "application/octet-stream", None)
            .unwrap();
        let overhead = bytes.len() - 1024;
        println!(
            "\u{2551} ES384 + x5chain       \u{2551} {:>10} B   \u{2551} {:>10} B ({:>4.1}%)    \u{2551}",
            bytes.len(),
            overhead,
            (overhead as f64 / 1024.0) * 100.0
        );
    }

    // PQC cert-based message sizes
    #[cfg(feature = "pqc")]
    {
        let cert_factory = EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()));
        let cert = cert_factory
            .create_certificate(
                CertificateOptions::new()
                    .with_subject_name("CN=Size Test ML-DSA-65")
                    .with_key_algorithm(KeyAlgorithm::MlDsa)
                    .with_key_size(65),
            )
            .unwrap();
        let factory = create_cert_signing_factory(&cert, ML_DSA_65);
        let bytes = factory
            .create_bytes(&payload, "application/octet-stream", None)
            .unwrap();
        let overhead = bytes.len() - 1024;
        println!(
            "\u{2551} ML-DSA-65 + x5chain   \u{2551} {:>10} B   \u{2551} {:>10} B ({:>4.1}%)    \u{2551}",
            bytes.len(),
            overhead,
            (overhead as f64 / 1024.0) * 100.0
        );
    }

    // Composite certificate sizes (feature-gated)
    #[cfg(feature = "composite")]
    {
        use cose_sign1_certificates_local::traits::CertificateFactory;
        use cose_sign1_certificates_local::{
            CertificateOptions, EphemeralCertificateFactory, KeyAlgorithm, SoftwareKeyProvider,
        };

        println!("\u{2560}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{256C}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{256C}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2563}");
        println!("\u{2551} Composite Certs       \u{2551}  Cert DER Size \u{2551}                       \u{2551}");
        println!("\u{2560}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{256C}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{256C}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2563}");

        let factory =
            EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()));

        for (name, key_size) in [
            ("p256_mldsa44", 44u32),
            ("p384_mldsa65", 65),
            ("p384_mldsa87", 87),
        ] {
            match factory.create_certificate(
                CertificateOptions::new()
                    .with_subject_name("CN=Composite Size Test")
                    .with_key_algorithm(KeyAlgorithm::Composite)
                    .with_key_size(key_size),
            ) {
                Ok(cert) => {
                    println!(
                        "\u{2551} {:21} \u{2551} {:>10} B   \u{2551}                       \u{2551}",
                        name,
                        cert.cert_der.len()
                    );
                }
                Err(e) => {
                    println!(
                        "\u{2551} {:21} \u{2551}        N/A   \u{2551} Error: {:14} \u{2551}",
                        name, e
                    );
                }
            }
        }
    }

    println!("\u{255A}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2569}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2569}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{255D}\n");
}

fn bench_message_sizes(c: &mut Criterion) {
    // Print sizes once (not benchmarked, just informational)
    print_message_sizes();

    // Benchmark message creation for size reference
    c.bench_function("message_size/ecdsa_p256_1kb", |b| {
        let (priv_key, _) = setup_ec_key();
        b.iter(|| {
            let bytes =
                create_signed_message(black_box(&priv_key), black_box(&[0x42u8; 1024]));
            black_box(bytes.len())
        })
    });
}

// ---------------------------------------------------------------------------
// EdDSA Ed25519 sign/verify benchmarks
// ---------------------------------------------------------------------------

fn bench_ed25519(c: &mut Criterion) {
    let pkey = PKey::generate_ed25519().unwrap();
    let priv_der = pkey.private_key_to_der().unwrap();
    let pub_der = pkey.public_key_to_der().unwrap();
    let signer = EvpSigner::from_der(&priv_der, EDDSA).unwrap();
    let verifier = EvpVerifier::from_der(&pub_der, EDDSA).unwrap();

    let payload = vec![0x42u8; 1024];
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(EDDSA);

    let mut group = c.benchmark_group("ed25519");

    group.bench_function("sign_1kb", |b| {
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

    group.bench_function("verify_1kb", |b| {
        b.iter(|| message.verify(black_box(&verifier), None).unwrap())
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Indirect signature benchmarks
// ---------------------------------------------------------------------------

fn bench_indirect_sign(c: &mut Criterion) {
    let (priv_key, pub_key) = setup_ec_key();
    let service: Arc<dyn SigningService> =
        Arc::new(BenchSigningService::new(&priv_key, &pub_key));
    let direct = DirectSignatureFactory::new(service);
    let indirect = IndirectSignatureFactory::new(direct);

    let payload = vec![0x42u8; 1024];

    let mut group = c.benchmark_group("indirect");
    group.bench_function("sign_es256_sha256_1kb", |b| {
        b.iter(|| {
            indirect
                .create_bytes(
                    black_box(&payload),
                    "application/octet-stream",
                    None,
                )
                .unwrap()
        })
    });
    group.finish();
}

// ---------------------------------------------------------------------------
// Composite/Hybrid PQC certificate benchmarks — feature-gated
// ---------------------------------------------------------------------------

#[cfg(feature = "composite")]
fn bench_composite(c: &mut Criterion) {
    use cose_sign1_certificates_local::traits::CertificateFactory;
    use cose_sign1_certificates_local::{
        CertificateChainFactory, CertificateChainOptions, CertificateOptions,
        EphemeralCertificateFactory, KeyAlgorithm, SoftwareKeyProvider,
    };

    let mut group = c.benchmark_group("composite");

    // Composite cert generation: ML-DSA-44 + ECDSA-P256
    group.bench_function("cert_mldsa44_ecdsa_p256", |b| {
        let factory =
            EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()));
        b.iter(|| {
            factory
                .create_certificate(
                    CertificateOptions::new()
                        .with_subject_name("CN=Composite Bench")
                        .with_key_algorithm(KeyAlgorithm::Composite)
                        .with_key_size(44),
                )
                .unwrap()
        })
    });

    // Composite cert generation: ML-DSA-65 + ECDSA-P384
    group.bench_function("cert_mldsa65_ecdsa_p384", |b| {
        let factory =
            EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()));
        b.iter(|| {
            factory
                .create_certificate(
                    CertificateOptions::new()
                        .with_subject_name("CN=Composite Bench")
                        .with_key_algorithm(KeyAlgorithm::Composite)
                        .with_key_size(65),
                )
                .unwrap()
        })
    });

    // Hybrid chain: ECDSA root → Composite leaf
    group.bench_function("hybrid_chain_ecdsa_root_composite_leaf", |b| {
        let factory =
            EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()));
        let chain_factory = CertificateChainFactory::new(factory);
        b.iter(|| {
            chain_factory
                .create_chain_with_options(
                    CertificateChainOptions::new()
                        .with_root_key_algorithm(KeyAlgorithm::Ecdsa)
                        .with_leaf_key_algorithm(KeyAlgorithm::Composite)
                        .with_leaf_key_size(65)
                        .with_intermediate_name(None::<String>),
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

#[cfg(not(any(feature = "pqc", feature = "composite")))]
criterion_group!(
    benches,
    bench_parse,
    bench_sign,
    bench_verify,
    bench_header_decode,
    bench_roundtrip,
    bench_allocations,
    bench_factory_sign,
    bench_cert_factory_sign,
    bench_rsa,
    bench_p384,
    bench_ed25519,
    bench_cert_keygen,
    bench_message_sizes,
    bench_indirect_sign,
);

#[cfg(all(feature = "pqc", not(feature = "composite")))]
criterion_group!(
    benches,
    bench_parse,
    bench_sign,
    bench_verify,
    bench_header_decode,
    bench_roundtrip,
    bench_allocations,
    bench_factory_sign,
    bench_cert_factory_sign,
    bench_rsa,
    bench_p384,
    bench_ed25519,
    bench_cert_keygen,
    bench_message_sizes,
    bench_indirect_sign,
    bench_pqc,
);

#[cfg(feature = "composite")]
criterion_group!(
    benches,
    bench_parse,
    bench_sign,
    bench_verify,
    bench_header_decode,
    bench_roundtrip,
    bench_allocations,
    bench_factory_sign,
    bench_cert_factory_sign,
    bench_rsa,
    bench_p384,
    bench_ed25519,
    bench_cert_keygen,
    bench_message_sizes,
    bench_indirect_sign,
    bench_pqc,
    bench_composite,
);

criterion_main!(benches);
