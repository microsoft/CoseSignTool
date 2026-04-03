# cose_sign1_certificates_local

Local certificate creation, ephemeral certs, chain building, and key loading.

## Purpose

This crate provides functionality for creating X.509 certificates with customizable options, supporting multiple key algorithms and pluggable key providers. It corresponds to `CoseSign1.Certificates.Local` in the V2 C# codebase.

## Architecture

- **Certificate** - DER-based certificate storage with optional private key and chain
- **CertificateOptions** - Fluent builder for certificate configuration with defaults:
  - Subject: "CN=Ephemeral Certificate"
  - Validity: 1 hour
  - Not-before offset: 5 minutes (for clock skew tolerance)
  - Key algorithm: RSA 2048
  - Hash algorithm: SHA-256
  - Key usage: Digital Signature
  - Enhanced key usage: Code Signing (1.3.6.1.5.5.7.3.3)
- **KeyAlgorithm** - RSA, ECDSA, and ML-DSA (post-quantum) key types
- **PrivateKeyProvider** - Trait for pluggable key generation (software, TPM, HSM)
- **CertificateFactory** - Trait for certificate creation
- **SoftwareKeyProvider** - Default in-memory key generation

## Design Notes

Unlike the C# version which uses `X509Certificate2`, this Rust implementation uses DER-encoded byte storage and delegates crypto operations to the `crypto_primitives` abstraction. This enables:

- Zero hard dependencies on specific crypto backends
- Support for multiple crypto providers (OpenSSL, Ring, BoringSSL)
- Integration with hardware security modules and TPMs

## Feature Flags

- `pqc` - Enables post-quantum cryptography support (ML-DSA / FIPS 204)

## V2 C# Mapping

| C# V2 | Rust |
|-------|------|
| `ICertificateFactory` | `CertificateFactory` trait |
| `IPrivateKeyProvider` | `PrivateKeyProvider` trait |
| `IGeneratedKey` | `GeneratedKey` struct |
| `CertificateOptions` | `CertificateOptions` struct |
| `KeyAlgorithm` | `KeyAlgorithm` enum |
| `SoftwareKeyProvider` | `SoftwareKeyProvider` struct |

## Example

```rust
use cose_sign1_certificates_local::*;
use std::time::Duration;

// Create certificate options with fluent builder
let options = CertificateOptions::new()
    .with_subject_name("CN=My Test Certificate")
    .with_key_algorithm(KeyAlgorithm::Ecdsa)
    .with_key_size(256)
    .with_validity(Duration::from_secs(3600));

// Use a key provider
let provider = SoftwareKeyProvider::new();
assert!(provider.supports_algorithm(KeyAlgorithm::Rsa));

// Certificate creation would be done via CertificateFactory trait
```

## Status

This is a stub implementation with the type system and trait structure in place. Full certificate generation requires integration with a concrete crypto backend (OpenSSL, Ring, etc.) via the `crypto_primitives` abstraction.
