# crypto_primitives

Zero-dependency cryptographic backend traits for pluggable crypto providers.

## Purpose

This crate defines pure traits for cryptographic operations without any implementation or external dependencies. It mirrors the `cbor_primitives` architecture in the workspace, providing a clean abstraction layer between COSE protocol logic and cryptographic implementations.

## Architecture

- **Zero external dependencies** — only `std` types
- **Backend-agnostic** — no knowledge of COSE, CBOR, or protocol details
- **Pluggable** — implementations can use OpenSSL, Ring, BoringSSL, or remote KMS
- **Streaming support** — optional trait methods for chunked signing/verification

## Core Traits

### CryptoSigner / CryptoVerifier

Single-shot signing and verification:

```rust
pub trait CryptoSigner: Send + Sync {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn algorithm(&self) -> i64;
    fn key_type(&self) -> &str;
    fn key_id(&self) -> Option<&[u8]> { None }
    
    // Optional streaming support
    fn supports_streaming(&self) -> bool { false }
    fn sign_init(&self) -> Result<Box<dyn SigningContext>, CryptoError> { ... }
}
```

### SigningContext / VerifyingContext

Streaming signing and verification for large payloads:

```rust
pub trait SigningContext: Send {
    fn update(&mut self, chunk: &[u8]) -> Result<(), CryptoError>;
    fn finalize(self: Box<Self>) -> Result<Vec<u8>, CryptoError>;
}
```

The builder feeds Sig_structure bytes through streaming contexts:
1. `update(cbor_prefix)` — array header + context + headers + aad + bstr header
2. `update(payload_chunk)` * N — raw payload bytes
3. `finalize()` — produces the signature

### CryptoProvider

Factory for creating signers and verifiers from DER-encoded keys:

```rust
pub trait CryptoProvider: Send + Sync {
    fn signer_from_der(&self, private_key_der: &[u8]) -> Result<Box<dyn CryptoSigner>, CryptoError>;
    fn verifier_from_der(&self, public_key_der: &[u8]) -> Result<Box<dyn CryptoVerifier>, CryptoError>;
    fn name(&self) -> &str;
}
```

## Error Handling

All crypto operations return `Result<T, CryptoError>`:

```rust
pub enum CryptoError {
    SigningFailed(String),
    VerificationFailed(String),
    InvalidKey(String),
    UnsupportedAlgorithm(i64),
    UnsupportedOperation(String),
}
```

Manual `Display` and `Error` implementations (no `thiserror` dependency).

## Algorithm Constants

All COSE algorithm identifiers are provided as constants:

```rust
pub const ES256: i64 = -7;
pub const ES384: i64 = -35;
pub const ES512: i64 = -36;
pub const EDDSA: i64 = -8;
pub const PS256: i64 = -37;
pub const PS384: i64 = -38;
pub const PS512: i64 = -39;
pub const RS256: i64 = -257;
pub const RS384: i64 = -258;
pub const RS512: i64 = -259;

// Post-quantum (feature-gated)
#[cfg(feature = "pqc")]
pub const ML_DSA_44: i64 = -48;
#[cfg(feature = "pqc")]
pub const ML_DSA_65: i64 = -49;
#[cfg(feature = "pqc")]
pub const ML_DSA_87: i64 = -50;
```

## Null Provider

A stub provider is included for compilation when no crypto backend is selected:

```rust
let provider = NullCryptoProvider;
// All operations return UnsupportedOperation errors
```

## Implementations

Implementations of these traits exist in separate crates:

- `cose_sign1_crypto_openssl` — OpenSSL backend
- (Future) `cose_sign1_crypto_ring` — Ring backend
- (Future) `cose_sign1_crypto_boringssl` — BoringSSL backend
- `cose_sign1_azure_key_vault` — Remote Azure Key Vault signing

## V2 C# Mapping

This crate maps to the crypto abstraction layer that will be extracted from `CoseSign1.Certificates` in the V2 C# codebase. The V2 C# code currently uses `X509Certificate2` directly; this Rust design separates the crypto primitives from X.509 certificate handling.

## Testing

Tests are located in `tests/signer_tests.rs` (separate from `src/` per workspace conventions). Tests use mock implementations to verify trait behavior without requiring real crypto implementations.

Run tests:
```bash
cargo test -p crypto_primitives
```

## License

MIT License. Copyright (c) Microsoft Corporation.
