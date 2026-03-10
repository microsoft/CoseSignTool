# native/rust

Rust implementation of the COSE Sign1 SDK.

Detailed design docs live in [native/rust/docs/](docs/).

## Primitives

| Crate | Path | Purpose |
|-------|------|---------|
| `cbor_primitives` | `primitives/cbor/` | Zero-dep CBOR trait crate (`CborProvider`, `CborEncoder`, `CborDecoder`) |
| `cbor_primitives_everparse` | `primitives/cbor/everparse/` | EverParse/cborrs CBOR backend (formally verified) |
| `crypto_primitives` | `primitives/crypto/` | Crypto trait crate (`CoseKey`, sign/verify/algorithm) |
| `cose_sign1_crypto_openssl` | `primitives/crypto/openssl/` | OpenSSL crypto backend (ECDSA, ML-DSA) |
| `cose_primitives` | `primitives/cose/` | RFC 9052 shared types and IANA constants |
| `cose_sign1_primitives` | `primitives/cose/sign1/` | `CoseSign1Message`, `CoseHeaderMap`, `CoseSign1Builder` |

## Signing

| Crate | Path | Purpose |
|-------|------|---------|
| `cose_sign1_signing` | `signing/core/` | `SigningService`, `HeaderContributor`, `TransparencyProvider` |
| `cose_sign1_factories` | `signing/factories/` | Extensible factory router (`DirectSignatureFactory`, `IndirectSignatureFactory`) |
| `cose_sign1_headers` | `signing/headers/` | CWT claims builder / header serialization |

## Validation

| Crate | Path | Purpose |
|-------|------|---------|
| `cose_sign1_validation_primitives` | `validation/primitives/` | Trust engine (facts, rules, compiled plans, audit) |
| `cose_sign1_validation` | `validation/core/` | Staged validator facade (parse → trust → signature → post-signature) |
| `cose_sign1_validation_demo` | `validation/demo/` | CLI demo executable (`selftest` + `validate`) |
| `cose_sign1_validation_test_utils` | `validation/test_utils/` | Shared test infrastructure |

## Extension Packs

| Crate | Path | Purpose |
|-------|------|---------|
| `cose_sign1_certificates` | `extension_packs/certificates/` | X.509 `x5chain` parsing + signature verification |
| `cose_sign1_certificates_local` | `extension_packs/certificates/local/` | Ephemeral certificate generation (test/dev) |
| `cose_sign1_transparent_mst` | `extension_packs/mst/` | Microsoft Transparency receipt verification |
| `cose_sign1_azure_key_vault` | `extension_packs/azure_key_vault/` | Azure Key Vault `kid` detection / allow-listing |
| `cose_sign1_azure_artifact_signing` | `extension_packs/azure_artifact_signing/` | Azure Artifact Signing (AAS) pack + `azure_artifact_signing_client` sub-crate |

## DID

| Crate | Path | Purpose |
|-------|------|---------|
| `did_x509` | `did/x509/` | DID:x509 parsing and utilities |

## CLI

| Crate | Path | Purpose |
|-------|------|---------|
| `cose_sign1_cli` | `cli/` | Command-line tool for signing, verifying, and inspecting COSE_Sign1 messages |

## FFI Projections

Each library crate has a `ffi/` subcrate that produces `staticlib` + `cdylib` outputs.

| FFI Crate | C Header | Approx. Exports |
|-----------|----------|-----------------|
| `cose_sign1_primitives_ffi` | `<cose/sign1.h>` | ~25 |
| `cose_sign1_crypto_openssl_ffi` | `<cose/crypto/openssl.h>` | ~8 |
| `cose_sign1_signing_ffi` | `<cose/sign1/signing.h>` | ~22 |
| `cose_sign1_factories_ffi` | `<cose/sign1/factories.h>` | ~10 |
| `cose_sign1_headers_ffi` | `<cose/sign1/cwt.h>` | ~12 |
| `cose_sign1_validation_ffi` | `<cose/sign1/validation.h>` | ~12 |
| `cose_sign1_validation_primitives_ffi` | `<cose/sign1/trust.h>` | ~29 |
| `cose_sign1_certificates_ffi` | `<cose/sign1/extension_packs/certificates.h>` | ~34 |
| `cose_sign1_certificates_local_ffi` | `<cose/sign1/extension_packs/certificates_local.h>` | ~6 |
| `cose_sign1_mst_ffi` | `<cose/sign1/extension_packs/mst.h>` | ~17 |
| `cose_sign1_akv_ffi` | `<cose/sign1/extension_packs/azure_key_vault.h>` | ~6 |
| `did_x509_ffi` | `<cose/did/x509.h>` | ~8 |

FFI crates use **compile-time CBOR provider selection** via Cargo features.
See [docs/cbor-providers.md](docs/cbor-providers.md).

## Quick Start

```bash
# Run all tests
cargo test --workspace

# Run the demo CLI
cargo run -p cose_sign1_validation_demo -- selftest

# Use the CLI tool
cargo run -p cose_sign1_cli -- sign --input payload.bin --output signed.cose --key private.der
cargo run -p cose_sign1_cli -- verify --input signed.cose --allow-embedded
cargo run -p cose_sign1_cli -- inspect --input signed.cose

# Build FFI libraries (static + shared)
cargo build --release --workspace
```
