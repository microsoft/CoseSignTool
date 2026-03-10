# Native Architecture

> **Canonical reference**: [`.github/instructions/native-architecture.instructions.md`](../.github/instructions/native-architecture.instructions.md)

This document summarises the complete architecture of the native (Rust + C + C++) COSE Sign1 SDK.

## Overview

Three layers of abstraction, all driven from a single Rust implementation:

| Layer | Language | Location | What it provides |
|-------|----------|----------|-----------------|
| **Library crates** | Rust | `native/rust/` | Signing, validation, trust-plan engine, extension packs |
| **FFI crates** | Rust (`extern "C"`) | `native/rust/*/ffi/` | C-ABI exports, panic safety, opaque handles |
| **Projection headers** | C / C++ | `native/c/include/cose/`, `native/c_pp/include/cose/` | Header-only wrappers consumed via CMake / vcpkg |

## Directory Layout

### Rust workspace (`native/rust/`)

```
primitives/
  cbor/                   cbor_primitives          — CBOR trait crate (zero deps)
  cbor/everparse/         cbor_primitives_everparse — EverParse CBOR backend
  crypto/                 crypto_primitives         — Crypto trait crate (zero deps)
  crypto/openssl/         cose_sign1_crypto_openssl — OpenSSL provider
  cose/                   cose_primitives           — RFC 9052 shared types & IANA constants
  cose/sign1/             cose_sign1_primitives     — Sign1 message, builder, headers
signing/
  core/                   cose_sign1_signing        — Builder, signing service, factory
  factories/              cose_sign1_factories      — Multi-factory extensible router
  headers/                cose_sign1_headers        — CWT claims builder
validation/
  core/                   cose_sign1_validation     — Staged validator facade
  primitives/             cose_sign1_validation_primitives — Trust engine (facts, rules, plans)
extension_packs/
  certificates/           cose_sign1_certificates   — X.509 chain trust pack
  certificates/local/     cose_sign1_certificates_local — Ephemeral cert generation
  azure_key_vault/        cose_sign1_azure_key_vault — AKV KID trust pack
  mst/                    cose_sign1_transparent_mst — Merkle Sealed Transparency pack
did/x509/                 did_x509                  — DID:x509 utilities
partner/cose_openssl/     cose_openssl              — Partner OpenSSL wrapper (excluded from workspace)
```

Each library crate above has a companion `ffi/` subcrate that exports the C ABI.

### C headers (`native/c/include/cose/`)

```
cose.h                          — Shared COSE types, status codes, IANA constants
sign1.h                         — COSE_Sign1 message primitives (auto-includes cose.h)
sign1/
  validation.h                  — Validator builder / runner
  trust.h                       — Trust plan / policy authoring
  signing.h                     — Sign1 builder, signing service, factory
  factories.h                   — Multi-factory wrapper
  cwt.h                         — CWT claims builder / serializer
  extension_packs/
    certificates.h              — X.509 certificate trust pack
    certificates_local.h        — Ephemeral certificate generation
    azure_key_vault.h           — Azure Key Vault trust pack
    mst.h                       — Microsoft Transparency trust pack
crypto/
  openssl.h                     — OpenSSL crypto provider
did/
  x509.h                        — DID:x509 utilities
```

### C++ headers (`native/c_pp/include/cose/`)

Same tree shape with `.hpp` extension plus:
- `cose.hpp` — umbrella header (conditional includes via `COSE_HAS_*` defines)
- Every header provides RAII classes in `namespace cose` / `namespace cose::sign1`

## Naming Conventions

### FFI two-tier prefix system

| Prefix | Scope | Examples |
|--------|-------|---------|
| `cose_` | Generic COSE operations | `cose_status_t`, `cose_headermap_*`, `cose_key_*`, `cose_crypto_*`, `cose_cwt_*` |
| `cose_sign1_` | Sign1-specific operations | `cose_sign1_message_*`, `cose_sign1_builder_*`, `cose_sign1_validator_*`, `cose_sign1_trust_*` |
| `did_x509_` | DID:x509 (separate RFC domain) | `did_x509_parse`, `did_x509_validate` |

### C++ namespaces

- `cose::` — shared types (`CoseHeaderMap`, `CoseKey`, `cose_error`)
- `cose::sign1::` — Sign1-specific classes (`CoseSign1Message`, `ValidatorBuilder`, `CwtClaims`)

## Key Capabilities

### Signing

```c
// C: create and sign a COSE_Sign1 message
#include <cose/sign1/signing.h>
#include <cose/crypto/openssl.h>

cose_crypto_signer_t* signer = NULL;
cose_crypto_openssl_signer_from_der(private_key, key_len, &signer);

cose_sign1_factory_t* factory = NULL;
cose_sign1_factory_from_crypto_signer(signer, &factory);

uint8_t* signed_bytes = NULL;
uint32_t signed_len = 0;
cose_sign1_factory_sign_direct(factory, payload, payload_len,
    "application/example", &signed_bytes, &signed_len, NULL);
```

```cpp
// C++: same operation with RAII
#include <cose/sign1/signing.hpp>
#include <cose/crypto/openssl.hpp>

auto provider = cose::CryptoProvider::New();
auto signer = provider.SignerFromDer(private_key);
auto factory = cose::sign1::SignatureFactory::FromCryptoSigner(signer);
auto bytes = factory.SignDirectBytes(payload, payload_len, "application/example");
```

### Validation with trust policy

```c
// C: build validator, add packs, author trust policy, validate
#include <cose/sign1/validation.h>
#include <cose/sign1/trust.h>
#include <cose/sign1/extension_packs/certificates.h>

cose_sign1_validator_builder_t* builder = NULL;
cose_sign1_validator_builder_new(&builder);
cose_sign1_validator_builder_with_certificates_pack(builder);

cose_sign1_trust_policy_builder_t* policy = NULL;
cose_sign1_trust_policy_builder_new_from_validator_builder(builder, &policy);
cose_sign1_trust_policy_builder_require_content_type_non_empty(policy);
cose_sign1_certificates_trust_policy_builder_require_x509_chain_trusted(policy);

cose_sign1_compiled_trust_plan_t* plan = NULL;
cose_sign1_trust_policy_builder_compile(policy, &plan);
cose_sign1_validator_builder_with_compiled_trust_plan(builder, plan);

cose_sign1_validator_t* validator = NULL;
cose_sign1_validator_builder_build(builder, &validator);

cose_sign1_validation_result_t* result = NULL;
cose_sign1_validator_validate_bytes(validator, cose_bytes, len, NULL, 0, &result);
```

```cpp
// C++: same with RAII and fluent API
#include <cose/sign1/validation.hpp>
#include <cose/sign1/trust.hpp>
#include <cose/sign1/extension_packs/certificates.hpp>

auto builder = cose::sign1::ValidatorBuilder();
cose::sign1::WithCertificates(builder);

auto policy = cose::sign1::TrustPolicyBuilder(builder);
policy.RequireContentTypeNonEmpty();
cose::sign1::RequireX509ChainTrusted(policy);

auto plan = policy.Compile();
cose::sign1::WithCompiledTrustPlan(builder, plan);

auto validator = builder.Build();
auto result = validator.Validate(cose_bytes);
```

### CWT claims

```cpp
// C++: build CWT claims for COSE_Sign1 protected headers
#include <cose/sign1/cwt.hpp>

auto claims = cose::sign1::CwtClaims::New();
claims.SetIssuer("did:x509:...");
claims.SetSubject("my-artifact");
claims.SetIssuedAt(std::time(nullptr));
auto cbor = claims.ToCbor();
```

### Message parsing

```cpp
// C++: parse and inspect a COSE_Sign1 message
#include <cose/sign1.hpp>

auto msg = cose::sign1::CoseSign1Message::Parse(cose_bytes);
auto alg = msg.Algorithm();           // std::optional<int64_t>
auto payload = msg.Payload();         // std::optional<std::vector<uint8_t>>
auto headers = msg.ProtectedHeaders(); // cose::CoseHeaderMap
auto kid = headers.GetBytes(COSE_HEADER_KID); // std::optional<std::vector<uint8_t>>
```

## Extension Packs

Each pack follows the same pattern:

| Pack | Rust crate | C header | C++ header | FFI prefix |
|------|-----------|----------|------------|------------|
| X.509 Certificates | `cose_sign1_certificates` | `<cose/sign1/extension_packs/certificates.h>` | `<cose/sign1/extension_packs/certificates.hpp>` | `cose_sign1_certificates_*` |
| Azure Key Vault | `cose_sign1_azure_key_vault` | `<cose/sign1/extension_packs/azure_key_vault.h>` | `<cose/sign1/extension_packs/azure_key_vault.hpp>` | `cose_sign1_akv_*` |
| Azure Artifact Signing | `cose_sign1_azure_artifact_signing` | `<cose/sign1/extension_packs/azure_artifact_signing.h>` | `<cose/sign1/extension_packs/azure_artifact_signing.hpp>` | `cose_sign1_ats_*` |
| Merkle Sealed Transparency | `cose_sign1_transparent_mst` | `<cose/sign1/extension_packs/mst.h>` | `<cose/sign1/extension_packs/mst.hpp>` | `cose_sign1_mst_*` |
| Ephemeral Certs (test) | `cose_sign1_certificates_local` | `<cose/sign1/extension_packs/certificates_local.h>` | `<cose/sign1/extension_packs/certificates_local.hpp>` | `cose_cert_local_*` |

## Build & Consume

### From Rust

```bash
cargo test --workspace
cargo run -p cose_sign1_validation_demo -- selftest
```

### From C/C++ via vcpkg

```bash
vcpkg install cosesign1-validation-native[certificates,mst,signing,cpp]
```

### From C/C++ via CMake (manual)

```bash
# 1. Build Rust FFI libs
cd native/rust && cargo build --release --workspace

# 2. Build C/C++ tests
cd native/c && cmake -B build -DBUILD_TESTING=ON && cmake --build build --config Release
cd native/c_pp && cmake -B build -DBUILD_TESTING=ON && cmake --build build --config Release
```

## CLI Tool

The `cose_sign1_cli` crate provides a command-line interface for signing, verifying, and inspecting COSE_Sign1 messages.

### Feature-Flag-Based Provider Selection

Unlike the V2 C# implementation which uses runtime plugin discovery, the CLI uses **compile-time provider selection**:

```rust
// V2 C# (runtime)
var plugins = pluginLoader.DiscoverPlugins();
var factory = router.GetFactory<AzureKeyVaultOptions>();

// Rust CLI (compile-time)
#[cfg(feature = "akv")]
providers.push(Box::new(AkvSigningProvider));
```

This provides several advantages:
- **Smaller binaries**: Only enabled providers are compiled in
- **Better performance**: No runtime reflection or plugin loading overhead
- **Security**: Attack surface is limited to compile-time selected features
- **Deterministic**: No runtime dependency on plugin discovery mechanisms

### Signing Providers

| Provider | `--provider` | Feature Flag | CLI Flags | V2 C# Equivalent |
|----------|-------------|-------------|-----------|-------------------|
| DER key | `der` | `crypto-openssl` | `--key key.der` | (base) |
| PFX/PKCS#12 | `pfx` | `crypto-openssl` | `--pfx cert.pfx [--pfx-password ...]` | `x509-pfx` |
| PEM files | `pem` | `crypto-openssl` | `--cert-file cert.pem --key-file key.pem` | `x509-pem` |
| Ephemeral | `ephemeral` | `certificates` | `[--subject CN=Test]` | `x509-ephemeral` |
| AKV certificate | `akv-cert` | `akv` | `--vault-url ... --cert-name ...` | `x509-akv-cert` |
| AKV key | `akv-key` | `akv` | `--vault-url ... --key-name ...` | `akv-key` |
| AAS | `ats` | `ats` | `--ats-endpoint ... --ats-account ... --ats-profile ...` | `x509-ats` |

### Verification Providers

| Provider | Feature Flag | CLI Flags | V2 C# Equivalent |
|----------|-------------|-----------|-------------------|
| X.509 Certificates | `certificates` | `--trust-root`, `--allow-embedded`, `--allowed-thumbprint` | `X509` |
| MST Receipts | `mst` | `--require-mst-receipt`, `--mst-offline-keys`, `--mst-ledger-instance` | `MST` |
| AKV KID | `akv` | `--require-akv-kid`, `--akv-allowed-vault` | `AzureKeyVault` |

### Feature Flag → Provider Mapping

| Feature Flag | Signing Providers | Verification Providers | Extension Pack Crate |
|-------------|------------------|----------------------|---------------------|
| `crypto-openssl` | `der`, `pfx`, `pem` | - | `cose_sign1_crypto_openssl` |
| `certificates` | `ephemeral` | `certificates` | `cose_sign1_certificates` |
| `akv` | `akv-cert`, `akv-key` | `akv` | `cose_sign1_azure_key_vault` |
| `ats` | `ats` | - | `cose_sign1_azure_artifact_signing` |
| `mst` | - | `mst` | `cose_sign1_transparent_mst` |

### V2 C# Plugin → Rust Feature Flag Mapping

| V2 C# Plugin Command | Rust CLI Provider | Rust Feature Flag | Example CLI Usage |
|---------------------|------------------|------------------|------------------|
| `x509-pfx` | `pfx` | `crypto-openssl` | `--provider pfx --pfx cert.pfx` |
| `x509-pem` | `pem` | `crypto-openssl` | `--provider pem --cert-file cert.pem --key-file key.pem` |
| `x509-ephemeral` | `ephemeral` | `certificates` | `--provider ephemeral --subject "CN=Test"` |
| `x509-akv-cert` | `akv-cert` | `akv` | `--provider akv-cert --vault-url ... --cert-name ...` |
| `akv-key` | `akv-key` | `akv` | `--provider akv-key --vault-url ... --key-name ...` |
| `x509-ats` | `ats` | `ats` | `--provider ats --ats-endpoint ... --ats-account ...` |

### Provider Trait Abstractions

#### SigningProvider
```rust
pub trait SigningProvider {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn create_signer(&self, args: &SigningProviderArgs) 
        -> Result<Box<dyn CryptoSigner>, anyhow::Error>;
}
```

#### VerificationProvider
```rust
pub trait VerificationProvider {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn create_trust_pack(&self, args: &VerificationProviderArgs) 
        -> Result<Arc<dyn CoseSign1TrustPack>, anyhow::Error>;
}
```

### Output Formatters

The CLI supports multiple output formats via the `OutputFormat` enum:
- **Text**: Human-readable tabular format (default)
- **JSON**: Structured JSON for programmatic consumption
- **Quiet**: Minimal output (exit codes only)

All commands consistently support these formats via the `--output-format` flag.

### Architecture Comparison

| Aspect | V2 C# | Rust CLI |
|--------|--------|----------|
| Plugin Discovery | Runtime via reflection | Compile-time via Cargo features |
| Provider Registration | `ICoseSignToolPlugin.Initialize()` | Static trait implementation |
| Configuration | Options classes + DI container | Command-line arguments + provider args |
| Async Model | `async Task<T>` throughout | Sync CLI with async internals |
| Error Handling | Exceptions + `Result<T>` | `anyhow::Error` + exit codes |
| Output | Logging frameworks | Structured output formatters |

## Quality Gates

| Gate | What | Enforced by |
|------|------|-------------|
| No tests in `src/` | `#[cfg(test)]` forbidden in `src/` directories | `Assert-NoTestsInSrc` |
| FFI parity | Every `require_*` helper has FFI export | `Assert-FluentHelpersProjectedToFfi` |
| Dependency allowlist | External deps must be in `allowed-dependencies.toml` | `Assert-AllowedDependencies` |
| Line coverage ≥ 95% | Production code only | `collect-coverage.ps1` |
