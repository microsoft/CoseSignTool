---
applyTo: "native/rust/**"
---
# Native Rust Coding Standards — CoseSignTool

> Applies to all files under `native/rust/`.

## Copyright Header

All `.rs` files MUST begin with:
```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
```

## Workspace Architecture

### Directory Structure

The workspace is organized by capability area:

```
native/rust/
├── primitives/           # Core primitives
│   ├── cbor/             #   CBOR trait crate + EverParse backend
│   ├── crypto/           #   Crypto trait crate + OpenSSL backend
│   └── cose/             #   Shared COSE types + Sign1 message/builder
├── signing/              # Signing functionality (core, factories, headers)
├── validation/           # Validation functionality (core, primitives, demo, test_utils)
├── extension_packs/      # Feature packs (certificates, mst, azure_key_vault)
├── did/                  # DID functionality (x509)
└── partner/              # Partner integrations (cose_openssl)
```

Each category contains crates with their FFI projections in `ffi/` subdirectories.

### Crate Categories

| Category | Location | Naming Pattern | Purpose |
|----------|----------|---------------|---------|
| Primitives | `primitives/` | `*_primitives` | Zero-policy, lowest-layer types and traits. Minimal dependencies. |
| Domain crates | `signing/`, `validation/` | `cose_sign1_*` | Capability areas: `_signing`, `_validation`, `_headers`, `_factories` |
| Feature packs | `extension_packs/` | `cose_sign1_*` | Service integrations: `_azure_key_vault`, `_transparent_mst`, `_certificates` |
| Local utilities | `extension_packs/*/local/` | `cose_sign1_*_local` | Local cert creation, ephemeral keys, test harness support: `_certificates_local` |
| FFI projections | `*/ffi/` | `*_ffi` | C-ABI exports. One FFI crate per library crate. |
| Test utilities | `validation/test_utils/` | `*_test_utils` | Shared test infrastructure (excluded from coverage). |
| Demos | `validation/demo/` | `*_demo` | Example executables (excluded from coverage). |
| Standalone | `did/`, `crypto/` | `did_x509`, `crypto_*` | Non-COSE-specific crates. |

### Module Structure

- **Feature pack crates** that contribute to both signing and validation use `signing/` and `validation/` submodule directories (e.g., `cose_sign1_certificates`).
- **Pure domain crates** (e.g., `cose_sign1_validation`, `cose_sign1_signing`) use flat module files.
- Every crate's `lib.rs` must have `//!` module-level doc comments describing purpose.
- Re-export key public types from `lib.rs` with `pub use`.

## Error Handling

### Production Crates — Manual `Display` + `Error`

**ALWAYS** use manual implementations. **NEVER** use `thiserror` or any derive-macro error crate.

```rust
#[derive(Debug)]
pub enum FooError {
    InvalidInput(String),
    CborError(String),
}

impl std::fmt::Display for FooError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidInput(s) => write!(f, "invalid input: {}", s),
            Self::CborError(s) => write!(f, "CBOR error: {}", s),
        }
    }
}

impl std::error::Error for FooError {}
```

### FFI Crates — Thread-Local Error + Panic Safety

FFI crates use `anyhow` at the boundary with thread-local error storage:
```rust
thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = RefCell::new(None);
}

pub fn with_catch_unwind<F>(f: F) -> cose_status_t
where F: FnOnce() -> Result<cose_status_t, anyhow::Error>
{ /* catches panics, sets LAST_ERROR */ }
```

## Test Organization — MANDATORY

**Tests MUST live in `tests/` directories.** The `Assert-NoTestsInSrc` gate blocks:
- `#[cfg(test)]` in any `src/` file
- `#[test]` in any `src/` file
- `mod tests` in any `src/` file

```
my_crate/
  src/
    lib.rs          ← NO test code here
    module.rs       ← NO #[cfg(test)] allowed
  tests/
    module_tests.rs ← All tests go here
```

**Coverage gate**: 95% line coverage required on production code. Non-production code (`tests/`, `examples/`, `_demo`, `_test_utils`) is excluded.

## Dependency Management — MANDATORY

Every external crate dependency MUST be listed in `native/rust/allowed-dependencies.toml`:

```toml
[global]           # Allowed in ANY crate (keep VERY small — crypto only)
[dev]              # Allowed in any [dev-dependencies]
[crate.<name>]     # Scoped to one specific crate
```

- `path = ...` dependencies (workspace-internal) are exempt.
- The `Assert-AllowedDependencies` gate enforces this on every build.
- To add a new dependency: add it to the allowlist with a justification, then get PR approval.
- Prefer zero-dependency alternatives. Inline trivial utilities (hex encoding, base64) rather than adding crates.

## CBOR Provider Pattern

CBOR encoding/decoding uses a compile-time provider singleton:

```rust
// Encoding
let mut enc = cose_sign1_primitives::provider::encoder();
enc.encode_array(4)?;
enc.encode_bstr(data)?;
let bytes = enc.into_bytes();

// Decoding
let mut dec = cose_sign1_primitives::provider::decoder(bytes);
let len = dec.decode_array_len()?;
let value = dec.decode_bstr()?;
```

**Rules:**
- Never construct CBOR providers directly — use `provider::encoder()` / `provider::decoder()`.
- The `cbor-everparse` feature flag selects the implementation.
- `compile_error!` fires if no provider is selected.

## Core Traits — Signing

| Trait | Crate | Purpose |
|-------|-------|---------|
| `CoseKey` | `cose_sign1_primitives` | Sign/verify operations. Must implement `sign()`, `verify()`, `algorithm()`, `key_type()`. |
| `SigningService` | `cose_sign1_signing` | Factory for `CoseSigner`. Methods: `get_cose_signer()`, `is_remote()`, `verify_signature()`. |
| `HeaderContributor` | `cose_sign1_signing` | Adds headers during signing. Must specify `merge_strategy()`. |
| `TransparencyProvider` | `cose_sign1_signing` | Augments messages with transparency proofs. Receipt merge handled by `add_proof_with_receipt_merge()`. |

## Core Traits — Validation

| Trait | Crate | Purpose |
|-------|-------|---------|
| `CoseSign1TrustPack` | `cose_sign1_validation` | Composable validation bundle: facts, resolvers, validators, default plan. |
| `TrustFactProducer` | `cose_sign1_validation_primitives` | Lazy fact production for trust evaluation. |
| `CoseKeyResolver` | `cose_sign1_validation` | Resolves signing keys. Sync + async paths. |
| `PostSignatureValidator` | `cose_sign1_validation` | Policy checks after signature verification. |

## Factory Pattern

The `CoseSign1MessageFactory` is an extensible router:
- `create_direct()` / `create_indirect()` are built-in convenience methods.
- `register<T>()` allows packs to add new signing workflows (CSS, etc.).
- `create_with<T>()` dispatches to registered factories by options type.
- `IndirectSignatureFactory` wraps `DirectSignatureFactory` (not parallel).
- Factories return `CoseSign1Message` (primary) or `Vec<u8>` (via `*_bytes()` overloads).

## Naming Conventions

- **Crate names**: `snake_case` (e.g., `cose_sign1_primitives`)
- **Modules**: `snake_case` (e.g., `receipt_verify.rs`)
- **Types**: `PascalCase` (e.g., `CoseSign1Message`, `AkvError`)
- **Functions**: `snake_case` (e.g., `create_from_public_key`)
- **Constants**: `SCREAMING_SNAKE_CASE` (e.g., `RECEIPTS_HEADER_LABEL`)
- **Feature flags**: `kebab-case` (e.g., `cbor-everparse`, `pqc-mldsa`)

## Documentation Requirements

- All `lib.rs` files: `//!` module docs with crate purpose and V2 C# mapping.
- All public types/traits/functions: `///` doc comments with:
  - Purpose description
  - `# Arguments` for complex methods
  - `# Safety` on `unsafe` functions
  - V2 mapping reference: `"Maps V2 ISigningService<TSigningOptions>"`
- Every crate: `README.md` with purpose, usage, and architecture notes.

## Feature Flags

- `cbor-everparse`: CBOR provider selection (default, mandatory).
- `pqc` / `pqc-mldsa`: Post-quantum algorithms behind `#[cfg(feature = "pqc")]`.
- Feature flags MUST have `compile_error!` fallbacks when nothing is selected.

## Async Patterns

- Core traits provide both sync and async methods (async defaults to sync).
- FFI boundary uses `tokio::runtime::Runtime::block_on()` to bridge async → sync.
- Use `OnceLock` for runtime singletons.
- Azure SDK crates (`azure_core`, `azure_identity`, `azure_security_keyvault_keys`) are async — bridge at the FFI/factory boundary.
