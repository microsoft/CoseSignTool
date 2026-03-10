---
applyTo: "native/**"
---
# Native Architecture & Design Principles — CoseSignTool

> Cross-cutting architectural guidance for all native code (Rust, C, C++).

## Layered Dependency Graph

```
┌─────────────────────────────────────────────────────────┐
│                    C / C++ Projections                   │
│   native/c/include/cose/   — C headers                  │
│   native/c_pp/include/cose/ — C++ RAII headers          │
│   Tree mirrors Rust: cose.h, sign1.h, sign1/*.h         │
├─────────────────────────────────────────────────────────┤
│                    FFI Crates (*_ffi)                    │
│   (C-ABI exports, panic safety, handle types)           │
├─────────────────────────────────────────────────────────┤
│              Feature Pack Crates                        │
│   (certificates, azure_key_vault, transparent_mst)      │
├─────────────────────────────────────────────────────────┤
│              Factory / Orchestration                    │
│   (cose_sign1_factories — extensible router)            │
├─────────────────────────────────────────────────────────┤
│              Domain Crates                              │
│   (signing, validation, headers, did_x509)              │
├─────────────────────────────────────────────────────────┤
│              Primitives Layer                           │
│   primitives/cbor/          — trait crate               │
│   primitives/cbor/everparse — EverParse CBOR backend    │
│   primitives/crypto/        — trait crate               │
│   primitives/crypto/openssl — OpenSSL crypto backend    │
│   primitives/cose/          — RFC 9052 types/constants  │
│   primitives/cose/sign1/    — Sign1 types/builder       │
└─────────────────────────────────────────────────────────┘
```

**Rule: Dependencies flow DOWN only. Never up, never sideways between packs.**

## Single Responsibility

- **Primitives crates**: Types & traits only. No policy, no I/O, no network.
- **Domain crates**: Business logic for one capability area.
- **Feature packs**: Implement domain traits for a specific service/standard.
- **Factory crate**: Orchestrates signing operations, applies transparency providers.
- **FFI crates**: Translation layer only. No business logic — delegate everything.
- **C/C++ projections**: Header-only wrappers. No compiled code — just inline RAII/convenience.

## Composition Over Inheritance

Rust doesn't have inheritance. Use trait composition:

```rust
// Trust pack composes: facts + resolvers + validators + default plan
pub trait CoseSign1TrustPack: Send + Sync {
    fn name(&self) -> &str;
    fn fact_producer(&self) -> Arc<dyn TrustFactProducer>;
    fn cose_key_resolvers(&self) -> Vec<Arc<dyn CoseKeyResolver>>;
    fn post_signature_validators(&self) -> Vec<Arc<dyn PostSignatureValidator>>;
    fn default_trust_plan(&self) -> Option<CompiledTrustPlan>;
}
```

## Extensibility Patterns

### Factory Extension Point
```rust
// Packs register via TypeId dispatch
factory.register::<CssSignatureOptions>(css_factory);
// Callers invoke via type
let msg = factory.create_with::<CssSignatureOptions>(&opts)?;
```

### Transparency Provider Pipeline
```rust
// N providers, each preserves prior receipts
for provider in &self.transparency_providers {
    bytes = add_proof_with_receipt_merge(provider.as_ref(), &bytes)?;
}
```

### Trust Pack Registration
```rust
// Packs contribute facts + resolvers + validators
builder.with_certificates_pack(options);
builder.with_mst_pack(options);
builder.with_akv_pack(options);
```

## V2 C# Mapping

When porting from the C# V2 branch (`users/jstatia/v2_clean_slate:V2/`), follow these mappings:

| C# V2 | Rust |
|--------|------|
| `ISigningService<TOptions>` | `SigningService` trait |
| `ICoseSign1MessageFactory<TOptions>` | `DirectSignatureFactory` / `IndirectSignatureFactory` |
| `ICoseSign1MessageFactoryRouter` | `CoseSign1MessageFactory` (extensible router) |
| `ITransparencyProvider` | `TransparencyProvider` trait |
| `TransparencyProviderBase` | `add_proof_with_receipt_merge()` function |
| `IHeaderContributor` | `HeaderContributor` trait |
| `DirectSignatureOptions` | `DirectSignatureOptions` struct |
| `IndirectSignatureOptions` | `IndirectSignatureOptions` struct |
| `CoseSign1Message` | `CoseSign1Message` struct |
| `ICoseSign1ValidatorFactory` | Validator fluent builders |

**Key difference**: V2 C# uses `async Task<T>` everywhere. Rust provides both sync and async paths, with `block_on()` bridges at the FFI boundary.

## Quality Gates (enforced by `collect-coverage.ps1`)

| Gate | What it Checks | Failure Mode |
|------|----------------|--------------|
| `Assert-NoTestsInSrc` | No test code in `src/` directories | Blocks merge |
| `Assert-FluentHelpersProjectedToFfi` | Every `require_*` helper has FFI export | Blocks merge |
| `Assert-AllowedDependencies` | Every external dep in allowlist | Blocks merge |
| Line coverage ≥ 95% | Production code only | Blocks merge |

## Security Principles

- **Panic safety**: All FFI exports catch panics with `with_catch_unwind()`.
- **Memory safety**: Handle ownership is explicit — create/free pairs.
- **No undefined behavior**: `#![deny(unsafe_op_in_unsafe_fn)]` enforced in FFI crates.
- **Minimal attack surface**: Global allowlist has only 3 crates (`ring`, `sha2`, `sha1`). Per-crate scoping for everything else.
- **No secrets in code**: Signing keys never cross the FFI boundary — handles/callbacks only.

## Performance Considerations

- **Streaming signatures**: Payloads > 85KB use streaming `Sig_structure` to avoid LOH allocation.
- **CBOR provider singleton**: `OnceLock` — initialized once, shared across threads.
- **Zero-copy**: `Arc<[u8]>` for shared payload bytes in the validation pipeline.
- **Move semantics**: RAII types in C++ are move-only — no unnecessary copies.

## Adding a New Feature Pack

1. Create library crate: `native/rust/extension_packs/new_pack/` with `signing/` and `validation/` submodules if needed.
2. Implement `CoseSign1TrustPack` for validation.
3. Optionally implement `TransparencyProvider` for transparency support.
4. Create FFI crate: `native/rust/extension_packs/new_pack/ffi/` with pack registration + trust policy helpers.
5. Create C header: `native/c/include/cose/sign1/extension_packs/new_pack.h`
6. Create C++ header: `native/c_pp/include/cose/sign1/extension_packs/new_pack.hpp`
7. Update CMake: add `find_library` + `COSE_HAS_NEW_PACK` define.
8. Update vcpkg: add feature to `vcpkg.json` + `portfile.cmake`.
9. Update `allowed-dependencies.toml` for any new external deps.
10. Update `.vscode/c_cpp_properties.json` with the new `COSE_HAS_*` define.
11. Update `cose.hpp` umbrella to conditionally include.
12. Add fluent helpers and ensure FFI parity (ABI gate).

## OpenSSL Discovery

OpenSSL is required by `cose_sign1_crypto_openssl`, `cose_sign1_certificates`, `cose_sign1_certificates_local`, and any crate that transitively depends on them (including their FFI projections).

### How `openssl-sys` finds OpenSSL (priority order)
1. **`OPENSSL_DIR` environment variable** — points to the prefix directory containing `include/` and `lib/` subdirectories.
2. **`pkg-config`** (Linux/macOS) — uses `PKG_CONFIG_PATH` to locate `openssl.pc`.
3. **vcpkg** (Windows) — uses `VCPKG_ROOT` env var or `vcpkg` on `PATH`.

### Discovering the correct `OPENSSL_DIR` on your machine

The `.cargo/config.toml` in this workspace sets a default `OPENSSL_DIR` with `force = false`, so a real environment variable always wins. If the default doesn't match your system, set `OPENSSL_DIR` via one of these methods:

**vcpkg (any platform)**
```powershell
# Windows
$triplet = "x64-windows"          # or x64-windows-static, arm64-windows, etc.
$env:OPENSSL_DIR = "$env:VCPKG_ROOT\installed\$triplet"

# Linux/macOS
export OPENSSL_DIR="$VCPKG_ROOT/installed/x64-linux"   # or x64-osx
```

**Homebrew (macOS)**
```bash
export OPENSSL_DIR="$(brew --prefix openssl@3)"
```

**System OpenSSL (Linux)**
```bash
export OPENSSL_DIR="/usr"           # headers in /usr/include/openssl, libs in /usr/lib
# or
export OPENSSL_DIR="/usr/local"     # if built from source
```

**Vendored (no system OpenSSL required)**
```bash
cargo check -p cose_sign1_crypto_openssl --features openssl/vendored
```
This compiles OpenSSL from source and requires Perl + a C compiler.

### Runtime DLL discovery (Windows)

On Windows with dynamically-linked OpenSSL, tests need the DLLs on `PATH`:
```powershell
$env:PATH = "$env:OPENSSL_DIR\bin;$env:PATH"
```
The `collect-coverage.ps1` script handles this automatically.

## Orchestrator Plan Configuration

When creating Copilot orchestrator plans for native code:

### Environment
- **Plan-level `env`**: Set `OPENSSL_DIR` for crates that depend on OpenSSL. **Discover the path** rather than hardcoding it — use `$VCPKG_ROOT\installed\<triplet>` or the appropriate system path:
  ```json
  "env": { "OPENSSL_DIR": "<VCPKG_ROOT>\\installed\\x64-windows" }
  ```
  Replace `<VCPKG_ROOT>` with the actual vcpkg installation directory on the target machine (e.g., from `$env:VCPKG_ROOT` or `vcpkg env`).

### Work Specs — `allowedFolders`
- **Every agent work spec** that compiles Rust code linking OpenSSL MUST include `allowedFolders` pointing to the directory that contains the OpenSSL installation, so the agent sandbox can access headers and libraries:
  ```json
  "work": {
    "type": "agent",
    "model": "claude-sonnet-4.5",
    "allowedFolders": ["<VCPKG_ROOT>"],
    "instructions": "..."
  }
  ```
- Discover `<VCPKG_ROOT>` from `$env:VCPKG_ROOT`, or from the parent of whichever directory `OPENSSL_DIR` resolves to (e.g., if `OPENSSL_DIR` is `/usr/local`, allow `/usr/local`).
- This applies to ALL jobs in plans that build `cose_sign1_crypto_openssl`, `cose_sign1_certificates`, `cose_sign1_certificates_local`, or any crate that transitively depends on OpenSSL.
- Without `allowedFolders`, the agent cannot read OpenSSL headers and compilation will fail.

### Postchecks
- **Per-crate postchecks**: Use `cargo check -p <crate_name>` (NOT `--exclude` with `-p`)
- **Workspace postchecks**: Use `cargo check --workspace --exclude cose_openssl --exclude cose_openssl_ffi`
- **Test postchecks**: Use `cargo test --workspace --exclude cose_openssl --exclude cose_openssl_ffi --no-fail-fast`
- `cose_openssl` (partner crate) requires separate OpenSSL setup — always exclude from workspace checks.
