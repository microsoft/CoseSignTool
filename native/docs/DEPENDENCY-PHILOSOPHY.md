<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# Dependency Philosophy

> Why each dependency exists, what we removed, and the rules for adding new ones.

## Table of Contents

- [Guiding Principles](#guiding-principles)
- [Core Dependencies](#core-dependencies)
- [Azure Dependencies](#azure-dependencies)
- [Removed Dependencies](#removed-dependencies)
- [Dependency Decision Framework](#dependency-decision-framework)
- [Workspace Dependency Map](#workspace-dependency-map)

---

## Guiding Principles

1. **Every dependency must justify its existence.** If `std` can do it, use `std`.
2. **Core crates have minimal deps.** The signing/validation path should be
   auditable by reading a small set of well-known crates.
3. **Heavy deps stay in extension packs.** Azure SDK, `tokio`, `reqwest` — these
   are feature-gated and only compiled when an extension pack is enabled.
4. **No proc-macro crates in the core path.** Proc macros (`thiserror`,
   `derive_builder`, `serde_derive` in core) increase compile times
   and expand the trusted code surface.
5. **Pin major versions in `[workspace.dependencies]`.** All external crates are
   declared once in the workspace root `Cargo.toml` for consistent versioning.

---

## Core Dependencies

These dependencies are on the critical path for signing and validation. Each is
irreplaceable — there is no reasonable `std`-only alternative.

| Crate | Version | Used By | Why It Exists |
|-------|---------|---------|--------------|
| `openssl` | 0.10 | `cose_sign1_crypto_openssl` | ECDSA / RSA / ML-DSA signing and verification. OpenSSL is the crypto backend; abstracting it away is the job of `crypto_primitives`. No pure-Rust crate supports the full algorithm matrix (especially ML-DSA with OpenSSL 3.x). |
| `sha2` | 0.10 | Indirect signing, content hashing | SHA-256/384/512 for indirect signature payloads and trust subject IDs. Pure Rust, no C dependencies, widely audited. |
| `sha1` | 0.10 | Certificate thumbprints | SHA-1 thumbprints for X.509 certificates (required by the COSE x5t header). Deprecated for security, but required by the spec. |
| `x509-parser` | 0.18 | `cose_sign1_certificates` | X.509 certificate chain parsing (DER/PEM). The only mature Rust crate for full certificate parsing including extensions, SANs, and basic constraints. |
| `base64` | 0.22 | MST JWKS, PEM handling | Base64/Base64URL encoding for JWK parsing in MST receipts and PEM handling. |
| `hex` | 0.4 | Thumbprint display, debugging | Hex encoding for certificate thumbprints and diagnostic output. |
| `anyhow` | 1 | FFI crates only | Ergonomic error handling at the FFI boundary. Used in FFI crates (not library crates) because FFI errors are converted to thread-local strings anyway. Library crates use manual `Display + Error` impls. |
| `regex` | 1 | `did_x509`, trust policy | DID:x509 method-specific-id parsing and trust policy pattern matching. |
| `url` | 2 | AKV, AAS packs | URL parsing for Azure Key Vault URIs and Azure Artifact Signing endpoints. |

### CBOR Backend

| Crate | Version | Used By | Why It Exists |
|-------|---------|---------|--------------|
| `cborrs` (EverParse) | Vendored | `cbor_primitives_everparse` | Formally verified CBOR parser produced by Microsoft Research's EverParse toolchain. This is the default and recommended CBOR backend. The `cbor_primitives` trait crate abstracts it, allowing future backends without changing library code. |

### Serialization (Scoped)

| Crate | Version | Used By | Why It Exists |
|-------|---------|---------|--------------|
| `serde` | 1 | MST, AKV, AAS packs | JSON deserialization for JWKS keys (MST receipts), AKV API responses, and AAS client. Not used in core primitives or signing/validation. |
| `serde_json` | 1 | MST, AKV, AAS packs | JSON parsing companion to `serde`. Same scope restriction. |

> **Note**: `serde` and `serde_json` are **not** used in the primitives, signing,
> or validation core crates. They appear only in extension packs that interact
> with JSON-based external services.

### Tracing

| Crate | Version | Used By | Why It Exists |
|-------|---------|---------|--------------|
| `tracing` | 0.1 | Library crates | Structured diagnostic logging. Instrumentation points in signing, validation, and crypto operations. Zero overhead when no subscriber is installed. |
| `tracing-subscriber` | 0.3 | CLI, demo | Console output for `tracing` events. Only in executable crates. |

---

## Azure Dependencies

These dependencies exist **only** in extension packs. They are feature-gated
in the vcpkg port and Cargo workspace — if you don't enable the `akv` or `ats`
feature, none of these crates are compiled.

| Crate | Version | Used By | Why It Exists |
|-------|---------|---------|--------------|
| `azure_core` | 0.33 | AKV, AAS packs | Azure SDK core (HTTP pipeline, retry, auth plumbing). Required by all `azure_*` crates. Features: `reqwest` + `reqwest_native_tls` (no rustls to avoid OpenSSL + rustls conflicts). |
| `azure_identity` | 0.33 | AKV, AAS packs | Azure credential providers (DefaultAzureCredential, managed identity, CLI). |
| `azure_security_keyvault_keys` | 0.12 | AKV pack | Azure Key Vault key operations (sign with HSM-backed keys). |
| `tokio` | 1 | AKV, AAS packs | Async runtime for Azure SDK calls. Features: `rt` + `macros` only (no full runtime). |
| `reqwest` | 0.13 | MST client, AAS client | HTTP client for MST ledger queries and AAS API calls. Features: `json` + `rustls-tls`. |
| `async-trait` | 0.1 | AKV, AAS packs | `async fn` in traits (pending stabilization of async trait methods). |

### Why Not `rustls` Everywhere?

The `azure_core` crate uses `reqwest_native_tls` (which delegates to the
platform TLS — SChannel on Windows, OpenSSL on Linux). This avoids shipping
two TLS stacks and ensures Azure SDK authentication works with corporate
proxies that require platform certificate stores.

The `reqwest` crate (used by MST/AAS clients) uses `rustls-tls` because these
clients don't need platform cert store integration.

---

## Removed Dependencies

These crates were previously in the dependency tree and have been intentionally
removed. Do not re-add them without a compelling justification.

| Removed Crate | Replaced By | Rationale |
|--------------|-------------|-----------|
| `once_cell` | `std::sync::LazyLock` | Rust 1.80 stabilized `LazyLock`, eliminating the need for `once_cell::sync::Lazy`. One fewer dependency in every crate that needed lazy initialization. |
| `parking_lot` | `std::sync::Mutex` | The performance difference is negligible for our usage patterns (low-contention locks in validation pipelines). Removing it simplifies the dependency tree and eliminates platform-specific lock code. |
| `azure_security_keyvault_certificates` | Direct key operations via `azure_security_keyvault_keys` | The certificates client was unused — AKV signing only needs key operations. Removing it eliminated a large transitive dependency subtree. |
| `thiserror` | Manual `Display` + `Error` impls | Proc macros increase compile time and expand the trusted code surface. Manual impls are ~10 lines per error type — a small cost for build transparency. `anyhow` is still used in FFI crates where error types are immediately stringified. |

---

## Dependency Decision Framework

When considering a new dependency, evaluate against this checklist:

### Must-Have Criteria

| # | Question | Required Answer |
|---|----------|----------------|
| 1 | Can `std` do this? | No |
| 2 | Is there a simpler alternative already in the dep tree? | No |
| 3 | Is the crate actively maintained (commit in last 6 months)? | Yes |
| 4 | Is the crate widely used (>1M downloads or well-known ecosystem)? | Yes |
| 5 | Does it avoid `unsafe` or have a credible safety argument? | Yes |

### Placement Rules

| If the dependency is needed by... | Place it in... |
|----------------------------------|---------------|
| Primitives (`cbor_primitives`, `crypto_primitives`, `cose_primitives`) | `[workspace.dependencies]` — but think very hard first |
| Domain crates (signing, validation, headers) | `[workspace.dependencies]` |
| A single extension pack | That pack's `Cargo.toml` only |
| Azure SDK integration | Extension pack, behind a Cargo feature |
| CLI/demo only | Executable crate's `Cargo.toml` |
| Tests only | `[dev-dependencies]` in the relevant crate |

### Red Flags

These should trigger extra scrutiny or rejection:

| Red Flag | Why |
|----------|-----|
| Proc-macro crate in core path | Compile-time cost, opaque code generation |
| Pulls in `tokio` or `reqwest` transitively | Async runtime in core is an architecture violation |
| Crate has `unsafe` without justification | Expands the trusted code surface |
| Crate is maintained by a single person with no recent activity | Bus-factor risk |
| Crate duplicates functionality already in `std` | Use `std` instead |
| Crate requires a specific allocator or global state | Conflicts with our zero-allocation goals |

---

## Workspace Dependency Map

Visual overview of which crate categories use which dependencies:

```
                        ┌─────────────────────────────────────────────┐
                        │              Primitives Layer               │
                        │  cbor_primitives: (zero external deps)      │
                        │  crypto_primitives: (zero external deps)    │
                        │  cose_primitives: (zero external deps)      │
                        │  cose_sign1_primitives: sha2                │
                        └─────────────────────┬───────────────────────┘
                                              │
                        ┌─────────────────────▼───────────────────────┐
                        │              Domain Crates                  │
                        │  signing: sha2, tracing                     │
                        │  validation: sha2, tracing                  │
                        │  headers: (minimal)                         │
                        │  factories: sha2, tracing                   │
                        └─────────────────────┬───────────────────────┘
                                              │
          ┌───────────────────────────────────┼───────────────────────────┐
          │                                   │                           │
┌─────────▼──────────┐  ┌────────────────────▼──────────┐  ┌────────────▼───────────┐
│  Certificates Pack │  │       MST Pack               │  │    AKV / AAS Packs     │
│  x509-parser       │  │  serde, serde_json           │  │  azure_core            │
│  sha1              │  │  base64, reqwest             │  │  azure_identity        │
│  openssl           │  │  sha2                        │  │  azure_security_kv_keys│
│  base64            │  │                              │  │  tokio, reqwest        │
│                    │  │                              │  │  async-trait           │
└────────────────────┘  └───────────────────────────────┘  └────────────────────────┘
          │                         │                                │
          └─────────────────────────┼────────────────────────────────┘
                                    │
                        ┌───────────▼─────────────────────────────────┐
                        │              FFI Crates                     │
                        │  + anyhow (error stringification at ABI)    │
                        └───────────────────────────────────────────── ┘
```

### Dependency Counts

| Layer | Direct External Deps | Transitive Deps (approx.) |
|-------|---------------------|--------------------------|
| Primitives (no crypto) | 0–1 | < 10 |
| Domain crates | 2–3 | < 20 |
| Certificates pack | 4–5 | < 30 |
| Azure extension packs | 8–10 | < 80 |
| Full workspace | ~20 direct | ~120 total |

The core signing + validation path (without Azure packs) has approximately
20 transitive dependencies — a fraction of typical Rust projects of this scope.