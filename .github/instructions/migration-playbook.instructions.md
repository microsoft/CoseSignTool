---
applyTo: "native/**"
---
# Migration Playbook — V2 C# to Native Rust

> Step-by-step guidance for porting feature packs and capabilities from the
> V2 C# branch (`users/jstatia/v2_clean_slate:V2/`) to native Rust.

## Migration Phases

The native port follows a layered merge strategy. Each phase is a staged PR
from a working branch into `native_ports_final`.

| Phase | What | Status |
|-------|------|--------|
| 1 | Primitives (CBOR, Crypto, COSE types, Sign1 builder) | ✅ Complete |
| 2 | OpenSSL crypto provider + PEM support | ✅ Complete |
| 3 | Signing, Validation, DID, Factories, Headers + FFI + C/C++ | ✅ Complete (PR #186) |
| 4 | Certificates extension pack + local cert utilities | 🔜 Next |
| 5 | Azure Key Vault extension pack | Planned |
| 6 | MST (Microsoft Transparency) extension pack | Planned |
| 7 | CLI tool + packaging | Planned |

## Porting a New Extension Pack

### 1. Identify V2 C# Source
```
V2/CoseSign1.Certificates/        → native/rust/extension_packs/certificates/
V2/CoseSign1.Transparent.MST/     → native/rust/extension_packs/mst/
```

### 2. Create Rust Crate Structure
```
extension_packs/new_pack/
├── Cargo.toml
├── src/
│   ├── lib.rs              # Module-level docs, pub use re-exports
│   ├── signing/            # If pack contributes to signing
│   │   └── mod.rs
│   └── validation/         # If pack contributes to validation
│       ├── mod.rs
│       ├── trust_pack.rs   # impl CoseSign1TrustPack
│       ├── fact_producer.rs
│       └── key_resolver.rs
├── tests/                  # Integration tests (not in src/)
└── ffi/
    ├── Cargo.toml
    ├── src/
    │   ├── lib.rs          # FFI exports + catch_unwind
    │   ├── types.rs        # Opaque handle types
    │   └── error.rs        # Thread-local error storage
    └── tests/              # FFI smoke + null safety tests
```

### 3. Implement Core Traits

Every extension pack implements some subset of:

```rust
// Validation side
impl CoseSign1TrustPack for MyPack {
    fn name(&self) -> &str;
    fn fact_producer(&self) -> Arc<dyn TrustFactProducer>;
    fn cose_key_resolvers(&self) -> Vec<Arc<dyn CoseKeyResolver>>;
    fn post_signature_validators(&self) -> Vec<Arc<dyn PostSignatureValidator>>;
    fn default_trust_plan(&self) -> Option<CompiledTrustPlan>;
}

// Signing side (if applicable)
impl TransparencyProvider for MyProvider {
    fn submit_and_poll(&self, message: &[u8]) -> Result<Vec<u8>, TransparencyError>;
}

// Factory extension (if applicable)
impl SignatureFactoryProvider for MyFactory {
    fn create_bytes(&self, ...) -> Result<Vec<u8>, FactoryError>;
}
```

### 4. Create FFI Projection

Follow these mandatory patterns (see `native-ffi.instructions.md` for full details):

- `#![deny(unsafe_op_in_unsafe_fn)]`
- All functions: `catch_unwind(AssertUnwindSafe(|| { ... }))`
- All pointer params: null-checked before dereference
- Handle-to-inner: bounded `<'a>` lifetimes
- Thread-local error storage: `LAST_ERROR: RefCell<Option<ErrorInner>>`
- ABI version export: `cose_*_abi_version() -> u32`

### 5. Create C/C++ Headers

**C header**: `native/c/include/cose/sign1/extension_packs/new_pack.h`
**C++ header**: `native/c_pp/include/cose/sign1/extension_packs/new_pack.hpp`

C++ must provide:
- RAII wrapper class (move-only, no copy)
- `release()` method for ownership transfer
- `@see` cross-references for zero-copy alternatives
- `ByteView` return types for byte accessors

### 6. Update Build Configuration

- Add to `Cargo.toml` workspace members
- Add to `CMakeLists.txt` with `COSE_HAS_NEW_PACK` feature guard
- Add to `cose.hpp` umbrella include
- Update `vcpkg.json` if new features needed

### 7. Test Requirements

| Test Type | Location | Minimum |
|-----------|----------|---------|
| Rust unit tests | `extension_packs/new_pack/tests/` | All public APIs |
| FFI smoke tests | `extension_packs/new_pack/ffi/tests/` | Null safety + lifecycle |
| C smoke test | `native/c/tests/` | Roundtrip with feature guard |
| C++ smoke test | `native/c_pp/tests/` | RAII lifecycle test |
| Coverage | Via `collect-coverage.ps1` | ≥ 90% line coverage |

## V2 C# → Rust Translation Patterns

### Async
```csharp
// C#: Everything is async
public async Task<T> DoSomethingAsync(CancellationToken ct) { ... }
```
```rust
// Rust: Provide both sync and async variants
pub fn do_something(&self) -> Result<T, Error> { ... }
pub async fn do_something_async(&self) -> Result<T, Error> { ... }
```

### Options / Configuration
```csharp
// C#: Options class with defaults
public class MyOptions {
    public string Endpoint { get; set; } = "https://default";
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);
}
```
```rust
// Rust: Struct with Default impl
#[derive(Default)]
pub struct MyOptions {
    pub endpoint: Option<String>,
    pub timeout: Duration,
}

impl Default for MyOptions {
    fn default() -> Self {
        Self {
            endpoint: None,
            timeout: Duration::from_secs(30),
        }
    }
}
```

### Dependency Injection
```csharp
// C#: Constructor injection
public MyService(IHttpClient client, ILogger logger) { ... }
```
```rust
// Rust: Trait objects in Arc
pub struct MyService {
    client: Arc<dyn HttpClient>,
    log_verbose: Option<fn(&str)>,
}
```

### Error Handling
```csharp
// C#: Exceptions
throw new InvalidOperationException("message");
```
```rust
// Rust: Result + manual error types (NO thiserror)
#[derive(Debug)]
pub enum MyError {
    InvalidOperation(String),
}
impl std::fmt::Display for MyError { ... }
impl std::error::Error for MyError {}
```

## Performance Evaluation Checklist

When porting Azure SDK interactions (e.g., MST client, AKV client), evaluate:

- [ ] Does the Azure Rust SDK cache HTTP connections? (V2 C# required explicit caching)
- [ ] Does the SDK handle LRO polling efficiently? (V2 required custom poller)
- [ ] Are retry policies configurable? (V2 needed custom retry wrapper)
- [ ] Is the transaction log response cached? (V2 had a caching policy issue)
- [ ] Can we avoid serialization copies in the SDK's request/response pipeline?

## CI Workflow

PRs to `native_ports_final` trigger:
- `native-rust`: `cargo build + cargo test + collect-coverage.ps1` (90% gate)
- `native-c-cpp`: CMake build + GTest + smoke tests
- `CodeQL` (Rust + C/C++)
- `dependency-review`

All must pass before merge.
