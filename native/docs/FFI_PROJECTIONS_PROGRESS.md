# FFI Projections (C / C++) – Progress Log

Date started: 2026-01-19
Owner: repo-local work

## Goal
Expose the Rust `cose_sign1_validation::fluent` user experience to native consumers by:
- Adding a Rust **C ABI** `cdylib` (FFI crate) that wraps the fluent surface.
- Adding one Rust **FFI crate per major Rust extension crate** (e.g., MST vs X509 remain distinct) so native users can link only what they need.
- Creating a **C projection** (`native/c`) that is feature-equivalent to the Rust crates, with function names/calls as close as practical to the fluent surface.
- Creating a **C++ projection** (`native/c_pp`) that is feature-equivalent to the Rust crates, with OOP/RAII wrapper classes that mimic the fluent builder experience.
- Providing **unique docs** per projection.
- Providing **coverage scripts** per projection.
- Adding **unit tests** for:
  - the Rust FFI crate
  - the C projection
  - the C++ projection

Non-goals (initial slice):
- Providing a stable ABI across major versions without a versioning strategy.

## Guiding Principles
- **Stable ABI**: only expose C ABI types (`extern "C"`), opaque handles, explicit destroy functions.
- **No panics across FFI**: catch panics and convert to error codes.
- **Explicit ownership**: all returned buffers/strings have paired free functions.
- **Thread-safe error reporting**: last-error string stored thread-locally for debugging.
- **Versioned API**: provide `cose_ffi_version()` and `cose_ffi_abi_version()`.

## Proposed Public Surface (v0)
Full parity is required. Implementation will proceed in vertical slices, but the final state must be feature-equivalent to the Rust crates.

### Types (opaque)
- `cose_validator_builder_t`
- `cose_validator_t`
- `cose_validation_result_t`

### Builder
- `cose_validator_builder_new()`
- `cose_validator_builder_with_default_packs(...)` (or explicit pack adders)
- `cose_validator_builder_with_mst_pack(options)`
- `cose_validator_builder_with_certificates_pack(options)`
- `cose_validator_builder_with_akv_pack(options)`
- `cose_validator_builder_build(...)`

### Validate
- `cose_validator_validate_bytes(...)`
  - input: COSE bytes, optional detached payload bytes
  - output: validation result handle

### Result inspection
- `cose_validation_result_is_success(...)`
- `cose_validation_result_failure_message(...)`

### Errors
- `cose_last_error_message_utf8()`
- `cose_last_error_clear()`

### Memory
- `cose_string_free(char*)`
- `cose_*_free(handle)`

## C++ Projection API Shape (v0)
- `cose::ValidatorBuilder`
  - `.WithMst(...)`
  - `.WithCertificates(...)`
  - `.WithAzureKeyVault(...)`
  - `.Build()`
- `cose::Validator`
  - `.Validate(bytes, detachedPayload)`
- `cose::ValidationResult`
  - `.Ok()`
  - `.FailureMessage()`

## Build / Tooling
- Rust: per-pack `staticlib` crates built by Cargo.
- C: CMake finds Rust FFI libraries and conditionally links packs, defining `COSE_HAS_<PACK>_PACK` macros.
- C++: CMake per-pack targets wrapping C headers with RAII, each pack optional.
- vcpkg (future): manifest mode with per-pack features (e.g., `cose-sign1[certificates,mst]`).

## Coverage
- Rust: existing `native/rust/collect-coverage.ps1` should include new FFI crate.
- C/C++: PowerShell scripts will run CTest and collect coverage.
  - Primary path: `OpenCppCoverage` (MSVC-friendly).
  - Fallback path: clang/llvm-cov (optional; depends on toolchain availability).

## Milestones
- [ ] M1: Add Rust FFI crate skeletons (`cdylib`) per pack + shared base.
- [ ] M2: Implement C ABI parity for validation + default trust plans.
- [ ] M3: Implement trust-policy authoring (C ABI + C + C++ projections).
- [ ] M4: C++ projection wraps C ABI with RAII + fluent builder (feature-equivalent).
- [ ] M5: C projection provides ergonomic API (feature-equivalent).
- [ ] M6: Tests for Rust FFI + C + C++ (coverage-driven).
- [ ] M7: Coverage scripts for C + C++ (plus Rust FFI crates included).
- [ ] M8: Docs per projection (unique, with end-to-end examples).

## Notes / Decisions Log

### 2026-01-19: Per-pack architecture across all layers (Rust FFI, C, C++)
**Decision**: We will split the FFI surface AND the C/C++ projections into per-pack modules to allow native consumers to link only what they need:

**Rust FFI layer** (staticlib/cdylib):
- `cose_sign1_validation_ffi` (shared base): core validator + builder types, ABI versioning, error handling.
- `cose_sign1_validation_ffi_certificates`: X.509 pack FFI (builder methods, pack options).
- `cose_sign1_validation_ffi_mst`: MST pack FFI (builder methods, pack options).
- `cose_sign1_validation_ffi_akv`: Azure Key Vault pack FFI (builder methods, pack options).
- `cose_sign1_validation_ffi_trust`: trust policy authoring FFI (rule builders, predicates, plan compilation).

**C projection** (headers + CMake targets):
- `native/c/include/cose/cose_sign1.h` + base CMake target: core API
- `native/c/include/cose/cose_certificates.h`: X.509 pack (separate header)
- `native/c/include/cose/cose_mst.h`: MST pack (separate header)
- `native/c/include/cose/cose_azure_key_vault.h`: AKV pack (separate header)
- `native/c/include/cose/cose_trust.h`: trust policy authoring (separate header, TBD)

**C++ projection** (headers + CMake targets, per-pack):
- `native/c_pp/include/cose/validator.hpp`: core RAII wrappers (depends on base FFI)
- `native/c_pp/include/cose/certificates.hpp`: X.509 pack wrappers (separate, optional)
- `native/c_pp/include/cose/mst.hpp`: MST pack wrappers (separate, optional)
- `native/c_pp/include/cose/azure_key_vault.hpp`: AKV pack wrappers (separate, optional)
- `native/c_pp/include/cose/trust.hpp`: trust policy DSL (separate, optional, TBD)

**Rationale**: This mirrors the Rust crate structure ALL THE WAY UP through C/C++ projections. Native consumers (whether C or C++) can produce binaries with only the packs they need (e.g., MST-only, X509-only, or combined) without linking unused code. Each layer provides modular composition.

**Build contract**:
- Rust FFI: Base FFI crate exports core validator + builder. Each pack FFI crate is a separate staticlib.
- C projection: CMake finds pack FFI libraries optionally and defines `COSE_HAS_<PACK>_PACK` when available.
- C++ projection: Each pack header is standalone, consumers `#include` only what they need.
- vcpkg packaging (future): Each pack will be a separate vcpkg feature, allowing `vcpkg install cose-sign1[certificates,mst]` for selective installation.

- TBD: exact pack option structs to expose.
- Required: trust policy authoring must be exposed in C and C++ (fluent-style), not just validation.
- Required: default trust plans must be supported so native usage can be "secure-by-default" like Rust.
- TBD: ABI versioning strategy (function table vs symbol versioning vs explicit vN namespace).

---

## Progress Log (chronological)

### 2026-01-19 11:00 - Initial spec created
- Added this progress document to `native/FFI_PROJECTIONS_PROGRESS.md`.
- Defined goal: full parity C/C++ projections with Rust fluent API.
- Identified milestones M1–M8.

### 2026-01-19 11:15 - Verified existing FFI crate
- Confirmed `cose_sign1_validation_ffi` exists and builds clean (`cargo test` passes).
- Current state: monolithic FFI exposing default packs (certificates, MST, AKV) via builder.
- Next: split into per-pack FFI crates for modular linking.

### 2026-01-19 11:20 - Scaffolded per-pack FFI crate structure
- Created 4 new FFI crate directories: `cose_sign1_validation_ffi_{certificates,mst,akv,trust}`
- Each has Cargo.toml configured as `crate-type = ["staticlib", "cdylib"]` for flexible linking
- Each depends on base FFI and respective pack crate
- Updated workspace Cargo.toml to include new members

### 2026-01-19 11:30 - Implemented pack registration functions
- Created lib.rs skeleton for each pack FFI crate
- Each exports `cose_validator_builder_with_<pack>_pack()` and `_ex()` variant
- All use `with_catch_unwind()` helper from base FFI for consistent error handling
- All have placeholder smoke tests

### 2026-01-19 11:40 - Refactored base FFI crate
- Made types/helpers public: `cose_status_t`, `cose_validator_builder_t` (with public `packs` field), `with_catch_unwind()`, `set_last_error()`, `clear_last_error()`
- Changed crate-type to `["cdylib", "staticlib", "rlib"]` so pack FFI crates can import it
- Removed pack-specific functions (moved to separate pack crates)
- Updated test to just test builder without pack (pack tests now in pack FFI crates)
- Removed circular dev-dependencies

### 2026-01-19 11:45 - Fixed MST pack API usage
- MST pack doesn't have `MstTrustOptions` type or `new()` constructor
- Updated MST FFI to use `MstTrustPack::online()` and `offline_with_jwks()` factory methods
- `_ex()` variant now uses online mode as placeholder (TODO: define C ABI options struct)

### 2026-01-19 11:50 - ✅ All crates build and test successfully
- `cargo build --workspace` succeeds - all 12 crates compile
- `cargo test --workspace` passes - 272 tests across entire workspace
- Architecture validated: pack FFI crates successfully import from base FFI
- Smoke tests pass for all pack FFI crates (certificates, MST, AKV, trust placeholder)
- Per-pack FFI split complete and functional

### 2026-01-19 12:00 - ✅ Defined C ABI option structs for all packs
- **Certificates**: `cose_certificate_trust_options_t` with:
  - `trust_embedded_chain_as_trusted` (bool)
  - `identity_pinning_enabled` (bool)
  - `allowed_thumbprints` (null-terminated string array)
  - `pqc_algorithm_oids` (null-terminated string array)
- **MST**: `cose_mst_trust_options_t` with:
  - `allow_network` (bool)
  - `offline_jwks_json` (nullable c_char*)
  - `jwks_api_version` (nullable c_char*)
- **AKV**: `cose_akv_trust_options_t` with:
  - `require_azure_key_vault_kid` (bool)
  - `allowed_kid_patterns` (null-terminated string array, defaults to *.vault.azure.net and *.managedhsm.azure.net)
- Helper function `string_array_to_vec()` implemented for parsing null-terminated arrays
- All `_ex()` functions now use real option structs instead of void* placeholders
- All pack options support NULL to use defaults (secure-by-default)

### 2026-01-19 12:05 - ✅ Build and test verification complete
- `cargo build --workspace` succeeds after adding option structs
- `cargo test --workspace` passes - all 272 tests still green

### 2026-01-19 12:10 - ✅ Created C projection structure (per-pack headers)
- Created `native/c/include/cose/` with modular headers:
  - `cose_sign1.h`: base API (builder, validator, result, error handling)
  - `cose_certificates.h`: X.509 pack with options struct
  - `cose_mst.h`: MST pack with options struct
  - `cose_azure_key_vault.h`: AKV pack with options struct
- Created CMakeLists.txt with conditional pack linking based on found FFI libraries
- CMake defines `COSE_HAS_<PACK>_PACK` when pack is available
- Created basic smoke test in C that validates builder creation and pack registration
- Created README.md with usage examples for each pack

### 2026-01-19 12:15 - 📝 Architecture decision: Per-pack modularity across all layers
- **Decision**: C and C++ projections will ALSO be per-pack modular, not monolithic
- **Rationale**: Consumers should be able to `#include` and link only the packs they need at every layer
- **Impact**:
  - C projection has separate headers per pack (already implemented)
  - C++ projection will have separate headers per pack (to be implemented)
  - vcpkg packaging will use features for per-pack installation
  - CMake targets will be granular (base + optional pack targets)

**Current state**: M1 (FFI crate skeletons) ✅ complete. M2 (C ABI validation parity) substantially complete - FFI options done, C headers created, CMake structure in place. Next steps: build and test C projection, implement C++ RAII wrappers with per-pack modularity, implement trust policy authoring FFI

**Current state**: M1 (FFI crate skeletons) and substantial M2 (C ABI validation parity) complete. Pack options fully defined and functional. Next steps: implement trust policy authoring FFI, create C/C++ projections with CMake.

### 2026-01-19 12:30 - ✅ Completed C++ projection structure (per-pack RAII wrappers)
- Created `native/c_pp/include/cose/` with modular C++ headers:
  - `validator.hpp`: Base RAII classes (cose_error exception, ValidationResult, Validator, ValidatorBuilder)
  - `certificates.hpp`: CertificateOptions struct, ValidatorBuilderWithCertificates
  - `mst.hpp`: MstOptions struct, ValidatorBuilderWithMst
  - `azure_key_vault.hpp`: AzureKeyVaultOptions struct, ValidatorBuilderWithAzureKeyVault
  - `cose.hpp`: Convenience header with conditional includes for all available packs
- All C++ wrappers use modern C++17 RAII patterns:
  - Non-copyable, movable resource handles
  - Automatic cleanup via destructors
  - Exception-based error handling with cose_error
  - Fluent builder pattern with method chaining
- Options structs use C++ types (std::vector, std::string) with conversion to C ABI
- Created CMakeLists.txt with interface library and conditional pack linking
- Created smoke test (tests/smoke_test.cpp) validating builder usage with all packs
- Created README.md with usage examples, API comparison, and design principles
- C++ projection now complete with full per-pack modularity matching C and Rust FFI layers

### 2026-01-19 12:45 - ✅ Built and tested C and C++ projections
- Successfully configured both C and C++ projections using CMake with VS 2022
- CMake correctly found all Rust FFI libraries (base + certificates + MST + AKV packs)
- Built C projection: smoke_test.exe compiled successfully
- Built C++ projection: smoke_test_cpp.exe compiled successfully
- C smoke test passed: verified builder creation, pack registration, and validator build
- C++ smoke test passed: verified all RAII wrappers with default and custom options for all packs
- All tests require Rust FFI DLLs in PATH (located in native/rust/target/release/)
- Both projections fully functional with per-pack modularity
- **Milestone M2 (C ABI validation parity) substantially complete**: FFI + C + C++ all working with pack options

### 2026-01-19 13:00 - 📚 Created comprehensive architecture documentation
- Created ARCHITECTURE.md documenting the complete three-layer native FFI architecture
- Documented per-pack modularity design across all layers (Rust FFI, C, C++)
- Included directory structures, build artifacts, and key function signatures for each layer
- Documented RAII design principles and exception handling strategy
- Provided usage examples for both C and C++ projections
- Documented error handling patterns for each layer
- Outlined build system integration with CMake and future vcpkg packaging
- Documented testing strategy and coverage plans
- Defined future milestones (M3: Trust Policy, M4: Testing, M5: Packaging, M6: Coverage)

**Status Summary**: M1 and M2 substantially complete. Three-layer architecture (Rust FFI + C + C++) fully implemented with per-pack modularity. All smoke tests passing. Documentation comprehensive. Next major milestone: M3 (Trust Policy Authoring FFI).

---