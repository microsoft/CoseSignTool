---
applyTo: "native/**"
---
# Code Review Standards — Native CoseSignTool

> Criteria for reviewing PRs and evaluating code quality across the native stack.

## Review Dimensions

Every review of native code should evaluate these dimensions:

### 1. Zero-Copy / No-Allocation Architecture
- Are unnecessary `.clone()`, `.to_vec()`, `.to_owned()`, `.to_string()` present?
- Do FFI handle conversions use bounded lifetimes (`<'a>`) not `'static`?
- Do C++ accessors return `ByteView` (borrowed) not `std::vector` (copied)?
- Are `_consume` / `_to_message` zero-copy variants available where appropriate?
- See `zero-copy-design.instructions.md` for the full checklist.

### 2. Safety & Correctness
- **Null checks**: Every FFI pointer param checked before dereference.
- **Panic safety**: Every `extern "C"` function wrapped in `catch_unwind`.
- **SAFETY comments**: Every `unsafe` block has a `// SAFETY:` justification.
- **Lifetimes**: No `'static` references to heap-allocated handles.
- **Memory ownership**: `*const` for borrowed, `*mut` for owned/consumed. Documented in C header and C++ wrapper.

### 3. API Design & Ergonomics
- Builder patterns are fluent (return `&mut self` or `Self`).
- Error types use manual `Display` + `Error` impls (no `thiserror`).
- Traits are `Send + Sync` when stored in `Arc`.
- C++ classes are move-only (delete copy ctor/assign).
- Destructors check `if (handle_)` before calling `*_free()`.

### 4. Test Quality
- Tests follow Arrange-Act-Assert.
- Both success and error paths are tested.
- FFI null-pointer safety tests for every parameter.
- Roundtrip tests: sign → parse → validate.
- No shared mutable state between tests (parallel-safe).
- Temp files use unique names (thread ID or nanos).

### 5. Documentation
- Public APIs have `///` doc comments.
- FFI functions have `# Safety` sections.
- Module-level `//!` comments in every `lib.rs`.
- C++ methods have `@see` cross-refs to zero-copy alternatives.

## Grading Scale

| Grade | Meaning |
|-------|---------|
| A+ | Exceptional. No issues. Exemplary patterns. |
| A  | Excellent. Minor style nits only. |
| A- | Very good. 1-2 non-blocking improvements identified. |
| B+ | Good. Several improvements needed but no bugs. |
| B  | Acceptable. Notable gaps in docs, tests, or design. |
| C  | Needs work. Missing safety checks, unsound lifetimes, or significant test gaps. |
| F  | Blocking issues. UB, memory leaks, or security vulnerabilities. |

## Common Anti-Patterns to Flag

### Rust
```rust
// ❌ Cloning when moving is possible (builder consumed via Box::from_raw)
builder_inner.protected.clone()

// ❌ 'static lifetime on FFI handle reference
fn handle_to_inner(h: *const H) -> Option<&'static Inner>

// ❌ .to_string() on string literals in error paths
Err(MyError::InvalidFormat("expected:format".to_string()))
// ✅ Use .into()
Err(MyError::InvalidFormat("expected:format".into()))

// ❌ thiserror in production crates
#[derive(thiserror::Error)]  // Not allowed

// ❌ expect()/unwrap() in production code (tests are fine)
let value = map.get("key").unwrap();
```

### C++
```cpp
// ❌ const_cast to work around ownership semantics
const char* s = const_cast<const char*>(raw_ptr);

// ❌ Forgetting to null-out source in move constructor
HeaderMap(HeaderMap&& other) : handle_(other.handle_) { }
// ✅ Must null the source
HeaderMap(HeaderMap&& other) noexcept : handle_(other.handle_) {
    other.handle_ = nullptr;
}

// ❌ Missing copy deletion
class MyHandle { /* no copy ctor/assign declaration */ };
// ✅ Explicitly delete
MyHandle(const MyHandle&) = delete;
MyHandle& operator=(const MyHandle&) = delete;
```

### C Headers
```c
// ❌ Missing extern "C" guard
// ✅ Every C header needs:
#ifdef __cplusplus
extern "C" {
#endif

// ❌ Using const for output ownership-transfer pointers
int func(const char** out_string);  // implies borrowed
// ✅ Non-const for caller-owned allocations
int func(char** out_string);  // caller must free
```

## Coverage Exclusion Policy

Only FFI boundary stubs may use `#[cfg_attr(coverage_nightly, coverage(off))]`.
**Never exclude**: business logic, validation, parsing, crypto, error handling.

Justified exclusions:
- `handle_panic()` — unreachable without `catch_unwind` triggering
- `write_signed_bytes/message()` — unreachable due to mandatory post-sign verification
- `*_abi_version()` — compile-time constants
- `*_free()` / `*_string_free()` — pointer deallocation stubs
- `cose_last_error_*()` — thread-local error accessors

Flag any exclusion on non-FFI code as a review blocker.
