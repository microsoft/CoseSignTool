<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# FFI Ownership Model

> The definitive guide to memory ownership across the Rust ↔ C ↔ C++ boundary.

## Table of Contents

- [Core Principle](#core-principle)
- [Handle Lifecycle](#handle-lifecycle)
- [Borrowing vs. Consuming](#borrowing-vs-consuming)
- [ByteView: Zero-Copy Access](#byteview-zero-copy-access)
- [Thread-Local Error Pattern](#thread-local-error-pattern)
- [Panic Safety](#panic-safety)
- [C++ RAII Wrappers](#c-raii-wrappers)
- [Ownership Flow Diagrams](#ownership-flow-diagrams)
- [Anti-Patterns](#anti-patterns)
- [Quick Reference](#quick-reference)

---

## Core Principle

**Rust owns all heap memory. C/C++ borrows through opaque handles.**

Every object allocated by the SDK lives on the Rust heap. C and C++ code
receives opaque pointers (handles) that reference — but never directly access —
the Rust-side data. When C/C++ is done with a handle, it calls the
corresponding `*_free()` function, which transfers ownership back to Rust for
deallocation.

This design ensures:

- **No double-free** — exactly one owner at all times.
- **No use-after-free** — handles are opaque; you cannot dereference into freed memory.
- **No allocator mismatch** — Rust allocates, Rust frees. C's `malloc`/`free` are never involved for SDK objects.

---

## Handle Lifecycle

Every SDK object follows the same three-phase lifecycle:

```
  Rust                            C / C++
  ────                            ───────
  Box::new(value)
  Box::into_raw(box) ──────────→  *mut Handle (opaque pointer)
                                    │
                                    │  use via cose_*() functions
                                    │
  Box::from_raw(ptr) ←────────── cose_*_free(handle)
  drop(box)
```

### Phase 1: Creation

Rust allocates the object and converts it to a raw pointer:

```rust
// Rust FFI — creation
#[no_mangle]
pub extern "C" fn cose_sign1_validator_builder_new(
    out: *mut *mut ValidatorBuilderHandle,
) -> cose_status_t {
    with_catch_unwind(|| {
        if out.is_null() {
            anyhow::bail!("out must not be null");
        }
        let builder = ValidatorBuilder::new();
        // SAFETY: out is non-null (checked above), we transfer ownership to caller
        unsafe { *out = Box::into_raw(Box::new(ValidatorBuilderHandle(builder))) };
        Ok(COSE_OK)
    })
}
```

```c
// C — receiving the handle
cose_sign1_validator_builder_t* builder = NULL;
cose_status_t status = cose_sign1_validator_builder_new(&builder);
// builder is now a valid opaque pointer — do NOT dereference it
```

### Phase 2: Usage

C/C++ passes the handle back to Rust functions. Rust converts the raw pointer
to a reference (borrow) to access the inner data:

```rust
// Rust FFI — borrowing for read access
pub(crate) unsafe fn handle_to_inner<'a>(
    handle: *const ValidatorBuilderHandle,
) -> Option<&'a ValidatorBuilder> {
    // SAFETY: caller guarantees handle is valid for 'a
    unsafe { handle.as_ref() }.map(|h| &h.0)
}
```

The `<'a>` lifetime is critical — it ties the reference lifetime to the handle's
validity, not to `'static`.

### Phase 3: Destruction

C/C++ calls the free function. Rust reclaims and drops the object:

```rust
// Rust FFI — destruction
#[no_mangle]
pub extern "C" fn cose_sign1_validator_builder_free(
    handle: *mut ValidatorBuilderHandle,
) {
    if !handle.is_null() {
        // SAFETY: handle was created by Box::into_raw in _new(),
        // caller guarantees this is the last use
        unsafe { drop(Box::from_raw(handle)) };
    }
}
```

```c
// C — releasing the handle
cose_sign1_validator_builder_free(builder);
builder = NULL;  // good practice: null out after free
```

---

## Borrowing vs. Consuming

FFI functions use pointer mutability to signal ownership semantics:

| Pointer Type | Meaning | After Call |
|-------------|---------|------------|
| `*const Handle` | **Borrow** — Rust reads but does not take ownership | Handle remains valid; caller still owns it |
| `*mut Handle` (non-out) | **Consume** — Rust takes ownership via `Box::from_raw` | Handle is **invalidated**; caller must NOT use or free it |
| `*mut *mut Handle` | **Output** — Rust creates and transfers ownership to caller | Caller receives a new handle; must eventually free it |

### Borrow Example (set_protected)

```rust
// Rust: borrows headers, clones internally because handle stays valid
#[no_mangle]
pub extern "C" fn cose_sign1_builder_set_protected(
    builder: *mut BuilderHandle,       // borrowed (mutated but not consumed)
    headers: *const HeaderMapHandle,   // borrowed (read-only)
) -> cose_status_t {
    with_catch_unwind(|| {
        let builder = unsafe { builder.as_mut() }.context("null builder")?;
        let headers = unsafe { headers.as_ref() }.context("null headers")?;
        builder.0.set_protected(headers.0.clone()); // clone required — we borrow
        Ok(COSE_OK)
    })
}
```

```c
// C: both handles remain valid after the call
cose_sign1_builder_set_protected(builder, headers);
// builder and headers are still usable
```

### Consume Example (consume_protected)

```rust
// Rust: takes ownership of headers via Box::from_raw — no clone needed
#[no_mangle]
pub extern "C" fn cose_sign1_builder_consume_protected(
    builder: *mut BuilderHandle,       // borrowed (mutated)
    headers: *mut HeaderMapHandle,     // CONSUMED — ownership transferred
) -> cose_status_t {
    with_catch_unwind(|| {
        let builder = unsafe { builder.as_mut() }.context("null builder")?;
        // SAFETY: headers was created by Box::into_raw; we are the new owner
        let headers = unsafe { Box::from_raw(headers) };
        builder.0.set_protected(headers.0); // move, not clone
        Ok(COSE_OK)
    })
}
```

```c
// C: headers is INVALIDATED after this call — do NOT use or free it
cose_sign1_builder_consume_protected(builder, headers);
headers = NULL;  // must not touch headers again
```

### When to Provide Both Variants

Provide both `set_*` (borrow + clone) and `consume_*` (move) when the cloned
type is non-trivial (e.g., `CoseHeaderMap`, `Vec<u8>`, `CoseSign1Message`).
For small/cheap types (integers, booleans), a single borrow variant suffices.

---

## ByteView: Zero-Copy Access

`ByteView` is a C/C++ struct that borrows bytes directly from a Rust-owned
`Arc<[u8]>` — no copy, no allocation:

```c
// C definition
typedef struct {
    const uint8_t* data;   // pointer into Rust Arc<[u8]>
    size_t         size;   // byte count
} cose_byte_view_t;
```

```cpp
// C++ usage — zero-copy payload access
cose::sign1::CoseSign1Message msg = /* ... */;
ByteView payload = msg.Payload();     // {data, size} pointing into Rust Arc
// Use payload.data / payload.size — valid as long as msg is alive
```

### Lifetime Rule

`ByteView` data is valid **only as long as the parent handle is alive**:

```cpp
// ✅ GOOD: use ByteView while message is alive
auto msg = cose::sign1::CoseSign1Message::FromBytes(raw);
ByteView payload = msg.Payload();
process(payload.data, payload.size);

// ❌ BAD: ByteView outlives the message
ByteView dangling;
{
    auto msg = cose::sign1::CoseSign1Message::FromBytes(raw);
    dangling = msg.Payload();
}  // msg destroyed here — dangling.data is now invalid!
process(dangling.data, dangling.size);  // use-after-free!
```

### When to Copy

If you need the data to outlive the handle, copy explicitly:

```cpp
auto msg = cose::sign1::CoseSign1Message::FromBytes(raw);
std::vector<uint8_t> owned_payload = msg.PayloadAsVector(); // explicit copy
// owned_payload is independent of msg's lifetime
```

---

## Thread-Local Error Pattern

FFI functions return status codes, not error messages. Detailed error
information is stored in a **thread-local** buffer:

```rust
// Rust FFI — thread-local error storage
thread_local! {
    static LAST_ERROR: RefCell<Option<String>> = RefCell::new(None);
}

fn set_last_error(msg: String) {
    LAST_ERROR.with(|e| *e.borrow_mut() = Some(msg));
}

#[no_mangle]
pub extern "C" fn cose_last_error_message_utf8() -> *mut c_char {
    LAST_ERROR.with(|e| {
        match e.borrow().as_deref() {
            Some(msg) => CString::new(msg).unwrap().into_raw(),
            None => std::ptr::null_mut(),
        }
    })
}
```

```c
// C — retrieving the error after a failed call
cose_status_t status = cose_sign1_validator_builder_build(builder, &validator);
if (status != COSE_OK) {
    char* err = cose_last_error_message_utf8();
    fprintf(stderr, "Error: %s\n", err ? err : "(no message)");
    cose_string_free(err);  // caller owns the returned string
}
```

### Thread Safety

- Error messages are **per-thread** — concurrent calls on different threads
  never interfere.
- The error is overwritten by the **next** FFI call on the same thread — read
  it immediately after the failing call.
- The returned `char*` is Rust-allocated — always free with `cose_string_free()`,
  never with C's `free()`.

---

## Panic Safety

Every `extern "C"` function is wrapped in `catch_unwind` to prevent Rust panics
from unwinding across the FFI boundary (which is undefined behavior):

```rust
pub(crate) fn with_catch_unwind<F>(f: F) -> cose_status_t
where
    F: FnOnce() -> anyhow::Result<cose_status_t> + std::panic::UnwindSafe,
{
    match std::panic::catch_unwind(f) {
        Ok(Ok(status)) => status,
        Ok(Err(err)) => {
            set_last_error(format!("{:#}", err));
            COSE_ERR
        }
        Err(_) => {
            set_last_error("internal panic".into());
            COSE_PANIC
        }
    }
}
```

### Status Codes

| Code | Constant | Meaning |
|------|----------|---------|
| 0 | `COSE_OK` | Success |
| 1 | `COSE_ERR` | Error — call `cose_last_error_message_utf8()` for details |
| 2 | `COSE_PANIC` | Rust panic caught — should not occur in normal usage |
| 3 | `COSE_INVALID_ARG` | Invalid argument (null pointer, bad length) |

---

## C++ RAII Wrappers

The C++ projection wraps every C handle in a move-only RAII class:

```cpp
namespace cose::sign1 {

class ValidatorBuilder {
public:
    // Factory method — throws cose_error on failure
    ValidatorBuilder() {
        cose_status_t st = cose_sign1_validator_builder_new(&handle_);
        if (st != COSE_OK) throw cose::cose_error("failed to create builder");
    }

    // Move constructor — transfers ownership
    ValidatorBuilder(ValidatorBuilder&& other) noexcept
        : handle_(other.handle_) {
        other.handle_ = nullptr;  // CRITICAL: null out source
    }

    // Move assignment
    ValidatorBuilder& operator=(ValidatorBuilder&& other) noexcept {
        if (this != &other) {
            if (handle_) cose_sign1_validator_builder_free(handle_);
            handle_ = other.handle_;
            other.handle_ = nullptr;
        }
        return *this;
    }

    // Copy is deleted — handles are unique owners
    ValidatorBuilder(const ValidatorBuilder&) = delete;
    ValidatorBuilder& operator=(const ValidatorBuilder&) = delete;

    // Destructor — automatic cleanup
    ~ValidatorBuilder() {
        if (handle_) cose_sign1_validator_builder_free(handle_);
    }

    // Interop: access raw handle when needed
    cose_sign1_validator_builder_t* native_handle() { return handle_; }

private:
    cose_sign1_validator_builder_t* handle_ = nullptr;
};

} // namespace cose::sign1
```

### RAII Rules

| Rule | Why |
|------|-----|
| Delete copy ctor + copy assignment | Prevents double-free |
| Null-out source in move ctor/assignment | Prevents use-after-move |
| Check `if (handle_)` before free in destructor | Allows moved-from objects to destruct safely |
| Throw `cose_error` in constructors on failure | RAII: if constructor succeeds, object is valid |
| `native_handle()` for interop | Escape hatch for mixing C and C++ APIs |

---

## Ownership Flow Diagrams

### Create → Use → Free (Happy Path)

```
        C / C++                              Rust
        ───────                              ────
    ┌─ new(&out) ─────────────────→  Box::new(T)
    │                                Box::into_raw → *mut T
    │  out ← ─────────────────────── return pointer
    │
    │  use(handle, ...) ──────────→  handle.as_ref() → &T
    │  use(handle, ...) ──────────→  handle.as_ref() → &T
    │
    └─ free(handle) ──────────────→  Box::from_raw(*mut T)
                                     drop(T)
```

### Consume Pattern (Ownership Transfer)

```
        C / C++                              Rust
        ───────                              ────
    ┌─ new_headers(&h) ──────────→  Box::into_raw → *mut H
    │  h ← ─────────────────────── return pointer
    │
    │  consume(builder, h) ──────→  Box::from_raw(h) → owned H
    │  h = NULL  (invalidated)       move H into builder
    │
    └─ free(builder) ─────────────→  drops builder + contained H
```

### String Ownership

```
        C / C++                              Rust
        ───────                              ────
    ┌─ error_message_utf8() ─────→  CString::new(msg)
    │                                CString::into_raw → *mut c_char
    │  err ← ────────────────────── return pointer
    │
    │  fprintf(stderr, err)          (string data lives on Rust heap)
    │
    └─ string_free(err) ─────────→  CString::from_raw(*mut c_char)
                                     drop(CString)
```

---

## Anti-Patterns

### ❌ Using `'static` for Handle References

```rust
// BAD: unsound — handle can be freed at any time
unsafe fn handle_to_inner(h: *const H) -> Option<&'static Inner> { ... }

// GOOD: lifetime bounded to handle validity
unsafe fn handle_to_inner<'a>(h: *const H) -> Option<&'a Inner> { ... }
```

### ❌ Freeing with the Wrong Allocator

```c
// BAD: C's free() on Rust-allocated memory
char* err = cose_last_error_message_utf8();
free(err);  // WRONG — allocated by Rust, not malloc

// GOOD: use the SDK's free function
cose_string_free(err);
```

### ❌ Using a Handle After Consume

```c
// BAD: headers was consumed — handle is invalid
cose_sign1_builder_consume_protected(builder, headers);
cose_headermap_get_int(headers, 1, &alg);  // use-after-free!

// GOOD: null out after consume
cose_sign1_builder_consume_protected(builder, headers);
headers = NULL;
```

### ❌ Forgetting to Null-Out in Move Constructor

```cpp
// BAD: both objects think they own the handle
MyHandle(MyHandle&& other) : handle_(other.handle_) { }

// GOOD: null out the source
MyHandle(MyHandle&& other) noexcept : handle_(other.handle_) {
    other.handle_ = nullptr;
}
```

### ❌ Cloning When Moving is Possible

```rust
// BAD: builder is consumed via Box::from_raw — we own the data, no need to clone
let inner = unsafe { Box::from_raw(builder) };
rust_builder.set_protected(inner.protected.clone());

// GOOD: move out of the consumed box
let inner = unsafe { Box::from_raw(builder) };
rust_builder.set_protected(inner.protected);  // moved, not cloned
```

### ❌ ByteView Outliving Its Parent

```cpp
// BAD: ByteView dangles after message is destroyed
ByteView payload;
{
    auto msg = CoseSign1Message::FromBytes(raw);
    payload = msg.Payload();
} // msg freed here — payload.data is dangling

// GOOD: keep the message alive, or copy
auto msg = CoseSign1Message::FromBytes(raw);
auto payload = msg.Payload();
process(payload.data, payload.size);  // msg still alive
```

---

## Quick Reference

| Operation | Rust | C | C++ |
|-----------|------|---|-----|
| **Create** | `Box::into_raw(Box::new(T))` | `cose_*_new(&out)` | Constructor / `T::New()` |
| **Borrow** | `handle.as_ref()` → `&T` | pass `const *handle` | method call on object |
| **Consume** | `Box::from_raw(handle)` → `T` | pass `*mut handle` + null out | `std::move(obj)` |
| **Free** | `drop(Box::from_raw(handle))` | `cose_*_free(handle)` | Destructor (automatic) |
| **Error** | `set_last_error(msg)` | `cose_last_error_message_utf8()` | `throw cose_error(...)` |
| **Zero-copy read** | `&data[range]` | `cose_byte_view_t` | `ByteView` |
| **Copy read** | `.to_vec()` | `memcpy` from `cose_byte_view_t` | `.PayloadAsVector()` |

### Memory Ownership Summary

| Resource Type | Created By | Freed By |
|--------------|-----------|----------|
| Handle (`cose_*_t*`) | `cose_*_new()` / `cose_*_build()` | `cose_*_free()` |
| String (`char*`) | `cose_*_utf8()` | `cose_string_free()` |
| Byte buffer (`uint8_t*`, len) | `cose_*_bytes()` | `cose_*_bytes_free()` |
| `ByteView` | Borrowed from handle | Do NOT free — valid while parent lives |
| C++ RAII object | Constructor | Destructor (automatic) |