---
applyTo: "native/**"
---
# Zero-Copy & No-Allocation Design Principles — CoseSignTool

> Applies to all native code. These principles govern how data flows through the
> Rust → FFI → C/C++ stack without unnecessary copies.

## Core Principle

**Every byte should be allocated at most once.** When data must cross a boundary
(parse, sign, validate, FFI), prefer borrowing or moving over copying.

## Rust-Side Patterns

### Arc-Based Message Sharing
```rust
// GOOD: Share parsed message via Arc (ref-count bump, not deep copy)
let message = Arc::new(CoseSign1Message::parse(&bytes)?);
validator.validate_arc(message.clone(), bytes_arc.clone())?;

// BAD: Clone the entire message struct
validator.validate(&message, bytes_arc)?;  // clones internally — use validate_arc when you own an Arc
```

### Builder Consumption (Move, Don't Clone)
```rust
// GOOD: Destructure consumed builder and move fields
let builder_inner = unsafe { Box::from_raw(builder as *mut BuilderInner) };
let rust_builder = CoseSign1Builder::new()
    .protected(builder_inner.protected)      // moved
    .tagged(builder_inner.tagged);           // moved

// BAD: Clone fields from a consumed builder
let rust_builder = CoseSign1Builder::new()
    .protected(builder_inner.protected.clone())  // unnecessary clone
    .tagged(builder_inner.tagged);
```

### FFI Handle Lifetimes
```rust
// GOOD: Bounded lifetime tied to handle validity
pub(crate) unsafe fn handle_to_inner<'a>(
    handle: *const SomeHandle,
) -> Option<&'a SomeInner> { ... }

// BAD: 'static lifetime is unsound — handle can be freed at any time
pub(crate) unsafe fn handle_to_inner(
    handle: *const SomeHandle,
) -> Option<&'static SomeInner> { ... }
```

### Ownership Transfer vs. Borrowing in FFI

When an FFI function **borrows** a handle (`*const`), it must clone inner data
if it needs to keep a copy. When it **consumes** a handle (`*mut` + `Box::from_raw`),
it can move data out without cloning.

Provide **both** variants when the clone is non-trivial:
```rust
// Borrow variant: clones (safe to reuse handle after call)
cose_sign1_builder_set_protected(builder, headers);      // headers: *const

// Consume variant: moves (handle invalidated after call)
cose_sign1_builder_consume_protected(builder, headers);  // headers: *mut, consumed
```

## C++ Side Patterns

### ByteView for Borrowed Data
```cpp
// GOOD: Borrow bytes from Rust handle — zero-copy
ByteView payload = message.Payload();  // {data, size} pointing into Rust Arc

// BAD: Copy into a vector
std::vector<uint8_t> payload = message.PayloadAsVector();  // unnecessary heap alloc
```

### release() for Ownership Transfer
```cpp
// GOOD: Move header map into builder (zero-copy)
auto headers = HeaderMap::New();
headers.SetInt(1, -7);
builder.ConsumeProtected(std::move(headers));  // calls headers.release()

// ACCEPTABLE: Copy header map (safe but slower)
builder.SetProtected(headers);  // clones inside Rust
```

### @see Cross-References
When a method returns `std::vector<uint8_t>` (copy), always add `@see` pointing
to the zero-copy `ToMessage` alternative:
```cpp
/**
 * @brief Signs payload
 * @return COSE_Sign1 bytes (caller-owned copy)
 * @see SignDirectToMessage() for zero-copy alternative returning CoseSign1Message
 */
std::vector<uint8_t> SignDirect(...);
```

## Known Trade-Offs (Documented, Not Bugs)

These copies are **structurally required** and should NOT be "fixed":

| Copy | Location | Why Required |
|------|----------|-------------|
| `payload.to_vec()` in factory | `factories/direct/factory.rs` | `SigningContext` owns payload; changing to borrowed would cascade lifetimes through `SigningService` trait + FFI |
| `.to_vec()` on FFI callback signature | `signing/core/ffi/lib.rs` (CallbackKey) | C callback allocates with `malloc`; must copy to Rust heap before `free()` |
| `message.clone()` in `validate()` | `validation/core/validator.rs` | Backward-compat; `validate_arc()` is the zero-copy alternative |
| `headers.clone()` in `set_protected` | `signing/core/ffi/lib.rs` | Handle is borrowed (*const); `consume_protected` is the zero-copy alternative |
| `create_bytes()` + `parse()` in factory | `factories/direct/factory.rs` | Post-sign verification needs raw bytes; reparse is O(n) vs O(1000×) crypto |

## Allocation Review Checklist

When reviewing native code changes, check for:

- [ ] No `.clone()` on `CoseHeaderMap`, `Vec<u8>`, or `CoseSign1Message` unless documented
- [ ] FFI handle-to-inner functions use bounded `<'a>`, not `'static`
- [ ] C++ byte accessors return `ByteView`, not `std::vector<uint8_t>`
- [ ] New FFI functions that take ownership use `*mut` (not `*const`) and `Box::from_raw`
- [ ] String ownership in DID/FFI: `*mut c_char` for allocated strings, `*const c_char` for borrowed
- [ ] Error paths use `.into()` or `format!()` directly — no `.to_string()` on literals
