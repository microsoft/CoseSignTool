<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# Memory Design Principles

> **The definitive reference for memory architecture across the native Rust, C, and C++ stack.**
>
> Every design decision in this document traces back to one axiom:
>
> ***Every byte should be allocated at most once.***

---

## Table of Contents

1. [Philosophy](#1-philosophy)
2. [Core Primitives](#2-core-primitives)
3. [Operation Memory Profiles](#3-operation-memory-profiles)
4. [Cross-Layer Patterns](#4-cross-layer-patterns)
5. [Structurally Required Allocations](#5-structurally-required-allocations)
6. [Allocation Review Checklist](#6-allocation-review-checklist)

---

## 1. Philosophy

The native COSE stack is built on five interlocking design principles. Each one
eliminates an entire class of unnecessary memory operations.

### 1.1 — Parse Once, Share Everywhere

When a COSE_Sign1 message is parsed, the raw CBOR bytes are wrapped in a
single `Arc<[u8]>`. Every downstream structure — headers, payload, signature —
holds a `Range<usize>` into that same allocation. Cloning a
`CoseSign1Message` increments a reference count; it never deep-copies the
backing buffer.

```
                     ┌──────────────────────────────────────────┐
                     │           Arc<[u8]>  (one allocation)    │
                     │  ┌──────┬──────────┬──────┬───────────┐  │
                     │  │ tag? │protected │ pay- │ signature │  │
                     │  │      │ headers  │ load │           │  │
                     │  └──┬───┴────┬─────┴──┬───┴─────┬─────┘  │
                     └─────│────────│────────│─────────│─────────┘
                           │        │        │         │
                    Range<usize> Range<usize> Range<usize> Range<usize>
                           │        │        │         │
                           ▼        ▼        ▼         ▼
                     LazyHeaderMap  LazyHeaderMap  payload_range  signature_range
```

*Source: `cose_primitives::data::CoseData`, `cose_sign1_primitives::CoseSign1Message`*

### 1.2 — Lazy Parsing via `OnceLock`

Header maps are **not decoded at parse time**. `LazyHeaderMap` stores the raw
CBOR byte range and a `OnceLock<CoseHeaderMap>`. Parsing happens at most once,
on first access, and the decoded values share the original `Arc<[u8]>` through
`ArcSlice` and `ArcStr` — zero additional copies for byte/text string values.

```
LazyHeaderMap
  ├── raw: Arc<[u8]>       ← same allocation as parent message
  ├── range: Range<usize>  ← byte range of CBOR header map
  └── parsed: OnceLock<CoseHeaderMap>
              │
              └─ populated on first .headers() call
                 │
                 ├── ArcSlice { data: Arc<[u8]>, range }  ← zero-copy bstr value
                 └── ArcStr   { data: Arc<[u8]>, range }  ← zero-copy tstr value
```

**Why this matters:** A validation pipeline that only inspects the algorithm
header and content type will never decode the KID, CWT claims, or any other
header field. For messages with large unprotected headers (e.g., embedded
receipts), this avoids substantial CBOR decoding work entirely.

*Source: `cose_primitives::lazy_headers::LazyHeaderMap`*

### 1.3 — Streaming for Large Payloads

For payloads that exceed available memory (multi-GB files), the stack uses
streaming modes that keep peak memory independent of payload size:

| Operation | Streaming API | Peak Memory |
|-----------|---------------|-------------|
| Parse     | `parse_stream()` | `O(header_size + sig_size)` — typically < 1 KB |
| Sign      | `sign_streaming()` via `SigStructureHasher` | `O(64 KB)` — one chunk buffer |
| Verify    | `verify_payload_streaming()` | `O(64 KB)` — one chunk buffer |

The payload never touches Rust heap memory. It flows from disk/stream directly
through the cryptographic hasher or verifier in 64 KB chunks.

```
 ┌─────────┐     64 KB chunks     ┌──────────────┐     digest      ┌──────────┐
 │  File /  │ ──────────────────▶  │  SigStructure │ ────────────▶  │  Signer  │
 │  Stream  │                      │    Hasher      │               │ /Verifier│
 └─────────┘                      └──────────────┘               └──────────┘
                                   stack-allocated
                                   hash output:
                                   [u8; 32] (SHA-256)
                                   [u8; 48] (SHA-384)
                                   [u8; 64] (SHA-512)
```

*Source: `cose_sign1_primitives::sig_structure`, `CoseData::Streamed`*

### 1.4 — Error Paths Use `Cow<'static, str>`

All error types use `Cow<'static, str>` for message fields. The critical
insight: **most error messages are static string literals known at compile
time**. They borrow directly from the read-only data segment — zero heap
allocation on the error path.

```rust
// Static literal → borrows from binary, zero alloc
Cow::Borrowed("payload must not be empty")

// Dynamic message → allocates only when needed (rare path)
Cow::Owned(format!("expected algorithm {}, got {}", expected, actual))
```

This pattern appears throughout the stack:

| Type | Location | Fields using `Cow<'static, str>` |
|------|----------|----------------------------------|
| `SigningError` | `signing/core/src/error.rs` | `detail` in all variants |
| `ValidationFailure` | `validation/core/src/validator.rs` | `message`, `error_code`, `property_name`, `attempted_value`, `exception` |
| `ValidationResult` | `validation/core/src/validator.rs` | `validator_name` |
| `ValidatorError` | `validation/core/src/validator.rs` | `CoseDecode`, `Trust` variants |

### 1.5 — Facts Use `Arc<str>` for Shared Immutable Strings

The trust-fact engine produces facts that may be queried by multiple trust plan
rules. String-valued facts (certificate thumbprints, subjects, issuers, DID
components) use `Arc<str>` — a reference-counted immutable string — so that
fact lookups never clone the underlying string data.

```rust
// Arc<str> created once during fact production
let thumbprint: Arc<str> = Arc::from(hex_encode_upper(&sha256_hasher.finalize()));

// Every rule that reads this fact gets a cheap Arc clone (pointer + refcount)
let t = facts.get::<CertificateThumbprintFact>();  // Arc<str> clone, not String clone
```

*Source: `validation/primitives/src/facts.rs`, `extension_packs/certificates/src/validation/facts.rs`*

---

## 2. Core Primitives

### 2.1 — Type Reference Table

| Type | Heap Allocs | Copy Cost | Use Case |
|------|-------------|-----------|----------|
| `Arc<[u8]>` | 1 (backing buffer) | Refcount increment | Message backing store — all parsed fields index into this |
| `ArcSlice` | 0 (borrows `Arc<[u8]>`) | Refcount increment | Zero-copy sub-range: payload, signature, header bstr values |
| `ArcStr` | 0 (borrows `Arc<[u8]>`) | Refcount increment | Zero-copy UTF-8 sub-range: header tstr values |
| `Arc<str>` | 1 (small string) | Refcount increment | Immutable shared strings: fact values, content types |
| `Cow<'static, str>` | 0 (static) or 1 (dynamic) | Borrow or clone | Error messages: static literals borrow, dynamic strings own |
| `LazyHeaderMap` | 0 until accessed | OnceLock init cost | Deferred CBOR deserialization of header maps |
| `GenericArray<u8, N>` | 0 (stack) | `memcpy` on stack | Hash digests: SHA-256 (32B), SHA-384 (48B), SHA-512 (64B) |
| `[u8; 32]` | 0 (stack) | `memcpy` on stack | Fixed-size hash digests for known algorithms |
| `CoseData::Buffered` | 1 (`Arc<[u8]>`) | Refcount increment | In-memory COSE message bytes |
| `CoseData::Streamed` | 1 (small `header_buf`) | Refcount increment | Large payloads: headers buffered, payload on disk |
| `Range<usize>` | 0 (2 × `usize`) | Trivial copy | Byte range into backing `Arc<[u8]>` |

### 2.2 — `ArcSlice`: Zero-Copy Byte Window

`ArcSlice` holds a shared reference to the parent `Arc<[u8]>` and a
`Range<usize>` describing the sub-region it represents. Dereferencing an
`ArcSlice` returns `&[u8]` — a borrow into the original allocation.

```
 ArcSlice                      Arc<[u8]>
 ┌──────────────┐              ┌──────────────────────────────┐
 │ data ─────────────────────▶ │ 0xD8 0x12 0xA1 0x01 0x26 …  │
 │ range: 3..7  │              └──────────────────────────────┘
 └──────────────┘                         ▲▲▲▲
                                          ││││
                                    .as_bytes() returns &[0x01, 0x26, …, …]
```

**Construction paths:**

| Path | How | Allocates? |
|------|-----|------------|
| **Parse path** | `ArcSlice::new(arc, range)` — shares parent's `Arc` | No |
| **Parse path** | `ArcSlice::from_sub_slice(parent, sub_slice)` — pointer arithmetic | No |
| **Builder path** | `ArcSlice::from(vec)` — wraps `Vec<u8>` in new `Arc` | Yes (small) |

*Source: `cose_primitives::arc_types::ArcSlice`*

### 2.3 — `ArcStr`: Zero-Copy UTF-8 String Window

Identical layout to `ArcSlice`, but guarantees UTF-8 validity. Constructed from
CBOR tstr values during header map decoding — shares the message's `Arc<[u8]>`
buffer with no additional allocation.

*Source: `cose_primitives::arc_types::ArcStr`*

### 2.4 — `LazyHeaderMap`: Deferred CBOR Deserialization

| Method | Behavior | Triggers parse? |
|--------|----------|-----------------|
| `as_bytes()` | Returns raw CBOR `&[u8]` | No |
| `range()` | Returns byte range | No |
| `arc()` | Returns `&Arc<[u8]>` | No |
| `is_parsed()` | Check if parsed | No |
| `headers()` | Decode and cache; return `&CoseHeaderMap` | Yes (once) |
| `try_headers()` | Same, propagating CBOR errors | Yes (once) |
| `get(label)` | Delegate to `headers().get(label)` | Yes (once) |
| `insert(label, value)` | Mutate parsed map | Yes (once) |

The `OnceLock` ensures thread-safe one-time initialization. Concurrent callers
block on the first parse; all subsequent calls return the cached result.

*Source: `cose_primitives::lazy_headers::LazyHeaderMap`*

### 2.5 — `CoseData`: The Ownership Root

`CoseData` is an enum with two variants that govern the memory model for the
entire message:

```
CoseData::Buffered                    CoseData::Streamed
┌────────────────────────┐            ┌─────────────────────────────┐
│ raw: Arc<[u8]>         │            │ header_buf: Arc<[u8]>       │
│   (entire CBOR msg)    │            │   (headers + sig only)      │
│ range: 0..len          │            │ protected_range, unprotected│
│   (sub-messages may    │            │   _range, signature_range   │
│    use a sub-range)    │            │ source: Arc<Mutex<ReadSeek>>│
└────────────────────────┘            │ payload_offset: u64         │
                                      │ payload_len: u64            │
                                      └─────────────────────────────┘
```

For `Streamed`, the payload is *never* loaded into memory. It lives on the
underlying `ReadSeek` source (typically a file) and is accessed by seeking to
`payload_offset` and reading `payload_len` bytes in chunks.

*Source: `cose_primitives::data::CoseData`*

---

## 3. Operation Memory Profiles

### 3.1 — Parse

| Mode | API | Peak Memory | Allocations | Description |
|------|-----|-------------|-------------|-------------|
| **Buffered** | `CoseSign1Message::parse()` | `O(n)` where n = message size | 1 × `Arc<[u8]>` | Entire CBOR in one allocation; all fields are ranges |
| **Streamed** | `CoseSign1Message::parse_stream()` | `O(h + s)` where h = headers, s = signature | 1 × small `Arc<[u8]>` | Typically < 1 KB; payload stays on disk |

**Buffered parse — allocation sequence:**

```
Input bytes ──▶ Arc::from(bytes)  ──▶ CoseSign1Message
                     │                    ├── protected:   LazyHeaderMap { arc, 4..47 }
                     │                    ├── unprotected: LazyHeaderMap { arc, 47..52 }
                     │                    ├── payload_range:  Some(52..1052)
                     │                    └── signature_range: 1052..1116
                     │
                     └── ONE heap allocation. Everything else is Range<usize>.
```

### 3.2 — Sign

| Mode | API | Peak Memory | Description |
|------|-----|-------------|-------------|
| **Buffered** | `CoseSign1Builder::sign()` | `O(p + s)` | p = payload, s = Sig_structure |
| **Streaming** | `sign_streaming()` | `O(64 KB + prefix)` | Payload streamed through hasher in 64 KB chunks |

**Streaming sign — memory timeline:**

```
Time ─────────────────────────────────────────────────────────▶

1. Sig_structure prefix   ┌─ ~200 bytes (CBOR array header + protected bytes)
                          └─ stack-allocated, written to hasher

2. Payload streaming      ┌─ 64 KB chunk buffer (reused)
   (10 GB file)           │  read → hash → read → hash → ...
                          └─ 64 KB constant, regardless of payload size

3. Hash finalization      ┌─ 32–64 bytes (stack GenericArray or [u8; N])
                          └─ no heap allocation

4. Signing                ┌─ ~72–132 bytes (ECDSA/RSA signature)
                          └─ one Vec<u8> allocation for the signature output

Peak total: ~65 KB
```

### 3.3 — Verify

| Mode | API | Peak Memory | Description |
|------|-----|-------------|-------------|
| **Buffered** | `verify()` / `verify_detached()` | `O(p + s)` | Full Sig_structure materialized |
| **Streaming** | `verify_payload_streaming()` | `O(64 KB)` | Prefix + payload chunks fed to `VerifyingContext` |
| **Fallback** | (non-streaming verifier) | `O(p + s)` | Ed25519/ML-DSA must buffer entire payload |

### 3.4 — Algorithm Streaming Support Matrix

| Algorithm | COSE ID | Streaming? | Reason |
|-----------|---------|------------|--------|
| ES256 | -7 | ✅ | OpenSSL `EVP_DigestVerify` — incremental |
| ES384 | -35 | ✅ | OpenSSL `EVP_DigestVerify` — incremental |
| ES512 | -36 | ✅ | OpenSSL `EVP_DigestVerify` — incremental |
| PS256 | -37 | ✅ | OpenSSL `EVP_DigestVerify` — incremental |
| PS384 | -38 | ✅ | OpenSSL `EVP_DigestVerify` — incremental |
| PS512 | -39 | ✅ | OpenSSL `EVP_DigestVerify` — incremental |
| RS256 | -257 | ✅ | OpenSSL `EVP_DigestVerify` — incremental |
| RS384 | -258 | ✅ | OpenSSL `EVP_DigestVerify` — incremental |
| RS512 | -259 | ✅ | OpenSSL `EVP_DigestVerify` — incremental |
| EdDSA | -8 | ❌ | Ed25519 requires full message before sign/verify |
| ML-DSA-* | TBD | ❌ | Post-quantum; requires full message |

> **Design implication:** `verify_payload_streaming()` queries
> `supports_streaming()` on the verifier. When it returns `false`, the
> function falls back to full materialization. For a 10 GB payload
> with Ed25519, you need 10 GB of RAM.

### 3.5 — Scenario Profiles

#### Small Payload (100 bytes)

All modes are equivalent. Overhead is dominated by Sig_structure CBOR
framing (~200 bytes) and signature size (~64–132 bytes).

**Total peak: ~500 bytes.** Use `parse()` + `verify()` for simplicity.

#### Large Streaming Verify (10 GB payload, ECDSA)

```
parse_stream(file)            →   ~1 KB   (headers + signature in header_buf)
verify_payload_streaming()    →  ~65 KB   (64 KB chunk buffer + prefix)
                              ─────────
Peak total:                     ~66 KB
```

The 10 GB payload is never loaded into memory.

#### Large Streaming Sign (10 GB payload)

```
SigStructureHasher::init()    →  ~200 B   (CBOR prefix)
stream 10 GB in 64 KB chunks  →   64 KB   (reused buffer)
hasher.finalize()             →  32–64 B   (stack-allocated hash)
signer.sign(&hash)            →  ~100 B   (signature output)
                              ─────────
Peak total:                     ~65 KB
```

---

## 4. Cross-Layer Patterns

### 4.1 — Data Flow Through the Stack

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           C++ Application                                   │
│                                                                             │
│   auto msg = CoseSign1Message::Parse(bytes);                                │
│   ByteView payload = msg.Payload();     ← borrowed pointer into Rust Arc    │
│   auto vec = msg.PayloadAsVector();     ← copies only if caller needs it    │
│   builder.ConsumeProtected(std::move(h)); ← release() transfers ownership  │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                           C Headers                                         │
│                                                                             │
│   cose_sign1_message_payload(handle, &ptr, &len);  ← ptr borrows from Arc  │
│   // ptr valid until handle is freed — caller never allocates               │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                           FFI Boundary (extern "C")                         │
│                                                                             │
│   // Borrow: return pointer into Arc-backed data                            │
│   *out_ptr = inner.payload().as_ptr();  ← zero copy                         │
│   *out_len = inner.payload().len();                                         │
│                                                                             │
│   // Ownership transfer: .to_vec() only when C must own the bytes           │
│   let vec = inner.encode();             ← allocates caller-owned copy       │
│   *out_ptr = Box::into_raw(vec);                                            │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                           Rust Library Layer                                │
│                                                                             │
│   CoseSign1Message::parse(bytes)        ← one Arc<[u8]>, everything shared  │
│   message.protected().headers()         ← OnceLock parse, ArcSlice values   │
│   validator.validate(&message, &arc)    ← Arc clones only (refcount bump)   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 4.2 — Layer-by-Layer Rules

#### Rust Library Layer

| Pattern | Rule | Example |
|---------|------|---------|
| Message fields | `Range<usize>` into `Arc<[u8]>` | `payload_range: Option<Range<usize>>` |
| Header values | `ArcSlice` / `ArcStr` from shared buffer | `CoseHeaderValue::Bytes(ArcSlice)` |
| Fact strings | `Arc<str>` for shared immutable strings | `thumbprint: Arc<str>` |
| Error messages | `Cow<'static, str>` | `Cow::Borrowed("missing content type")` |
| Message sharing | `Arc<CoseSign1Message>` | Validator and fact producers share same `Arc` |
| Builder consumption | Move fields out of `self`, never clone | `builder.protected` → moved into message |

#### FFI Boundary

| Operation | Technique | Allocates? |
|-----------|-----------|------------|
| **Borrow data to C** | Return `*const u8` + `u32` length pointing into `Arc` | No |
| **Transfer ownership to C** | `.to_vec()` → `Box::into_raw()` | Yes (required) |
| **Borrow handle from C** | `*const Handle` → `handle.as_ref()` | No |
| **Consume handle from C** | `*mut Handle` → `Box::from_raw()` | No |
| **Receive C callback output** | `slice::from_raw_parts()` → `.to_vec()` | Yes (required) |

#### C Projection

| Pattern | Rule |
|---------|------|
| **Byte access** | Always `const uint8_t* + uint32_t len` (borrowed from Rust handle) |
| **Caller never allocates** | All output buffers are Rust-allocated; C receives pointers |
| **Lifetime** | Borrowed pointers valid until the owning handle is freed |
| **Ownership transfer** | `*_free()` function documented on every handle |

#### C++ Projection

| Type | What It Does | Allocates? |
|------|-------------|------------|
| `ByteView` | `{const uint8_t* data, size_t size}` — borrows from Rust handle | No |
| `std::vector<uint8_t>` return | Copies bytes out — caller owns the vector | Yes |
| `release()` | Transfers handle ownership to another wrapper | No |
| `std::move()` | C++ move semantics → calls `release()` internally | No |

> **Design rule:** Every C++ method that returns `std::vector<uint8_t>` (a copy)
> must have a `@see` comment pointing to the zero-copy `ByteView` or
> `ToMessage` alternative.

### 4.3 — Ownership Transfer Patterns

```
  Borrow (zero-copy)                    Consume (zero-copy move)
  ─────────────────────                 ─────────────────────────
  C++: headers.GetBytes(label)          C++: builder.ConsumeProtected(move(h))
       → ByteView (borrowed)                → h.release() transfers handle
  FFI: *const HeaderMapHandle           FFI: *mut HeaderMapHandle
       → handle.as_ref()                    → Box::from_raw(handle)
  Rust: &CoseHeaderMap                  Rust: CoseHeaderMap (moved into builder)
       → ArcSlice from shared Arc            → no clone needed

  Copy (when ownership transfer         Copy-on-write (amortized)
  to C caller is required)              ─────────────────────────
  ─────────────────────────             C++: builder.SetProtected(headers)
  C++: msg.PayloadAsVector()                 → copies headers (handle still valid)
       → std::vector<uint8_t>           FFI: *const HeaderMapHandle
  FFI: inner.encode().to_vec()               → headers.clone() inside Rust
       → Box::into_raw(boxed_vec)       Rust: CoseHeaderMap::clone()
  Caller: must free with *_free()            → deep copy of map entries
```

---

## 5. Structurally Required Allocations

These allocations **cannot be eliminated** without fundamental architecture
changes. Each one is documented here to prevent well-intentioned "optimization"
attempts that would cascade breakage through the stack.

### 5.1 — Allocation Inventory

| # | Allocation | Location | Why Required | Zero-Copy Alternative |
|---|-----------|----------|--------------|----------------------|
| 1 | `payload.to_vec()` in factory | `signing/factories/` | `SigningContext` takes ownership of payload bytes. Changing to borrowed would cascade lifetime parameters through `SigningService` trait, all factory implementations, and the FFI boundary. | None — ownership boundary |
| 2 | `.to_vec()` on FFI callback return | `signing/core/ffi/` | C callbacks allocate with `malloc`; Rust must copy to its own heap before the C caller can `free()` the original. Two allocators cannot share ownership. | None — allocator boundary |
| 3 | `message.clone()` in `validate()` | `validation/core/src/validator.rs` | Backward-compatible API. `validate()` takes `&CoseSign1Message` and must clone internally for the pipeline. | **`validate_arc()`** — takes `Arc<CoseSign1Message>`, zero-copy sharing |
| 4 | `headers.clone()` in `set_protected()` | `signing/core/ffi/` | FFI handle is borrowed (`*const`), so Rust must clone the headers to own them. | **`consume_protected()`** — takes `*mut`, moves via `Box::from_raw` |
| 5 | `ContentType` as `String` | `validation/core/src/message_facts.rs` | The `ContentType` field in the `ContentTypeFact` uses `String` because the trust plan engine's `Field<T, String>` binding requires an owned string for type erasure. | `Arc<str>` used for fact values; `String` at plan binding boundary |
| 6 | Post-sign verification reparse | `signing/factories/` | After signing, the factory calls `CoseSign1Message::parse()` on the output bytes to verify the signature. This is an `O(n)` CBOR reparse on top of the `O(1000×n)` crypto cost — negligible. The reparse catches serialization bugs before the bytes escape the factory. | None — defense-in-depth requirement |
| 7 | `ArcSlice::from(vec)` on builder path | `cose_primitives::arc_types` | Builder-constructed header values are typically small (`Vec<u8>` from CWT claim encoding). Each wraps in its own `Arc`. Acceptable because builder values are small header fields (< 1 KB), not megabyte payloads. | None for builder path — parse path is zero-copy |

### 5.2 — Decision Diagram

When encountering a `.clone()`, `.to_vec()`, or `.to_owned()` call, use this
decision tree to determine if it's justified:

```
                    Is the data crossing an FFI boundary?
                    ┌───── YES ────────────────────┐
                    │                              │
                    ▼                              │
          Is C caller taking             Is it a callback return
          ownership of bytes?            from C → Rust?
          ┌─── YES ──┐                  ┌─── YES ──┐
          │           │                  │           │
          ▼           ▼                  ▼           ▼
     .to_vec()    Return *const      .to_vec()    Return ref
     REQUIRED     (zero-copy         REQUIRED     (zero-copy
                   borrow)           (allocator    borrow)
                                      boundary)
                    │
                    ▼ NO
                    │
          Is there a zero-copy alternative API?
          ┌─── YES ──────────────────────┐
          │                              │
          ▼                              ▼ NO
     Use it:                       Document in this table
     validate_arc()                (Section 5.1) and add
     consume_protected()           a code comment explaining
     SignDirectToMessage()         why the allocation exists.
```

---

## 6. Allocation Review Checklist

Use this checklist when reviewing PRs that touch native code. Any unchecked
item is a potential review blocker.

### 6.1 — Rust Code

- [ ] **No gratuitous `.clone()` on `Arc<[u8]>`, `ArcSlice`, `Vec<u8>`, or `CoseSign1Message`.**
      If a clone exists, it must be in the [Structurally Required](#5-structurally-required-allocations)
      table or have a `// clone required because: ...` comment.

- [ ] **Error types use `Cow<'static, str>`, not `String`.**
      Static error messages must use `Cow::Borrowed("...")`, not `"...".to_string()`.

- [ ] **Fact values use `Arc<str>`, not `String`.**
      Trust fact fields that are shared across rules must be `Arc<str>` to avoid
      cloning on each rule evaluation.

- [ ] **No `.to_string()` on string literals in error paths.**
      Use `.into()` instead, which resolves to `Cow::Borrowed` for `&'static str`.

- [ ] **FFI handle-to-inner functions use bounded `<'a>`, not `'static`.**
      A `'static` lifetime on a handle reference is unsound — the handle can be
      freed at any time.

      ```rust
      // ✅ Correct: bounded lifetime
      unsafe fn handle_to_inner<'a>(h: *const H) -> Option<&'a Inner>

      // ❌ Unsound: 'static on heap-allocated handle
      unsafe fn handle_to_inner(h: *const H) -> Option<&'static Inner>
      ```

- [ ] **Builder patterns move fields, not clone them.**
      When a builder is consumed (`Box::from_raw` on FFI side, or `self` consumption
      in Rust), fields should be moved out of the struct, not cloned.

- [ ] **New `LazyHeaderMap` access does not trigger unnecessary parsing.**
      If only raw bytes are needed (e.g., for Sig_structure), use `.as_bytes()`
      not `.headers()`.

- [ ] **Streaming APIs use fixed-size buffers.**
      Chunk buffers in sign/verify streaming paths must be constant-size (64 KB),
      never proportional to payload size.

- [ ] **Hash digests are stack-allocated.**
      SHA-256/384/512 outputs use `GenericArray` or `[u8; N]`, not `Vec<u8>`.

### 6.2 — FFI Code

- [ ] **Borrow vs. own is explicit in pointer types.**
      `*const` = borrowed (caller may reuse handle). `*mut` = consumed (handle
      invalidated after call).

- [ ] **Every `Box::into_raw()` has a documented `*_free()` counterpart.**

- [ ] **Null checks on ALL pointer parameters before dereference.**

- [ ] **`catch_unwind` wraps all `extern "C"` function bodies.**

- [ ] **String ownership is documented.** `*mut c_char` = caller must free.
      `*const c_char` = borrowed from Rust, valid until handle is freed.

### 6.3 — C/C++ Projection Code

- [ ] **Byte accessors return `ByteView` (borrowed), not `std::vector<uint8_t>` (copied).**
      If a copy method exists, it must have a `@see` pointing to the zero-copy alternative.

- [ ] **C++ classes are move-only.** Copy constructor and copy assignment are
      `= delete`. Move constructor nulls the source handle.

      ```cpp
      // ✅ Correct
      MyHandle(MyHandle&& other) noexcept : handle_(other.handle_) {
          other.handle_ = nullptr;
      }
      ```

- [ ] **Destructors guard against double-free.** `if (handle_)` before calling
      the Rust `*_free()` function.

- [ ] **`release()` is used for ownership transfer**, not raw pointer
      extraction followed by manual free.

### 6.4 — Quick Reference: Preferred vs. Avoided

| Context | ✅ Preferred | ❌ Avoided |
|---------|-------------|-----------|
| Error detail | `Cow::Borrowed("msg")` | `"msg".to_string()` |
| Error detail (dynamic) | `Cow::Owned(format!(...))` | `format!(...).to_string()` |
| Fact string | `Arc::<str>::from(s)` | `s.to_string()` stored as `String` |
| Header byte value | `ArcSlice::new(arc, range)` | `arc[range].to_vec()` |
| Message sharing | `Arc::new(message)` then `.clone()` | `message.clone()` (deep copy) |
| Builder field transfer | `std::mem::take(&mut self.field)` | `self.field.clone()` |
| Hash output | `GenericArray<u8, U32>` (stack) | `Vec<u8>` (heap) |
| C++ byte access | `ByteView payload = msg.Payload()` | `std::vector<uint8_t> p = msg.PayloadAsVector()` |
| FFI handle borrow | `handle.as_ref()` (`*const`) | `Box::from_raw()` on `*const` (unsound) |
| FFI handle consume | `Box::from_raw(handle)` (`*mut`) | `handle.as_ref()` then `.clone()` |

---

## Further Reading

- [Memory Characteristics](../rust/docs/memory-characteristics.md) — per-crate memory breakdown and scenario analysis
- [Architecture](ARCHITECTURE.md) — full native stack architecture and layer diagram
- [Zero-Copy Design Instructions](../.github/instructions/zero-copy-design.instructions.md) — Copilot agent instructions for maintaining zero-copy patterns