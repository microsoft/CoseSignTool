# cose_sign1_primitives

Core types and traits for CoseSign1 signing and verification with a zero-copy, streaming-first architecture.

## Overview

This crate provides the foundational types for working with COSE_Sign1 messages
as defined in [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052). It depends on
`cose_primitives` and `crypto_primitives` and uses a compile-time-selected CBOR
provider (enabled via feature flags) — callers do **not** pass a provider at
runtime.

**Default feature**: `cbor-everparse` — uses `cbor_primitives_everparse` as the
CBOR backend.

## Features

- **CoseSign1Message** — Parse and verify COSE_Sign1 messages (buffered or streamed)
- **CoseSign1Builder** — Fluent API for creating signed messages
- **CoseHeaderMap** / **CoseHeaderLabel** / **CoseHeaderValue** — Protected and unprotected header handling  
- **Sig_structure** — RFC 9052 compliant signature structure construction
- **Streaming support** — Handle large payloads without full memory load via `StreamingPayload`

## Design Philosophy

This crate intentionally has minimal dependencies:

- Uses `cose_primitives` for shared COSE types and `crypto_primitives` for key traits
- No `thiserror`, no `once_cell`
- Uses `std::sync::OnceLock` (stable since Rust 1.70) for lazy header parsing
- Compile-time CBOR provider selection keeps the API clean

This keeps the crate lightweight for customers who need minimal footprint.

## Usage

```rust
use cose_sign1_primitives::{
    CoseSign1Builder, CoseSign1Message, CoseHeaderMap, algorithms,
};

// Create protected headers
let mut protected = CoseHeaderMap::new();
protected.set_alg(algorithms::ES256);

// Sign a message (provider is selected at compile time)
let message_bytes = CoseSign1Builder::new()
    .protected(protected)
    .sign(&signer, b"payload")?;

// Parse and verify
let message = CoseSign1Message::parse(&message_bytes)?;
let valid = message.verify(&verifier, None, None)?;
```

## Key Components

### CoseSign1Builder

Fluent builder for creating COSE_Sign1 messages. Supports both in-memory
(`sign`) and streaming (`sign_streaming`) payloads:

```rust
// In-memory signing
let bytes = CoseSign1Builder::new()
    .protected(headers)
    .detached(false)
    .sign(&signer, payload)?;

// Streaming signing (avoids loading large payloads into memory)
let bytes = CoseSign1Builder::new()
    .protected(headers)
    .detached(true)
    .sign_streaming(&signer, Arc::new(file_payload))?;
```

### Sig_structure

The `build_sig_structure` and `build_sig_structure_prefix` functions construct
the To-Be-Signed (TBS) structure per RFC 9052:

```text
Sig_structure = [
    context: "Signature1",
    body_protected: bstr,
    external_aad: bstr,
    payload: bstr
]
```

## Streaming Large Payloads

### The Challenge: CBOR Requires Length Upfront

COSE signatures are computed over the `Sig_structure`, which includes the payload
as a CBOR byte string (`bstr`). CBOR byte strings require the length to be encoded
in the header **before** the actual content bytes:

```text
bstr header: 0x5a 0x00 0x10 0x00 0x00  (indicates 1MB of bytes follow)
bstr content: <1MB of actual payload bytes>
```

This creates a problem for streaming: you need to know the total length before
you can start writing the CBOR encoding.

### The Solution: `StreamingPayload` Trait

We provide the `StreamingPayload` trait that combines `open()` with a required
`size()` method:

```rust
pub trait StreamingPayload: Send + Sync {
    /// Returns the total number of bytes in this payload.
    fn size(&self) -> u64;
    /// Opens a reader for the payload content.
    fn open(&self) -> Result<Box<dyn Read>, PayloadOpenError>;
}
```

### Built-in Implementations

| Type | How Length is Determined |
|------|--------------------------|
| `MemoryPayload` | `Arc<[u8]>` length |
| `FilePayload` | `metadata().len()` |

### Wrapping Unknown Streams

For streams where you know the length externally (e.g., HTTP Content-Length header):

```rust
use cose_sign1_primitives::SizedReader;

// HTTP response with known Content-Length
let body = response.into_reader();
let content_length = response.content_length().unwrap();
let payload = SizedReader::new(body, content_length);
```

### Payload Size Threshold

Payloads larger than `LARGE_PAYLOAD_THRESHOLD` bytes (85 KB) should use the
streaming APIs to avoid loading the entire content into memory.

## License

MIT License - see LICENSE file for details.
