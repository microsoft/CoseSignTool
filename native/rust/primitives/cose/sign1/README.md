# cose_sign1_primitives

Core types and traits for CoseSign1 signing and verification with pluggable CBOR.

## Overview

This crate provides the foundational types for working with COSE_Sign1 messages
as defined in [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052). It depends on
`cose_primitives`, `cbor_primitives`, and `crypto_primitives`.

The CBOR provider is selected at compile time via Cargo features (default:
`cbor-everparse`). Callers do not need to pass a provider — signing and parsing
use the compile-time-selected singleton internally.

## Features

- **CryptoSigner / CryptoVerifier traits** - Abstraction for signing/verification operations
- **CoseHeaderMap** - Protected and unprotected header handling
- **CoseSign1Message** - Parse and verify COSE_Sign1 messages
- **CoseSign1Builder** - Fluent API for creating messages
- **Sig_structure** - RFC 9052 compliant signature structure construction
- **Streaming support** - Handle large payloads without full memory load via `StreamingPayload`

## Design Philosophy

This crate intentionally has minimal dependencies:

- Only `cose_primitives`, `cbor_primitives`, and `crypto_primitives` as dependencies (no `thiserror`, no `once_cell`)
- Manual `std::error::Error` implementations
- Uses `std::sync::OnceLock` (stable since Rust 1.70) instead of `once_cell`

This keeps the crate dependency-free for customers who need minimal footprint.

## Usage

```rust
use crypto_primitives::CryptoSigner;
use cose_sign1_primitives::{
    CoseSign1Builder, CoseSign1Message, CoseHeaderMap,
    algorithms,
};

// Create protected headers
let mut protected = CoseHeaderMap::new();
protected.set_alg(algorithms::ES256);

// Sign a message (CBOR provider is selected at compile time)
let message_bytes = CoseSign1Builder::new()
    .protected(protected)
    .sign(&signer, b"payload")?;

// Parse and verify
let message = CoseSign1Message::parse(&message_bytes)?;
let valid = message.verify(&verifier, None)?;
```

## Key Components

### CryptoSigner / CryptoVerifier Traits

The `CryptoSigner` and `CryptoVerifier` traits abstract over different key types.
Sign and verify methods operate on raw bytes (the Sig_structure is built
internally by the builder/message):

```rust
pub trait CryptoSigner: Send + Sync {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

pub trait CryptoVerifier: Send + Sync {
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, CryptoError>;
}
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

### Why Rust's `Read` Doesn't Include Length

Rust's standard `Read` trait intentionally doesn't include a `len()` method because:

- **Many streams have unknown length** - network sockets, pipes, stdin, compressed data
- **`Seek::stream_len()` mutates** - it requires `&mut self` since it seeks to end and back
- **Length is context-dependent** - a `File` knows its length via `metadata()`, but wrapping
  it in `BufReader` loses that information

### The Solution: `SizedRead` Trait

We provide the `SizedRead` trait that combines `Read` with a required `len()` method:

```rust
pub trait SizedRead: Read {
    /// Returns the total number of bytes in this stream.
    fn len(&self) -> Result<u64, std::io::Error>;
}
```

### Built-in Implementations

`SizedRead` is automatically implemented for common types:

| Type | How Length is Determined |
|------|--------------------------|
| `std::fs::File` | `metadata().len()` |
| `std::io::Cursor<T>` | `get_ref().as_ref().len()` |
| `&[u8]` | slice `.len()` |

### Wrapping Unknown Streams

For streams where you know the length externally (e.g., HTTP Content-Length header):

```rust
use cose_sign1_primitives::{SizedReader, sized_from_reader};

// HTTP response with known Content-Length
let body = response.into_reader();
let content_length = response.content_length().unwrap();
let payload = sized_from_reader(body, content_length);
// or equivalently:
let payload = SizedReader::new(body, content_length);
```

### Streaming Hash Functions

Once you have a `SizedRead`, use the streaming functions:

```rust
use sha2::{Sha256, Digest};
use cose_sign1_primitives::{hash_sig_structure_streaming, open_sized_file};

// Open a file (File implements SizedRead via metadata)
let payload = open_sized_file("large_payload.bin")?;

// Hash the Sig_structure in 64KB chunks - never loads full payload into memory
let hasher = hash_sig_structure_streaming(
    &cbor_provider,
    Sha256::new(),
    protected_header_bytes,
    None,  // external_aad
    payload,
)?;

let hash: [u8; 32] = hasher.finalize().into();
// Now sign the hash with your key
```

### Convenience Functions

| Function | Purpose |
|----------|---------|
| `open_sized_file(path)` | Open a file as `SizedRead` |
| `sized_from_reader(r, len)` | Wrap any `Read` with known length |
| `sized_from_bytes(bytes)` | Wrap `Vec<u8>` / `&[u8]` as `Cursor` |
| `hash_sig_structure_streaming(...)` | Hash Sig_structure in chunks (64KB default) |
| `hash_sig_structure_streaming_chunked(...)` | Same with custom chunk size |
| `stream_sig_structure(...)` | Write complete Sig_structure to any `Write` |

### IntoSizedRead Trait

For ergonomic conversions, use the `IntoSizedRead` trait:

```rust
use cose_sign1_primitives::IntoSizedRead;
use std::fs::File;

// File already implements SizedRead, so this is a no-op wrapper
let payload = File::open("payload.bin")?.into_sized()?;

// Vec<u8> converts to Cursor<Vec<u8>>
let payload = my_bytes.into_sized()?;
```

## License

MIT License - see LICENSE file for details.
