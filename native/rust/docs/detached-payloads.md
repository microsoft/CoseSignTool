# Detached Payloads + Streaming

## When detached payloads happen

COSE_Sign1 can be encoded with `payload = nil`, meaning the content is supplied out-of-band.

The validator treats `payload = nil` as "detached content required".

## How to provide detached content

`CoseSign1ValidationOptions` supports:

- `Payload::Bytes(Vec<u8>)` for small payloads
- `Payload::Streaming(Box<dyn StreamingPayload>)` for stream-like sources

A provider must support opening a fresh `Read` each time the validator needs the payload.

## Streaming-friendly signature verification

Signature verification needs `Sig_structure`, which includes a CBOR byte-string that contains the payload.

For large payloads with a known length hint, the validator can build a streaming `Sig_structure` reader that:

- writes the CBOR structure framing
- streams the payload bytes into the byte string

To take advantage of this:

- Supply `Payload::Streaming` with a `StreamingPayload` implementation that returns a correct `size()`.
- Ensure `size() > LARGE_STREAM_THRESHOLD`.
- Provide a `CoseKey` implementation that overrides `verify_reader(...)`.

If `verify_reader` is not overridden, the default implementation will buffer into memory.

## The Streaming Challenge: CBOR Requires Length Upfront

CBOR byte strings encode the length **before** the content:

```text
bstr header: 0x5a 0x00 0x10 0x00 0x00  (indicates 1MB follows)
bstr content: <1MB of payload bytes>
```

This is why streaming COSE requires knowing the payload length upfront - you can't
start writing the `Sig_structure` CBOR until you know how big the payload will be.

### Why Rust's `Read` Doesn't Include Length

Rust's `Read` trait intentionally omits length because:

- Many streams have unknown length (network sockets, pipes, stdin, compressed data)
- `Seek::stream_len()` requires `&mut self` (it seeks to end and back)
- Length is context-dependent (`File` knows via `metadata()`, but `BufReader<File>` loses it)

## Low-Level Streaming with `cose_sign1_primitives`

The `cose_sign1_primitives` crate provides the `SizedRead` trait for true streaming:

### SizedRead Trait

```rust
use cose_sign1_primitives::SizedRead;

pub trait SizedRead: Read {
    fn len(&self) -> Result<u64, std::io::Error>;
}
```

### Automatic Implementations

| Type | How Length is Determined |
|------|--------------------------|
| `std::fs::File` | `metadata().len()` |
| `std::io::Cursor<T>` | `get_ref().as_ref().len()` |
| `&[u8]` | slice `.len()` |

### Wrapping Streams with Known Length

For streams where you know the length externally (HTTP Content-Length, etc.):

```rust
use cose_sign1_primitives::{SizedReader, sized_from_reader};

// HTTP response with Content-Length header
let body = response.into_reader();
let content_length = response.content_length().unwrap();
let payload = sized_from_reader(body, content_length);
```

### Streaming Hash Functions

```rust
use sha2::{Sha256, Digest};
use cose_sign1_primitives::{hash_sig_structure_streaming, open_sized_file};

// Open file (implements SizedRead via metadata)
let payload = open_sized_file("large_payload.bin")?;

// Hash in 64KB chunks - never loads full payload into memory
let hasher = hash_sig_structure_streaming(
    &cbor_provider,
    Sha256::new(),
    protected_header_bytes,
    None,  // external_aad
    payload,
)?;

let hash: [u8; 32] = hasher.finalize().into();
```

### Convenience Functions

| Function | Purpose |
|----------|---------|
| `open_sized_file(path)` | Open file as `SizedRead` |
| `sized_from_reader(r, len)` | Wrap any `Read` with known length |
| `sized_from_bytes(bytes)` | Wrap bytes as `Cursor` |
| `hash_sig_structure_streaming(...)` | Hash Sig_structure in chunks |
| `stream_sig_structure(...)` | Write Sig_structure to any `Write` |

## Example

See [cose_sign1_validation/examples/detached_payload_provider.rs](../cose_sign1_validation/examples/detached_payload_provider.rs).
