<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# cose_primitives

RFC 9052 COSE generic building blocks for Rust.

## Overview

This crate provides the foundational types for working with CBOR Object Signing
and Encryption (COSE) messages as defined in [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052).
It is designed as a **zero-copy**, **streaming-capable** layer that all
higher-level COSE message types (Sign1, Encrypt, MAC, etc.) build upon.

Key capabilities:

- **Header management** — `CoseHeaderMap`, `CoseHeaderLabel`, `CoseHeaderValue`,
  `ProtectedHeader` for encoding and decoding COSE headers
- **Lazy header parsing** — `LazyHeaderMap` defers CBOR decoding until first access
- **Zero-copy data model** — `ArcSlice` and `ArcStr` reference a shared `Arc<[u8]>`
  backing buffer without copying
- **Streaming support** — `CoseData` enum supports both fully-buffered and
  stream-backed message payloads
- **IANA algorithm constants** — Re-exports from `crypto_primitives` (ES256, ES384,
  RS256, EdDSA, etc.)
- **CBOR provider abstraction** — Compile-time selection of the CBOR backend
  (currently EverParse)

## Architecture

```
┌───────────────────────────────────────────────────┐
│                 cose_primitives                    │
├───────────┬───────────┬───────────┬───────────────┤
│ headers   │ data      │ arc_types │ lazy_headers   │
│ ┌────────┐│ ┌────────┐│ ┌───────┐│ ┌────────────┐│
│ │HeaderMap││ │CoseData││ │ArcSlice│ │LazyHeaderMap││
│ │Label   ││ │Buffered││ │ArcStr ││ │  OnceLock   ││
│ │Value   ││ │Streamed││ └───────┘│ └────────────┘│
│ │Protected│ └────────┘│          │                │
│ └────────┘│           │          │                │
├───────────┴───────────┴──────────┴────────────────┤
│  algorithms (re-exports)  │  error  │  provider    │
└───────────────────────────┴─────────┴──────────────┘
        │                          │
        ▼                          ▼
  crypto_primitives          cbor_primitives
  (IANA algorithm IDs)       (CBOR encode/decode)
```

## Modules

| Module | Description |
|--------|-------------|
| `headers` | `CoseHeaderMap`, `CoseHeaderLabel`, `CoseHeaderValue`, `ProtectedHeader` — full CBOR-backed header management |
| `lazy_headers` | `LazyHeaderMap` — lazy-parsed headers cached via `OnceLock` |
| `arc_types` | `ArcSlice` and `ArcStr` — zero-copy shared-ownership byte/string references into an `Arc<[u8]>` buffer |
| `data` | `CoseData` enum — `Buffered` (in-memory) and `Streamed` (seekable reader) message data |
| `algorithms` | Re-exported IANA algorithm constants from `crypto_primitives` |
| `error` | `CoseError` — CBOR, structural, and I/O error variants |
| `provider` | Compile-time CBOR provider singleton selection |

## Key Types

### CoseHeaderMap

The primary type for reading and writing COSE headers:

```rust
use cose_primitives::headers::{CoseHeaderMap, CoseHeaderLabel, CoseHeaderValue};

let mut headers = CoseHeaderMap::new();

// Set algorithm (label 1) to ES256 (-7)
headers.set(CoseHeaderLabel::Int(1), CoseHeaderValue::Int(-7));

// Read a header value
if let Some(CoseHeaderValue::Int(alg)) = headers.get(&CoseHeaderLabel::Int(1)) {
    assert_eq!(*alg, -7);
}
```

### ArcSlice / ArcStr

Zero-copy shared-ownership byte slices backed by `Arc<[u8]>`:

```rust
use cose_primitives::arc_types::ArcSlice;
use std::sync::Arc;

// Create from raw bytes — one allocation shared across sub-slices
let buffer: Arc<[u8]> = Arc::from(b"hello world".as_slice());
let slice = ArcSlice::new(buffer.clone(), 0..5); // "hello"

assert_eq!(slice.as_ref(), b"hello");
```

### CoseData

Supports both in-memory and stream-backed message payloads:

```rust
use cose_primitives::data::CoseData;

// Fully buffered payload
let data = CoseData::Buffered { bytes: payload_bytes };

// Streaming payload (headers in memory, body in a seekable reader)
let data = CoseData::Streamed { headers, reader };
```

### LazyHeaderMap

Defers CBOR header parsing until first access:

```rust
use cose_primitives::lazy_headers::LazyHeaderMap;

let lazy = LazyHeaderMap::from_bytes(raw_cbor_bytes);

// No parsing happens until you call .get() or .map()
let map = lazy.map()?; // parsed on first call, cached thereafter
```

## Memory Design

- **Zero-copy throughout**: All decoded data references a shared `Arc<[u8]>` backing
  buffer. Sub-structures (headers, payload, signature) hold `ArcSlice` ranges into
  the original bytes — no heap allocations for parsed fields.
- **Lazy evaluation**: `LazyHeaderMap` uses `OnceLock` to parse headers exactly
  once, on demand.
- **Streaming**: `CoseData::Streamed` keeps only headers in memory while the payload
  remains in a seekable stream, enabling large-file processing.

## Dependencies

- `cbor_primitives` — CBOR encoding/decoding trait and EverParse backend
- `crypto_primitives` — IANA algorithm constants and crypto trait definitions

## See Also

- [primitives/cose/sign1/](sign1/) — COSE_Sign1 message type and builder
- [primitives/cbor/](../cbor/) — CBOR provider abstraction
- [primitives/crypto/](../crypto/) — Cryptographic trait definitions

## License

Licensed under the [MIT License](../../../../LICENSE).