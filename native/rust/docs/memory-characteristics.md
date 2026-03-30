# Memory Characteristics

Reference documentation for memory usage across the native Rust COSE implementation.

## Architecture Overview

The stack uses a **layered zero-copy design**:

1. **Parse once, share everywhere** — `CoseSign1Message::parse()` wraps raw CBOR bytes in an `Arc<[u8]>`. All fields (headers, payload, signature) are `Range<usize>` into that single allocation. Cloning a message is a cheap reference-count increment.

2. **Stream parse for large payloads** — `CoseSign1Message::parse_stream()` reads only headers and signature into memory (~1 KB typical). The payload stays on disk/stream, accessed via seekable byte range.

3. **Lazy header parsing** — `LazyHeaderMap` defers CBOR decoding of header maps until first access. Header byte/text values use `ArcSlice`/`ArcStr` for zero-copy sharing.

4. **Streaming sign/verify** — `SigStructureHasher`, `build_sig_structure_prefix()`, and `verify_payload_streaming()` feed payload through hashers or verifiers in 64 KB chunks, never materializing the full payload.

## Per-Crate Memory Breakdown

| Crate | Allocations | Notes |
|-------|-------------|-------|
| `cbor_primitives` | Zero-copy decode; borrows from input buffer | EverParse backend reads from stream |
| `crypto_primitives` | Trait-only; no allocations | Backend (OpenSSL) allocates internally |
| `cose_primitives` | `CoseData` holds `Arc<[u8]>` or stream handle | `Streamed` variant: small `header_buf` only |
| `cose_sign1_primitives` | `CoseSign1Message` wraps `CoseData` + ranges | No additional payload copies |

## Operation Memory Profiles

### Parse

| Mode | Peak Memory | Description |
|------|-------------|-------------|
| **Buffered** (`parse`) | `O(message_size)` | Entire CBOR message in one `Arc<[u8]>` |
| **Streamed** (`parse_stream`) | `O(header_size + sig_size)` | Typically < 1 KB; payload not read |

### Sign

| Mode | Peak Memory | Description |
|------|-------------|-------------|
| **Buffered** (`CoseSign1Builder::sign`) | `O(payload + sig_structure)` | Payload + Sig_structure both in memory |
| **Streaming** (`sign_streaming`) | `O(64 KB + sig_structure_prefix)` | Payload streamed in 64 KB chunks through hasher |

### Verify

| Mode | Peak Memory | Description |
|------|-------------|-------------|
| **Buffered** (`verify` / `verify_detached`) | `O(payload + sig_structure)` | Full Sig_structure materialized |
| **Streaming** (`verify_payload_streaming`) | `O(64 KB)` | Prefix + payload chunks fed to `VerifyingContext` |
| **Fallback** (non-streaming verifier) | `O(payload + sig_structure)` | Ed25519/ML-DSA: must buffer entire payload |

## Scenario Analysis

### 1. Small Payload (100 bytes)

All paths are equivalent. Total memory: ~500 bytes (Sig_structure overhead + header bytes).
Use `parse()` + `verify()` for simplicity.

### 2. Large Streamed Verify (10 GB payload)

```
parse_stream(file)          → ~1 KB   (headers + signature only)
verify_streamed(&verifier)  → ~65 KB  (64 KB chunk buffer + prefix)
                            ─────────
Total peak:                   ~66 KB  (with ECDSA/RSA verifier)
```

The 10 GB payload is never loaded into memory. The source stream is seeked to the payload offset and read in 64 KB chunks through the `VerifyingContext`.

### 3. Large Streamed Sign (10 GB payload)

```
SigStructureHasher::init()  → ~200 bytes (CBOR prefix)
stream 10 GB in 64 KB chunks → 64 KB    (reused buffer)
hasher.finalize()           → 32-64 bytes (hash output)
signer.sign(&hash)          → ~100 bytes (signature)
                            ─────────
Total peak:                   ~65 KB
```

## Streaming Support Matrix

| Algorithm | COSE ID | `supports_streaming()` | Notes |
|-----------|---------|------------------------|-------|
| ES256     | -7      | ✅ Yes | OpenSSL EVP_DigestVerify |
| ES384     | -35     | ✅ Yes | OpenSSL EVP_DigestVerify |
| ES512     | -36     | ✅ Yes | OpenSSL EVP_DigestVerify |
| PS256     | -37     | ✅ Yes | OpenSSL EVP_DigestVerify |
| PS384     | -38     | ✅ Yes | OpenSSL EVP_DigestVerify |
| PS512     | -39     | ✅ Yes | OpenSSL EVP_DigestVerify |
| RS256     | -257    | ✅ Yes | OpenSSL EVP_DigestVerify |
| RS384     | -258    | ✅ Yes | OpenSSL EVP_DigestVerify |
| RS512     | -259    | ✅ Yes | OpenSSL EVP_DigestVerify |
| EdDSA     | -8      | ❌ No  | Ed25519 requires full message |
| ML-DSA-*  | TBD     | ❌ No  | Post-quantum; requires full message |

When `supports_streaming()` returns `false`, `verify_payload_streaming()` falls back to buffering the entire payload before verification.

## EverParse Streaming Security Note

When using `parse_stream()` with the EverParse CBOR backend, headers are read from the stream and stored in `header_buf`. On first access via `LazyHeaderMap`, they are re-parsed and validated by the same EverParse decoder. This means:

- **Headers are validated at parse time** (structural CBOR correctness) AND at access time (semantic correctness via lazy decode).
- The payload is **not** validated by the CBOR parser — it is a raw bstr content region accessed by byte offset.
- Signature bytes are validated as a CBOR bstr during stream parsing.

## Known Limitations

1. **Ed25519 and ML-DSA cannot stream** — These algorithms require the complete message before verification. `verify_payload_streaming()` detects this via `supports_streaming()` and falls back to full materialization. For 10 GB payloads with Ed25519, you need 10 GB of memory.

2. **`verify_detached()` always buffers** — The non-streaming `verify_detached(&[u8])` requires the caller to provide the full payload as a byte slice. Use `verify_payload_streaming()` or `verify_detached_streaming()` for large detached payloads.

3. **Stream source is mutex-protected** — `CoseData::Streamed` wraps the source in `Arc<Mutex<Box<dyn ReadSeek>>>`. Concurrent reads require external synchronization or separate `parse_stream()` calls.

4. **`payload_reader()` on streamed messages buffers** — The current `payload_reader()` implementation for streamed messages reads the full payload into a `Vec<u8>` to avoid holding the mutex lock. For large payloads, use `verify_streamed()` or access the stream directly via `cose_data()`.
