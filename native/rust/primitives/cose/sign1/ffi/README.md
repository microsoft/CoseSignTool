# cose_sign1_primitives_ffi

C/C++ FFI projections for `cose_sign1_primitives` types and message verification.

## Exported Functions (~25)

- `cosesign1_message_parse` -- Parse COSE_Sign1 from bytes
- `cosesign1_message_verify` / `cosesign1_message_verify_detached` -- Verify signature
- `cosesign1_message_protected_headers` / `cosesign1_message_unprotected_headers` -- Header access
- `cosesign1_headermap_get_int` / `cosesign1_headermap_get_bytes` / `cosesign1_headermap_get_text`
- `cosesign1_message_payload` / `cosesign1_message_signature` / `cosesign1_message_alg`
- `cosesign1_key_*` -- Key handle operations
- `cosesign1_error_*` / `cosesign1_string_free` -- Error handling + memory management
- `cosesign1_ffi_abi_version` -- ABI version check

## CBOR Provider

Selected at compile time via Cargo feature (default: `cbor-everparse`).
See `src/provider.rs`.

## Build

```bash
cargo build --release -p cose_sign1_primitives_ffi
```
