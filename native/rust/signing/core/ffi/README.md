# cose_sign1_signing_ffi

C/C++ FFI for COSE_Sign1 message signing operations.

## Exported Functions

- `cose_sign1_signing_abi_version` — ABI version check
- `cose_sign1_builder_new` / `cose_sign1_builder_free` — Create/free signing builder
- `cose_sign1_builder_set_tagged` / `set_detached` / `set_protected` / `set_unprotected` / `set_external_aad` — Builder configuration
- `cose_sign1_builder_sign` — Sign payload with key
- `cose_headermap_new` / `cose_headermap_set_int` / `set_bytes` / `set_text` / `len` / `free` — Header map construction
- `cose_key_from_callback` / `cose_key_free` — Create key from C sign/verify callbacks
- `cose_sign1_signing_service_create` / `from_crypto_signer` / `free` — Signing service lifecycle
- `cose_sign1_factory_create` / `from_crypto_signer` / `free` — Factory lifecycle
- `cose_sign1_factory_sign_direct` / `sign_indirect` / `_file` / `_streaming` — Signing operations
- `cose_sign1_signing_error_message` / `error_code` / `error_free` — Error handling
- `cose_sign1_string_free` / `cose_sign1_bytes_free` / `cose_sign1_cose_bytes_free` — Memory management

## C Header

`<cose/sign1/signing.h>`

## Build

```bash
cargo build --release -p cose_sign1_signing_ffi
```
