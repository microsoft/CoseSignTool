# FFI Guide

This document describes how to use the C/C++ FFI projections for the Rust COSE_Sign1 implementation.

## FFI Crates

| Crate | Purpose | Exports |
|-------|---------|---------|
| `cose_sign1_primitives_ffi` | Parse/verify/headers | ~25 |
| `cose_sign1_signing_ffi` | Sign/build | ~22 |
| `cose_sign1_validation_ffi` | Staged validator | ~12 |
| `cose_sign1_validation_primitives_ffi` | Trust plan authoring | ~29 |
| `cose_sign1_validation_ffi_certificates` | X.509 pack | ~34 |
| `cose_sign1_transparent_mst_ffi` | MST pack | ~17 |
| `cose_sign1_validation_ffi_akv` | AKV pack | ~6 |

## CBOR Provider Selection

FFI crates use compile-time CBOR provider selection via Cargo features:

```toml
[features]
default = ["cbor-everparse"]
cbor-everparse = ["cbor_primitives_everparse"]
```

Build with specific provider:

```bash
cargo build --release -p cose_sign1_primitives_ffi --features cbor-everparse
```

## ABI Stability

Each FFI crate exports an `abi_version` function:

```c
uint32_t cose_sign1_ffi_abi_version(void);
```

Check ABI compatibility before using other functions.

## Memory Management

### Rust-allocated Memory

Functions returning allocated memory include corresponding `free` functions:

```c
// Allocate
char* error_message = cose_sign1_error_message(result);

// Use...

// Free
cose_sign1_string_free(error_message);
```

### Buffer Patterns

Output buffers follow the "length probe" pattern:

```c
// First call: get required length
size_t len = 0;
cose_sign1_message_payload(msg, NULL, &len);

// Allocate
uint8_t* buffer = malloc(len);

// Second call: fill buffer
cose_sign1_message_payload(msg, buffer, &len);
```

## Common Patterns

### Parsing a Message

```c
#include <cose/sign1.h>

const uint8_t* cose_bytes = /* ... */;
size_t cose_len = /* ... */;

CoseSign1Message* msg = cose_sign1_message_parse(cose_bytes, cose_len);
if (!msg) {
    // Handle error
}

// Use message...

cose_sign1_message_free(msg);
```

### Creating a Signature

```c
#include <cose/sign1/signing.h>

CoseSign1Builder* builder = cose_sign1_builder_new();
cose_sign1_builder_set_protected(builder, protected_headers);

const uint8_t* payload = /* ... */;
size_t payload_len = /* ... */;

uint8_t* signature = NULL;
size_t sig_len = 0;
int result = cose_sign1_builder_sign(builder, key, payload, payload_len, &signature, &sig_len);

// Use signature...

cose_sign1_builder_free(builder);
cose_sign1_bytes_free(signature);
```

### Callback-based Keys

For custom key implementations:

```c
int my_sign_callback(
    const uint8_t* protected_bytes, size_t protected_len,
    const uint8_t* payload, size_t payload_len,
    const uint8_t* external_aad, size_t aad_len,
    uint8_t** signature_out, size_t* signature_len_out,
    void* user_data
) {
    // Your signing logic
    return 0; // Success
}

CoseKey* key = cose_key_from_callback(my_sign_callback, my_verify_callback, user_data);
```

## Error Handling

All FFI functions return error codes or NULL on failure:

```c
int result = cose_sign1_some_operation(/* ... */);
if (result != 0) {
    char* error = cose_sign1_error_message(result);
    fprintf(stderr, "Error: %s\n", error);
    cose_sign1_string_free(error);
}
```

## Thread Safety

- FFI functions are thread-safe for distinct objects
- Do not share mutable objects across threads without synchronization
- Error message retrieval is thread-local

## Build Integration

### CMake

```cmake
find_library(COSE_SIGN1_LIB cose_sign1_primitives_ffi PATHS ${RUST_LIB_DIR})
target_link_libraries(my_app ${COSE_SIGN1_LIB})
```

### pkg-config

```bash
pkg-config --libs cose_sign1_primitives_ffi
```

## See Also

- [Architecture Overview](../../ARCHITECTURE.md)
- [CBOR Provider Selection](cbor-providers.md)
- [cose_sign1_primitives_ffi README](../cose_sign1_primitives_ffi/README.md)
- [cose_sign1_signing_ffi README](../cose_sign1_signing_ffi/README.md)