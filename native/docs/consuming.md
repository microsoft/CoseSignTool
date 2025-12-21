# Consuming the libraries

There are two typical integration patterns:

1. **vcpkg overlay ports** (recommended for consumers)
2. **`add_subdirectory`** (recommended for hacking on the libraries in-tree)

## Option 1: Consume via vcpkg overlay ports

### Install

```sh
vcpkg install cosesign1-common --overlay-ports=native/vcpkg-ports
vcpkg install cosesign1-validation --overlay-ports=native/vcpkg-ports
vcpkg install cosesign1-x509 --overlay-ports=native/vcpkg-ports
vcpkg install cosesign1-mst --overlay-ports=native/vcpkg-ports
```

### CMake usage

```cmake
find_package(cosesign1_common CONFIG REQUIRED)
find_package(cosesign1_validation CONFIG REQUIRED)
# optional extras:
find_package(cosesign1_x509 CONFIG REQUIRED)
find_package(cosesign1_mst CONFIG REQUIRED)

add_executable(app main.cpp)

target_link_libraries(app PRIVATE
  cosesign1::cosesign1_common
  cosesign1::cosesign1_validation
  cosesign1::cosesign1_x509
  cosesign1::cosesign1_mst
)
```

### What you get

- Headers under `include/cosesign1/...`
- Imported targets with the `cosesign1::` namespace
- Transitive dependency linkage (OpenSSL, tinycbor, etc.)

## Option 2: Consume via `add_subdirectory`

If you’re working within this repo (or vendoring the source), you can add the project folders directly.

Example:

```cmake
add_subdirectory(native/cosesign1-common)
add_subdirectory(native/cosesign1-validation)
add_subdirectory(native/cosesign1-x509)
add_subdirectory(native/cosesign1-mst)

target_link_libraries(app PRIVATE
  cosesign1_common
  cosesign1_validation
  cosesign1_x509
  cosesign1_mst
)
```

Note: in this mode you link the *local* targets (`cosesign1_validation`, etc.) rather than the installed/imported ones.

## Header overview

- `cosesign1_common`
  - `cosesign1/common/cbor.h` (umbrella header)
  - `cosesign1/common/cose_sign1.h` (ParsedCoseSign1 + ParseCoseSign1)

- `cosesign1_validation`
  - `cosesign1/validation/cose_sign1_verifier.h`
  - `cosesign1/validation/cose_sign1_hash_message_verifier.h`
  - `cosesign1/validation/cose_sign1_validation_builder.h`

- `cosesign1_x509`
  - `cosesign1/x509/x5c_verifier.h`

- `cosesign1_mst`
  - `cosesign1/mst/mst_verifier.h`
  - `cosesign1/mst/jwk_ec_key.h` (umbrella header)

## Common integration pitfalls

- **Detached payloads**: COSE_Sign1 can have a `null` payload; you must provide external payload bytes.
- **Algorithm expectations**: `VerifyOptions::expected_alg` can be set to enforce the COSE `alg` header.
- **PQC**: ML-DSA verification requires `COSESIGN1_ENABLE_PQC` and liboqs.

## Hello world consumer app

See [Hello world (consumer app)](hello-world.md) for a buildable example that reads a COSE_Sign1 from disk and validates it using:

- a known public key / certificate (DER)
- `x5c` with certificate chain validation
- detached payload handling
- MST transparent statement receipt verification
