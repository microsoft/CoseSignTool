# Native C++ Libraries Documentation

This documentation covers the native (C++) COSE_Sign1-related libraries under `native/`.

## Navigation

- [Architecture](architecture.md)
- [Build](build.md)
- [Consuming the libraries](consuming.md)
- Verifiers
  - [Overview](verifiers/index.md)
  - [COSE_Sign1 signature verifier (`cosesign1_signature`)](verifiers/cose-sign1-signature.md)
  - [COSE Hash Envelope payload-hash verifier](verifiers/cose-hash-envelope.md)
  - [X.509 / `x5c` verifier (`cosesign1_x509`)](verifiers/x5c-x509.md)
  - [MST receipt verifier (`cosesign1_mst`)](verifiers/mst.md)

## Quick start

### Install via vcpkg overlay ports

From the repo root:

- `vcpkg install cosesign1-signature --overlay-ports=native/vcpkg-ports`
- `vcpkg install cosesign1-x509 --overlay-ports=native/vcpkg-ports`
- `vcpkg install cosesign1-mst --overlay-ports=native/vcpkg-ports`

Then in CMake:

```cmake
find_package(cosesign1_signature CONFIG REQUIRED)
find_package(cosesign1_x509 CONFIG REQUIRED)     # optional
find_package(cosesign1_mst CONFIG REQUIRED)      # optional

target_link_libraries(your_target PRIVATE
  cosesign1::cosesign1_signature
  cosesign1::cosesign1_x509
  cosesign1::cosesign1_mst
)
```

### Local build

Each project has `CMakePresets.json` and a `vcpkg.json` for manifest-mode builds:

- `native/cosesign1-validation` (package name `cosesign1_signature`)
- `native/cosesign1-x509` (package name `cosesign1_x509`)
- `native/cosesign1-mst` (package name `cosesign1_mst`)

See [Build](build.md) for end-to-end steps.
