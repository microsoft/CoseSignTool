# C projection

For the full C developer guide (including vcpkg consumption and trust plans), see `native/c/docs/README.md`.

## Audience

You want a stable C API you can call from C/C++ (or other languages that can call a C ABI).

## API surface

- Headers live in `native/c/include/cose/`.
- The core header is:
  - `<cose/cose_sign1.h>`
- Pack headers (optional):
  - `<cose/cose_certificates.h>`
  - `<cose/cose_mst.h>`
  - `<cose/cose_azure_key_vault.h>`
  - `<cose/cose_trust.h>`

When consuming via vcpkg, the correct pack macros are defined automatically.

## Quickstart (CMake + vcpkg)

1) Install:

```powershell
vcpkg install cosesign1-validation-native[certificates,mst,akv,trust] --overlay-ports=<repo>/native/vcpkg_ports
```

2) Link:

```cmake
find_package(cose_sign1_validation CONFIG REQUIRED)

target_link_libraries(your_target PRIVATE cosesign1_validation_native::cose_sign1)
```

## Error handling

- Most APIs return a status code.
- When a call fails, you can fetch a human-readable error message:

```c
char* msg = cose_last_error_message_utf8();
// use msg
cose_string_free(msg);
```

Always free returned strings with `cose_string_free`.

## Testing and examples

- Examples: `native/c/examples/`
- Tests: `native/c/tests/`

See [testing + ASAN + coverage](06-testing-coverage-asan.md).
