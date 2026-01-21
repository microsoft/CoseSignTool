# vcpkg: single-port native consumption

## The port

- vcpkg port name: `cosesign1-validation-native`
- CMake package name: `cose_sign1_validation`
- CMake targets:
  - `cosesign1_validation_native::cose_sign1` (C)
  - `cosesign1_validation_native::cose_sign1_cpp` (C++) when feature `cpp` is enabled

The port is implemented as an **overlay port** in this repo at:

- `native/vcpkg_ports/cosesign1-validation-native/`

## Features (configuration options)

Feature | Purpose | C compile define
---|---|---
`cpp` | Install C++ projection headers + CMake target | (n/a)
`certificates` | Enable X.509 pack | `COSE_HAS_CERTIFICATES_PACK`
`mst` | Enable MST pack | `COSE_HAS_MST_PACK`
`akv` | Enable AKV pack | `COSE_HAS_AKV_PACK`
`trust` | Enable trust-policy/trust-plan pack | `COSE_HAS_TRUST_PACK`

Defaults: `cpp, certificates`.

## Install with overlay ports

Assuming you have a vcpkg checkout at `C:\vcpkg` and this repo at `C:\src\repos\CoseSignTool`:

```powershell
C:\vcpkg\vcpkg install cosesign1-validation-native[cpp,certificates,mst,akv,trust] --overlay-ports=C:\src\repos\CoseSignTool\native\vcpkg_ports
```

Notes:

- The port runs `cargo build` internally. Ensure Rust is installed and on PATH.
- The port is **static-only** (it installs static libraries).

## Use from CMake (toolchain)

Configure your project with the vcpkg toolchain file:

```powershell
cmake -S . -B out -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake
```

In your `CMakeLists.txt`:

```cmake
find_package(cose_sign1_validation CONFIG REQUIRED)

# C API
target_link_libraries(your_target PRIVATE cosesign1_validation_native::cose_sign1)

# C++ API (requires feature "cpp")
target_link_libraries(your_cpp_target PRIVATE cosesign1_validation_native::cose_sign1_cpp)
```

The port’s config file also links required platform libs (e.g., Windows system libs) for the C target.

## What gets installed

- C headers under `include/cose/…`
- C++ headers under `include/cose/…` (when `cpp` is enabled)
- Rust FFI static libraries under `lib/` and `debug/lib/`

## Development workflow tips

- If you’re iterating on the port, prefer `--editable` workflows by pointing vcpkg at this repo and using overlay ports.
- If a vcpkg install seems stale, use:

```powershell
C:\vcpkg\vcpkg remove cosesign1-validation-native
```

or bump the port version for internal testing.
