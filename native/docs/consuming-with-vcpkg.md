<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# Consuming the native verifier via vcpkg

This repo publishes the native verifier as **vcpkg overlay ports** under:

- `native/vcpkg-ports`

A consumer project can use those ports in either:

- **Manifest mode** (recommended; dependencies are declared in `vcpkg.json`), or
- **Classic mode** (you run `vcpkg install ...` yourself)

The examples below assume Windows + MSVC, but the overall approach (overlay ports + vcpkg toolchain + `find_package`) is the same on other platforms.

## Option A (recommended): manifest mode in your consumer repo

### 1) Make the overlay ports available

You need a local path to the overlay ports directory.

Common options:

- Clone this repo somewhere on disk, or
- Add this repo as a git submodule in your consumer repo

Then pass the overlay ports path to vcpkg.

You can do that either by environment variable:

- PowerShell:
  - `$env:VCPKG_OVERLAY_PORTS = "<path-to-CoseSignTool>\native\vcpkg-ports"`

Or by a CMake cache variable on configure:

- `-DVCPKG_OVERLAY_PORTS="<path-to-CoseSignTool>\native\vcpkg-ports"`

Notes:

- If you already use other overlays, `VCPKG_OVERLAY_PORTS` can be a list (separator is `;` on Windows).
- Avoid hardcoding absolute paths in scripts; prefer a repo-relative path (for example: a submodule).

### 2) Add a `vcpkg.json` to your consumer repo

In your consumer repo root, add a `vcpkg.json` similar to:

```json
{
  "name": "my-app",
  "version-string": "0.0.0",
  "dependencies": [
    "cosesign1",
    "cosesign1-x509",
    "cosesign1-mst"
  ]
}
```

If you only need signature verification (no X.509 or MST), depend on just:

- `cosesign1`

### 3) Configure your CMake project to use the vcpkg toolchain

Configure with the vcpkg toolchain file and (optionally) a per-build installed directory:

PowerShell example:

```powershell
cmake -S . -B out\build `
  -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT\scripts\buildsystems\vcpkg.cmake" `
  -DVCPKG_OVERLAY_PORTS="<path-to-CoseSignTool>\native\vcpkg-ports" `
  -DVCPKG_INSTALLED_DIR="out\build\vcpkg_installed" `
  -DVCPKG_TARGET_TRIPLET=x64-windows

cmake --build out\build --config Release
```

Notes:

- `VCPKG_INSTALLED_DIR` is optional, but it keeps dependencies scoped to your build directory (helpful for CI and for avoiding global state).
- If you are using a Visual Studio generator, add `-A x64` (or set an appropriate CMake preset).

### 4) Link from CMake

In your `CMakeLists.txt`:

```cmake
find_package(cosesign1_abstractions_ffi CONFIG REQUIRED)
find_package(cosesign1_validation CONFIG REQUIRED)
find_package(cosesign1_mst CONFIG REQUIRED)
find_package(cosesign1_x509 CONFIG REQUIRED)

target_link_libraries(your_target PRIVATE
  cosesign1::abstractions
  cosesign1::validation
  cosesign1::mst
  cosesign1::x509
)
```

If you only depend on `cosesign1`, you typically need only:

```cmake
find_package(cosesign1_validation CONFIG REQUIRED)

target_link_libraries(your_target PRIVATE
  cosesign1::validation
)
```

## Option B: classic mode (manual `vcpkg install`)

If you prefer to install packages into an existing vcpkg instance:

- Install using the overlay ports:
  - `vcpkg install cosesign1 --overlay-ports=<path-to-CoseSignTool>\native\vcpkg-ports --triplet x64-windows`

Then configure your consumer project with the vcpkg toolchain file:

- `-DCMAKE_TOOLCHAIN_FILE=<path-to-vcpkg>\scripts\buildsystems\vcpkg.cmake`

## Working examples

The runnable consumer apps in this repo show end-to-end usage:

- C++ hello-world: `native/docs/hello-world/cpp`
- C hello-world: `native/docs/hello-world/c`
