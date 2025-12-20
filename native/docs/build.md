# Build

This repo supports **local development builds** (manifest-mode vcpkg + CMake presets) and **consumption builds** (overlay ports).

## Prerequisites

- CMake 3.23+
- A C++20 compiler
  - Windows: Visual Studio 2022
  - Linux/macOS: Clang or GCC (project is CMake-based)
- vcpkg (manifest mode)

## Option A: Build using project `CMakePresets.json`

Each library has a `vcpkg.json` and `CMakePresets.json` in its folder:

- `native/cosesign1-common` → builds `cosesign1_common`
- `native/cosesign1-validation` → builds `cosesign1_validation`
- `native/cosesign1-x509` → builds `cosesign1_x509`
- `native/cosesign1-mst` → builds `cosesign1_mst`

### Windows (Visual Studio generator)

From the repo root:

```powershell
# Validation/signature
cmake --preset vs2022 -S native/cosesign1-validation
cmake --build --preset vs2022-release -S native/cosesign1-validation
ctest --preset vs2022-release -S native/cosesign1-validation --output-on-failure

# X.509
cmake --preset vs2022 -S native/cosesign1-x509
cmake --build --preset vs2022-release -S native/cosesign1-x509
ctest --preset vs2022-release -S native/cosesign1-x509 --output-on-failure

# MST
cmake --preset vs2022 -S native/cosesign1-mst
cmake --build --preset vs2022-release -S native/cosesign1-mst
ctest --preset vs2022-release -S native/cosesign1-mst --output-on-failure
```

(Exact preset names may vary by environment; use `cmake --list-presets -S <dir>` to see what’s available.)

## Option B: Install via vcpkg overlay ports

The easiest way to consume these libraries from another project is via vcpkg overlay ports.

From the repo root:

```powershell
# Install overlay ports
vcpkg install cosesign1-common --overlay-ports=native/vcpkg-ports
vcpkg install cosesign1-validation --overlay-ports=native/vcpkg-ports
vcpkg install cosesign1-x509 --overlay-ports=native/vcpkg-ports
vcpkg install cosesign1-mst --overlay-ports=native/vcpkg-ports
```

## Coverage

On Windows, `native/collect-coverage.ps1` runs all native tests and enforces a minimum line coverage target:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\native\collect-coverage.ps1
```

Output artifacts are written under `native/coverage-report/`.

## Build options

### PQC support (liboqs)

`cosesign1_validation` defines `COSESIGN1_ENABLE_PQC`:

- Default: ON
- When ON: links `OQS::oqs` and enables ML-DSA verification logic.

Configure example:

```powershell
cmake -S native/cosesign1-validation -B native/cosesign1-validation/out/build/local -DCOSESIGN1_ENABLE_PQC=OFF
```
