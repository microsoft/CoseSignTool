# Native (C ABI / vcpkg)

This folder contains Rust-backed native (C ABI) libraries plus vcpkg overlay ports.

Documentation: see `native/docs/README.md`.

## Packages (vcpkg overlay ports)

These are provided as **overlay ports** under `native/vcpkg-ports`:

- `cosesign1-common`: shared CBOR + COSE_Sign1 parsing primitives
- `cosesign1-validation`: base validation types + COSE_Sign1 signature verification
- `cosesign1-x509`: x5c/X.509-based helpers that depend on `cosesign1-validation`
- `cosesign1-mst`: Microsoft Signing Transparency (MST) receipt verification

### Install using overlay ports

From a shell where `VCPKG_ROOT` points at your vcpkg clone:

- Set overlay ports:
  - PowerShell: `setx VCPKG_OVERLAY_PORTS "c:\src\repos\CoseSignTool\native\vcpkg-ports"`
  - Or pass `--overlay-ports=<path>` directly to vcpkg

- Install:
  - `vcpkg install cosesign1-common --overlay-ports=native/vcpkg-ports`
  - `vcpkg install cosesign1-validation --overlay-ports=native/vcpkg-ports`
  - `vcpkg install cosesign1-x509 --overlay-ports=native/vcpkg-ports`
  - `vcpkg install cosesign1-mst --overlay-ports=native/vcpkg-ports`

## Local development builds

For local builds (without vcpkg), build the CMake backend in `native/shim` which drives Cargo and installs headers + static libraries.

Example:

- `cmake -S native/shim -B out/shim-build`
- `cmake --build out/shim-build --config Release`
- `cmake --install out/shim-build --config Release --prefix out/shim-install`
