# Native (C++ / vcpkg)

This folder contains cross-platform C++ implementations that mirror the V2 validation style.

Documentation: see `native/docs/README.md`.

## Packages (vcpkg overlay ports)

These are provided as **overlay ports** under `native/vcpkg-ports`:

- `cosesign1-signature`: base validation types + COSE_Sign1 signature verification
- `cosesign1-x509`: x5c/X.509-based helpers that depend on `cosesign1-signature`

### Install using overlay ports

From a shell where `VCPKG_ROOT` points at your vcpkg clone:

- Set overlay ports:
  - PowerShell: `setx VCPKG_OVERLAY_PORTS "c:\src\repos\CoseSignTool\native\vcpkg-ports"`
  - Or pass `--overlay-ports=<path>` directly to vcpkg

- Install:
  - `vcpkg install cosesign1-signature --overlay-ports=native/vcpkg-ports`
  - `vcpkg install cosesign1-x509 --overlay-ports=native/vcpkg-ports`

## Local development builds

Each project folder has a `vcpkg.json` and `CMakePresets.json` for manifest-mode development builds:

- `native/cosesign1-validation` (cosesign1-signature)
- `native/cosesign1-x509` (cosesign1-x509)
