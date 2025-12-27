<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# cosesign1_c_hello_world (consumer example)

This is the C equivalent of the C++ hello-world sample.

It shows how to consume the **C ABI** headers + static libraries produced from the Rust verifier crates.

## Build

For end-to-end setup (vcpkg overlay ports + MSVC generator details), follow `native/docs/README.md`.

Minimal PowerShell (from repo root):

```powershell
$env:VCPKG_OVERLAY_PORTS = "$PWD\native\vcpkg-ports"

cmake -S native\docs\hello-world\c -B out\build\native-hello-c `
  -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT\scripts\buildsystems\vcpkg.cmake" `
  -DVCPKG_OVERLAY_PORTS="$env:VCPKG_OVERLAY_PORTS" `
  -DVCPKG_INSTALLED_DIR="out\build\native-hello-c\vcpkg_installed" `
  -DVCPKG_TARGET_TRIPLET=x64-windows

cmake --build out\build\native-hello-c --config Release
```

## Run

`cosesign1_c_hello_world.exe <mode> [args...]`

Modes:

- `key` — verify a COSE_Sign1 using a known public key (DER SPKI or DER cert)
  - `key --cose <file> --public-key <der> [--payload <file>]`

- `x5c` — verify a COSE_Sign1 using embedded `x5c` and then enforce X.509 chain trust
  - `x5c --cose <file> [--payload <file>] --trust <system|custom> [--root <der>] [--revocation <online|offline|none>] [--allow-untrusted]`
  - `x5c` may be encoded as a single certificate (`bstr`) or a certificate chain (array of `bstr`). Both forms are accepted.

- `mst` — verify an MST transparent statement using an offline JWKS file
  - `mst --statement <file> --issuer-host <host> --jwks <file>`
