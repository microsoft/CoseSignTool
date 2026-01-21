# Troubleshooting

## vcpkg can’t find the port

This repo ships an overlay port under `native/vcpkg_ports`.

Example:

```powershell
vcpkg install cosesign1-validation-native --overlay-ports=<repo>/native/vcpkg_ports
```

## Rust target mismatch

The vcpkg port maps the vcpkg triplet to a Rust target triple. If you use a custom triplet, ensure the port knows how to map it (see `native/vcpkg_ports/cosesign1-validation-native/portfile.cmake`).

## Linker errors about CRT mismatch

The port enforces static linkage on the vcpkg side. Ensure your consuming project uses a compatible runtime library selection.

## OpenCppCoverage not found

The coverage scripts try:

- `OPENCPPCOVERAGE_PATH`
- `OpenCppCoverage.exe` on `PATH`
- common install locations

Install via Chocolatey:

```powershell
choco install opencppcoverage
```
