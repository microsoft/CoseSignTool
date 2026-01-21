# Testing, coverage, and ASAN (Windows)

This repo supports running native tests under MSVC AddressSanitizer (ASAN) and collecting line coverage on Windows using OpenCppCoverage.

## Prerequisites

- Visual Studio 2022 with C++ workload
- CMake + Ninja (or VS generator)
- Rust toolchain (for building the Rust FFI static libs)
- OpenCppCoverage

## One-command runner

From repo root:

```powershell
./native/collect-coverage-asan.ps1 -Configuration Debug -MinimumLineCoveragePercent 95
```

This:

- builds required Rust FFI crates
- runs `native/c/collect-coverage.ps1` (C projection)
- runs `native/c_pp/collect-coverage.ps1` (C++ projection)
- fails if either projection is < 95% **union** line coverage

## Why Debug?

For header-heavy C++ wrappers, Debug tends to produce more reliable line mapping for OpenCppCoverage than optimized configurations.

You still get ASAN’s memory checking in Debug.

## Coverage output

Each language script emits:

- HTML report
- Cobertura XML

The scripts compute a deduplicated union metric across all files by `(filename, lineNumber)` taking the maximum hit count.

## Common failures

### Missing ASAN runtime DLLs

If tests fail to start with `0xc0000135`, ASAN runtime DLLs are missing from the test folder. The native build scripts copy required runtime DLLs next to test executables.

### Coverage is 0%

Ensure the OpenCppCoverage command is invoked with child-process coverage enabled (CTest spawns test processes). The scripts already pass `--cover_children`.
