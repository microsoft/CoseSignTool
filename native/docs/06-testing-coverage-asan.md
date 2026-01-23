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
- runs [native/c/collect-coverage.ps1](../c/collect-coverage.ps1) (C projection)
- runs [native/c_pp/collect-coverage.ps1](../c_pp/collect-coverage.ps1) (C++ projection)
- fails if either projection is < 95% **union** line coverage

Runner script: [native/collect-coverage-asan.ps1](../collect-coverage-asan.ps1)

It also builds any Rust dependencies that compile native C/C++ code with ASAN enabled (e.g., PQClean-backed PQC implementations used by feature-gated crates).

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

If tests fail to start with `0xc0000135` (or you see modal “missing DLL” popups), ASAN runtime DLLs are not being found.

The scripts attempt to locate the Visual Studio ASAN runtime (e.g. `clang_rt.asan_dynamic-x86_64.dll`) and prepend its directory to `PATH` before running tests.

If that detection fails:

- ensure Visual Studio 2022 is installed with the C++ workload, or
- manually add the VS ASAN runtime directory to `PATH`.

### Coverage is 0%

Ensure the OpenCppCoverage command is invoked with child-process coverage enabled (CTest spawns test processes). The scripts already pass `--cover_children`.
