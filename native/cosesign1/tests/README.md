# Native C++ header tests

This folder contains a small Catch2-based test target that exists primarily to exercise the inline code paths in `cosesign1.hpp`.

## Configure + build (Windows)

From this folder:

```powershell
# Note: This repo often has both VS 2022 and VS 2026 installed; vcpkg will pick the newest toolset.
# Use the VS 2026 generator here so the toolset matches and Catch2 links cleanly.

& "C:\\Program Files\\Microsoft Visual Studio\\18\\Enterprise\\Common7\\IDE\\CommonExtensions\\Microsoft\\CMake\\CMake\\bin\\cmake.exe" -S . -B out-vs18 -G "Visual Studio 18 2026" -A x64 -DCMAKE_TOOLCHAIN_FILE=$env:VCPKG_ROOT\\scripts\\buildsystems\\vcpkg.cmake
& "C:\\Program Files\\Microsoft Visual Studio\\18\\Enterprise\\Common7\\IDE\\CommonExtensions\\Microsoft\\CMake\\CMake\\bin\\cmake.exe" --build out-vs18 --config Release -j
```

## Run tests

```powershell
& "C:\\Program Files\\Microsoft Visual Studio\\18\\Enterprise\\Common7\\IDE\\CommonExtensions\\Microsoft\\CMake\\CMake\\bin\\ctest.exe" --test-dir out-vs18 -C Release --output-on-failure
```

## Coverage

On Windows/MSVC, line coverage for header-only code generally requires a separate coverage tool (e.g. OpenCppCoverage) or Visual Studio Enterprise coverage.

There is a helper script that runs tests under OpenCppCoverage and exports HTML:

```powershell
./run_coverage.ps1 -AutoInstallTools
```

If OpenCppCoverage is already installed but not on PATH, you can point the script at it:

```powershell
$env:OPENCPPCOVERAGE_PATH = "C:\\Program Files\\OpenCppCoverage\\OpenCppCoverage.exe"
./run_coverage.ps1
```
