# Native C++ header tests

This folder contains a small Catch2-based test target that exists primarily to exercise the inline code paths in `cosesign1.hpp`.

## Configure + build (Windows)

From this folder:

```powershell
# Use CMake from PATH (or Visual Studio's CMake tools) and point it at vcpkg.

cmake -S . -B out-vs -A x64 -DCMAKE_TOOLCHAIN_FILE=$env:VCPKG_ROOT\\scripts\\buildsystems\\vcpkg.cmake
cmake --build out-vs --config Release -j
```

## Run tests

```powershell
ctest --test-dir out-vs -C Release --output-on-failure
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
