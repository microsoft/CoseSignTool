<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# Testing and coverage (native)

## Running tests

The native C++ wrapper layer is validated via Catch2 tests under `native/cosesign1/tests`.

Typical flow:

- Configure the CMake project under `native/cosesign1`.
- Build the test target.
- Run `ctest`.

(Exact commands depend on your generator/toolset; see your existing native build setup.)

## Coverage (C++ wrappers)

Coverage is collected on Windows with **OpenCppCoverage** and exported as HTML.

From `native/cosesign1/tests/`:

- Run coverage (auto-install tool if missing):
  - `pwsh -NoProfile -File ./run_coverage.ps1 -AutoInstallTools`

Notes:

- If you prefer a pinned tool location, set `OPENCPPCOVERAGE_PATH` (or pass `-OpenCppCoveragePath`).
- HTML output is written under `native/cosesign1/tests/out-*/coverage/`.
