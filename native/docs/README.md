# Native docs

This folder contains end-user documentation for consuming the **native** verifier libraries.

The canonical, end-to-end Windows instructions (vcpkg overlay ports + CMake) live at:

- `native/docs/README.md` (this folder)

## Architecture and behavior

- Architecture overview: `architecture.md`
- Verification guide: `verification.md`
- Copy/paste snippets: `examples.md`
- Testing and coverage: `testing-and-coverage.md`
- Consuming via vcpkg (overlay ports + CMake): `consuming-with-vcpkg.md`

## Consumer apps (hello-world)

- C++: `hello-world/cpp/README.md`
- C: `hello-world/c/README.md`

## Quick start (vcpkg overlay ports)

From the repo root:

- `vcpkg install cosesign1-abstractions --overlay-ports=native/vcpkg-ports`
- `vcpkg install cosesign1 --overlay-ports=native/vcpkg-ports`
- `vcpkg install cosesign1-x509 --overlay-ports=native/vcpkg-ports`
- `vcpkg install cosesign1-mst --overlay-ports=native/vcpkg-ports`

Then in CMake:

```cmake
find_package(cosesign1_abstractions_ffi CONFIG REQUIRED)
find_package(cosesign1_validation CONFIG REQUIRED)
find_package(cosesign1_mst CONFIG REQUIRED)
find_package(cosesign1_x509 CONFIG REQUIRED)

target_link_libraries(your_target PRIVATE
  cosesign1::abstractions
  cosesign1::validation
  cosesign1::mst
  cosesign1::x509
)

For a step-by-step guide (manifest mode vs classic mode, overlay ports, and CMake toolchain configuration), see `consuming-with-vcpkg.md`.
```
