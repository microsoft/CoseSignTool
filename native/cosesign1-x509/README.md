# cosesign1-x509 (C++)

Helpers/validators for X.509-based COSE_Sign1 verification (x5c), designed to be used alongside `cosesign1-signature`.

## Build (vcpkg)

- Configure: `cmake --preset default-vcpkg`
- Build: `cmake --build --preset build-vcpkg`
- Test: `ctest --preset test-vcpkg`

(Requires `VCPKG_ROOT` set and an overlay ports path pointing at `native/vcpkg-ports`.)
