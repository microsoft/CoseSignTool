# cosesign1-validation (C++)

A small, cross-platform C++ validation framework inspired by the V2 .NET validation pattern in this repo, plus a real COSE_Sign1 signature verifier.

## Build (vcpkg)

From this directory:

- Configure: `cmake --preset default-vcpkg`
- Build: `cmake --build --preset build-vcpkg`
- Test: `ctest --preset test-vcpkg`

Requirements:
- CMake 3.23+
- Ninja (recommended)
- vcpkg with `VCPKG_ROOT` set

## What’s included

- V2-like `ValidationResult` / `ValidationFailure`
- `CoseSign1ValidationBuilder` that composes COSE validators (optionally parallel)
- COSE_Sign1 signature verifier
	- ECDSA: ES256 / ES384 / ES512
	- RSA: RS256 + PS256
	- Optional PQC: ML-DSA-44/65/87 when built with `COSESIGN1_ENABLE_PQC` + liboqs

## Notes

This project intentionally keeps dependencies small (OpenSSL + tinycbor + Catch2).
