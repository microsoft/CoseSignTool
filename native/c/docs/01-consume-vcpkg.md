# Consume via vcpkg (C)

This projection ships as a single vcpkg port that installs headers + a CMake package.

## Install

Using the repo’s overlay port:

```powershell
vcpkg install cosesign1-validation-native[certificates,mst,akv,trust] --overlay-ports=<repo>/native/vcpkg_ports
```

Notes:

- Default features are `cpp` and `certificates`. If you’re consuming only the C projection, you can disable defaults:

```powershell
vcpkg install cosesign1-validation-native[certificates,mst,akv,trust] --no-default-features --overlay-ports=<repo>/native/vcpkg_ports
```

## CMake usage

```cmake
find_package(cose_sign1_validation CONFIG REQUIRED)

target_link_libraries(your_target PRIVATE cosesign1_validation_native::cose_sign1)
```

## Feature → header mapping

- `certificates` → `<cose/cose_certificates.h>` and `COSE_HAS_CERTIFICATES_PACK`
- `mst` → `<cose/cose_mst.h>` and `COSE_HAS_MST_PACK`
- `akv` → `<cose/cose_azure_key_vault.h>` and `COSE_HAS_AKV_PACK`
- `trust` → `<cose/cose_trust.h>` and `COSE_HAS_TRUST_PACK`

When consuming via vcpkg/CMake, the `COSE_HAS_*` macros are set for you based on enabled features.
