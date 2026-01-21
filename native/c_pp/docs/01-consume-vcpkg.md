# Consume via vcpkg (C++)

The C++ projection is delivered by the same vcpkg port as the C projection.

## Install

```powershell
vcpkg install cosesign1-validation-native[cpp,certificates,mst,akv,trust] --overlay-ports=<repo>/native/vcpkg_ports
```

Notes:

- Default features are `cpp` and `certificates`.

## CMake usage

```cmake
find_package(cose_sign1_validation CONFIG REQUIRED)

target_link_libraries(your_target PRIVATE cosesign1_validation_native::cose_sign1_cpp)
```

## Headers

- Convenience include-all: `<cose/cose.hpp>`
- Core API: `<cose/validator.hpp>`
- Optional packs (enabled by vcpkg features):
  - `<cose/certificates.hpp>` (`COSE_HAS_CERTIFICATES_PACK`)
  - `<cose/mst.hpp>` (`COSE_HAS_MST_PACK`)
  - `<cose/azure_key_vault.hpp>` (`COSE_HAS_AKV_PACK`)
  - `<cose/trust.hpp>` (`COSE_HAS_TRUST_PACK`)
