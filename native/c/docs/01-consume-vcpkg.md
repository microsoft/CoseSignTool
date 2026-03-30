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

- `certificates` → `<cose/sign1/extension_packs/certificates.h>` and `COSE_HAS_CERTIFICATES_PACK`
- `mst` → `<cose/sign1/extension_packs/mst.h>` and `COSE_HAS_MST_PACK`
- `akv` → `<cose/sign1/extension_packs/azure_key_vault.h>` and `COSE_HAS_AKV_PACK`
- `trust` → `<cose/sign1/trust.h>` and `COSE_HAS_TRUST_PACK`
- `signing` → `<cose/sign1/signing.h>` and `COSE_HAS_SIGNING`
- `primitives` → `<cose/sign1.h>` and `COSE_HAS_PRIMITIVES`
- `factories` → `<cose/sign1/signing.h>` and `COSE_HAS_FACTORIES`
- `crypto` → `<cose/crypto/cose_crypto.h>` and `COSE_HAS_CRYPTO_OPENSSL`
- `cbor-everparse` → `COSE_CBOR_EVERPARSE` (CBOR provider selection)

When consuming via vcpkg/CMake, the `COSE_HAS_*` macros are set for you based on enabled features.

## Provider Configuration

### Crypto Provider
The `crypto` feature enables OpenSSL-based cryptography support:
- Provides ECDSA signing and verification
- Supports ML-DSA (post-quantum) when available
- Required for signing operations via factories
- Sets `COSE_HAS_CRYPTO_OPENSSL` preprocessor define

### CBOR Provider
The `cbor-everparse` feature selects the EverParse CBOR parser (formally verified):
- Sets `COSE_CBOR_EVERPARSE` preprocessor define
- Default and recommended CBOR provider

### Factory Feature
The `factories` feature enables COSE Sign1 message construction:
- Requires `signing` and `crypto` features
- Provides high-level signing APIs
- Sets `COSE_HAS_FACTORIES` preprocessor define
- Example: `cose_sign1_factory_from_crypto_signer()`
