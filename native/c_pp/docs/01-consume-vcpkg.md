# Consume via vcpkg (C++)

The C++ projection is delivered by the same vcpkg port as the C projection.

## Install

```powershell
vcpkg install cosesign1-validation-native[cpp,certificates,mst,akv,trust,factories,crypto] --overlay-ports=<repo>/native/vcpkg_ports
```

Notes:

- Default features include `cpp`, `certificates`, `signing`, `primitives`, `mst`, `certificates-local`, `crypto`, and `factories`.

## CMake usage

```cmake
find_package(cose_sign1_validation CONFIG REQUIRED)

target_link_libraries(your_target PRIVATE cosesign1_validation_native::cose_sign1_cpp)
```

## Headers

- Convenience include-all: `<cose/cose.hpp>`
- Core API: `<cose/sign1/validation.hpp>`
- Optional packs (enabled by vcpkg features):
  - `<cose/sign1/extension_packs/certificates.hpp>` (`COSE_HAS_CERTIFICATES_PACK`)
  - `<cose/mst.hpp>` (`COSE_HAS_MST_PACK`)
  - `<cose/azure_key_vault.hpp>` (`COSE_HAS_AKV_PACK`)
  - `<cose/sign1/trust.hpp>` (`COSE_HAS_TRUST_PACK`)
- Signing and crypto:
  - `<cose/sign1/signing.hpp>` (`COSE_HAS_SIGNING`)
  - `<cose/crypto/openssl.hpp>` (`COSE_HAS_CRYPTO_OPENSSL`)

## Provider Configuration

### Crypto Provider
The `crypto` feature enables OpenSSL-based cryptography support:
- Provides ECDSA signing and verification  
- Supports ML-DSA (post-quantum) when available
- Required for signing operations via factories
- Sets `COSE_HAS_CRYPTO_OPENSSL` preprocessor define

Example usage:
```cpp
#ifdef COSE_HAS_CRYPTO_OPENSSL
auto signer = cose::CryptoProvider::New().SignerFromDer(private_key_der);
#endif
```

### CBOR Provider
The `cbor-everparse` feature selects the EverParse CBOR parser (formally verified):
- Sets `COSE_CBOR_EVERPARSE` preprocessor define
- Default and recommended CBOR provider

### Factory Feature
The `factories` feature enables COSE Sign1 message construction:
- Requires `signing` and `crypto` features
- Provides high-level signing APIs via `cose::SignatureFactory`
- Sets `COSE_HAS_FACTORIES` preprocessor define

Example usage:
```cpp
#if defined(COSE_HAS_FACTORIES) && defined(COSE_HAS_CRYPTO_OPENSSL)
auto signer = cose::CryptoProvider::New().SignerFromDer(key_der);
auto factory = cose::SignatureFactory::FromCryptoSigner(signer);
auto signed_bytes = factory.SignDirectBytes(payload.data(), payload.size(), "application/example");
#endif
```
