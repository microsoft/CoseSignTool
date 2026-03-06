# COSE Sign1 C++ API

Modern C++17 RAII projection for the COSE Sign1 SDK. Every header wraps the
corresponding C header with move-only classes, fluent builders, and exception-based
error handling.

## Prerequisites

| Tool | Version |
|------|---------|
| CMake | 3.20+ |
| C++ compiler | C++17 (MSVC 2017+, GCC 7+, Clang 5+) |
| Rust toolchain | stable (builds the FFI libraries) |

## Building

### 1. Build the Rust FFI libraries

```bash
cd native/rust
cargo build --release --workspace
```

### 2. Configure and build the C++ projection

```bash
cd native/c_pp
mkdir build && cd build
cmake .. -DBUILD_TESTING=ON
cmake --build . --config Release
```

### 3. Run tests

```bash
ctest -C Release
```

## Header Reference

| Header | Purpose |
|--------|---------|
| `<cose/cose.hpp>` | Umbrella — conditionally includes everything |
| `<cose/sign1.hpp>` | `CoseSign1Message`, `CoseHeaderMap` |
| `<cose/sign1/validation.hpp>` | `ValidatorBuilder`, `Validator`, `ValidationResult` |
| `<cose/sign1/trust.hpp>` | `TrustPlanBuilder`, `TrustPolicyBuilder` |
| `<cose/sign1/signing.hpp>` | `CoseSign1Builder`, `SigningService`, `SignatureFactory` |
| `<cose/sign1/factories.hpp>` | Factory multi-wrapper |
| `<cose/sign1/cwt.hpp>` | `CwtClaims` fluent builder / serializer |
| `<cose/sign1/extension_packs/certificates.hpp>` | X.509 certificate trust pack |
| `<cose/sign1/extension_packs/certificates_local.hpp>` | Ephemeral certificate generation |
| `<cose/sign1/extension_packs/azure_key_vault.hpp>` | Azure Key Vault trust pack |
| `<cose/sign1/extension_packs/mst.hpp>` | Microsoft Transparency trust pack |
| `<cose/crypto/openssl.hpp>` | `CryptoProvider`, `CryptoSigner`, `CryptoVerifier` |
| `<cose/did/x509.hpp>` | `ParsedDid`, DID:x509 free functions |

All types live in the `cose::sign1` namespace (or `cose::crypto`, `cose::did` where noted).
The umbrella header `<cose/cose.hpp>` imports `cose::sign1` into `cose::`, so you can use
the shorter `cose::ValidatorBuilder` form when including it.

## Validation Example

```cpp
#include <cose/cose.hpp>

#include <cstdint>
#include <iostream>
#include <vector>

int main() {
    try {
        // 1 — Create builder and register packs
        cose::ValidatorBuilder builder;
        cose::WithCertificates(builder);

        // 2 — Author a trust policy
        cose::TrustPolicyBuilder policy(builder);

        // Message-scope rules (methods on TrustPolicyBuilder chain fluently)
        policy
            .RequireContentTypeNonEmpty()
            .And()
            .RequireDetachedPayloadAbsent()
            .And()
            .RequireCwtClaimsPresent();

        // Pack-specific rules (free functions that also return TrustPolicyBuilder&)
        cose::RequireX509ChainTrusted(policy);
        policy.And();
        cose::RequireSigningCertificatePresent(policy);
        policy.And();
        cose::RequireSigningCertificateThumbprintPresent(policy);

        // 3 — Compile and attach
        auto plan = policy.Compile();
        cose::WithCompiledTrustPlan(builder, plan);

        // 4 — Build validator
        auto validator = builder.Build();

        // 5 — Validate
        std::vector<uint8_t> cose_bytes = /* ... */ {};
        auto result = validator.Validate(cose_bytes);

        if (result.Ok()) {
            std::cout << "Validation successful\n";
        } else {
            std::cout << "Validation failed: "
                      << result.FailureMessage() << "\n";
        }
    } catch (const cose::cose_error& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
```

## Signing Example

```cpp
#include <cose/sign1/signing.hpp>
#include <cose/crypto/openssl.hpp>

#include <cstdint>
#include <iostream>
#include <vector>

int main() {
    try {
        // Create a signer from a DER-encoded private key
        auto signer = cose::crypto::OpenSslSigner::FromDer(
            private_key_der.data(), private_key_der.size());

        // Create a factory wired to the signer
        auto factory = cose::sign1::SignatureFactory::FromCryptoSigner(signer);

        // Sign a payload directly
        auto signed_bytes = factory.SignDirectBytes(
            payload.data(),
            static_cast<uint32_t>(payload.size()),
            "application/example");

        std::cout << "Signed " << signed_bytes.size() << " bytes\n";
    } catch (const cose::cose_error& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
```

## CWT Claims Example

```cpp
#include <cose/sign1/cwt.hpp>

#include <cstdint>
#include <iostream>
#include <vector>

int main() {
    try {
        auto claims = cose::sign1::CwtClaims::New()
            .SetIssuer("did:x509:abc123")
            .SetSubject("my-artifact");

        // Serialize to CBOR for use as a protected header
        std::vector<uint8_t> cbor = claims.ToCbor();
        std::cout << "CWT claims: " << cbor.size() << " bytes of CBOR\n";
    } catch (const cose::cose_error& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
```

## Message Parsing Example

```cpp
#include <cose/sign1.hpp>

#include <iostream>
#include <optional>
#include <vector>

int main() {
    try {
        std::vector<uint8_t> raw = /* read from file */ {};
        auto msg = cose::sign1::CoseSign1Message::FromBytes(raw);

        std::cout << "Algorithm: " << msg.Algorithm() << "\n";

        auto ct = msg.ContentType();
        if (ct) {
            std::cout << "Content-Type: " << *ct << "\n";
        }

        auto payload = msg.Payload();
        std::cout << "Payload size: " << payload.size() << " bytes\n";
    } catch (const cose::cose_error& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
```

## RAII Design Principles

- All wrapper classes are **move-only** (copy ctor/assignment deleted).
- Destructors call the corresponding C `*_free()` function automatically.
- Factory methods are `static` and throw `cose::cose_error` on failure.
- `native_handle()` gives access to the underlying C handle for interop.
- Headers are **header-only** — no separate `.cpp` compilation needed.

## Exception Handling

Errors are reported via `cose::cose_error` (inherits `std::runtime_error`).
The exception message is populated from the FFI thread-local error string.

```cpp
try {
    auto validator = builder.Build();
} catch (const cose::cose_error& e) {
    // e.what() contains the detailed FFI error message
    std::cerr << e.what() << "\n";
}
```

## Feature Defines

CMake sets these automatically when the corresponding FFI library is found:

| Define | Set When |
|--------|----------|
| `COSE_HAS_CERTIFICATES_PACK` | certificates FFI lib found |
| `COSE_HAS_MST_PACK` | MST FFI lib found |
| `COSE_HAS_AKV_PACK` | AKV FFI lib found |
| `COSE_HAS_TRUST_PACK` | trust FFI lib found |
| `COSE_HAS_PRIMITIVES` | primitives FFI lib found |
| `COSE_HAS_SIGNING` | signing FFI lib found |
| `COSE_HAS_FACTORIES` | factories FFI lib found |
| `COSE_HAS_CWT_HEADERS` | headers FFI lib found |
| `COSE_HAS_DID_X509` | DID:x509 FFI lib found |
| `COSE_CRYPTO_OPENSSL` | OpenSSL crypto provider selected |
| `COSE_CBOR_EVERPARSE` | EverParse CBOR provider selected |

The umbrella header `<cose/cose.hpp>` uses these defines to conditionally include
pack headers, so including it gives you everything that was linked.

## Composable Pack Registration

Extension packs are registered on a `ValidatorBuilder` via free functions in each pack
header. These compose freely — register as many packs as you need on a single builder:

```cpp
cose::ValidatorBuilder builder;

// Register multiple packs on the same builder
cose::WithCertificates(builder);                       // default options

cose::MstOptions mst_opts;
mst_opts.allow_network = false;
mst_opts.offline_jwks_json = jwks_str;
cose::WithMst(builder, mst_opts);                      // custom options

cose::WithAzureKeyVault(builder);                      // default options

// Then author policies referencing facts from ANY registered pack
cose::TrustPolicyBuilder policy(builder);
cose::RequireX509ChainTrusted(policy);
policy.And();
cose::RequireMstReceiptTrusted(policy);

auto plan = policy.Compile();
cose::WithCompiledTrustPlan(builder, plan);
auto validator = builder.Build();
```

Each `With*` function has two overloads:
- Default options: `WithCertificates(builder)`
- Custom options: `WithCertificates(builder, opts)` where `opts` is a C++ options struct
  (`CertificateOptions`, `MstOptions`, `AzureKeyVaultOptions`)

## Coverage (Windows)

```powershell
./collect-coverage.ps1 -Configuration Debug -MinimumLineCoveragePercent 95
```

Outputs HTML to [native/c_pp/coverage/index.html](coverage/index.html).
