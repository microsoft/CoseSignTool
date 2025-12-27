<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# Verifying COSE_Sign1 in C/C++

This page focuses on the **native** (C and C++) consumption surface.

For full build instructions on Windows via vcpkg overlay ports, see `native/docs/README.md`.

## C++: basic signature verification

In C++, the recommended entry point is the header-only wrapper:

```cpp
#include <cosesign1/cosesign1.hpp>

#include <cstdint>
#include <vector>

bool verify_signature(const std::vector<std::uint8_t>& cose,
                      const std::vector<std::uint8_t>& public_key_der)
{
    auto msg = cosesign1::CoseSign1::from_bytes(cose);
    const auto res = msg.verify_signature(/*payload*/ nullptr, &public_key_der);
    return res.ok();
}
```

`public_key_der` should typically be **DER SubjectPublicKeyInfo (SPKI)**.

## Detached payload

If the COSE payload is detached (payload is `null`), pass an external payload byte buffer:

```cpp
auto msg = cosesign1::CoseSign1::from_bytes(cose);
if (msg.is_detached_payload()) {
    // Provide the detached payload bytes.
    const auto res = msg.verify_signature(&payload, &public_key_der);
    return res.ok();
}
```

## C++: x5c + X.509 chain trust

If the message includes an `x5c` chain, you can verify the signature and then enforce X.509 trust.

Notes:

- `x5c` (label 33) may be encoded as either a single CBOR `bstr` (one certificate) or an array of `bstr` values (certificate chain). The native verifier accepts both forms.

```cpp
#include <cosesign1/cosesign1.hpp>

cosesign1::X509ChainOptions opt;
opt.trust_mode = 0; // system
opt.revocation_mode = 0; // no-check
opt.allow_untrusted_roots = false;

std::vector<std::vector<std::uint8_t>> roots; // only used for custom trust

const auto settings = cosesign1::VerificationSettings::Default()
    .with_x5c_chain_validation_options(opt, std::move(roots));

auto msg = cosesign1::CoseSign1::from_bytes(cose);
const auto res = msg.verify(/*payload*/ nullptr, /*public_key*/ nullptr, settings);
```

Notes:

- Passing `public_key == nullptr` allows an `x5c` provider to supply the signing key.
- For custom trust, pass the root(s) as DER certificates.

## C++: MST receipt verification

For MST-only verification you typically disable COSE signature verification and enable MST validation.

```cpp
#include <cosesign1/cosesign1.hpp>

cosesign1::KeyStore store;
store.AddIssuerJwks("issuer.example", jwks_json_bytes);

std::vector<std::string> authorized_domains = {"issuer.example"};

auto msg = cosesign1::CoseSign1::from_bytes(statement_cose);
const auto settings = cosesign1::VerificationSettings::Default()
    .without_cose_signature()
    .with_mst_validation_options(
        store,
        authorized_domains,
        cosesign1::AuthorizedReceiptBehavior::VerifyAnyMatching,
        cosesign1::UnauthorizedReceiptBehavior::VerifyAll);

const auto res = msg.verify(/*payload*/ nullptr, /*public_key*/ nullptr, settings);
```

## C: basic signature verification

The C ABI exposes “verify and return a result object” APIs.

```c
#include <stdint.h>
#include <stdlib.h>

#include "cosesign1/cosesign1.h"

// cose/cose_len: COSE_Sign1 bytes
// payload/payload_len: optional detached payload bytes (or NULL, 0)
// public_key/public_key_len: DER SPKI or other encodings supported by the alg

cosesign1_validation_result* res = cosesign1_validation_verify_signature(
    cose, cose_len,
    payload, payload_len,
    public_key, public_key_len);

const bool ok = cosesign1_validation_result_is_valid(res);
cosesign1_validation_result_free(res);
return ok ? 0 : 1;
```

For complete runnable programs (including argument parsing and file IO), see:

- `native/docs/hello-world/cpp`
- `native/docs/hello-world/c`
