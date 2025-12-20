# Hello world (consumer app)

This guide shows a small **buildable** C++20 app that consumes the native verifier packages.

It covers common real-world scenarios:

1. **Verify COSE_Sign1 with a known public key or certificate** (DER SPKI or DER X.509 certificate)
2. **Verify COSE_Sign1 using embedded `x5c`** and validate the certificate chain
3. **Detached payload** handling (COSE payload is `null`)
4. **MST transparent statement** verification (offline key store loaded from a JWKS file)

The sample app lives in `native/examples/cosesign1-hello-world`.

---

## 1) Install the packages (overlay ports)

From the repo root:

```powershell
vcpkg install cosesign1-common --overlay-ports=native/vcpkg-ports
vcpkg install cosesign1-validation --overlay-ports=native/vcpkg-ports
vcpkg install cosesign1-x509 --overlay-ports=native/vcpkg-ports
vcpkg install cosesign1-mst --overlay-ports=native/vcpkg-ports
```

Notes:

- vcpkg package names use hyphens (e.g., `cosesign1-validation`).
- CMake package names use underscores (e.g., `cosesign1_validation`).

---

## 2) Build the sample app

From the repo root (PowerShell):

```powershell
$env:VCPKG_ROOT = "C:\vcpkg" # adjust if different

cmake -S native/examples/cosesign1-hello-world -B native/examples/cosesign1-hello-world/out/build \
  -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT\scripts\buildsystems\vcpkg.cmake" \
  -DVCPKG_OVERLAY_PORTS="${PWD}\native\vcpkg-ports"

cmake --build native/examples/cosesign1-hello-world/out/build --config Release
```

---

## 3) Run: verify with a known public key or cert (DER)

### Scenario

You have a COSE_Sign1 blob on disk, and you also have one of:

- a DER-encoded **SubjectPublicKeyInfo** (SPKI), or
- a DER-encoded **X.509 certificate** containing the public key

### Command

```powershell
native/examples/cosesign1-hello-world/out/build/Release/cosesign1_hello_world.exe key \
  --cose path\to\message.cose \
  --public-key path\to\signer_public_key_or_cert.der \
  --expected-alg ES256
```

If the COSE payload is detached (`null`), you must also supply the payload bytes:

```powershell
native/examples/cosesign1-hello-world/out/build/Release/cosesign1_hello_world.exe key \
  --cose path\to\message.cose \
  --public-key path\to\signer_public_key_or_cert.der \
  --expected-alg ES256 \
  --payload path\to\detached_payload.bin
```

### What it does

- Parses COSE_Sign1 to detect whether the payload is detached.
- Calls `cosesign1::validation::VerifyCoseSign1(...)`.
- Prints `ValidationResult` including failures and metadata.

---

## 4) Run: verify using `x5c` + certificate chain validation

### Scenario

You have a COSE_Sign1 on disk that embeds an `x5c` header (label 33) containing the signer certificate chain.

### Command (system trust)

```powershell
native/examples/cosesign1-hello-world/out/build/Release/cosesign1_hello_world.exe x5c \
  --cose path\to\message.cose \
  --trust system \
  --revocation none \
  --expected-alg ES256
```

### Command (custom roots)

This is common for private PKI or pinned roots:

```powershell
native/examples/cosesign1-hello-world/out/build/Release/cosesign1_hello_world.exe x5c \
  --cose path\to\message.cose \
  --trust custom \
  --root path\to\trusted_root.der \
  --revocation none
```

### Notes on revocation

- `--revocation online` may perform network access on Windows (CryptoAPI chain revocation checks).
- For offline verification, use `--revocation none`.

---

## 5) Run: verify MST transparent statements (offline JWKS)

### Scenario

You have a **transparent statement** (a COSE_Sign1 wrapper that contains MST receipts) on disk. You also have a JWKS JSON document on disk containing issuer keys.

### Command

```powershell
native/examples/cosesign1-hello-world/out/build/Release/cosesign1_hello_world.exe mst \
  --statement path\to\transparent_statement.cose \
  --issuer-host example.com \
  --jwks path\to\issuer_jwks.json
```

### What it does

- Loads JWKS JSON using `cosesign1::mst::ParseJwks`.
- Populates `cosesign1::mst::OfflineEcKeyStore` via `AddIssuerKeys`.
- Calls `cosesign1::mst::VerifyTransparentStatement(...)`.

---

## 6) Where to look

- Sample code: `native/examples/cosesign1-hello-world/main.cpp`
- Build file: `native/examples/cosesign1-hello-world/CMakeLists.txt`
- Base verifier API: `cosesign1/validation/cose_sign1_verifier.h`
- x5c verifier API: `cosesign1/x509/x5c_verifier.h`
- MST verifier API: `cosesign1/mst/mst_verifier.h`
