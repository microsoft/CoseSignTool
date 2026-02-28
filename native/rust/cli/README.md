# cose_sign1_cli

Command-line tool for signing, verifying, and inspecting COSE_Sign1 messages.

## Feature Flags

The CLI tool uses compile-time feature selection for cryptographic providers and extension packs:

| Feature | Default | Description |
|---------|---------|-------------|
| `crypto-openssl` | ✓ | OpenSSL cryptographic backend (ECDSA, RSA, EdDSA) |
| `certificates` | ✓ | X.509 certificate chain validation |
| `mst` | ✓ | Microsoft Transparency receipt verification |
| `akv` | ✗ | Azure Key Vault signing and validation |
| `ats` | ✗ | Azure Trusted Signing integration |

## Signing Providers

All signing providers are available through the `--provider` flag on the `sign` command:

| Provider | `--provider` | Feature | CLI Flags | V2 C# Equivalent |
|----------|-------------|---------|-----------|-------------------|
| DER key | `der` | `crypto-openssl` | `--key key.der` | (base) |
| PFX/PKCS#12 | `pfx` | `crypto-openssl` | `--pfx cert.pfx [--pfx-password ...]` | `x509-pfx` |
| PEM files | `pem` | `crypto-openssl` | `--cert-file cert.pem --key-file key.pem` | `x509-pem` |
| Ephemeral | `ephemeral` | `certificates` | `[--subject CN=Test]` | `x509-ephemeral` |
| AKV certificate | `akv-cert` | `akv` | `--vault-url ... --cert-name ...` | `x509-akv-cert` |
| AKV key | `akv-key` | `akv` | `--vault-url ... --key-name ...` | `akv-key` |
| ATS | `ats` | `ats` | `--ats-endpoint ... --ats-account ... --ats-profile ...` | `x509-ats` |

## Verification Providers

Verification providers contribute trust packs to the validator automatically when their features are enabled:

| Provider | Feature | CLI Flags | V2 C# Equivalent |
|----------|---------|-----------|-------------------|
| X.509 Certificates | `certificates` | `--trust-root`, `--allow-embedded`, `--allowed-thumbprint` | `X509` |
| MST Receipts | `mst` | `--require-mst-receipt`, `--mst-offline-keys`, `--mst-ledger-instance` | `MST` |
| AKV KID | `akv` | `--require-akv-kid`, `--akv-allowed-vault` | `AzureKeyVault` |

## Build Examples

```bash
# Minimal (DER signing + cert verification only)
cargo build -p cose_sign1_cli --features crypto-openssl,certificates

# Full (all providers)
cargo build -p cose_sign1_cli --all-features

# Cloud signing (AKV + ATS)
cargo build -p cose_sign1_cli --features crypto-openssl,akv,ats

# Default build (OpenSSL + certificates + MST)
cargo build -p cose_sign1_cli

# Release build for distribution
cargo build -p cose_sign1_cli --release
```

## Commands

### `sign` — Create COSE_Sign1 Messages

Creates a COSE_Sign1 message from a payload file and signing key.

#### Common Flags
- `--input` / `-i <PATH>`: Path to payload file
- `--output` / `-o <PATH>`: Path to write COSE_Sign1 message
- `--provider <PROVIDER>`: Signing provider (default: "der")
- `--content-type` / `-c <TYPE>`: Content type string (default: "application/octet-stream")
- `--format <FORMAT>`: Signature format: `direct` or `indirect` (default: "direct")
- `--detached`: Create detached signature (payload not embedded)
- `--issuer <ISSUER>`: CWT issuer claim (did:x509:... recommended)
- `--cwt-subject <SUBJECT>`: CWT subject claim
- `--output-format <FORMAT>`: Output format: `text`, `json`, or `quiet` (default: "text")
- `--add-mst-receipt`: Add MST transparency receipt after signing (requires: mst)
- `--mst-endpoint <URL>`: MST service endpoint URL (optional, defaults to public MST service)

#### Signing Provider Examples

**DER Key Provider (`--provider der`)**
```bash
# Basic signing with DER private key
cosesigntool sign --input payload.bin --output signed.cose --provider der --key private.der

# With content type and CWT claims
cosesigntool sign --input payload.bin --output signed.cose --provider der --key private.der \
  --content-type "application/spdx+json" --issuer "did:x509:example" --cwt-subject "my-artifact"
```

**PFX/PKCS#12 Provider (`--provider pfx`)**
```bash
# Sign with PFX certificate file
cosesigntool sign --input payload.bin --output signed.cose --provider pfx --pfx cert.pfx

# With password
cosesigntool sign --input payload.bin --output signed.cose --provider pfx \
  --pfx cert.pfx --pfx-password mypassword
```

**PEM Provider (`--provider pem`)**
```bash
# Sign with separate PEM certificate and key files
cosesigntool sign --input payload.bin --output signed.cose --provider pem \
  --cert-file cert.pem --key-file key.pem
```

**Ephemeral Provider (`--provider ephemeral`)**
```bash
# Generate ephemeral certificate for testing (requires: certificates)
cosesigntool sign --input payload.bin --output signed.cose --provider ephemeral \
  --subject "CN=Test Certificate"

# Minimal ephemeral cert
cosesigntool sign --input payload.bin --output signed.cose --provider ephemeral
```

**AKV Certificate Provider (`--provider akv-cert`)**
```bash
# Sign with AKV certificate (requires: akv)
cosesigntool sign --input payload.bin --output signed.cose --provider akv-cert \
  --vault-url "https://myvault.vault.azure.net" --cert-name "my-cert"
```

**AKV Key Provider (`--provider akv-key`)**
```bash
# Sign with AKV key only (kid header, no certificate) (requires: akv)
cosesigntool sign --input payload.bin --output signed.cose --provider akv-key \
  --vault-url "https://myvault.vault.azure.net" --key-name "my-key"
```

**ATS Provider (`--provider ats`)**
```bash
# Sign with Azure Trusted Signing (requires: ats)
cosesigntool sign --input payload.bin --output signed.cose --provider ats \
  --ats-endpoint "https://northcentralus.codesigning.azure.net" \
  --ats-account "MyAccount" --ats-profile "MyProfile"
```

### `verify` — Validate COSE_Sign1 Messages

Validates a COSE_Sign1 message using configurable trust policies.

#### Flags
- `--input` / `-i <PATH>`: Path to COSE_Sign1 message file
- `--payload` / `-p <PATH>`: Path to detached payload (if signature is detached)
- `--trust-root <PATH>`: Path to trusted root certificate DER file (can specify multiple)
- `--allow-embedded`: Allow embedded certificate chain as trusted (testing only)
- `--require-content-type`: Require content-type header to be present
- `--content-type <TYPE>`: Required content-type value (implies --require-content-type)
- `--require-cwt`: Require CWT claims header to be present
- `--require-issuer <ISSUER>`: Required CWT issuer value
- `--require-mst-receipt`: Require MST receipt to be present (requires: mst)
- `--mst-offline-keys <JSON>`: MST offline JWKS JSON for receipt verification (requires: mst)
- `--mst-ledger-instance <ID>`: Allowed MST ledger instance ID (requires: mst)
- `--require-akv-kid`: Require Azure Key Vault kid header (requires: akv)
- `--akv-allowed-vault <PATTERN>`: Allowed AKV vault URL patterns (requires: akv)
- `--allowed-thumbprint <HEX>`: Allowed certificate thumbprints for identity pinning (can specify multiple)
- `--output-format <FORMAT>`: Output format: `text`, `json`, or `quiet` (default: "text")

#### Examples

**Basic Certificate Verification**
```bash
# Verify with embedded certificate chain (testing)
cosesigntool verify --input signed.cose --allow-embedded

# Verify detached signature with trust roots
cosesigntool verify --input detached.cose --payload payload.bin \
  --trust-root ca-root.der --trust-root intermediate.der

# Verify with identity pinning
cosesigntool verify --input signed.cose --allow-embedded \
  --allowed-thumbprint abc123def456 --allowed-thumbprint fed654cba321
```

**Policy-Based Verification**
```bash
# Verify with content type and issuer requirements
cosesigntool verify --input signed.cose --allow-embedded \
  --require-content-type --content-type "application/spdx+json" \
  --require-issuer "did:x509:example"

# Verify with CWT claims
cosesigntool verify --input signed.cose --allow-embedded \
  --require-cwt --require-issuer "did:x509:cert:sha256:abc123..."
```

**MST Receipt Verification (requires: mst)**
```bash
# Verify MST transparency receipt
cosesigntool verify --input mst-signed.cose --allow-embedded --require-mst-receipt

# Verify with offline JWKS
cosesigntool verify --input mst-signed.cose --allow-embedded --require-mst-receipt \
  --mst-offline-keys '{"keys":[...]}'

# Verify specific ledger instance
cosesigntool verify --input mst-signed.cose --allow-embedded --require-mst-receipt \
  --mst-ledger-instance "my-ledger-id"
```

**AKV Verification (requires: akv)**
```bash
# Verify AKV kid header
cosesigntool verify --input signed.cose --require-akv-kid

# Verify with vault restrictions
cosesigntool verify --input signed.cose --require-akv-kid \
  --akv-allowed-vault "https://myvault.vault.azure.net/keys/*" \
  --akv-allowed-vault "https://*.managedhsm.azure.net/keys/*"
```

### `inspect` — Parse and Display Structure

Parse and display COSE_Sign1 message structure without validation.

#### Flags
- `--input` / `-i <PATH>`: Path to COSE_Sign1 message file
- `--output-format <FORMAT>`: Output format: `text`, `json`, or `quiet` (default: "text")
- `--all-headers`: Show all header entries (not just standard ones)
- `--show-certs`: Show certificate chain details (if x5chain present, requires: certificates)
- `--show-signature`: Show raw hex of signature bytes
- `--show-cwt`: Show CWT claims (if present in header label 15)

#### Examples
```bash
# Basic inspection
cosesigntool inspect --input signed.cose

# Detailed inspection with all information
cosesigntool inspect --input signed.cose --all-headers --show-certs --show-cwt --show-signature

# JSON output for programmatic consumption
cosesigntool inspect --input signed.cose --output-format json
```

## Global Options

- `-v`, `-vv`, `-vvv`: Increase verbosity (warn → info → debug → trace)

## Key Formats and Algorithms

### Private Key Format
- **DER provider**: PKCS#8 DER-encoded private key files
- **PFX provider**: PKCS#12 certificate files with embedded private keys
- **PEM provider**: PEM-encoded private key files
- **Conversion from PEM to DER**:
  ```bash
  openssl pkcs8 -in private.pem -out private.der -outform DER -nocrypt
  ```

### Supported Algorithms
| Algorithm | COSE Value | Description |
|-----------|------------|-------------|
| ES256 | -7 | ECDSA P-256 + SHA-256 |
| ES384 | -35 | ECDSA P-384 + SHA-384 |
| ES512 | -36 | ECDSA P-521 + SHA-512 |
| EdDSA | -8 | Ed25519 signature |
| PS256 | -37 | RSA PSS + SHA-256 |
| RS256 | -257 | RSA PKCS#1 v1.5 + SHA-256 |

## Output Formats

All commands support multiple output formats:

- **text**: Human-readable tabular output (default)
- **json**: Structured JSON for programmatic consumption
- **quiet**: Minimal output (exit code indicates success/failure)

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Validation failure (verify command only) |
| 2 | Error (invalid arguments, file not found, parsing error, etc.) |

## Provider Architecture

The CLI uses **compile-time provider selection** rather than runtime plugins (unlike V2 C# implementation):

- **Signing providers**: Implement `SigningProvider` trait to create `CryptoSigner` instances
- **Verification providers**: Implement `VerificationProvider` trait to create `CoseSign1TrustPack` instances
- **Feature-gated**: Providers are only available if their feature flag is enabled at compile time
- **Extensible**: New providers can be added by implementing traits and registering in provider modules

## Integration with V2 C#

The Rust CLI provides similar functionality to the V2 C# implementation but with key architectural differences:

| Aspect | V2 C# | Rust CLI |
|--------|--------|----------|
| Plugin Discovery | Runtime via `ICoseSignToolPlugin` | Compile-time via Cargo features |
| Provider Registration | `ICoseSignToolPlugin.Initialize()` | Static trait implementation |
| Configuration | Options classes + DI container | Command-line arguments + provider args |
| Async Model | `async Task<T>` throughout | Sync CLI with async internals |
| Error Handling | Exceptions + `Result<T>` | `anyhow::Error` + exit codes |
| Output | Logging frameworks | Structured output formatters |