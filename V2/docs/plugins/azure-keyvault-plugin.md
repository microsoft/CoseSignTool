# CoseSignTool.AzureKeyVault.Plugin

**Package**: `CoseSignTool.AzureKeyVault.Plugin`  
**Purpose**: Azure Key Vault integration for the CoseSignTool CLI

## Overview

This plugin adds Azure Key Vault-based signing commands and contributes verification support for key-only signatures.

It supports two primary signing modes:
- **Certificate-based signing**: sign using an X.509 certificate stored in Key Vault (PKI trust model; embeds `x5t`/`x5chain`).
- **Key-only signing**: sign using a Key Vault key without a certificate (uses a `kid` header to identify the key).

## Commands

### sign-akv-cert

Sign using a certificate stored in Azure Key Vault.

```bash
CoseSignTool sign-akv-cert <payload> \
  --akv-vault <vault-uri> \
  --akv-cert-name <cert-name> \
  [--akv-cert-version <version>] \
  [--akv-refresh-interval <minutes>] \
  [--signature-type embedded|detached|indirect] \
  [--output <file>]
```

### sign-akv-key

Sign using a key stored in Azure Key Vault (no certificate).

```bash
CoseSignTool sign-akv-key <payload> \
  --akv-vault <vault-uri> \
  --akv-key-name <key-name> \
  [--akv-key-version <version>] \
  [--akv-refresh-interval <minutes>] \
  [--signature-type embedded|detached|indirect] \
  [--output <file>]
```

## Verification Support

The plugin contributes a signature validator for **key-only** signatures.

By default, verification is **offline** when the message contains an embedded `COSE_Key` public key header.

### Programmatic Verification

Use the fluent API to configure Azure Key Vault signature validation:

```csharp
using CoseSign1.AzureKeyVault.Validation;
using CoseSign1.Validation;
using Azure.Identity;

var validator = Cose.Sign1Message()
    .ValidateAzureKeyVault(akv => akv
        .RequireAzureKey()              // Require AKV key-only signature shape
        .AllowOnlineVerify()            // Allow network calls to fetch public key
        .WithCredential(new DefaultAzureCredential()))
    .Build();

var result = validator.Validate(message);
```

### Trust Policy Validation

When using key-only signatures, you can configure trust validation to ensure the signing key comes from an approved set of Key Vaults. This is particularly useful when you need to enforce that signatures originate only from specific, authorized Key Vault instances.

```csharp
using CoseSign1.AzureKeyVault.Validation;
using CoseSign1.Validation;

// Validate that the kid matches allowed vault patterns
var validator = Cose.Sign1Message()
    .ValidateAzureKeyVault(akv => akv
        .RequireAzureKeyVaultOrigin()   // Enable trust validation
        .FromAllowedVaults(
            "https://production-vault.vault.azure.net/keys/*",    // Any key in this vault
            "https://signing-*.vault.azure.net/keys/release-*"))  // Wildcards supported
    .Build();

var result = validator.Validate(message);
```

#### Pattern Syntax

The `FromAllowedVaults` method accepts patterns in three formats:

| Format | Example | Description |
|--------|---------|-------------|
| Exact | `https://myvault.vault.azure.net/keys/mykey` | Matches exact kid URI |
| Wildcard | `https://*.vault.azure.net/keys/*` | `*` matches any characters |
| Regex | `regex:https://.*\.vault\.azure\.net/keys/signing-.*` | Full regex (prefix with `regex:`) |

#### Trust Claims

The AKV trust validator emits two trust assertions:

| Claim | Description |
|-------|-------------|
| `akv.key.detected` | True if the kid looks like an Azure Key Vault key URI |
| `akv.kid.allowed` | True if the kid matches one of the allowed patterns |

When patterns are configured, the default trust policy requires both claims to be satisfied.

### Online Verification (Optional)

The `verify` command gains two plugin options:

- `--allow-online-verify`: Allow network calls to Azure Key Vault to fetch the public key identified by `kid` when needed.
- `--require-az-key`: Require an Azure Key Vault key-only signature shape (i.e., a `kid` that looks like an AKV key id, and typically an embedded `COSE_Key`).

Online verification is only attempted when `--allow-online-verify` is specified, and one of these applies:
- The message does not include an embedded `COSE_Key` (but does include a `kid`).
- The message includes both a `kid` and an embedded `COSE_Key`, and the `kid` inside the `COSE_Key` does not match the message `kid`.

Notes:
- X.509 validators (chain/expiry/EKU/CN) only apply when the message contains `x5t` + `x5chain` headers.
- Detached signatures still require `--payload` so the signature can be verified.

Example:

```bash
# Offline verification (embedded COSE_Key)
CoseSignTool verify signature.cose --payload payload.bin

# Allow online verification if needed
CoseSignTool verify signature.cose --payload payload.bin --allow-online-verify

# Require the signature to be an AKV key-only signature
CoseSignTool verify signature.cose --payload payload.bin --require-az-key
```

## Authentication

The plugin uses Azure Identity (typically `DefaultAzureCredential`). Common supported flows include:
- Managed Identity
- Azure CLI (`az login`)
- Environment variables (service principal)

Online verification uses the same credential chain as signing and requires permission to fetch the key material referenced by `kid`.

## See Also

- [Verify Command](../cli/verify.md)
- [Plugins Overview](README.md)
