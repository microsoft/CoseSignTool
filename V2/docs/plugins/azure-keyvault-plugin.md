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

The plugin contributes:

- An **offline signing key resolver** that can verify key-only signatures when the message contains an embedded `COSE_Key` public key header.
- A **trust assertion provider** for evaluating `kid` (Azure Key Vault key URI) patterns.

By default, verification is **offline**.

### Programmatic Verification

Use the V2 validation builder to add Azure Key Vault assertions:

```csharp
using CoseSign1.AzureKeyVault.Validation;
using CoseSign1.Validation;
using System.Security.Cryptography.Cose;

var validator = new CoseSign1ValidationBuilder()
  .ValidateAzureKeyVault(akv => akv
    .RequireAzureKeyVaultOrigin())
    .Build();

CoseSign1Message message = CoseMessage.DecodeSign1(coseBytes);
var result = message.Validate(validator);
```

### Trust Policy Validation

When using key-only signatures, you can configure trust validation to ensure the signing key comes from an approved set of Key Vaults. This is particularly useful when you need to enforce that signatures originate only from specific, authorized Key Vault instances.

```csharp
using CoseSign1.AzureKeyVault.Validation;
using CoseSign1.Validation;

// Validate that the kid matches allowed vault patterns
var validator = new CoseSign1ValidationBuilder()
  .ValidateAzureKeyVault(akv => akv
    .FromAllowedVaults(
      "https://production-vault.vault.azure.net/keys/*",    // Any key in this vault
      "https://signing-*.vault.azure.net/keys/release-*"))  // Wildcards supported
    .Build();

var result = message.Validate(validator);
```

#### Pattern Syntax

The `FromAllowedVaults` method accepts patterns in three formats:

| Format | Example | Description |
|--------|---------|-------------|
| Exact | `https://myvault.vault.azure.net/keys/mykey` | Matches exact kid URI |
| Wildcard | `https://*.vault.azure.net/keys/*` | `*` matches any characters |
| Regex | `regex:https://.*\.vault\.azure\.net/keys/signing-.*` | Full regex (prefix with `regex:`) |

#### Assertions

The AKV assertion provider emits typed assertions:

- `AkvKeyDetectedAssertion` (whether the message `kid` looks like an AKV key URI)
- `AkvKidAllowedAssertion` (whether the `kid` matches one of the allowed patterns)

By default, each assertion supplies a `DefaultTrustPolicy`, so `TrustPolicy.FromAssertionDefaults()` will require them.

### CLI Options

The `verify` command gains two plugin options:

- `--require-az-key`: Require the message to look like an AKV key-only signature (`kid` must look like an AKV key id).
- `--allowed-vaults`: One or more allowed Key Vault URI patterns (glob or `regex:` prefix).

Notes:
- X.509 validators (chain/expiry/EKU/CN) only apply when the message contains `x5t` + `x5chain` headers.
- Detached signatures still require `--payload` so the signature can be verified.

Example:

```bash
# Require the signature to be an AKV key-only signature
CoseSignTool verify signature.cose --payload payload.bin --require-az-key

# Require that kid matches one of the allowed patterns
CoseSignTool verify signature.cose --payload payload.bin --allowed-vaults "https://production-vault.vault.azure.net/keys/*"
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
