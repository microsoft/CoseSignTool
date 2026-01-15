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
- An Azure Key Vault **trust pack** that produces `kid`-related trust facts for policy evaluation.

By default, verification is **offline**.

### Programmatic Verification

Enable the Azure Key Vault trust pack and register an explicit trust policy:

```csharp
using CoseSign1.AzureKeyVault.Trust;
using CoseSign1.Validation.DependencyInjection;
using CoseSign1.Validation.Trust;
using Microsoft.Extensions.DependencyInjection;
using System.Security.Cryptography.Cose;

var services = new ServiceCollection();
var validation = services.ConfigureCoseValidation();

validation.EnableAzureKeyVaultTrust(akv => akv
  .RequireAzureKeyVaultKid()
  .AllowKidPatterns(new[] { "https://production-vault.vault.azure.net/keys/*" })
  .OfflineOnly());

// AKV trust-pack defaults are not enforced automatically.
var trustPolicy = TrustPlanPolicy.Message(m => m
  .RequireFact<AzureKeyVaultKidAllowedFact>(f => f.IsAllowed, "AKV kid must match an allowed pattern"));

services.AddSingleton<CompiledTrustPlan>(sp => trustPolicy.Compile(sp));

using var sp = services.BuildServiceProvider();
using var scope = sp.CreateScope();

var validator = scope.ServiceProvider
  .GetRequiredService<ICoseSign1ValidatorFactory>()
  .Create();

CoseSign1Message message = CoseMessage.DecodeSign1(coseBytes);
var result = message.Validate(validator);
```

### Trust Policy Validation

When using key-only signatures, you can configure trust validation to ensure the signing key comes from an approved set of Key Vaults. This is particularly useful when you need to enforce that signatures originate only from specific, authorized Key Vault instances.

```csharp
using CoseSign1.AzureKeyVault.Trust;
using CoseSign1.Validation.DependencyInjection;
using CoseSign1.Validation.Trust;
using Microsoft.Extensions.DependencyInjection;

var services = new ServiceCollection();
var validation = services.ConfigureCoseValidation();

validation.EnableAzureKeyVaultTrust(akv => akv
    .RequireAzureKeyVaultKid()
    .AllowKidPatterns(new[]
    {
        "https://production-vault.vault.azure.net/keys/*",
        "https://signing-*.vault.azure.net/keys/release-*",
    })
    .OfflineOnly());

var trustPolicy = TrustPlanPolicy.Message(m => m
    .RequireFact<AzureKeyVaultKidAllowedFact>(f => f.IsAllowed, "AKV kid must match an allowed pattern"));

services.AddSingleton<CompiledTrustPlan>(sp => trustPolicy.Compile(sp));

using var sp = services.BuildServiceProvider();
using var scope = sp.CreateScope();

var validator = scope.ServiceProvider
    .GetRequiredService<ICoseSign1ValidatorFactory>()
    .Create();

var result = message.Validate(validator);
```

#### Pattern Syntax

The `FromAllowedVaults` method accepts patterns in three formats:

| Format | Example | Description |
|--------|---------|-------------|
| Exact | `https://myvault.vault.azure.net/keys/mykey` | Matches exact kid URI |
| Wildcard | `https://*.vault.azure.net/keys/*` | `*` matches any characters |
| Regex | `regex:https://.*\.vault\.azure\.net/keys/signing-.*` | Full regex (prefix with `regex:`) |

#### Facts

The Azure Key Vault trust pack can produce these facts:

- `AzureKeyVaultKidDetectedFact` (whether the message `kid` looks like an AKV key URI)
- `AzureKeyVaultKidAllowedFact` (whether the `kid` matches one of the allowed patterns)

Azure Key Vault defaults are not enforced automatically; supply a `TrustPlanPolicy` that requires the facts you care about.

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
