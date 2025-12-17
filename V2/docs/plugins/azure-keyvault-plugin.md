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
