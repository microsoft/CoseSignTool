# Signing Roots (Draft)

This document proposes an extensible architecture for V2 signing that mirrors the "multiple roots" work already done for `verify`.

## Problem statement

Today, signing is modeled as multiple independent provider-specific commands (each provided by an `ISigningCommandProvider`).

We need a model where:

- Signing has **root models** (e.g., **X.509**, **AKV key-only**, **Azure Trusted Signing**).
- Some roots can stand alone (e.g., **AKV protected keys** can sign without certificates).
- Some roots can be composed from **sub-providers** contributed by other plugins.
  - Example: **X.509 signing root** needs a certificate source.
  - `Certificates.Local` contributes PFX/store/PEM sources.
  - `AKV` contributes an AKV-backed certificate source (certificate + chain in AKV; signing performed remotely).

This implies plugins must be able to **extend features of other plugins** ("AKV provides an X.509 certificate provider").

## Proposed terminology

- **Signing root**: selects the signing trust model and owns the *contract* for what must be provided.
  - Examples: `x509`, `akv`, `ats`.
- **Material provider** (aka *feature provider*): supplies a concrete implementation required by a root.
  - Examples for X.509 root: `pfx`, `store`, `pem`, `akv-cert`.

## CLI shape (proposed)

The goal is to make roots explicit and help root-specific.

- Root list:
  - `cosesigntool sign --help`
- X.509 root:
  - `cosesigntool sign --x509 --help`
  - `cosesigntool sign --x509 --pfx cert.pfx --pfx-password-file pw.txt ...`
  - `cosesigntool sign --x509 --cert-store "CurrentUser/My" --thumbprint ...`
  - `cosesigntool sign --x509 --akv-certificate "https://..." --tenant-id ...`
- AKV key-only root:
  - `cosesigntool sign --akv --vault-uri ... --key-name ... --key-version ...`

Notes:
- X.509 root stays the default root *only when no other signing root is selected*.
- A root may also offer opt-in knobs (headers, content type constraints, etc.) without changing the material provider.

## Plugin architecture (proposed)

### Key idea: separate "root commands" from "providers"

- A **root plugin** defines the root command surface and the contract.
  - Example: a `CoseSignTool.Certificates.Plugin` owns the X.509 signing root.
- Provider plugins implement the material providers for that root.
  - Example: `CoseSignTool.Local.Plugin` implements PFX/PEM/store providers.
  - Example: `CoseSignTool.AzureKeyVault.Plugin` implements an AKV certificate provider and an AKV key-only root.

This avoids tight plugin-to-plugin dependencies:
- Provider plugins do not reference each other.
- The main executable aggregates all extensions from all plugins and hands them to the root command builder.

### Proposed extension points

(Names are illustrative; final naming should align with V2 conventions and existing plugin abstractions.)

- `ISigningRootProvider`
  - Declares root selector option (e.g., `--x509`, `--akv`)
  - Adds root-level options
  - Creates/configures the signing pipeline (DI registrations, header contributors, signing service factory)

- `ISigningMaterialProvider`
  - Declares which root it extends (e.g., `TargetRoot = "x509"`)
  - Adds provider-specific options
  - Produces the root-required material
    - For X.509: something that can produce a certificate-backed signing service

### Composition rules

- Exactly one signing root is selected.
  - Default root applies only when no explicit root is selected.
- A root may require one of several material providers.
  - For X.509: require exactly one certificate material provider.
- A material provider may be usable by multiple roots.
  - (Rare, but possible; keep the interface generic enough.)

## Given/When/Then scenarios

### Scenario: AKV key-only root signs without X.509

- Given the user selects `--akv`
- And the user provides a Key Vault key identifier
- When the tool signs a payload
- Then a valid COSE_Sign1 is produced
- And no X.509 certificate chain is required

### Scenario: X.509 root signs using AKV-backed certificate

- Given the user selects `--x509`
- And the user selects an AKV certificate material provider
- When the tool signs a payload
- Then the COSE headers include `x5chain` derived from the AKV certificate + chain
- And the signature is produced using Key Vault (private key never leaves AKV)

### Scenario: X.509 root signs using local PFX

- Given the user selects `--x509`
- And the user selects a local PFX certificate provider
- When the tool signs a payload
- Then the signature is produced using the local private key

### Scenario: Missing required material provider

- Given the user selects `--x509`
- And the user does not select any certificate material provider
- When the tool runs
- Then argument parsing fails with an actionable error indicating one provider must be selected

## Incremental migration plan

1. Introduce a new built-in `sign` command with root selection and per-root help (like `verify`).
2. Initially implement X.509 root with **only** the current local PFX/store/PEM providers.
3. Add AKV certificate provider under X.509 root and add AKV key-only root.
4. Make the unified `sign` command the primary UX and keep provider-specific commands internal-only (not part of the documented surface).

## Open questions

- How should roots and providers report structured metadata (e.g., which root/provider was used, key IDs, cert subjects) consistently with the existing output formatters?
- Should X.509 root force `x5chain` inclusion or allow alternative headers (e.g., `x5t`) depending on downstream needs?
