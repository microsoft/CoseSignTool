# Architecture Overview

CoseSignTool V2 is a complete architectural redesign providing modular, extensible COSE Sign1 message signing and verification.

## Design Principles

### 1. Security by Default
- **Deny-by-default trust**: No implicit trust; explicit policy required
- **Staged validation**: Trust evaluated before signature verification
- **Secure credential handling**: Support for HSM, cloud vaults, TPM

### 2. Modularity
- **Clean separation**: Signing, validation, certificates in separate packages
- **Composable validators**: Build validation pipelines from primitives
- **Plugin architecture**: Extend CLI without modifying core

### 3. Extensibility
- **Interface-driven**: All major components are interface-based
- **Dependency injection**: ILoggerFactory throughout
- **Builder patterns**: Fluent APIs for configuration

---

## Package Architecture

```
+---------------------------+     +---------------------------+
|      CoseSignTool         |     |  CoseSignTool.Abstractions|
|      (CLI Application)    |     |  (Plugin Interfaces)      |
+---------------------------+     +---------------------------+
            |                                 |
            v                                 v
+---------------------------+     +---------------------------+
|     CoseSign1.Factories   |     |   CoseSign1.Validation    |
|   (Signing Factories)     |     | (Validation Framework)    |
+---------------------------+     +---------------------------+
            |                                 |
            v                                 v
+---------------------------+     +---------------------------+
|   CoseSign1.Certificates  |     |  CoseSign1.Abstractions   |
|  (Certificate Services)   |     |   (Shared Interfaces)     |
+---------------------------+     +---------------------------+
```

### Core Packages

| Package | Purpose | Key Types |
|---------|---------|-----------|
| `CoseSign1.Factories` | Message creation | `CoseSign1MessageFactory`, `DirectSignatureFactory`, `IndirectSignatureFactory` |
| `CoseSign1.Abstractions` | Shared contracts | `ISigningService`, `SigningOptions` |
| `CoseSign1.Validation` | Staged validation | `CoseSign1ValidationBuilder`, `CoseSign1Validator`, `ICoseSign1Validator`, `TrustPolicy` |
| `CoseSign1.Certificates` | Certificate infrastructure | `ICertificateSource`, `ICertificateChainBuilder`, `CertificateSigningService` |

### Certificate Provider Packages

| Package | Purpose |
|---------|---------|
| `CoseSign1.Certificates.Local` | PFX, PEM, Windows Certificate Store |
| `CoseSign1.Certificates.AzureKeyVault` | Azure Key Vault certificates |
| `CoseSign1.Certificates.AzureTrustedSigning` | Azure Trusted Signing |

### CLI Packages

| Package | Purpose |
|---------|---------|
| `CoseSignTool` | CLI application |
| `CoseSignTool.Abstractions` | Plugin interfaces |
| `CoseSignTool.Local.Plugin` | Local signing commands |
| `CoseSignTool.AzureKeyVault.Plugin` | Azure Key Vault commands |
| `CoseSignTool.AzureTrustedSigning.Plugin` | Azure Trusted Signing commands |
| `CoseSignTool.MST.Plugin` | MST transparency verification |

---

## Architectural Layers

```
+-----------------------------------------------------------------------+
|                         Application Layer                             |
|                   (Your code using CoseSignTool V2)                   |
+-----------------------------------------------------------------------+
                                    |
                                    v
+-----------------------------------------------------------------------+
|                       Message Factory Layer                           |
|                       CoseSign1MessageFactory                         |
|           (Routes based on SigningOptions runtime type)               |
+-----------------------------------------------------------------------+
                                    |
                 +------------------+------------------+
                 |                                     |
                 v                                     v
+--------------------------------+   +--------------------------------+
|   DirectSignatureFactory       |   |  IndirectSignatureFactory      |
|   (DirectSignatureOptions)     |   |  (IndirectSignatureOptions)    |
|   - Embedded or detached       |   |  - Hash envelope pattern       |
+--------------------------------+   +--------------------------------+
                 |                                     |
                 +------------------+------------------+
                                    |
                                    v
+-----------------------------------------------------------------------+
|                          Factory Layer                                |
|              ICoseSign1MessageFactory<TOptions>                       |
+-----------------------------------------------------------------------+
                                    |
                                    v
+-----------------------------------------------------------------------+
|                      Signing Service Layer                            |
|                      ISigningService<TOptions>                        |
|                  - CertificateSigningService.Create()                 |
|                  - AzureTrustedSigningService                         |
|                  - CertificateSigningService (base)                   |
+-----------------------------------------------------------------------+
                                    |
                 +------------------+------------------+
                 |                                     |
                 v                                     v
+--------------------------------+   +--------------------------------+
|      Signing Key Management    |   |      Header Contribution       |
|                                |   |                                |
|  - ISigningKey                 |   |  - IHeaderContributor          |
|  - ICertSigningKey             |   |  - CWT Claims                  |
|  - Key Providers               |   |  - X5T/X5Chain                 |
+--------------------------------+   +--------------------------------+
                 |
                 v
+--------------------------------+
|     Certificate Management     |
|                                |
|  - ICertSource                 |
|  - Chain Builders              |
+--------------------------------+
```

---

## Signing Architecture

### CoseSign1MessageFactory

The `CoseSign1MessageFactory` is the **preferred entry point** for signing operations:

```csharp
var factory = new CoseSign1MessageFactory(signingService);

// Preferred: call the explicit method for your intent
var message = await factory.CreateDirectCoseSign1MessageAsync(
    payload,
    contentType: "application/octet-stream");
```

### Factory Selection

```
CoseSign1MessageFactory
        |
        +-- DirectSignatureOptions --> DirectSignatureFactory
        |                                    |
        |                                    +-- Embedded: payload in signature
        |                                    +-- Detached: payload separate
        |
        +-- IndirectSignatureOptions --> IndirectSignatureFactory
                                               |
                                               +-- Hash envelope pattern
                                               +-- Signs hash, not payload
```

### Direct vs Indirect Signatures

**Direct Signature:**
- Signs the payload directly
- Payload can be embedded (in signature) or detached (separate file)
- Standard COSE Sign1 format

**Indirect Signature (Hash Envelope):**
- Signs a hash of the payload
- Useful for large payloads (avoids loading entire payload into memory)
- Payload location stored in header
- Requires payload for verification

### Signing Service Abstraction

```csharp
public interface ISigningService<TOptions> where TOptions : SigningOptions
{
    Task<CoseSign1Message> SignAsync(
        ReadOnlyMemory<byte> payload,
        TOptions? options = default,
        CancellationToken cancellationToken = default);
    
    X509Certificate2? SigningCertificate { get; }
    IReadOnlyCollection<X509Certificate2>? CertificateChain { get; }
}
```

---

## Validation Architecture

### Entry Point

V2 validation is built around **stage-aware components** and a single orchestrator (`CoseSign1Validator`).

Build a reusable validator with `CoseSign1ValidationBuilder`:

```csharp
using CoseSign1.Validation;
using CoseSign1.Certificates.Validation;

var validator = new CoseSign1ValidationBuilder(loggerFactory)
    .ValidateCertificate(cert => cert.ValidateChain())
    .Build();

var result = message.Validate(validator);
```

For one-off validation, you can configure inline:

```csharp
var result = message.Validate(builder => builder
    .ValidateCertificate(cert => cert.ValidateChain())
    .OverrideDefaultTrustPolicy(TrustPolicy.Require("x509.chain.trusted")));
```

If you reference extension packages that register default components, `message.Validate()` uses **auto-discovery**.

See [Sequence Diagrams](sequence-diagrams.md) for the concrete call ordering.

### Trust Policy Configuration

Trust decisions are made by evaluating a `TrustPolicy` against the assertions produced by
`ISigningKeyAssertionProvider` components.

- If you call `OverrideDefaultTrustPolicy(...)`, that policy is used.
- Otherwise, the builder defaults to `TrustPolicy.FromAssertionDefaults()`.

See [Trust Policy Guide](../guides/trust-policy.md) for policy authoring.

### Validation Stages

V2 enforces a **secure-by-default** stage order:

| Stage | Purpose | Runs When |
|-------|---------|-----------|
| **KeyMaterialResolution** | Extract signing key from headers | Always |
| **KeyMaterialTrust** | Evaluate trust policy | Always |
| **Signature** | Cryptographic verification | Only if trust passes |
| **PostSignature** | Additional business rules | Only if signature passes |

### Why Trust Before Signature?

1. **Prevents oracle attacks**: Attacker can't use signature verification to probe valid inputs
2. **Fail fast**: Reject untrusted signatures without expensive crypto
3. **Clear semantics**: Trust establishes whether to verify, not whether verification succeeds


### Component Model

Validation logic is composed from:

- `ISigningKeyResolver` (stage 1)
- `ISigningKeyAssertionProvider` (stage 2)
- Signature verification (stage 3, performed by the orchestrator using the resolved key)
- `IPostSignatureValidator` (stage 4)

See [Validation Framework](validation-framework.md) for the full API surface.

---

## Certificate Architecture

### Certificate Source Pattern

```csharp
public interface ICertificateSource : IDisposable
{
    X509Certificate2 GetSigningCertificate();
    bool HasPrivateKey { get; }
    ICertificateChainBuilder GetChainBuilder();
}
```

### Implementations

| Source | Class | Use Case |
|--------|-------|----------|
| PFX File | `PfxCertificateSource` | Development, CI/CD |
| PEM Files | `PemCertificateSource` | Linux/containerized environments |
| Windows Store | `CertificateStoreCertificateSource` | Windows production |
| Azure Key Vault | `AzureKeyVaultCertificateSource` | Enterprise cloud |
| Azure Trusted Signing | `TrustedSigningCertificateSource` | Managed signing service |

### Certificate Signing Service

Unified signing service for all certificate sources:

```csharp
// Factory methods handle complexity
var service = CertificateSigningService.Create(certificate, chainBuilder, logger);
var service = CertificateSigningService.Create(certificate, certificateChain, logger);
var service = CertificateSigningService.Create(remoteCertificateSource, logger);
```

---

## CLI Architecture

### Command Structure

```
cosesigntool
+-- verify <signature>        # Built-in verify command
+-- inspect <file>            # Built-in inspect command
+-- sign-pfx ...              # Plugin: Local
+-- sign-pem ...              # Plugin: Local
+-- sign-certstore ...        # Plugin: Local
+-- sign-ephemeral ...        # Plugin: Local
+-- sign-akv-cert ...         # Plugin: AzureKeyVault
+-- sign-azure ...            # Plugin: AzureTrustedSigning
```

### Plugin System

Plugins contribute:

1. **Signing Commands** via `ISigningCommandProvider`
2. **Verification Providers** via `IVerificationProvider`
3. **Transparency Providers** via `ITransparencyProviderContributor`

See [Plugin Development Guide](../plugins/README.md).

### Output System

```csharp
public interface IOutputFormatter
{
    void WriteInfo(string message);
    void WriteSuccess(string message);
    void WriteError(string message);
    void WriteKeyValue(string key, string value);
    void WriteStructuredData<T>(T data);
}
```

Implementations: `TextOutputFormatter`, `JsonOutputFormatter`, `XmlOutputFormatter`, `QuietOutputFormatter`

---

## Logging Architecture

### ILoggerFactory Integration

All components accept `ILoggerFactory` for observability:

```csharp
// Signing
var service = CertificateSigningService.Create(cert, chain, loggerFactory.CreateLogger<CertificateSigningService>());

// Validation
var validator = new CoseSign1.Validation.CoseSign1ValidationBuilder(loggerFactory)
    .AddComponent(new CoseSign1.Certificates.Validation.CertificateSigningKeyResolver(
        certificateHeaderLocation: System.Security.Cryptography.Cose.CoseHeaderLocation.Any))
    .ValidateCertificate(cert => cert.ValidateChain(allowUntrusted: true))
    .AllowAllTrust("logging example")
    .Build();
```

### Per-Provider Levels

- **Console**: Respects verbosity (-q, -vv, -vvv)
- **Log File**: Always Debug level for full diagnostics

See [Logging and Diagnostics Guide](../guides/logging-diagnostics.md).

---

## Extension Points

| Extension Point | Interface | Use Case |
|----------------|-----------|----------|
| Signing Services | `ISigningService<TOptions>` | Custom signing backends |
| Certificate Sources | `ICertificateSource` | Custom certificate retrieval |
| Chain Builders | `ICertificateChainBuilder` | Custom chain building |
| Validation components | `IValidationComponent` | Custom validation logic |
| Transparency | `ITransparencyProvider` | Custom transparency services |
| CLI Plugins | `IPlugin` | Custom CLI commands |
| Signing Commands | `ISigningCommandProvider` | Custom signing commands |
| Verification | `IVerificationProvider` | Custom verification |

---

## Data Flow

### Signing Flow

```
1. Load certificate source
   +-- PfxCertificateSource, PemCertificateSource, etc.
         |
         v
2. Create signing service
   +-- CertificateSigningService.Create(...)
         |
         v
3. Create message factory
   +-- new CoseSign1MessageFactory(signingService)
         |
         v
4. Sign payload
   +-- factory.CreateCoseSign1MessageAsync(payload, options)
         |
         v
5. [Optional] Add transparency proof
   +-- transparencyProvider.AddTransparencyProofAsync(message)
         |
         v
6. Return signed COSE message bytes
```

### Verification Flow

```
1. Decode COSE message
    +-- CoseMessage.DecodeSign1(bytes)
         |
         v
2. Validate message (builds pipeline internally)
    +-- message.Validate(builder => { ... }, loggerFactory?)
         |
         v
3. Execute staged validation
   +-- Stage 1: Key Material Resolution
   |     +-- Extract certificates from headers
   |
   +-- Stage 2: Key Material Trust
   |     +-- Run trust validators
   |     +-- Collect trust assertions
   |     +-- Evaluate trust policy
   |     +-- SHORT-CIRCUIT if policy fails
   |
   +-- Stage 3: Signature Verification
   |     +-- Cryptographic signature check
   |
   +-- Stage 4: Post-Signature Policy
         +-- Additional business rules
         |
         v
4. Return CoseSign1ValidationResult
   +-- Resolution, Trust, Signature, PostSignature stage results
   +-- Overall result
```

In code, the most concise form is the validation extension method:

```csharp
using System.Security.Cryptography.Cose;
using Microsoft.Extensions.Logging;

ILoggerFactory? loggerFactory = null;

var message = CoseMessage.DecodeSign1(signatureBytes);
var result = message.Validate(builder =>
{
    // Configure your validation components here.
    // Examples are documented in the validation and trust-policy guides.
}, loggerFactory);
```

If you will validate many messages with the same configuration, prefer building an `ICoseSign1Validator` once via `new CoseSign1ValidationBuilder(loggerFactory).Build()` and reusing it.
