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
|        CoseSign1          |     |   CoseSign1.Validation    |
|    (Signing Library)      |     | (Validation Framework)    |
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
| `CoseSign1` | Message creation | `CoseSign1MessageFactory`, `DirectSignatureFactory`, `IndirectSignatureFactory` |
| `CoseSign1.Abstractions` | Shared contracts | `ISigningService`, `SigningOptions` |
| `CoseSign1.Validation` | Staged validation | `Cose`, `IValidator`, `TrustPolicy` |
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
|                         Application Layer                              |
|                   (Your code using CoseSignTool V2)                    |
+-----------------------------------------------------------------------+
                                    |
                                    v
+-----------------------------------------------------------------------+
|                       Message Factory Layer                            |
|                       CoseSign1MessageFactory                          |
|           (Routes based on SigningOptions runtime type)                |
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
|                          Factory Layer                                 |
|              ICoseSign1MessageFactory<TOptions>                        |
+-----------------------------------------------------------------------+
                                    |
                                    v
+-----------------------------------------------------------------------+
|                      Signing Service Layer                             |
|                      ISigningService<TOptions>                         |
|                  - CertificateSigningService.Create()                  |
|                  - AzureTrustedSigningService                          |
|                  - CertificateSigningService (base)                    |
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

// Routes to appropriate factory based on options type
byte[] signature = await factory.CreateCoseSign1MessageAsync(
    payload,
    contentType: "application/octet-stream",
    options: new DirectSignatureOptions { EmbedPayload = true });
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

`Cose.Sign1Message()` is the fluent entry point for building validators:

```csharp
var validator = Cose.Sign1Message(loggerFactory)
    .ValidateCertificate(cert => cert
        .NotExpired()
        .ValidateChain())
    .OverrideDefaultTrustPolicy(policy)
    .Build();
```

### Trust Policy Configuration

The builder resolves trust policy in this order:

1. **Explicit Override**: `OverrideDefaultTrustPolicy(policy)` replaces all defaults
2. **Aggregated Defaults**: Validators implementing `IProvidesDefaultTrustPolicy` contribute policies combined with `TrustPolicy.And()`
3. **Fallback**: `DenyAll` if no trust validators, `AllowAll` if trust validators exist but don't provide policies

```csharp
// Using validator defaults (certificate validators provide x509.chain.trusted)
var validator = Cose.Sign1Message()
    .ValidateCertificate(cert => cert.ValidateChain())
    .Build();

// Explicit policy - replaces all validator defaults
var policy = TrustPolicy.And(
    TrustPolicy.Claim("x509.chain.trusted"),
    TrustPolicy.Claim("cert.eku.codesigning")
);
var validator = Cose.Sign1Message()
    .ValidateCertificate(cert => cert.ValidateChain())
    .OverrideDefaultTrustPolicy(policy)  // Single call with combined policy
    .Build();
```

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

### Validator Interface

```csharp
public interface IValidator
{
    IReadOnlyCollection<ValidationStage> Stages { get; }
    
    ValidationResult Validate(CoseSign1Message input, ValidationStage stage);
    
    Task<ValidationResult> ValidateAsync(
        CoseSign1Message input,
        ValidationStage stage,
        CancellationToken cancellationToken = default);
}
```

### Validation Result Model

```csharp
public sealed class ValidationResult
{
    public ValidationResultKind Kind { get; }  // Success, Failure, NotApplicable
    public ValidationStage? Stage { get; }
    public string ValidatorName { get; }
    public IReadOnlyList<ValidationFailure> Failures { get; }
    public IReadOnlyDictionary<string, object> Metadata { get; }
}

public sealed class ValidationFailure
{
    public string ErrorCode { get; }
    public string Message { get; }
    public Exception? Exception { get; }
}
```

### Trust Policy System

Trust is evaluated declaratively via `TrustPolicy`:

```csharp
// Require trusted chain AND valid EKU
var policy = TrustPolicy.And(
    TrustPolicy.Claim("x509.chain.trusted"),
    TrustPolicy.Claim("cert.eku.codesigning")
);

// Validators emit claims
var validator = new CertificateChainValidator();
// Emits: x509.chain.trusted = true/false

// Policy evaluated against collected claims
policy.IsSatisfied(claims); // true or false
```

See [Trust Policy Guide](../guides/trust-policy.md) for comprehensive documentation.

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
+-- sign-cert-store ...       # Plugin: Local
+-- sign-ephemeral ...        # Plugin: Local
+-- sign-akv-cert ...         # Plugin: AzureKeyVault
+-- sign-ats ...              # Plugin: AzureTrustedSigning
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
var validator = Cose.Sign1Message(loggerFactory)
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
| Validators | `IValidator` | Custom validation logic |
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
   +-- CoseSign1Message.DecodeSign1(bytes)
         |
         v
2. Build validation pipeline
   +-- Cose.Sign1Message().AddValidator(...).OverrideDefaultTrustPolicy(...).Build()
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
