# Architecture Overview

CoseSignTool V2 is built on a modern, modular architecture designed for extensibility, testability, and maintainability.

## Design Principles

1. **Separation of Concerns**: Each component has a single, well-defined responsibility
2. **Dependency Injection**: All dependencies are injected, enabling easy testing and composition
3. **Interface-Based Design**: Programming to interfaces, not implementations
4. **Immutability**: Prefer immutable data structures and value objects
5. **Fail-Fast**: Early validation and clear error messages
6. **Async-First**: Asynchronous operations are first-class citizens

## Architectural Layers

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                        │
│  (Your code using CoseSignTool V2)                         │
└─────────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────────┐
│                    Factory Layer                            │
│  DirectSignatureFactory | IndirectSignatureFactory          │
│  ICoseSign1MessageFactory<TOptions>                         │
└─────────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────────┐
│                 Signing Service Layer                       │
│  ISigningService<TOptions>                                  │
│  - CertificateSigningService.Create()                       │
│  - AzureTrustedSigningService                               │
│  - CertificateSigningService (base)                         │
└─────────────────────────────────────────────────────────────┘
                            │
        ┌───────────────────┴───────────────────┐
        │                                       │
┌───────────────────┐                  ┌───────────────────┐
│ Signing Key       │                  │ Header            │
│ Management        │                  │ Contribution      │
│                   │                  │                   │
│ - ISigningKey     │                  │ - IHeaderContrib  │
│ - ICertSigningKey │                  │ - CWT Claims      │
│ - Key Providers   │                  │ - X5T/X5Chain     │
└───────────────────┘                  └───────────────────┘
        │
┌───────────────────┐
│ Certificate       │
│ Management        │
│                   │
│ - ICertSource     │
│ - Chain Builders  │
└───────────────────┘
                            │
┌─────────────────────────────────────────────────────────────┐
│                  Validation Layer                           │
│  IValidator | ValidationResult                              │
│  - Composable validators                                    │
│  - Certificate validation                                   │
│  - Signature validation                                     │
└─────────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────────┐
│               Transparency Layer                            │
│  ITransparencyProvider                                      │
│  - MstTransparencyProvider                                  │
│  - Custom transparency services                             │
└─────────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────────┐
│                  Foundation Layer                           │
│  CoseSign1.Abstractions                                     │
│  - ICoseSign1MessageFactory<TOptions>                       │
│  - ISigningService<TOptions>                                │
│  - ISigningKey                                              │
│  - IHeaderContributor                                       │
│  - SigningContext, SigningOptions                           │
└─────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Abstractions (`CoseSign1.Abstractions`)

Defines the foundational interfaces and contracts:

- **`ICoseSign1MessageFactory<TOptions>`**: Generic factory for creating COSE Sign1 messages with type-safe options
- **`ISigningService<TOptions>`**: Service that provides `CoseSigner` instances for signing operations
- **`ISigningKey`**: Abstraction for cryptographic signing keys (emits `CoseKey` instances)
- **`IHeaderContributor`**: Extension point for adding headers to COSE messages at sign-time
- **`SigningContext`**: Encapsulates signing operation context (payload, content type)
- **`SigningOptions`**: Base class for signing options
- **`SigningKeyMetadata`**: Metadata about cryptographic keys (algorithm, key type, size)
- **`SigningServiceMetadata`**: Metadata about signing services

### 2. Signing Services

Implementations of `ISigningService<TOptions>`:

```csharp
public interface ISigningService<out TSigningOptions> : IDisposable
    where TSigningOptions : SigningOptions
{
    CoseSigner GetCoseSigner(SigningContext context);
    TSigningOptions CreateSigningOptions();
    bool IsRemote { get; }
    SigningServiceMetadata ServiceMetadata { get; }
}
```

**Available Implementations**:
- **`CertificateSigningService.Create()`**: Factory methods for local and remote certificate signing
- **`AzureTrustedSigningService`**: Signs using Azure Trusted Signing
- **`CertificateSigningService`**: Abstract base class for certificate-based signing

Key characteristics:
- Returns `CoseSigner` instances from .NET's `System.Security.Cryptography.Cose`
- Uses `ISigningKey` to access underlying `CoseKey`
- Applies header contributors during `GetCoseSigner()`
- Thread-safe implementations

### 3. Signing Keys

The `ISigningKey` interface abstracts cryptographic keys:

```csharp
public interface ISigningKey : IDisposable
{
    CoseKey GetCoseKey();
    SigningKeyMetadata Metadata { get; }
    ISigningService<SigningOptions> SigningService { get; }
}
```

**Key Providers** (`ISigningKeyProvider`):
- **`DirectSigningKeyProvider`**: Local key from X509Certificate2 private key
- **`RemoteSigningKeyProvider`**: Delegates to remote signing service

**Certificate Signing Key** (`ICertificateSigningKey`):
- Extends `ISigningKey` with certificate chain access
- Used by certificate header contributors

### 4. Signature Factories

High-level APIs for creating COSE Sign1 messages:

**`DirectSignatureFactory`**: Creates standard COSE Sign1 messages
```csharp
var factory = new DirectSignatureFactory(signingService);
byte[] signed = factory.CreateCoseSign1MessageBytes(payload, "application/json");
```

**`IndirectSignatureFactory`**: Creates indirect signatures (hash envelopes)
```csharp
var factory = new IndirectSignatureFactory(signingService);
byte[] signed = factory.CreateCoseSign1MessageBytes(largePayload, "application/octet-stream");
```

Factories handle:
- Header contribution coordination
- Content type management  
- Embedded vs detached payloads (via options)
- Transparency proof addition (optional)

### 5. Certificate Management

Multi-layered certificate handling in `CoseSign1.Certificates`:

**Certificate Sources** (`ICertificateSource`):
- `DirectCertificateSource`: Certificate provided directly in-memory
- `PfxCertificateSource`: Load from PFX/PKCS#12 files
- `WindowsCertificateStoreCertificateSource`: Windows certificate store
- `LinuxCertificateStoreCertificateSource`: Linux certificate store
- `RemoteCertificateSource`: Abstract base for remote signing

**Chain Builders** (`ICertificateChainBuilder`):
- `X509ChainBuilder`: Automatic chain building using system trust
- `ExplicitCertificateChainBuilder`: Explicit chain specification

### 6. Header Contributors

Extensible header contribution system:

```csharp
public interface IHeaderContributor
{
    HeaderMergeStrategy MergeStrategy { get; }
    void ContributeProtectedHeaders(CoseHeaderMap headers, HeaderContributorContext context);
    void ContributeUnprotectedHeaders(CoseHeaderMap headers, HeaderContributorContext context);
}
```

**Built-in Contributors**:
- **`CertificateHeaderContributor`**: Adds X5T (thumbprint), X5Chain headers
- **`ContentTypeHeaderContributor`**: Adds content type header
- **`CwtClaimsHeaderContributor`**: Adds CWT claims for SCITT compliance
- **`CoseHashEnvelopeHeaderContributor`**: Adds hash envelope headers for indirect signatures

**HeaderContributorContext** provides:
- `SigningContext`: Payload, content type, additional headers
- `SigningKey`: Access to key metadata for header derivation

### 7. Verification Framework

Composable staged verification architecture in `CoseSign1.Validation`:

```csharp
public interface IValidator
{
    IReadOnlyCollection<ValidationStage> Stages { get; }
    ValidationResult Validate(CoseSign1Message input, ValidationStage stage);
    Task<ValidationResult> ValidateAsync(CoseSign1Message input, ValidationStage stage, CancellationToken cancellationToken = default);
}
```

**Entry Point** - Fluent staged builder API:
```csharp
var verifier = Cose.Sign1Message()
    .AllowAllTrust("TrustedSigner")
    .ValidateCertificateSignature()
    .Build();

var result = verifier.Verify(message);
```

**Core Types**:
- `ICoseSign1VerificationBuilder`: Builder for staged verification pipelines
- `ICoseSign1Verifier`: Built verifier instance (`Verify` / `VerifyAsync`)
- `CoseSign1VerificationResult`: Per-stage results (`Resolution`, `Trust`, `Signature`, `PostSignature`, `Overall`)
- `CompositeValidator`: Combines multiple validators

**Certificate Validators** (in `CoseSign1.Certificates.Validation`):
- `CertificateSignatureValidator`: Verifies cryptographic signature
- `CertificateChainValidator`: Validates certificate chain
- `CertificateExpirationValidator`: Checks validity period
- `CertificateCommonNameValidator`: Validates CN
- `CertificateKeyUsageValidator`: Validates EKU/key usage
- `CertificatePredicateValidator`: Custom predicate validation

### 8. Transparency Support

First-class support for transparency receipts via `ITransparencyProvider`:

```csharp
public interface ITransparencyProvider
{
    string ProviderName { get; }
    Task<CoseSign1Message> AddTransparencyProofAsync(
        CoseSign1Message message,
        CancellationToken cancellationToken = default);
}
```

**MST (Microsoft's Signing Transparency)** in `CoseSign1.Transparent.MST`:
- `MstTransparencyProvider`: Submits to MST service
- `MstReceiptValidator`: Validates MST receipts
- Integration with Azure Confidential Ledger

### 9. DID:x509 Integration

Native support for decentralized identifiers in `DIDx509`:

- **`DidX509Builder`**: Create DID:x509 URIs from certificate chains
- **`DidX509Parser`**: Parse DID:x509 URIs
- **`DidX509Validator`**: Validate DID against certificate chains

**Supported Policies**:
- `subject` - Match certificate subject attributes
- `san` - Match subject alternative names
- `eku` - Match enhanced key usage OIDs
- `fulcio-issuer` - Match Fulcio issuer extension

## Data Flow

### Signing Flow

```
1. Application provides: payload, content type, options
                ↓
2. Factory creates SigningContext
                ↓
3. SigningService.GetCoseSigner(context)
   a. Gets ISigningKey via GetSigningKey(context)
   b. Gets CoseKey from ISigningKey.GetCoseKey()
   c. Builds headers using IHeaderContributors
   d. Returns CoseSigner (CoseKey + headers)
                ↓
4. CoseSign1Message.SignDetached/SignEmbedded
                ↓
5. [Optional] TransparencyProvider.AddTransparencyProofAsync
                ↓
6. Returns signed COSE message bytes
```

### Validation Flow

```
1. Application provides: signed COSE message bytes
                     ↓
2. CoseSign1Message.DecodeSign1(bytes)
                     ↓
3. CoseSign1Verifier.Verify(message, ...)
    - Runs stages in order:
      resolution → trust → signature → post-signature
    - Short-circuits on failure (later stages become NotApplicable)

     Preferred: build a `CoseSign1VerificationPipeline` via `Cose.Sign1Verifier()` and call `pipeline.Verify(message)`.
                     ↓
4. Returns CoseSign1VerificationResult
    - Resolution/Trust/Signature/PostSignaturePolicy stage results
    - Overall result
                     ↓
5. Application acts on verification result
```

## Extension Points

V2 is designed for extensibility at multiple levels:

| Extension Point | Interface | Use Case |
|----------------|-----------|----------|
| Signing Services | `ISigningService<TOptions>` | Custom signing backends (HSM, cloud) |
| Certificate Sources | `ICertificateSource` | Custom certificate retrieval |
| Chain Builders | `ICertificateChainBuilder` | Custom chain building logic |
| Key Providers | `IPrivateKeyProvider` | Custom key generation (HSM, TPM) |
| Header Contributors | `IHeaderContributor` | Custom header injection |
| Validators | `IValidator` | Custom validation logic |
| Transparency | `ITransparencyProvider` | Custom transparency services |
| CLI Plugins | `IPlugin` | Custom CoseSignTool commands |
| CLI Signing Commands | `ISigningCommandProvider` | Custom signing commands (e.g., `sign-pfx`) |
| CLI Verification | `IVerificationProvider` | Custom verification providers |
| CLI Transparency | `ITransparencyProviderContributor` | Custom transparency integration |

### 10. Local Certificate Generation

The `CoseSign1.Certificates.Local` package provides ephemeral certificate generation for testing and development:

**Key Provider** (`IPrivateKeyProvider`):
```csharp
public interface IPrivateKeyProvider
{
    string ProviderName { get; }
    bool SupportsAlgorithm(KeyAlgorithm algorithm);
    IGeneratedKey GenerateKey(KeyAlgorithm algorithm, int? keySize = null);
}
```

**Available Key Providers**:
- **`SoftwareKeyProvider`**: In-memory key generation (default)
- Custom providers can support HSM, TPM, or cloud-based key storage

**Certificate Factories**:
- **`EphemeralCertificateFactory`**: Creates single certificates with configurable options
- **`CertificateChainFactory`**: Creates complete certificate hierarchies (Root → Intermediate → Leaf)

**Supported Algorithms**:
| Algorithm | Description |
|-----------|-------------|
| RSA | RSA with RSASSA-PSS (1024-16384 bit) |
| ECDSA | ECDSA with NIST curves (P-256, P-384, P-521) |
| ML-DSA | Post-quantum ML-DSA/Dilithium (44, 65, 87) |

For detailed documentation, see [CoseSign1.Certificates.Local](../components/certificates-local.md).

### 11. CLI Plugin Architecture

The `CoseSignTool.Abstractions` package defines the CLI plugin system:

**Core Plugin Interface**:
```csharp
public interface IPlugin
{
    string Name { get; }
    string Version { get; }
    string Description { get; }
    
    PluginExtensions GetExtensions();
    void RegisterCommands(Command rootCommand);
    Task InitializeAsync(IDictionary<string, string>? configuration = null);
}
```

**PluginExtensions Model**:
Plugins return all their capabilities through a single `PluginExtensions` object:
```csharp
public sealed class PluginExtensions
{
    public PluginExtensions(
        IEnumerable<ISigningCommandProvider> signingCommandProviders,
        IEnumerable<IVerificationProvider> verificationProviders,
        IEnumerable<ITransparencyProviderContributor> transparencyProviders);
    
    public IEnumerable<ISigningCommandProvider> SigningCommandProviders { get; }
    public IEnumerable<IVerificationProvider> VerificationProviders { get; }
    public IEnumerable<ITransparencyProviderContributor> TransparencyProviders { get; }
    
    public static PluginExtensions None => new(); // Empty extensions
}
```

**Extension Interfaces**:

| Interface | Purpose | Example |
|-----------|---------|---------|
| `ISigningCommandProvider` | Adds signing commands | `sign-pfx`, `sign-azure` |
| `IVerificationProvider` | Adds verification validators | Certificate validation, MST verification |
| `ITransparencyProviderContributor` | Integrates transparency services | MST receipt generation |

See [CLI Plugin Documentation](../plugins/README.md) for complete details.

## Thread Safety

| Component | Thread Safety | Notes |
|-----------|---------------|-------|
| Factories | Thread-safe | Can be shared across threads |
| Signing Services | Thread-safe | Most implementations use locks for key access |
| Validators | Thread-safe | Typically stateless |
| Header Contributors | Should be stateless | Avoid mutable state |

## Performance Considerations

1. **Certificate Caching**: Chain builders cache built chains
2. **CoseKey Caching**: `ISigningKey` implementations cache `CoseKey` instances
3. **Async Operations**: Non-blocking I/O for remote operations
4. **Memory Efficiency**: Uses `ReadOnlyMemory<byte>` and `Stream` overloads
5. **Minimal Allocations**: Value types and span-based APIs where appropriate

## Testing Strategy

V2 is designed for testability:

1. **Interface-based**: Easy to mock all dependencies
2. **Dependency Injection**: Dependencies are explicit constructor parameters
3. **Test Utilities**: `TestCertificateUtils` for test certificate generation
4. **High Coverage**: 95%+ code coverage with comprehensive tests

## Package Dependencies

```
CoseSign1.Abstractions (foundation)
    ↑
CoseSign1 (factories)
    ↑
CoseSign1.Certificates (certificate signing)
    ↑
CoseSign1.Certificates.AzureTrustedSigning (Azure integration)

CoseSign1.Abstractions
    ↑
CoseSign1.Validation (validation framework)
    ↑
CoseSign1.Certificates (certificate validators)

CoseSign1.Abstractions
    ↑
CoseSign1.Headers (CWT claims)

CoseSign1.Abstractions
    ↑
CoseSign1.Transparent.MST (MST receipts)

DIDx509 (standalone, minimal dependencies)
```

## Next Steps

- [Core Concepts](core-concepts.md) - Deep dive into key abstractions
- [Component Documentation](../components/README.md) - Per-package documentation
- [Plugin Documentation](../plugins/README.md) - CLI plugin architecture
- [Getting Started](../getting-started/quick-start.md) - Quick start guide
