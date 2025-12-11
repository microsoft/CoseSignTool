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
│  (High-level signing operations)                            │
└─────────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────────┐
│                 Signing Service Layer                       │
│  ISigningService<TOptions>                                  │
│  - LocalCertificateSigningService                           │
│  - AzureTrustedSigningService                               │
│  - Custom implementations                                   │
└─────────────────────────────────────────────────────────────┘
                            │
        ┌───────────────────┴───────────────────┐
        │                                       │
┌───────────────────┐                  ┌───────────────────┐
│ Certificate       │                  │ Header            │
│ Management        │                  │ Contribution      │
│                   │                  │                   │
│ - Sources         │                  │ - IHeaderContrib  │
│ - Chain Builders  │                  │ - CWT Claims      │
│ - Key Providers   │                  │ - X5T/X5Chain     │
└───────────────────┘                  └───────────────────┘
                            │
┌─────────────────────────────────────────────────────────────┐
│                  Validation Layer                           │
│  IValidator<T> | ValidationResult                           │
│  - Composable validators                                    │
│  - Certificate validation                                   │
│  - Signature validation                                     │
│  - Custom validators                                        │
└─────────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────────┐
│                  Foundation Layer                           │
│  CoseSign1.Abstractions                                     │
│  - ISigningService<TOptions>                                │
│  - IHeaderContributor                                       │
│  - IValidator<T>                                            │
│  - SigningContext                                           │
└─────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Abstractions (`CoseSign1.Abstractions`)

Defines the foundational interfaces and contracts:

- **`ISigningService<TOptions>`**: Contract for signing services (local, remote, etc.)
- **`IHeaderContributor`**: Extension point for adding headers to COSE messages
- **`IValidator<T>`**: Contract for validation logic
- **`SigningContext`**: Encapsulates signing operation context
- **`SigningKeyMetadata`**: Metadata about cryptographic keys

### 2. Signing Services

Implementations of `ISigningService<TOptions>`:

- **`LocalCertificateSigningService`**: Signs with local certificates
- **`AzureTrustedSigningService`**: Signs using Azure Trusted Signing
- **Custom services**: Implement `ISigningService<TOptions>` for custom backends

Key characteristics:
- Stateless or thread-safe
- Dispose of unmanaged resources properly
- Support both sync and async operations
- Provide rich metadata about capabilities

### 3. Signature Factories

High-level APIs for creating COSE Sign1 messages:

- **`DirectSignatureFactory`**: Creates standard COSE Sign1 messages
- **`IndirectSignatureFactory`**: Creates indirect signatures (hash envelopes)

Factories handle:
- Header contribution coordination
- Content type management
- Embedded vs detached payloads
- Options processing

### 4. Certificate Management

Multi-layered certificate handling:

**Certificate Sources** (`ICertificateSource`):
- `PfxCertificateSource`: Load from PFX files
- `WindowsCertificateStoreCertificateSource`: Windows cert store
- `LinuxCertificateStoreCertificateSource`: Linux cert store
- Custom implementations

**Chain Builders** (`ICertificateChainBuilder`):
- `X509ChainBuilder`: Automatic chain building using system trust
- `ExplicitCertificateChainBuilder`: Explicit chain specification
- Custom chain building logic

**Key Providers** (`ISigningKeyProvider`):
- `DirectSigningKeyProvider`: Local key access
- `RemoteSigningKeyProvider`: Remote signing (HSM, cloud)
- ML-DSA support for post-quantum cryptography

### 5. Header Contributors

Extensible header contribution system:

```csharp
public interface IHeaderContributor
{
    HeaderMergeStrategy MergeStrategy { get; }
    void ContributeProtectedHeaders(CoseHeaderMap headers, HeaderContributorContext context);
    void ContributeUnprotectedHeaders(CoseHeaderMap headers, HeaderContributorContext context);
}
```

Built-in contributors:
- **`CertificateHeaderContributor`**: Adds X5T, X5Chain headers
- **`ContentTypeHeaderContributor`**: Adds content type header
- **`CwtClaimsHeaderContributor`**: Adds CWT claims (for SCITT)
- **`CoseHashEnvelopeHeaderContributor`**: Adds hash envelope headers

Custom contributors can:
- Add application-specific headers
- Implement custom merge strategies
- Access signing context and metadata

### 6. Validation Framework

Composable validation architecture:

```csharp
public interface IValidator<in T>
{
    ValidationResult Validate(T input);
    Task<ValidationResult> ValidateAsync(T input, CancellationToken cancellationToken = default);
}
```

**ValidationResult**:
- `IsValid`: Overall validation status
- `Failures`: Collection of validation failures
- `Metadata`: Additional validation metadata

**Validators**:
- **Certificate Validators**: Signature, expiration, EKU, SAN, common name, chain
- **Composite Validators**: Combine multiple validators with AND/OR logic
- **Function Validators**: Inline validation logic
- **Custom Validators**: Implement `IValidator<T>`

Builder pattern for fluent validation:

```csharp
var validator = new CoseMessageValidationBuilder()
    .AddCertificateValidator(builder => builder
        .ValidateSignature()
        .ValidateExpiration()
        .ValidateCommonName("TrustedSigner")
    )
    .AddCustomValidator(new MyCustomValidator())
    .Build();
```

### 7. Transparency Support

First-class support for transparency receipts:

- **MST (Merkle Search Tree)**: `CoseSign1.Transparent.MST`
- **CTS (Certificate Transparency Service)**: `CoseSign1.Transparent.CTS`
- **Abstract interfaces**: Implement custom transparency services

### 8. DID:x509 Integration

Native support for decentralized identifiers:

- **`DidX509Parser`**: Parse and validate DID:x509 identifiers
- **`DidX509Resolver`**: Resolve DIDs to DID documents
- **`DidX509Validator`**: Validate DID:x509 compliance
- **Policy validators**: EKU and SAN policy validation

## Data Flow

### Signing Flow

```
1. Application provides: payload, content type, options
                ↓
2. Factory creates SigningContext
                ↓
3. SigningService.GetCoseSigner(context)
   - Gets signing key
   - Applies header contributors (in order)
   - Returns CoseSigner
                ↓
4. CoseSign1Message.Sign(payload, signer)
   - Creates COSE Sign1 structure
   - Computes signature
   - Returns signed message bytes
                ↓
5. Application receives: signed COSE message
```

### Validation Flow

```
1. Application provides: signed COSE message
                ↓
2. Decode CoseSign1Message
                ↓
3. Validator.ValidateAsync(message)
   - Runs all configured validators
   - Collects validation results
   - Merges results
                ↓
4. Returns ValidationResult
   - IsValid: true/false
   - Failures: list of failures (if any)
   - Metadata: validation metadata
                ↓
5. Application acts on validation result
```

## Extension Points

V2 is designed for extensibility at multiple levels:

1. **Custom Signing Services**: Implement `ISigningService<TOptions>`
2. **Custom Certificate Sources**: Implement `ICertificateSource`
3. **Custom Chain Builders**: Implement `ICertificateChainBuilder`
4. **Custom Header Contributors**: Implement `IHeaderContributor`
5. **Custom Validators**: Implement `IValidator<T>`
6. **Custom Transparency Services**: Implement transparency interfaces

## Thread Safety

- **Factories**: Thread-safe, can be shared across threads
- **Signing Services**: Most implementations are thread-safe (documented per class)
- **Validators**: Typically stateless and thread-safe
- **Header Contributors**: Should be stateless and thread-safe

## Performance Considerations

1. **Certificate Caching**: Chain builders cache built chains
2. **Lazy Loading**: Resources loaded only when needed
3. **Async Operations**: Non-blocking I/O operations
4. **Streaming Support**: Large payloads can be streamed
5. **Minimal Allocations**: Value types and span-based APIs where appropriate

## Testing Strategy

V2 is designed for testability:

1. **Interface-based**: Easy to mock dependencies
2. **Dependency Injection**: Dependencies are explicit
3. **Pure Functions**: Many operations are pure and deterministic
4. **Test Utilities**: `TestCertificateUtils` for test certificate generation
5. **High Coverage**: 88.7% code coverage with comprehensive tests

## Next Steps

- [Core Concepts](core-concepts.md) - Deep dive into key abstractions
- [Signing Services](signing-services.md) - Learn about signing service patterns
- [Certificate Management](certificate-management.md) - Certificate handling details
- [Validation Framework](validation-framework.md) - Validation architecture deep dive
