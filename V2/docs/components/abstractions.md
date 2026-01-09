# CoseSign1.Abstractions Package

**NuGet**: `CoseSign1.Abstractions`  \
**Purpose**: Core interfaces and contracts shared across the V2 ecosystem  \
**Dependencies**: `System.Security.Cryptography.Cose`

## Overview

`CoseSign1.Abstractions` defines the shared contracts used by factories, signing services, header contributors, and transparency integrations. Most consumers will use concrete packages (like `CoseSign1` and `CoseSign1.Certificates`), but these abstractions are the surface you implement when adding a new signing backend or custom header logic.

## Key Abstractions

### ISigningService<TSigningOptions>

The signing service is responsible for producing a `CoseSigner` (from the .NET runtime) for a specific signing operation.

- Generic and covariant: `ISigningService<CertificateSigningOptions>` can be used as `ISigningService<SigningOptions>`.
- Provides `CreateSigningOptions()` so callers can discover/configure service-specific options.

Core members:

- `CoseSigner GetCoseSigner(SigningContext context)`
- `TSigningOptions CreateSigningOptions()`
- `bool IsRemote`
- `SigningServiceMetadata ServiceMetadata`

### SigningContext

`SigningContext` carries per-operation information into the signing service and header contributors:

- Payload as either `Stream` or `ReadOnlyMemory<byte>`
- `ContentType`
- `AdditionalHeaderContributors` (per operation)
- `AdditionalContext` (arbitrary key/value for contributors)

### SigningOptions

`SigningOptions` is the base options type for operations. Concrete services may derive from it (e.g., `CertificateSigningOptions`).

Common properties include:

- `AdditionalHeaderContributors`
- `AdditionalContext`
- `AdditionalData` (AAD covered by the signature)
- `DisableTransparency` / `FailOnTransparencyError`

### ICoseSign1MessageFactory<TOptions>

Factories create COSE_Sign1 messages using an `ISigningService<SigningOptions>`.

- Generic over an options type that derives from `SigningOptions`
- Supports sync and async creation
- Supports bytes or `CoseSign1Message` results
- Exposes `TransparencyProviders` (applied after signing)

Key methods include:

- `CreateCoseSign1MessageBytes(...)` / `CreateCoseSign1MessageBytesAsync(...)`
- `CreateCoseSign1Message(...)` / `CreateCoseSign1MessageAsync(...)`

### IHeaderContributor

Header contributors add protected and/or unprotected headers at sign time.

- Synchronous (no async API)
- Must be thread-safe
- Supports explicit conflict behavior via `HeaderMergeStrategy`

Key members:

- `HeaderMergeStrategy MergeStrategy { get; }`
- `void ContributeProtectedHeaders(CoseHeaderMap headers, HeaderContributorContext context)`
- `void ContributeUnprotectedHeaders(CoseHeaderMap headers, HeaderContributorContext context)`

### ISigningKey

`ISigningKey` is the abstraction between the signing service and the underlying key material.

- Emits a `CoseKey` via `GetCoseKey()`
- Exposes key metadata via `SigningKeyMetadata`
- Links back to the owning signing service

## Transparency

`CoseSign1.Abstractions.Transparency` defines `ITransparencyProvider`, which can:

- Augment a signed `CoseSign1Message` with a transparency proof (e.g., a receipt)
- Verify transparency proofs on an existing message

In V2, this is typically implemented by embedding receipt/proof data into COSE headers.

Factories in `CoseSign1` can apply configured transparency providers automatically after signing.

## See Also

- [Core Concepts](../architecture/core-concepts.md)
- [CoseSign1 Package](cosesign1.md)
- [Headers Package](headers.md)
- [Validation Package](validation.md)

