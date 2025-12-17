# CoseSign1 Package

**NuGet**: `CoseSign1`  \
**Purpose**: Concrete factories for creating COSE_Sign1 messages (direct and indirect)  \
**Dependencies**: `CoseSign1.Abstractions`

## Overview

`CoseSign1` provides two primary implementations of `ICoseSign1MessageFactory<TOptions>`:

- **Direct signatures**: sign the payload bytes (optionally embedded, optionally detached).
- **Indirect signatures**: hash the payload bytes, then sign the hash (adds a COSE hash envelope to the message headers).

Both factories are built around `ISigningService<SigningOptions>` (from `CoseSign1.Abstractions`), which supplies a `CoseSigner` and any required header contributors for the chosen signing backend.

## Key Types

### DirectSignatureFactory

`DirectSignatureFactory` creates COSE_Sign1 messages over the payload bytes.

- Implements: `ICoseSign1MessageFactory<DirectSignatureOptions>`
- Constructor:

```csharp
public DirectSignatureFactory(
    ISigningService<SigningOptions> signingService,
    IReadOnlyList<ITransparencyProvider>? transparencyProviders = null,
    ILogger<DirectSignatureFactory>? logger = null);
```

**Basic usage (bytes-in, bytes-out):**

```csharp
using CoseSign1.Abstractions;
using CoseSign1.Direct;

ISigningService<SigningOptions> signingService = /* e.g. CertificateSigningService, Azure Key Vault, ... */;

using var factory = new DirectSignatureFactory(signingService);

byte[] payload = Encoding.UTF8.GetBytes("hello");
byte[] coseBytes = factory.CreateCoseSign1MessageBytes(payload, "text/plain");

File.WriteAllBytes("payload.cose", coseBytes);
```

**Create a `CoseSign1Message` (decoded object):**

```csharp
using System.Security.Cryptography.Cose;

var message = factory.CreateCoseSign1Message(payload, "text/plain");
// or decode bytes later:
var decoded = CoseMessage.DecodeSign1(coseBytes);
```

**Detached signatures (payload not embedded):**

```csharp
var options = new DirectSignatureOptions
{
    EmbedPayload = false,
};

byte[] signatureOnly = factory.CreateCoseSign1MessageBytes(payload, "application/octet-stream", options);

File.WriteAllBytes("payload.bin", payload);
File.WriteAllBytes("payload.cose", signatureOnly);
```

### IndirectSignatureFactory

`IndirectSignatureFactory` hashes the payload and signs the hash. The resulting COSE_Sign1 message includes headers describing the hash envelope.

- Implements: `ICoseSign1MessageFactory<IndirectSignatureOptions>`
- Constructors:

```csharp
public IndirectSignatureFactory(
    ISigningService<SigningOptions> signingService,
    IReadOnlyList<ITransparencyProvider>? transparencyProviders = null,
    ILogger<IndirectSignatureFactory>? logger = null,
    ILoggerFactory? loggerFactory = null);

public IndirectSignatureFactory(
    DirectSignatureFactory directFactory,
    ILogger<IndirectSignatureFactory>? logger = null);
```

**Basic usage:**

```csharp
using CoseSign1.Indirect;

using var factory = new IndirectSignatureFactory(signingService);

byte[] payload = File.ReadAllBytes("large.bin");
var options = new IndirectSignatureOptions
{
    HashAlgorithm = HashAlgorithmName.SHA256,
    PayloadLocation = "https://example.invalid/large.bin",
};

byte[] coseBytes = factory.CreateCoseSign1MessageBytes(payload, "application/octet-stream", options);
```

## Common Signing Options

Both `DirectSignatureOptions` and `IndirectSignatureOptions` inherit from `SigningOptions`, which supports:

- `AdditionalHeaderContributors`: add extra headers for a specific signing operation.
- `AdditionalContext`: pass custom data to header contributors.
- `AdditionalData`: AAD covered by the signature.
- `DisableTransparency` / `FailOnTransparencyError`: per-operation transparency behavior.

## Resource Ownership

- Both factories implement `IDisposable`.
- Disposing a factory disposes the underlying signing service it was constructed with.

## See Also

- [Abstractions Package](abstractions.md)
- [Certificates Package](certificates.md)
- [Validation Package](validation.md)
- [Headers Package](headers.md)
- [Direct vs Indirect Signatures Guide](../guides/direct-vs-indirect.md)
