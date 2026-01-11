# CoseSign1.Factories Package

**NuGet**: `CoseSign1.Factories`  \
**Purpose**: Concrete factories for creating COSE_Sign1 messages (direct and indirect)  \
**Dependencies**: `CoseSign1.Abstractions`

## Overview

`CoseSign1.Factories` provides:

- A unified `CoseSign1MessageFactory` router that selects **direct vs indirect signing** based on the runtime type of the provided `SigningOptions`.
- The underlying `DirectSignatureFactory` and `IndirectSignatureFactory` implementations.

- **Direct signatures**: sign the payload bytes (optionally embedded, optionally detached).
- **Indirect signatures**: hash the payload bytes, then sign the hash (adds a COSE hash envelope to the message headers).

Both factories are built around `ISigningService<SigningOptions>` (from `CoseSign1.Abstractions`), which supplies a `CoseSigner` and any required header contributors for the chosen signing backend.

**Preferred entry point**: use `CoseSign1MessageFactory` and call the explicit overload that matches your intent:

- `CreateDirectCoseSign1MessageBytes*` for direct signatures (payload signed)
- `CreateIndirectCoseSign1MessageBytes*` for indirect signatures (hash envelope)

The generic `CreateCoseSign1MessageBytes*` overloads still exist for scenarios where you need to route dynamically based on a `SigningOptions` instance.

## Key Types

## CoseSign1MessageFactory (preferred)

`CoseSign1MessageFactory` is a router that implements `ICoseSign1MessageFactory<SigningOptions>`.

- Delegates to `DirectSignatureFactory` when `options` is `DirectSignatureOptions`.
- Delegates to `IndirectSignatureFactory` when `options` is `IndirectSignatureOptions`.

**Basic usage (single factory, choose per call):**

```csharp
using System.Text;
using CoseSign1.Abstractions;
using CoseSign1.Factories;
using CoseSign1.Factories.Direct;
using CoseSign1.Factories.Indirect;

ISigningService<SigningOptions> signingService = /* e.g. CertificateSigningService, Azure Key Vault, ... */;

using var factory = new CoseSign1MessageFactory(signingService);

byte[] payload = Encoding.UTF8.GetBytes("hello");

// Direct signature
byte[] direct = factory.CreateDirectCoseSign1MessageBytes(payload, "text/plain");

// Indirect signature (hash envelope)
byte[] indirect = factory.CreateIndirectCoseSign1MessageBytes(payload, "text/plain");
```

## DirectSignatureFactory

`DirectSignatureFactory` creates COSE_Sign1 messages over the payload bytes.

- Implements: `ICoseSign1MessageFactory<DirectSignatureOptions>`

**Basic usage (bytes-in, bytes-out):**

```csharp
using System.Text;
using CoseSign1.Abstractions;
using CoseSign1.Factories.Direct;

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

## IndirectSignatureFactory

`IndirectSignatureFactory` hashes the payload and signs the hash. The resulting COSE_Sign1 message includes headers describing the hash envelope.

- Implements: `ICoseSign1MessageFactory<IndirectSignatureOptions>`

**Basic usage:**

```csharp
using System.Security.Cryptography;
using CoseSign1.Factories.Indirect;

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

- All factories implement `IDisposable`.
- Disposing a factory disposes the underlying signing service it was constructed with.

## See Also

- [Abstractions Package](abstractions.md)
- [Certificates Package](certificates.md)
- [Validation Package](validation.md)
- [Headers Package](headers.md)
- [Direct vs Indirect Signatures Guide](../guides/direct-vs-indirect.md)
