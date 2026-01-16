# CoseSign1.Factories Package

**NuGet**: `CoseSign1.Factories`  \
**Purpose**: Concrete factories for creating COSE_Sign1 messages (direct and indirect)  \
**Dependencies**: `CoseSign1.Abstractions`

## Overview

`CoseSign1.Factories` provides:

- A unified `CoseSign1MessageFactory` router that selects **direct vs indirect signing** based on the requested options type.
- The underlying `DirectSignatureFactory` and `IndirectSignatureFactory` implementations.

- **Direct signatures**: sign the payload bytes (optionally embedded, optionally detached).
- **Indirect signatures**: hash the payload bytes, then sign the hash (adds a COSE hash envelope to the message headers).

Both factories are built around `ISigningService<SigningOptions>` (from `CoseSign1.Abstractions`), which supplies a `CoseSigner` and any required header contributors for the chosen signing backend.

**Preferred entry point**: use `CoseSign1MessageFactory` and call the explicit overload that matches your intent:

- Use `CreateCoseSign1MessageBytes<DirectSignatureOptions>(...)` / `CreateCoseSign1Message<DirectSignatureOptions>(...)` for direct signatures.
- Use `CreateCoseSign1MessageBytes<IndirectSignatureOptions>(...)` / `CreateCoseSign1Message<IndirectSignatureOptions>(...)` for indirect signatures.
- If you pass an options instance, `TOptions` can be inferred (so you don’t have to write the generic argument explicitly).

## Extensibility (DI + Generic Routing)

V2 supports an extensibility model where additional packages can contribute new signing styles by implementing and registering:

- `ICoseSign1MessageFactory<TOptions>` for a custom options type `TOptions : SigningOptions`

Once registered in DI, the router can route calls to the correct factory.

### Taking full control of message creation

If you want to replace **all aspects** of COSE_Sign1 construction (not only key/digest behavior), implement `ICoseSign1MessageFactory<TOptions>` and register it for the options type you want to own.

See [Factory Extension Packages](../guides/factory-extension-packages.md).

### Recommended call pattern

Prefer the generic router API when you want extensibility beyond direct/indirect:

- `CreateCoseSign1MessageBytes<TOptions>(...)`
- `CreateCoseSign1Message<TOptions>(...)`

This avoids relying on runtime type checks and keeps `ReadOnlySpan<byte>` overloads efficient.

### Registering the default router and factories

`CoseSign1.Factories` ships a DI helper:

```csharp
using Microsoft.Extensions.DependencyInjection;

var services = new ServiceCollection();

// You still register the signing service (certs, AKV, etc.)
services.AddSingleton<ISigningService<SigningOptions>>(/* ... */);

// Registers DirectSignatureFactory, IndirectSignatureFactory, and CoseSign1MessageFactory router
services.AddCoseSign1Factories();
```

Resolve either:

- `ICoseSign1MessageFactoryRouter`.

### Example: future "Confidential Signing Service" factory package

A future package (for example `CoseSign1.Factories.CSS`) can add a new options type and factory:

```csharp
public sealed class ConfidentialSigningOptions : SigningOptions
{
    public bool SendDigestOnly { get; set; }
}

public sealed class ConfidentialSigningFactory : ICoseSign1MessageFactory<ConfidentialSigningOptions>
{
    // Call remote service, return already-transparent CoseSign1Message, etc.
}
```

And register it:

```csharp
services.AddTransient<ICoseSign1MessageFactory<ConfidentialSigningOptions>, ConfidentialSigningFactory>();
```

Then consumers can route cleanly:

```csharp
var router = serviceProvider.GetRequiredService<ICoseSign1MessageFactoryRouter>();

byte[] cose = router.CreateCoseSign1MessageBytes<ConfidentialSigningOptions>(
    payload,
    contentType: "application/octet-stream",
    options: new ConfidentialSigningOptions { SendDigestOnly = true });
```

## Key Types

## CoseSign1MessageFactory (preferred)

`CoseSign1MessageFactory` is a router that implements `ICoseSign1MessageFactoryRouter`.

- Delegates to the registered `ICoseSign1MessageFactory<TOptions>` implementation for the selected `TOptions`.
- Supports additional factories contributed by other packages via DI.

**Basic usage (single factory, choose per call):**

```csharp
using System.Security.Cryptography;
using System.Text;
using CoseSign1.Abstractions;
using CoseSign1.Factories;
using CoseSign1.Factories.Direct;
using CoseSign1.Factories.Indirect;

ISigningService<SigningOptions> signingService = /* e.g. CertificateSigningService, Azure Key Vault, ... */;

using var factory = new CoseSign1MessageFactory(signingService);

byte[] payload = Encoding.UTF8.GetBytes("hello");

// Direct signature
byte[] direct = factory.CreateCoseSign1MessageBytes(
    payload,
    "text/plain",
    new DirectSignatureOptions { EmbedPayload = true });

// Indirect signature (hash envelope)
byte[] indirect = factory.CreateCoseSign1MessageBytes(
    payload,
    "text/plain",
    new IndirectSignatureOptions { HashAlgorithm = HashAlgorithmName.SHA256 });
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
