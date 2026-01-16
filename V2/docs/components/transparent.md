# CoseSign1.Transparent

Transparency abstractions for integrating COSE Sign1 messages with transparency services.

## Overview

Transparency providers can:

- **Augment** a signed `CoseSign1Message` with a verifiable proof (for example, an MST receipt) in unprotected headers.
- **Verify** the embedded proof later.

When you pass providers to `DirectSignatureFactory` / `IndirectSignatureFactory`, the factory can call the providers automatically after signing.

## Installation

```bash
dotnet add package CoseSign1.Transparent --version 2.0.0-preview
```

## ITransparencyProvider

```csharp
using System.Security.Cryptography.Cose;
using System.Threading;
using System.Threading.Tasks;

public interface ITransparencyProvider
{
    string ProviderName { get; }

    Task<CoseSign1Message> AddTransparencyProofAsync(
        CoseSign1Message message,
        CancellationToken cancellationToken = default);

    Task<TransparencyValidationResult> VerifyTransparencyProofAsync(
        CoseSign1Message message,
        CancellationToken cancellationToken = default);
}
```

## Available Implementations

### Microsoft's Signing Transparency (MST)

```csharp
using Azure.Security.CodeTransparency;
using CoseSign1.Transparent.MST;

var client = new CodeTransparencyClient(new Uri("https://dataplane.codetransparency.azure.net"));
var provider = new MstTransparencyProvider(client);
```

See [MST Documentation](mst.md) for details.

## Usage

### Add a Proof

```csharp
using CoseSign1.Factories.Direct;

var signed = factory.CreateCoseSign1Message<DirectSignatureOptions>(payload, contentType: "application/octet-stream");
var withProof = await provider.AddTransparencyProofAsync(signed);
```

### Verify a Proof

```csharp
var result = await provider.VerifyTransparencyProofAsync(withProof);
Console.WriteLine(result.IsValid);
```

## See Also

- [MST Component](mst.md)
- [SCITT Compliance Guide](../guides/scitt-compliance.md)
- [Validation Framework](../architecture/validation-framework.md)
