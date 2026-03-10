# Authoring Factory Extension Packages

This guide is for authors who want to ship a NuGet package that plugs into the **V2 signing pipeline** by contributing a custom `ICoseSign1MessageFactory<TOptions>`.

Use this approach when you want to take over **all aspects** of COSE_Sign1 construction and return:

- raw COSE bytes (`byte[]`), and/or
- a decoded `CoseSign1Message`

…instead of only extending key resolution or digest/signing behavior.

## What problem this solves

V2 intentionally supports extensibility at multiple layers:

- **Key/signing layer**: implement `ISigningService<TSigningOptions>` / `ISigningKey` to control key material and how a `CoseSigner` is created.
- **Header layer**: implement `IHeaderContributor` to add or validate headers while still using the built-in factories.
- **Message factory layer (this guide)**: implement `ICoseSign1MessageFactory<TOptions>` to control the *entire* COSE message creation process.

If you need to produce a COSE_Sign1 message via a completely different mechanism (custom message layout, remote signer that returns an already-formed COSE message, alternate hashing/envelope strategy, etc.), the factory abstraction is the right integration point.

## What an extension package contributes

A factory extension package typically contributes one or more of:

- A custom options type: `TOptions : SigningOptions`
- A factory implementation: `ICoseSign1MessageFactory<TOptions>`
- A DI opt-in extension method (recommended): `Add*Factories(...)`

Once registered, consumers route to your factory through `ICoseSign1MessageFactoryRouter` using the generic `TOptions` overloads.

## Minimal pattern

### 1) Define an options type

```csharp
using CoseSign1.Abstractions;

public sealed class MySigningOptions : SigningOptions
{
    // Add whatever knobs your factory needs.
    // Example: route to a remote signing endpoint, change header layout, etc.
    public Uri? Endpoint { get; set; }
}
```

### 2) Implement `ICoseSign1MessageFactory<MySigningOptions>`

Your factory can do as much (or as little) as it needs:

- create and sign a message locally using `System.Security.Cryptography.Cose`
- call a remote signing service that returns COSE bytes
- embed/detach payload
- apply custom protected/unprotected headers
- optionally apply transparency proofs

```csharp
using CoseSign1.Abstractions;
using CoseSign1.Abstractions.Transparency;
using System.Security.Cryptography.Cose;

public sealed class MySigningFactory : ICoseSign1MessageFactory<MySigningOptions>
{
    public IReadOnlyList<ITransparencyProvider>? TransparencyProviders { get; }

    public MySigningFactory(IReadOnlyList<ITransparencyProvider>? transparencyProviders = null)
    {
        TransparencyProviders = transparencyProviders;
    }

    public byte[] CreateCoseSign1MessageBytes(byte[] payload, string contentType, MySigningOptions? options = default)
    {
        // 1. Construct the COSE_Sign1 message (however your package needs)
        // 2. Return encoded bytes
        throw new NotImplementedException();
    }

    public byte[] CreateCoseSign1MessageBytes(ReadOnlySpan<byte> payload, string contentType, MySigningOptions? options = default)
        => CreateCoseSign1MessageBytes(payload.ToArray(), contentType, options);

    public Task<byte[]> CreateCoseSign1MessageBytesAsync(byte[] payload, string contentType, MySigningOptions? options = default, CancellationToken cancellationToken = default)
        => Task.FromResult(CreateCoseSign1MessageBytes(payload, contentType, options));

    public Task<byte[]> CreateCoseSign1MessageBytesAsync(ReadOnlyMemory<byte> payload, string contentType, MySigningOptions? options = default, CancellationToken cancellationToken = default)
        => Task.FromResult(CreateCoseSign1MessageBytes(payload.ToArray(), contentType, options));

    public Task<byte[]> CreateCoseSign1MessageBytesAsync(Stream payloadStream, string contentType, MySigningOptions? options = default, CancellationToken cancellationToken = default)
        => throw new NotImplementedException();

    public CoseSign1Message CreateCoseSign1Message(byte[] payload, string contentType, MySigningOptions? options = default)
        => throw new NotImplementedException();

    public CoseSign1Message CreateCoseSign1Message(ReadOnlySpan<byte> payload, string contentType, MySigningOptions? options = default)
        => CreateCoseSign1Message(payload.ToArray(), contentType, options);

    public Task<CoseSign1Message> CreateCoseSign1MessageAsync(byte[] payload, string contentType, MySigningOptions? options = default, CancellationToken cancellationToken = default)
        => Task.FromResult(CreateCoseSign1Message(payload, contentType, options));

    public Task<CoseSign1Message> CreateCoseSign1MessageAsync(ReadOnlyMemory<byte> payload, string contentType, MySigningOptions? options = default, CancellationToken cancellationToken = default)
        => Task.FromResult(CreateCoseSign1Message(payload.ToArray(), contentType, options));

    public Task<CoseSign1Message> CreateCoseSign1MessageAsync(Stream payloadStream, string contentType, MySigningOptions? options = default, CancellationToken cancellationToken = default)
        => throw new NotImplementedException();

    public void Dispose()
    {
    }
}
```

Notes:

- If your factory applies transparency proofs, respect `SigningOptions.DisableTransparency` and `SigningOptions.FailOnTransparencyError`.
- The `TransparencyProviders` property exists so DI can supply providers and so callers can inspect what is configured.

### 3) Register the factory in DI

```csharp
using CoseSign1.Abstractions;
using CoseSign1.Factories;
using Microsoft.Extensions.DependencyInjection;

var services = new ServiceCollection();

services.AddTransient<ICoseSign1MessageFactory<MySigningOptions>, MySigningFactory>();

// Router resolves factories by TOptions from DI.
services.AddTransient<ICoseSign1MessageFactoryRouter, CoseSign1MessageFactory>();
```

### 4) Route to your factory

```csharp
var provider = services.BuildServiceProvider();
var router = provider.GetRequiredService<ICoseSign1MessageFactoryRouter>();

byte[] cose = router.CreateCoseSign1MessageBytes<MySigningOptions>(
    payload,
    contentType: "application/octet-stream",
    options: new MySigningOptions { Endpoint = new Uri("https://sign.example") });
```

## Taking over direct/indirect signing end-to-end

If your goal is to replace the built-in **direct** and/or **indirect** behavior entirely (not just the key/digest layer), you have two common patterns.

### Pattern A: Don’t register the built-ins

Register only the router and your factories:

```csharp
using CoseSign1.Abstractions;
using CoseSign1.Factories;

services.AddTransient<ICoseSign1MessageFactoryRouter, CoseSign1MessageFactory>();

services.AddTransient<ICoseSign1MessageFactory<DirectSignatureOptions>, MyDirectFactory>();
services.AddTransient<ICoseSign1MessageFactory<IndirectSignatureOptions>, MyIndirectFactory>();
```

This makes it unambiguous that *your* package owns message creation for those option types.

### Pattern B: Register the built-ins, then override by options type

If you still want the convenience of `AddCoseSign1Factories()` (router wiring, default types, etc.), register your factory **after** it:

```csharp
using CoseSign1.Abstractions;
using CoseSign1.Factories;

services.AddCoseSign1Factories();

// Override routing for DirectSignatureOptions
services.AddTransient<ICoseSign1MessageFactory<DirectSignatureOptions>, MyDirectFactory>();
```

Guidance:

- Prefer consuming `ICoseSign1MessageFactoryRouter` rather than resolving `DirectSignatureFactory` / `IndirectSignatureFactory` directly.
- If you want to prevent accidental use of the built-in concrete types, avoid documenting/resolving those concrete types in your integration.

## Recommended “opt-in” surface for packages

Like validation trust packs, factory packages should expose a single opt-in DI extension method so consumers can adopt your behavior explicitly.

Example shape:

```csharp
using CoseSign1.Abstractions;
using CoseSign1.Factories;
using Microsoft.Extensions.DependencyInjection;

public static class MyFactoriesServiceCollectionExtensions
{
    public static IServiceCollection AddMySigningFactories(this IServiceCollection services)
    {
        services.AddTransient<ICoseSign1MessageFactoryRouter, CoseSign1MessageFactory>();
        services.AddTransient<ICoseSign1MessageFactory<MySigningOptions>, MySigningFactory>();
        return services;
    }
}
```

## See also

- [CoseSign1.Factories](../components/cosesign1.factories.md)
- [CoseSign1.Abstractions](../components/abstractions.md)
- [Signing Services](../architecture/signing-services.md)
- [Header Contributors](../architecture/header-contributors.md)
