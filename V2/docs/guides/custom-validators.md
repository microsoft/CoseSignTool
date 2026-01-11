# Custom Validators Guide

This guide explains how to add custom validation logic to the CoseSignTool V2 validation pipeline.

If you are authoring a reusable NuGet package that plugs into validation (and you want applicability caching + default component auto-discovery), see [Authoring Validation Extension Packages](validation-extension-packages.md).

## Overview

V2 validation is **component-based**. You provide one or more `IValidationComponent`s and the orchestrator runs them in a fixed order:

1. Key material resolution (`ISigningKeyResolver`)
2. Trust assertions + trust policy (`ISigningKeyAssertionProvider` + `TrustPolicy`)
3. Signature verification (crypto using the resolved key)
4. Post-signature checks (`IPostSignatureValidator`)

Most custom business rules belong in a post-signature validator.

## Implementing a post-signature validator

Use `IPostSignatureValidator` when your check depends on verified signature + resolved identity + trust decision.

For applicability caching, inherit from `ValidationComponentBase`.

```csharp
using CoseSign1.Abstractions.Extensions;
using CoseSign1.Validation;
using CoseSign1.Validation.Abstractions;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Results;

public sealed class ContentTypeValidator : ValidationComponentBase, IPostSignatureValidator
{
    private readonly HashSet<string> _allowed;

    public ContentTypeValidator(IEnumerable<string> allowedContentTypes)
    {
        _allowed = new HashSet<string>(allowedContentTypes, StringComparer.OrdinalIgnoreCase);
    }

    public string ComponentName => nameof(ContentTypeValidator);

    public override bool IsApplicableTo(System.Security.Cryptography.Cose.CoseSign1Message? message, CoseSign1ValidationOptions? options = null)
        => message != null;

    public ValidationResult Validate(IPostSignatureValidationContext context)
    {
        if (!context.Message.TryGetContentType(out string? contentType) || string.IsNullOrWhiteSpace(contentType))
        {
            return ValidationResult.Failure(ComponentName, "Missing content type header", errorCode: "MISSING_CONTENT_TYPE");
        }

        if (!_allowed.Contains(contentType))
        {
            return ValidationResult.Failure(ComponentName, $"Content type '{contentType}' is not allowed", errorCode: "CONTENT_TYPE_NOT_ALLOWED");
        }

        return ValidationResult.Success(ComponentName);
    }

    public Task<ValidationResult> ValidateAsync(IPostSignatureValidationContext context, CancellationToken cancellationToken = default)
        => Task.FromResult(Validate(context));
}
```

## Registering components

### Inline (single call)

```csharp
var result = message.Validate(builder => builder
    .ValidateCertificate(cert => cert.ValidateChain())
    .AddComponent(new ContentTypeValidator(new[] { "application/json" })));
```

### Reusable validator

```csharp
var validator = new CoseSign1ValidationBuilder()
    .ValidateCertificate(cert => cert.ValidateChain())
    .AddComponent(new ContentTypeValidator(new[] { "application/json" }))
    .Build();

var result = message.Validate(validator);
```

### With dependency injection

Register components as `IValidationComponent` and add them to the builder:

```csharp
services.AddSingleton<IValidationComponent>(
    _ => new ContentTypeValidator(new[] { "application/json" }));

// ... later, when validating:
var result = message.Validate(builder =>
{
    // Ensure you add at least one signing key resolver (for example, certificate validation)
    builder.ValidateCertificate(cert => cert.ValidateChain());

    foreach (var component in serviceProvider.GetServices<IValidationComponent>())
    {
        builder.AddComponent(component);
    }
});
```

## Ordering

Ordering is primarily driven by the orchestrator stages. Within a given stage, components run in the order they were added to the builder.

## Async validation

If your component needs network I/O (OCSP/CRL, external policy service, etc.), implement the `ValidateAsync(...)` method and use `message.ValidateAsync(...)`.

## See also

- [Architecture: Validation Framework](../architecture/validation-framework.md)
- [Trust Policy Guide](trust-policy.md)
- [Authoring Validation Extension Packages](validation-extension-packages.md)
