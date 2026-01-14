# Custom Validators Guide

This guide explains how to add custom validation logic to the CoseSignTool V2 validation pipeline.

If you are authoring a reusable NuGet package that plugs into validation (and you want applicability caching + default component auto-discovery), see [Authoring Validation Extension Packages](validation-extension-packages.md).

## Overview

V2 validation is **component-based**. You provide one or more `IValidationComponent`s and the orchestrator runs them in a fixed order:
If you are authoring a reusable NuGet package that plugs into validation, see [Authoring Validation Extension Packages](validation-extension-packages.md).
1. Key material resolution (`ISigningKeyResolver`)
2. Trust assertions + trust policy (`ISigningKeyAssertionProvider` + `TrustPolicy`)
3. Signature verification (crypto using the resolved key)
V2 validation is **staged**. You register services for specific stages and the orchestrator runs them in a fixed order:

Most custom business rules belong in a post-signature validator.
2. Signature verification (crypto using the resolved key)
3. Trust evaluation (compiled trust plan)
4. Post-signature checks (`IPostSignatureValidator`)
Use `IPostSignatureValidator` when your check depends on verified signature + resolved identity + trust decision.

For applicability caching, inherit from `ValidationComponentBase`.

```csharp
using CoseSign1.Abstractions.Extensions;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Results;
    private readonly HashSet<string> _allowed;

    public ContentTypeValidator(IEnumerable<string> allowedContentTypes)
public sealed class ContentTypeValidator : IPostSignatureValidator
        _allowed = new HashSet<string>(allowedContentTypes, StringComparer.OrdinalIgnoreCase);
    }

    public string ComponentName => nameof(ContentTypeValidator);

    public override bool IsApplicableTo(System.Security.Cryptography.Cose.CoseSign1Message? message, CoseSign1ValidationOptions? options = null)
        => message != null;
            return ValidationResult.Failure(ComponentName, "Missing content type header", errorCode: "MISSING_CONTENT_TYPE");
        }

        const string Name = nameof(ContentTypeValidator);

        if (!_allowed.Contains(contentType))
        {
            return ValidationResult.Failure(Name, new ValidationFailure("Missing content type header", errorCode: "MISSING_CONTENT_TYPE"));
        }

        return ValidationResult.Success(ComponentName);
    }
            return ValidationResult.Failure(Name, new ValidationFailure($"Content type '{contentType}' is not allowed", errorCode: "CONTENT_TYPE_NOT_ALLOWED"));
    public Task<ValidationResult> ValidateAsync(IPostSignatureValidationContext context, CancellationToken cancellationToken = default)
        => Task.FromResult(Validate(context));
        return ValidationResult.Success(Name);
```

## Registering components

### Inline (single call)

## Registering validators
var result = message.Validate(builder => builder
### With dependency injection
    .AddComponent(new ContentTypeValidator(new[] { "application/json" })));
```
using CoseSign1.Validation;
using CoseSign1.Validation.DependencyInjection;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Trust.Plan;
using Microsoft.Extensions.DependencyInjection;

var result = message.Validate(builder =>
var builder = services.ConfigureCoseValidation();

// Enable one or more trust packs that contribute signing-key resolvers and trust policy.
builder.EnableCertificateTrust();

// Add your custom post-signature validator.
services.AddSingleton<IPostSignatureValidator>(
    _ => new ContentTypeValidator(new[] { "application/json" }));

using var serviceProvider = services.BuildServiceProvider();

var trustPlan = CompiledTrustPlan.CompileDefaults(serviceProvider);
var validator = new CoseSign1Validator(
    serviceProvider.GetServices<ISigningKeyResolver>(),
    serviceProvider.GetServices<IPostSignatureValidator>(),
    trustPlan);
{
    builder.ValidateCertificate(cert => cert.ValidateChain());

    foreach (var component in serviceProvider.GetServices<IValidationComponent>())

Ordering is primarily driven by the orchestrator stages. Within a given stage, components run in the order they were added to the builder.

## Async validation
If your component needs network I/O (OCSP/CRL, external policy service, etc.), implement the `ValidateAsync(...)` method and use `message.ValidateAsync(...)`.

## See also

- [Architecture: Validation Framework](../architecture/validation-framework.md)
- [Trust Policy Guide](trust-policy.md)
- [Authoring Validation Extension Packages](validation-extension-packages.md)
