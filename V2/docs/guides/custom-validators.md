# Custom Validators

This guide explains how to add custom validation logic to the **V2 staged validation pipeline**.

## Where custom logic belongs

V2 validation is orchestrated by `CoseSign1Validator` and runs stages in this order:

1. Key material resolution (`ISigningKeyResolver`)
2. Signing key trust (`CompiledTrustPlan`)
3. Signature verification
4. Post-signature validation (`IPostSignatureValidator`)

Most app-specific rules should be implemented as `IPostSignatureValidator`.

Use a custom `ISigningKeyResolver` only when you need a new way to locate/construct signing keys (e.g., a new header type or external key store).

## Example: post-signature validator (content type allow-list)

This validator rejects messages whose logical content type (direct or indirect) is not in an allow-list:

```csharp
using System.Security.Cryptography.Cose;
using CoseSign1.Abstractions.Extensions;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Results;

public sealed class ContentTypeAllowListValidator : IPostSignatureValidator
{
    private readonly HashSet<string> _allowed;

    public ContentTypeAllowListValidator(IEnumerable<string> allowedContentTypes)
    {
        _allowed = new HashSet<string>(allowedContentTypes, StringComparer.OrdinalIgnoreCase);
    }

    public ValidationResult Validate(IPostSignatureValidationContext context)
    {
        if (!context.Message.TryGetContentType(out var contentType) || string.IsNullOrWhiteSpace(contentType))
        {
            return ValidationResult.Failure(
                validatorName: nameof(ContentTypeAllowListValidator),
                message: "Missing content type header",
                errorCode: "MISSING_CONTENT_TYPE");
        }

        if (!_allowed.Contains(contentType))
        {
            return ValidationResult.Failure(
                validatorName: nameof(ContentTypeAllowListValidator),
                message: $"Content type '{contentType}' is not allowed",
                errorCode: "CONTENT_TYPE_NOT_ALLOWED");
        }

        return ValidationResult.Success(nameof(ContentTypeAllowListValidator));
    }

    public Task<ValidationResult> ValidateAsync(
        IPostSignatureValidationContext context,
        CancellationToken cancellationToken = default)
        => Task.FromResult(Validate(context));
}
```

## Registering your validator (DI)

Register your post-signature validator in DI and enable the trust packs you want:

```csharp
using CoseSign1.Validation.DependencyInjection;
using CoseSign1.Validation.Interfaces;
using Microsoft.Extensions.DependencyInjection;

var services = new ServiceCollection();
var validation = services.ConfigureCoseValidation();

validation.EnableCertificateSupport();
validation.EnableMstSupport();

services.AddSingleton<IPostSignatureValidator>(
    _ => new ContentTypeAllowListValidator(new[] { "application/json" }));

using var sp = services.BuildServiceProvider();
var validator = sp.GetRequiredService<ICoseSign1ValidatorFactory>().Create();
```

## Async validators

If your validator needs network I/O (policy service call, online revocation check, etc.), implement `ValidateAsync(...)` and use `message.ValidateAsync(...)` in your app.

## See also

- [Validation Framework](../architecture/validation-framework.md)
- [Trust Plan Deep Dive](trust-policy.md)
- [Validation Extension Packages](validation-extension-packages.md)
