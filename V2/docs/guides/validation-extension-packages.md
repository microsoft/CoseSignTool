# Authoring Validation Extension Packages

This guide is for authors who want to ship a NuGet package that plugs into the **V2 staged validation model** (similar to the built-in extension packages in this repo: Certificates, Azure Key Vault, and MST transparency).

If you only need app-specific rules in your own code, see [Creating Custom Validators](custom-validators.md).

## What to build (the V2 model)

V2 validation is **staged** and composed through dependency injection. Extension packages contribute one or more of:

- `ISigningKeyResolver` — resolves an `ISigningKey` used to verify the COSE signature.
- `ICounterSignatureResolver` — discovers counter-signatures (if your trust model needs them).
- `IPostSignatureValidator` — runs after signature verification and trust evaluation.
- `ITrustPack` — contributes default trust-plan fragments and related services.

Packages are expected to expose a single opt-in extension method of the form `Enable*Trust(...)` (for example `EnableCertificateTrust`, `EnableAzureKeyVaultTrust`, `EnableMstTrust`).

## Registration pattern: `ConfigureCoseValidation` + `Enable*Trust`

The core package provides a DI “gate” so trust-pack extensions don’t pollute `IServiceCollection` IntelliSense:

```csharp
using Microsoft.Extensions.DependencyInjection;
using CoseSign1.Validation.DependencyInjection;

var services = new ServiceCollection();
var builder = services.ConfigureCoseValidation();

// Your package should expose an extension like this:
builder.EnableFooTrust(foo =>
{
    // optional configuration
});
```

Inside your `EnableFooTrust` implementation, register services (typically singletons):

```csharp
services.AddSingleton<ISigningKeyResolver, FooSigningKeyResolver>();
services.AddSingleton<IPostSignatureValidator, FooPostSignatureValidator>();
services.AddSingleton<ITrustPack, FooTrustPack>();
```

## Applicability and performance

V2 no longer uses a component list with `IsApplicableTo(...)` pre-filtering or reflection-based discovery.

If your logic only applies when specific headers are present, keep the check inside your resolver/validator and return a `ValidationResult.NotApplicable(...)` (or a “no result” from a resolver) cheaply.

## Testing patterns

Recommended tests for extension packages:

- `Enable*Trust` tests: ensure expected services are registered in the container.
- Trust pack tests: ensure your `ITrustPack` contributes the expected trust-plan fragments.
- End-to-end tests: sign a test message and validate it with a service provider configured with your trust pack.

## See also

- [Validation Framework](../architecture/validation-framework.md)
- [Creating Custom Validators](custom-validators.md)

### Core base + caching

- `ValidationComponentBase` (caching + `ComputeApplicability` hook):
    - ../../CoseSign1.Validation/Abstractions/ValidationComponentBase.cs
- `ValidationComponentOptions` (`CachingStrategy`, defaults, `NoCache`):
    - ../../CoseSign1.Validation/Abstractions/ValidationComponentOptions.cs

### Extension-specific base classes

- Certificates:
    - `CertificateValidationComponentBase`: ../../CoseSign1.Certificates/Validation/CertificateValidationComponentBase.cs
- Azure Key Vault:
    - `AkvValidationComponentBase`: ../../CoseSign1.AzureKeyVault/Validation/AkvValidationComponentBase.cs
- MST:
    - `MstValidationComponentBase`: ../../CoseSign1.Transparent.MST/Validation/MstValidationComponentBase.cs

### Default component auto-discovery

- Contract + attribute:
    - `IDefaultValidationComponentProvider`: ../../CoseSign1.Validation/Abstractions/IDefaultValidationComponentProvider.cs
    - Assembly attribute usage:
        - Certificates: ../../CoseSign1.Certificates/DefaultComponentRegistration.cs
        - Azure Key Vault: ../../CoseSign1.AzureKeyVault/DefaultComponentRegistration.cs
        - MST: ../../CoseSign1.Transparent.MST/DefaultComponentRegistration.cs

- Default providers:
    - Certificates: ../../CoseSign1.Certificates/Validation/CertificateDefaultComponentProvider.cs
    - Azure Key Vault: ../../CoseSign1.AzureKeyVault/Validation/AkvDefaultComponentProvider.cs
    - MST: ../../CoseSign1.Transparent.MST/Validation/MstDefaultComponentProvider.cs

### Fluent builder extensions (`ValidateX(...)`)

- Certificates: ../../CoseSign1.Certificates/Validation/SignatureValidationExtensions.cs
- Azure Key Vault: ../../CoseSign1.AzureKeyVault/Validation/AzureKeyVaultValidationExtensions.cs
- MST: ../../CoseSign1.Transparent.MST/Validation/MstValidationExtensions.cs

### Tests that lock in the patterns

- Default provider tests:
    - Certificates: ../../CoseSign1.Certificates.Tests/Validation/CertificateDefaultComponentProviderTests.cs
    - Azure Key Vault: ../../CoseSign1.AzureKeyVault.Tests/Validation/AkvDefaultComponentProviderTests.cs
    - MST: ../../CoseSign1.Transparent.MST.Tests/Validation/MstDefaultComponentProviderTests.cs

- Builder extension tests:
    - Certificates: ../../CoseSign1.Certificates.Tests/Validation/SignatureValidationExtensionsTests.cs
    - Azure Key Vault: ../../CoseSign1.AzureKeyVault.Tests/Validation/AzureKeyVaultValidationExtensionsTests.cs
    - MST: ../../CoseSign1.Transparent.MST.Tests/Validation/MstValidationExtensionsTests.cs
