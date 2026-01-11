# Authoring Validation Extension Packages

This guide is for authors who want to ship a NuGet package that adds new validation behavior to the V2 validation pipeline (similar to the built-in extension packages in this repo: Certificates, Azure Key Vault, and MST transparency).

If you only need app-specific rules in your own code, see [Creating Custom Validators](custom-validators.md).

## What to build (the V2 model)

V2 validation is composed from a list of **validation components** (`IValidationComponent`). The validator orchestrator pre-filters components by calling `IsApplicableTo(...)`, and then invokes stage-specific interfaces implemented by the component (for example signing-key resolution, trust assertion extraction, post-signature checks).

Your extension package typically provides:

- One or more components implementing `IValidationComponent` and one or more stage interfaces.
- A package-specific base class (recommended) that inherits from `ValidationComponentBase`.
- A default component provider for auto-discovery (optional but recommended).
- Fluent builder extensions (recommended) so callers can configure your components without referencing concrete types.

## Inherit from `ValidationComponentBase` (to get applicability caching)

`CoseSign1.Validation.Abstractions.ValidationComponentBase` provides a default `IsApplicableTo(...)` implementation with configurable caching. To benefit from the caching behavior:

- Derive your components from `ValidationComponentBase` (directly or indirectly).
- Override `ComputeApplicability(...)` (not `IsApplicableTo(...)`).

This is the recommended pattern used by the extension packages in this repo.

### Why this matters

`IsApplicableTo(...)` can be called repeatedly during validation composition and execution. Keeping it **fast** and letting the base class cache the result avoids recomputing header checks for every stage.

### Best practices for `ComputeApplicability(...)`

- Keep it **cheap and deterministic** (header presence, content type checks, etc.).
- Do **not** perform network I/O, chain-building, or cryptographic verification here.
- Prefer applicability checks that depend only on the message (+ explicit validation options).
  - The base class cache key is type + message identity + a small subset of options.
  - If applicability depends on per-instance configuration, either refactor so it doesn’t (preferred), or disable caching for that component.

### Disabling caching (only if you must)

If you have a component whose applicability truly depends on mutable state or per-instance configuration, pass `ValidationComponentOptions.NoCache` to the base constructor:

```csharp
public sealed class MyComponent : ValidationComponentBase
{
    public MyComponent() : base(ValidationComponentOptions.NoCache) { }

    public override string ComponentName => nameof(MyComponent);
}
```

## Recommended: provide an extension-specific base class

Follow the pattern used by:

- Certificates: `CertificateValidationComponentBase` (requires `x5chain` based on `CertificateHeaderLocation`)
- Azure Key Vault: `AkvValidationComponentBase` (requires a `kid` header; optionally AKV-shaped)
- MST: `MstValidationComponentBase` (optionally requires an MST receipt)

This keeps applicability logic consistent across all components in your package and centralizes helper utilities.

A minimal pattern:

```csharp
public abstract class FooValidationComponentBase : ValidationComponentBase
{
    protected FooValidationComponentBase(ValidationComponentOptions? options = null) : base(options) { }

    protected override bool ComputeApplicability(CoseSign1Message message, CoseSign1ValidationOptions? options = null)
        => HasFooHeader(message);

    protected static bool HasFooHeader(CoseSign1Message message) => /* cheap header check */;
}
```

## Recommended: support default component auto-discovery

If you want your components to be picked up automatically when a caller uses the “default validation” path (for example `message.Validate(...)` without manually composing a pipeline), implement `IDefaultValidationComponentProvider` and add the assembly-level attribute.

1) Add an assembly attribute (commonly in `DefaultComponentRegistration.cs`):

```csharp
using CoseSign1.Validation.Abstractions;

[assembly: DefaultValidationComponentProvider(typeof(FooDefaultComponentProvider))]
```

2) Implement the provider:

```csharp
public sealed class FooDefaultComponentProvider : IDefaultValidationComponentProvider
{
    public int Priority => 250;

    public IEnumerable<IValidationComponent> GetDefaultComponents(ILoggerFactory? loggerFactory)
    {
        yield return new FooAssertionProvider(/* ... */);
    }
}
```

Notes:

- Use `Priority` to place your components relative to others (see the tier guidance on `IDefaultValidationComponentProvider`).
- Prefer **detection / fact emission** as defaults (safe, low-risk). Require explicit configuration for expensive validation or networked checks.

## Recommended: add fluent builder extensions

Extension packages in this repo expose configuration through `ICoseSign1ValidationBuilder` extension methods:

- `ValidateCertificate(...)`
- `ValidateAzureKeyVault(...)`
- `ValidateMst(...)`

This gives a consistent call-site experience and allows you to evolve internal component structure without breaking users.

Guidelines:

- Prefer `ValidateX(...)` naming for consistency.
- Throw on null `builder` / `configure`.
- Only add components if the configuration actually requested them (see the AKV builder pattern).

## Testing patterns

Recommended tests for extension packages:

- Default provider tests: ensure `GetDefaultComponents(...)` returns the expected component set.
- Builder extension tests: verify the extension method adds the expected components to `ICoseSign1ValidationBuilder`.
- Applicability tests: validate that your base class correctly opts-in/out based on headers/options (these are cheap unit tests and help keep caching assumptions safe).

## See also

- [Validation Framework](../architecture/validation-framework.md)
- [CoseSign1.Validation component docs](../components/validation.md)
- [Creating Custom Validators](custom-validators.md)

## Reference implementations in this repo

These are the concrete patterns this guide is describing.

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
