# Authoring Validation Extension Packages

This guide is for authors who want to ship a NuGet package that plugs into the **V2 staged validation model**.

If you only need app-specific rules in your own code, see [Custom Validators](custom-validators.md).

## What an extension package contributes

V2 validation is composed via DI. Extension packages typically contribute one or more of:

- `ISigningKeyResolver`: resolves an `ISigningKey` (key material resolution stage).
- `IPostSignatureValidator`: business rules that run after trust + signature verification.
- `ITrustPack`: contributes both fact production and secure-by-default trust-plan fragments.

In V2, a trust pack is the preferred unit of reuse:

- It implements `ITrustPack : IMultiTrustFactProducer` (so it can produce facts).
- It exposes its default trust contribution via `ITrustPack.GetDefaults()`.

## Opt-in API surface (`Enable*Support`)

Packages should expose a single opt-in extension method on `ICoseValidationBuilder`, typically named `Enable*Support(...)`.

Examples in this repo:

- `EnableCertificateSupport`
- `EnableAzureKeyVaultSupport`
- `EnableMstSupport`

Consumers use the “gate” created by `ConfigureCoseValidation()`:

```csharp
using Microsoft.Extensions.DependencyInjection;
using CoseSign1.Validation.DependencyInjection;

var services = new ServiceCollection();
var validation = services.ConfigureCoseValidation();

validation.EnableFooSupport(foo =>
{
    // optional configuration
});
```

## Inside `EnableFooSupport(...)`

Your extension method should register any staged services and your trust pack (usually as singletons):

```csharp
services.AddSingleton<ISigningKeyResolver, FooSigningKeyResolver>();
services.AddSingleton<IPostSignatureValidator, FooPostSignatureValidator>();

// The trust pack can also register any dependencies it needs (HTTP clients, options, etc.).
services.AddSingleton<ITrustPack, FooTrustPack>();
```

Design guidance:

- Keep registrations additive (multiple trust packs can be enabled together).
- Make fact production lazy and bounded (use `TrustEvaluationOptions` budgets where applicable).

## Adding explicit requirements (policy fragments)

If your extension needs to impose requirements beyond its default fragments, prefer exposing that configuration as a `TrustPlanPolicy` fragment.

- In the CLI plugin model, providers can implement `IVerificationProviderWithTrustPlanPolicy` and return a policy fragment that will be AND-ed with other active providers.
- In library/app integrations, callers can author `TrustPlanPolicy` directly and register a `CompiledTrustPlan` (see [Validation Framework](../architecture/validation-framework.md)).

## Testing patterns

Recommended tests for extension packages:

- `Enable*Support` tests: verify the expected services are registered.
- Trust pack tests: verify defaults (`GetDefaults()`) and fact production behavior.
- End-to-end tests: sign a test message, enable your trust pack, validate the message.

## See also

- [Validation Framework](../architecture/validation-framework.md)
- [Trust Plan Deep Dive](trust-policy.md)
- [Audit and Replay](audit-and-replay.md)
