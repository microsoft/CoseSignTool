// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.Extensions.DependencyInjection;

using CoseSign1.Validation.Trust.PlanPolicy.Spec.Registry;

/// <summary>
/// ServiceCollection extensions that wire the Phase 3 attribute-driven fact registry into a
/// host's DI container.
/// </summary>
/// <remarks>
/// This entry point is additive — existing DI defaults are unchanged. Phase 2 (frontend-json)
/// and Phase 4 (conformance) consume <see cref="IFactRegistry"/> through this registration.
/// </remarks>
public static class AttributeDrivenFactRegistryServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="AttributeDrivenFactRegistry"/> as the singleton implementation of
    /// <see cref="IFactRegistry"/>. The registry is built once on first resolution by scanning
    /// every loaded assembly whose simple name starts with <c>CoseSign1.</c>.
    /// </summary>
    /// <param name="services">The service collection to configure.</param>
    /// <returns>The same <paramref name="services"/> instance for chaining.</returns>
    /// <exception cref="System.ArgumentNullException">Thrown when <paramref name="services"/> is null.</exception>
    /// <remarks>
    /// Idempotent: calling this method multiple times does not register duplicate factories.
    /// If an <see cref="IFactRegistry"/> registration already exists in the container, this
    /// call is a no-op so callers can opt into the attribute-driven default without overriding
    /// a host-supplied registry.
    /// </remarks>
    public static IServiceCollection AddAttributeDrivenFactRegistry(this IServiceCollection services)
    {
        Cose.Abstractions.Guard.ThrowIfNull(services);

        for (int i = 0; i < services.Count; i++)
        {
            if (services[i].ServiceType == typeof(IFactRegistry))
            {
                return services;
            }
        }

        services.AddSingleton<IFactRegistry>(static _ => AttributeDrivenFactRegistry.FromLoadedAssemblies());
        return services;
    }
}
