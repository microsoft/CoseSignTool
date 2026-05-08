// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.Extensions.DependencyInjection;

using CoseSign1.Validation.Trust.Frontends;
using CoseSign1.Validation.TrustFrontends.Json;
using System.Text.Json;

/// <summary>
/// ServiceCollection extensions for registering the <c>cose-tp-json/v1</c> frontend and its
/// translator cache.
/// </summary>
public static class TrustFrontendsJsonServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="CoseTpJsonFrontend"/> as a singleton implementation of
    /// <see cref="ICoseTrustPolicyFrontend{JsonDocument}"/> plus a singleton
    /// <see cref="TrustPolicyTranslatorCache"/>.
    /// </summary>
    /// <param name="services">The service collection to configure.</param>
    /// <param name="options">Optional cache options; defaults to capacity 32 (D9).</param>
    /// <returns>The same <paramref name="services"/> instance for chaining.</returns>
    /// <exception cref="System.ArgumentNullException">Thrown when <paramref name="services"/> is null.</exception>
    public static IServiceCollection AddCoseTpJsonFrontend(this IServiceCollection services, TrustPolicyTranslatorOptions? options = null)
    {
        Cose.Abstractions.Guard.ThrowIfNull(services);

        services.AddSingleton<CoseTpJsonFrontend>();
        services.AddSingleton<ICoseTrustPolicyFrontend<JsonDocument>>(sp => sp.GetRequiredService<CoseTpJsonFrontend>());
        services.AddSingleton(options ?? new TrustPolicyTranslatorOptions());
        services.AddSingleton<TrustPolicyTranslatorCache>();
        return services;
    }
}
