// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.Extensions.DependencyInjection;

using CoseSign1.Abstractions;
using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Certificates.Interfaces;
using Microsoft.Extensions.DependencyInjection.Extensions;

/// <summary>
/// Service registration extensions for certificate chain building.
/// </summary>
public static class CertificateChainBuilderServiceCollectionExtensions
{
    /// <summary>
    /// Registers default certificate chain builder services.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The same collection for chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="services"/> is <see langword="null"/>.</exception>
    public static IServiceCollection AddCertificateChainBuilders(this IServiceCollection services)
    {
        Guard.ThrowIfNull(services);

        // Default chain builder used across local and remote certificate sources.
        services.TryAddTransient<X509ChainBuilder>();
        services.TryAddTransient<ICertificateChainBuilder>(sp => sp.GetRequiredService<X509ChainBuilder>());

        return services;
    }
}
