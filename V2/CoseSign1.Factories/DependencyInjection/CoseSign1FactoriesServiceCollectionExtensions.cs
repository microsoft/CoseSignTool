// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.Extensions.DependencyInjection;

using System.Linq;
using CoseSign1.Abstractions;
using CoseSign1.Abstractions.Transparency;
using CoseSign1.Factories;
using CoseSign1.Factories.Direct;
using CoseSign1.Factories.Indirect;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;

/// <summary>
/// Service registration extensions for COSE_Sign1 factories.
/// </summary>
public static class CoseSign1FactoriesServiceCollectionExtensions
{
    /// <summary>
    /// Registers the default COSE_Sign1 factories and the <see cref="CoseSign1MessageFactory"/> router.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The same collection for chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="services"/> is <see langword="null"/>.</exception>
    /// <remarks>
    /// This enables an extensibility model where additional packages can register their own
    /// <see cref="ICoseSign1MessageFactory{TOptions}"/> implementations and the router can select them.
    /// </remarks>
    public static IServiceCollection AddCoseSign1Factories(this IServiceCollection services)
    {
        if (services is null)
        {
            throw new ArgumentNullException(nameof(services));
        }

        services.TryAddTransient(sp =>
        {
            var signingService = sp.GetRequiredService<ISigningService<SigningOptions>>();
            var logger = sp.GetService<ILogger<DirectSignatureFactory>>();

            var providers = sp.GetService<IReadOnlyList<ITransparencyProvider>>();
            if (providers is null)
            {
                var enumerable = sp.GetService<IEnumerable<ITransparencyProvider>>() ?? Enumerable.Empty<ITransparencyProvider>();
                var list = enumerable as IReadOnlyList<ITransparencyProvider> ?? enumerable.ToList();
                providers = list.Count == 0 ? null : list;
            }

            return new DirectSignatureFactory(signingService, providers, logger);
        });

        services.TryAddTransient(sp =>
        {
            var direct = sp.GetRequiredService<DirectSignatureFactory>();
            var logger = sp.GetService<ILogger<IndirectSignatureFactory>>();
            return new IndirectSignatureFactory(direct, logger);
        });

        services.TryAddTransient(sp => new CoseSign1MessageFactory(sp, sp.GetService<ILoggerFactory>()));

        services.TryAddTransient<ICoseSign1MessageFactory<DirectSignatureOptions>>(sp => sp.GetRequiredService<DirectSignatureFactory>());
        services.TryAddTransient<ICoseSign1MessageFactory<IndirectSignatureOptions>>(sp => sp.GetRequiredService<IndirectSignatureFactory>());
        services.TryAddTransient<ICoseSign1MessageFactoryRouter>(sp => sp.GetRequiredService<CoseSign1MessageFactory>());

        return services;
    }
}
