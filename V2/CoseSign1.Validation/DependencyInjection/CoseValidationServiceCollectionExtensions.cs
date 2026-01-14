// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.Extensions.DependencyInjection;
using CoseSign1.Validation.DependencyInjection;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.PostSignature;


/// <summary>
/// ServiceCollection extensions for configuring COSE validation.
/// </summary>
public static class CoseValidationServiceCollectionExtensions
{
    /// <summary>
    /// Enables staged configuration for COSE validation.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>A builder that can be extended by trust packs.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="services"/> is null.</exception>
    public static ICoseValidationBuilder ConfigureCoseValidation(this IServiceCollection services)
    {
        if (services == null)
        {
            throw new ArgumentNullException(nameof(services));
        }

        // Core message facts are safe to register by default because fact producers are lazy:
        // they will not execute unless requested by an active policy rule.
        var builder = new CoseValidationBuilder(services);
        builder.EnableMessageFacts();

        // Register core staged services.
        // - Counter-signature resolution is contributed by trust packs via DI.
        // - Indirect signature payload validation is secure-by-default and runs post-signature.
        AddIfMissing<IPostSignatureValidator, IndirectSignatureValidator>(services);

        // DI convenience factory for creating a fully-wired validator.
        AddIfMissingScoped<ICoseSign1ValidatorFactory, CoseSign1ValidatorFactory>(services);

        return builder;
    }

    private static void AddIfMissing<TService, TImplementation>(IServiceCollection services)
        where TService : class
        where TImplementation : class, TService
    {
        var alreadyAdded = false;
        foreach (var sd in services)
        {
            if (sd.ServiceType == typeof(TService) && sd.ImplementationType == typeof(TImplementation))
            {
                alreadyAdded = true;
                break;
            }
        }

        if (!alreadyAdded)
        {
            services.AddSingleton<TService, TImplementation>();
        }
    }

    private static void AddIfMissingScoped<TService, TImplementation>(IServiceCollection services)
        where TService : class
        where TImplementation : class, TService
    {
        var alreadyAdded = false;
        foreach (var sd in services)
        {
            if (sd.ServiceType == typeof(TService) && sd.ImplementationType == typeof(TImplementation))
            {
                alreadyAdded = true;
                break;
            }
        }

        if (!alreadyAdded)
        {
            services.AddScoped<TService, TImplementation>();
        }
    }
}
