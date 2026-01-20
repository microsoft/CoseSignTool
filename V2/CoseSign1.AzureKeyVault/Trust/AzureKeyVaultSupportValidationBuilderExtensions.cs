// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.Extensions.DependencyInjection;

using CoseSign1.Abstractions;
using CoseSign1.AzureKeyVault.Trust;
using CoseSign1.AzureKeyVault.Validation;
using CoseSign1.Validation.DependencyInjection;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Trust;

/// <summary>
/// Validation builder extensions for enabling Azure Key Vault support.
/// </summary>
public static class AzureKeyVaultSupportValidationBuilderExtensions
{
    /// <summary>
    /// Enables Azure Key Vault support by registering the Azure Key Vault trust pack and related services.
    /// </summary>
    /// <param name="validationBuilder">The validation builder.</param>
    /// <param name="configure">Optional configuration callback.</param>
    /// <returns>The same builder instance for chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="validationBuilder"/> is null.</exception>
    public static ICoseValidationBuilder EnableAzureKeyVaultSupport(
        this ICoseValidationBuilder validationBuilder,
        Action<AzureKeyVaultTrustBuilder>? configure = null)
    {
        Guard.ThrowIfNull(validationBuilder);

        var services = validationBuilder.Services;

        var trustBuilder = new AzureKeyVaultTrustBuilder();
        configure?.Invoke(trustBuilder);

        services.AddSingleton(trustBuilder.Options);
        services.AddSingleton<ITrustPack, AzureKeyVaultTrustPack>();

        AddSigningKeyResolverIfMissing<AzureKeyVaultCoseKeySigningKeyResolver>(services);
        if (!trustBuilder.Options.OfflineOnly)
        {
            AddSigningKeyResolverIfMissing<AzureKeyVaultOnlineSigningKeyResolver>(services);
        }

        return validationBuilder;
    }

    private static void AddSigningKeyResolverIfMissing<TImplementation>(IServiceCollection services)
        where TImplementation : class, ISigningKeyResolver
    {
        var alreadyAdded = false;
        foreach (var sd in services)
        {
            if (sd.ServiceType == typeof(ISigningKeyResolver) && sd.ImplementationType == typeof(TImplementation))
            {
                alreadyAdded = true;
                break;
            }
        }

        if (!alreadyAdded)
        {
            services.AddSingleton<ISigningKeyResolver, TImplementation>();
        }
    }
}
