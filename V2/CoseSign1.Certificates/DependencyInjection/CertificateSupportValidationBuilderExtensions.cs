// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.Extensions.DependencyInjection;

using CoseSign1.Abstractions;
using CoseSign1.Certificates.Validation;
using CoseSign1.Certificates.Trust;
using CoseSign1.Certificates.Trust.Facts.Producers;
using CoseSign1.Validation.DependencyInjection;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Trust;

/// <summary>
/// Validation builder extensions for enabling certificate support.
/// </summary>
public static class CertificateSupportValidationBuilderExtensions
{
    /// <summary>
    /// Enables certificate support by registering the certificate trust pack and related services.
    /// </summary>
    /// <param name="validationBuilder">The validation builder.</param>
    /// <param name="configure">Optional configuration callback.</param>
    /// <returns>The same builder instance for chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="validationBuilder"/> is null.</exception>
    public static ICoseValidationBuilder EnableCertificateSupport(
        this ICoseValidationBuilder validationBuilder,
        Action<CertificateTrustBuilder>? configure = null)
    {
        Guard.ThrowIfNull(validationBuilder);

        var services = validationBuilder.Services;

        var trustBuilder = new CertificateTrustBuilder();
        configure?.Invoke(trustBuilder);

        services.AddSingleton(trustBuilder.Options);

        // Trust packs are the only registration surface: each pack provides both default policy fragments
        // and fact production capabilities.
        services.AddSingleton<ITrustPack, X509CertificateTrustPack>();

        // Staged services: enable key resolution for x5chain/x5t.
        var alreadyAddedResolver = false;
        foreach (var sd in services)
        {
            if (sd.ServiceType == typeof(ISigningKeyResolver) && sd.ImplementationType == typeof(CertificateSigningKeyResolver))
            {
                alreadyAddedResolver = true;
                break;
            }
        }

        if (!alreadyAddedResolver)
        {
            services.AddSingleton<ISigningKeyResolver, CertificateSigningKeyResolver>();
        }

        return validationBuilder;
    }
}
