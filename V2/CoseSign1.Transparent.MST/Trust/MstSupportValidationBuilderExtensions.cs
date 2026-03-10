// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.Extensions.DependencyInjection;

using CoseSign1.Transparent.MST;
using CoseSign1.Transparent.MST.Trust;
using CoseSign1.Abstractions;
using CoseSign1.Validation.DependencyInjection;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Trust;

/// <summary>
/// Validation builder extensions for enabling MST support.
/// </summary>
public static class MstSupportValidationBuilderExtensions
{
    /// <summary>
    /// Enables MST support by registering the MST trust pack and related services.
    /// </summary>
    /// <param name="validationBuilder">The validation builder.</param>
    /// <param name="configure">Optional configuration callback.</param>
    /// <returns>The same builder instance for chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="validationBuilder"/> is null.</exception>
    public static ICoseValidationBuilder EnableMstSupport(
        this ICoseValidationBuilder validationBuilder,
        Action<MstTrustBuilder>? configure = null)
    {
        Guard.ThrowIfNull(validationBuilder);

        var services = validationBuilder.Services;

        var trustBuilder = new MstTrustBuilder();
        configure?.Invoke(trustBuilder);

        services.AddSingleton(trustBuilder.Options);

        // Default verifier adapter can be overridden by callers/tests.
        var verifierAlreadyAdded = false;
        foreach (var sd in services)
        {
            if (sd.ServiceType == typeof(ICodeTransparencyVerifier))
            {
                verifierAlreadyAdded = true;
                break;
            }
        }

        if (!verifierAlreadyAdded)
        {
            services.AddSingleton<ICodeTransparencyVerifier>(_ => (ICodeTransparencyVerifier)CodeTransparencyVerifierAdapter.Default);
        }

        services.AddSingleton<ITrustPack, MstTrustPack>();
        services.AddSingleton<ICounterSignatureResolver, MstReceiptCounterSignatureResolver>();
        services.AddSingleton<IToBeSignedAttestor, MstReceiptToBeSignedAttestor>();

        return validationBuilder;
    }
}
