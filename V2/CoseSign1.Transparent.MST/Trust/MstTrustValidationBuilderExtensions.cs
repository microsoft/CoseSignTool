// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.Extensions.DependencyInjection;

using CoseSign1.Transparent.MST.Trust;
using CoseSign1.Abstractions;
using CoseSign1.Validation.DependencyInjection;
using CoseSign1.Validation.Trust;

/// <summary>
/// Validation builder extensions for enabling the MST trust pack.
/// </summary>
public static class MstTrustValidationBuilderExtensions
{
    /// <summary>
    /// Enables the MST trust pack by registering default trust-plan fragments and related services.
    /// </summary>
    /// <param name="validationBuilder">The validation builder.</param>
    /// <param name="configure">Optional configuration callback.</param>
    /// <returns>The same builder instance for chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="validationBuilder"/> is null.</exception>
    public static ICoseValidationBuilder EnableMstTrust(
        this ICoseValidationBuilder validationBuilder,
        Action<MstTrustBuilder>? configure = null)
    {
        Guard.ThrowIfNull(validationBuilder);

        var services = validationBuilder.Services;

        var trustBuilder = new MstTrustBuilder();
        configure?.Invoke(trustBuilder);

        services.AddSingleton(trustBuilder.Options);
        services.AddSingleton<ITrustPack, MstTrustPack>();

        return validationBuilder;
    }
}
