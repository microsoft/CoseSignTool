// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Validation;

using CoseSign1.Validation.Abstractions;
using CoseSign1.Validation.Interfaces;
using Microsoft.Extensions.Logging;

/// <summary>
/// Provides default X.509 certificate validation components for auto-discovery.
/// </summary>
/// <remarks>
/// <para>
/// This provider supplies the fundamental certificate-based validation components:
/// <list type="bullet">
/// <item><description><see cref="CertificateSigningKeyResolver"/> - Resolves signing keys from x5chain headers</description></item>
/// <item><description><see cref="CertificateChainAssertionProvider"/> - Validates certificate chain trust</description></item>
/// </list>
/// </para>
/// <para>
/// Additional certificate validation (expiration, issuer, key usage, etc.) can be added
/// explicitly using the builder pattern.
/// </para>
/// </remarks>
public sealed class CertificateDefaultComponentProvider : IDefaultValidationComponentProvider
{
    /// <inheritdoc/>
    /// <remarks>
    /// Priority 100 places certificate components in the core validation tier,
    /// after any fundamental resolvers but before trust/transparency providers.
    /// </remarks>
    public int Priority => 100;

    /// <inheritdoc/>
    public IEnumerable<IValidationComponent> GetDefaultComponents(ILoggerFactory? loggerFactory)
    {
        // Core signing key resolution - required for signature verification
        yield return new CertificateSigningKeyResolver(logger:loggerFactory?.CreateLogger<CertificateSigningKeyResolver>());

        // Chain trust validation - establishes certificate trust assertions
        yield return new CertificateChainAssertionProvider(logger:loggerFactory?.CreateLogger<CertificateChainAssertionProvider>());
    }
}
