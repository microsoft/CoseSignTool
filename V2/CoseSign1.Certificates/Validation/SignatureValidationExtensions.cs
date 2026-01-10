// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Validation;

/// <summary>
/// Extension methods for adding certificate validation to the builder.
/// </summary>
public static class SignatureValidationExtensions
{
    /// <summary>
    /// Adds certificate validation using a fluent builder API.
    /// This is the preferred entry point for certificate-based validation.
    /// </summary>
    /// <param name="builder">The validation builder.</param>
    /// <param name="configure">Action to configure the certificate validation builder.</param>
    /// <returns>The builder for method chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="builder"/> or <paramref name="configure"/> is null.</exception>
    /// <example>
    /// <code>
    /// var validator = Cose.Sign1Message()
    ///     .ValidateCertificate(cert => cert
    ///         .NotExpired()
    ///         .HasCommonName("TrustedSigner")
    ///         .ValidateChain())
    ///     .OverrideDefaultTrustPolicy(TrustPolicy.Claim("x509.chain.trusted"))
    ///     .Build();
    /// </code>
    /// </example>
    public static ICoseSign1ValidationBuilder ValidateCertificate(
        this ICoseSign1ValidationBuilder builder,
        Action<ICertificateValidationBuilder> configure)
    {
        if (builder is null)
        {
            throw new ArgumentNullException(nameof(builder));
        }

        if (configure is null)
        {
            throw new ArgumentNullException(nameof(configure));
        }

        var certBuilder = new CertificateValidationBuilder(builder.LoggerFactory);
        configure(certBuilder);

        // Add each assertion provider component to the builder
        foreach (var component in certBuilder.Build())
        {
            builder.AddComponent(component);
        }

        return builder;
    }
}