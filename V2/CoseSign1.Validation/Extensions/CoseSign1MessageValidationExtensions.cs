// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace System.Security.Cryptography.Cose;

using CoseSign1.Validation;
using CoseSign1.Validation.Interfaces;
using Microsoft.Extensions.Logging;

/// <summary>
/// Extension methods for validating <see cref="CoseSign1Message"/> instances.
/// </summary>
/// <example>
/// Validation with a pre-built validator:
/// <code>
/// var validator = new CoseSign1ValidationBuilder()
///     .ValidateCertificate(cert => cert.ValidateChain())
///     .Build();
/// 
/// var message = CoseSign1Message.DecodeSign1(signatureBytes);
/// var result = message.Validate(validator);
/// 
/// if (result.Overall.IsValid)
/// {
///     Console.WriteLine("Signature is valid!");
/// }
/// </code>
/// 
/// Inline validation with configuration:
/// <code>
/// var result = message.Validate(builder => builder
///     .ValidateCertificate(cert => cert.ValidateChain())
///     .OverrideDefaultTrustPolicy(TrustPolicy.Require&lt;ChainTrustedAssertion&gt;()));
/// </code>
/// 
/// Auto-discovery validation (uses default components from referenced packages):
/// <code>
/// // Automatically discovers and uses default components from CoseSign1.Certificates, etc.
/// var result = message.Validate();
/// </code>
/// </example>
public static class CoseSign1MessageValidationExtensions
{
    /// <summary>
    /// Validates the COSE Sign1 message using a pre-built validator.
    /// </summary>
    /// <param name="message">The COSE Sign1 message to validate.</param>
    /// <param name="validator">The validator to use for validation.</param>
    /// <returns>A validation result containing results for each validation stage.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="message"/> or <paramref name="validator"/> is null.</exception>
    /// <example>
    /// <code>
    /// // Build a reusable validator
    /// var validator = new CoseSign1ValidationBuilder()
    ///     .ValidateCertificate(cert => cert.ValidateChain())
    ///     .Build();
    /// 
    /// // Validate multiple messages
    /// foreach (var signatureBytes in signatures)
    /// {
    ///     var message = CoseSign1Message.DecodeSign1(signatureBytes);
    ///     var result = message.Validate(validator);
    ///     // Process result...
    /// }
    /// </code>
    /// </example>
    public static CoseSign1ValidationResult Validate(
        this CoseSign1Message message,
        ICoseSign1Validator validator)
    {
        if (message == null)
        {
            throw new ArgumentNullException(nameof(message));
        }

        if (validator == null)
        {
            throw new ArgumentNullException(nameof(validator));
        }

        return validator.Validate(message);
    }

    /// <summary>
    /// Validates the COSE Sign1 message using a custom validation pipeline.
    /// </summary>
    /// <param name="message">The COSE Sign1 message to validate.</param>
    /// <param name="configure">A delegate to configure the validation builder. Must add at least one signing key resolver.</param>
    /// <param name="loggerFactory">Optional logger factory for creating loggers in validators.</param>
    /// <returns>A validation result containing results for each validation stage.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="message"/> or <paramref name="configure"/> is null.</exception>
    /// <exception cref="InvalidOperationException">Thrown when the configured builder does not include a signing key resolver.</exception>
    /// <remarks>
    /// This method builds a new validator for each call. For validating multiple messages with the same
    /// configuration, build a validator once with <see cref="CoseSign1ValidationBuilder"/> and reuse it
    /// via <see cref="Validate(CoseSign1Message, ICoseSign1Validator)"/>.
    /// </remarks>
    /// <example>
    /// <code>
    /// var result = message.Validate(builder => builder
    ///     .ValidateCertificate(cert => cert
    ///         .NotExpired()
    ///         .ValidateChain())
    ///     .OverrideDefaultTrustPolicy(TrustPolicy.Require&lt;ChainTrustedAssertion&gt;()));
    /// 
    /// if (result.Overall.IsValid)
    /// {
    ///     Console.WriteLine("Valid signature from trusted certificate chain!");
    /// }
    /// </code>
    /// </example>
    public static CoseSign1ValidationResult Validate(
        this CoseSign1Message message,
        Action<ICoseSign1ValidationBuilder>? configure = null,
        ILoggerFactory? loggerFactory = null)
    {
        if (message == null)
        {
            throw new ArgumentNullException(nameof(message));
        }

        if (configure == null)
        {
            throw new ArgumentNullException(nameof(configure));
        }

        var builder = new CoseSign1ValidationBuilder(loggerFactory);
        configure(builder);
        var validator = builder.Build();

        return validator.Validate(message);
    }

    /// <summary>
    /// Asynchronously validates the COSE Sign1 message using a pre-built validator.
    /// </summary>
    /// <param name="message">The COSE Sign1 message to validate.</param>
    /// <param name="validator">The validator to use for validation.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task containing the validation result.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="message"/> or <paramref name="validator"/> is null.</exception>
    /// <remarks>
    /// Use this overload when validation components may require network I/O
    /// (e.g., OCSP checks, CRL fetching, external trust services).
    /// </remarks>
    public static Task<CoseSign1ValidationResult> ValidateAsync(
        this CoseSign1Message message,
        ICoseSign1Validator validator,
        CancellationToken cancellationToken = default)
    {
        if (message == null)
        {
            throw new ArgumentNullException(nameof(message));
        }

        if (validator == null)
        {
            throw new ArgumentNullException(nameof(validator));
        }

        return validator.ValidateAsync(message, cancellationToken);
    }

    /// <summary>
    /// Asynchronously validates the COSE Sign1 message using a custom validation pipeline.
    /// </summary>
    /// <param name="message">The COSE Sign1 message to validate.</param>
    /// <param name="configure">A delegate to configure the validation builder. Must add at least one signing key resolver.</param>
    /// <param name="loggerFactory">Optional logger factory for creating loggers in validators.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task containing the validation result.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="message"/> or <paramref name="configure"/> is null.</exception>
    /// <exception cref="InvalidOperationException">Thrown when the configured builder does not include a signing key resolver.</exception>
    /// <remarks>
    /// <para>
    /// Use this overload when validation components may require network I/O
    /// (e.g., OCSP checks, CRL fetching, external trust services).
    /// </para>
    /// <para>
    /// This method builds a new validator for each call. For validating multiple messages with the same
    /// configuration, build a validator once with <see cref="CoseSign1ValidationBuilder"/> and reuse it
    /// via <see cref="ValidateAsync(CoseSign1Message, ICoseSign1Validator, CancellationToken)"/>.
    /// </para>
    /// </remarks>
    public static Task<CoseSign1ValidationResult> ValidateAsync(
        this CoseSign1Message message,
        Action<ICoseSign1ValidationBuilder>? configure = null,
        ILoggerFactory? loggerFactory = null,
        CancellationToken cancellationToken = default)
    {
        if (message == null)
        {
            throw new ArgumentNullException(nameof(message));
        }

        if (configure == null)
        {
            throw new ArgumentNullException(nameof(configure));
        }

        var builder = new CoseSign1ValidationBuilder(loggerFactory);
        configure(builder);
        var validator = builder.Build();

        return validator.ValidateAsync(message, cancellationToken);
    }
}
