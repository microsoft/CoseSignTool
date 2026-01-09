// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Extensions;

using System.Security.Cryptography.Cose;
using CoseSign1.Validation.Interfaces;
using Microsoft.Extensions.Logging;

/// <summary>
/// Extension methods for validating <see cref="CoseSign1Message"/> instances.
/// Provides shorthand validation methods that use the fluent builder internally.
/// </summary>
/// <example>
/// Validation with a pre-built validator:
/// <code>
/// var validator = Cose.Sign1Message()
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
/// Validation with custom configuration:
/// <code>
/// var result = message.Validate(builder => builder
///     .ValidateCertificate(cert => cert.ValidateChain())
///     .OverrideDefaultTrustPolicy(TrustPolicy.Claim("x509.chain.trusted")));
/// </code>
/// </example>
public static class CoseSign1MessageValidationExtensions
{
    /// <summary>
    /// Validates the COSE Sign1 message using a pre-built validator.
    /// </summary>
    /// <param name="message">The COSE Sign1 message to validate.</param>
    /// <param name="validator">The validator to use for validation.</param>
    /// <returns>A staged validation result containing results for each validation stage.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="message"/> or <paramref name="validator"/> is null.</exception>
    /// <example>
    /// <code>
    /// // Build a reusable validator
    /// var validator = Cose.Sign1Message()
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
    /// <param name="configure">A delegate to configure the validation builder. Must add at least one signature validator.</param>
    /// <param name="loggerFactory">Optional logger factory for creating loggers in validators.</param>
    /// <returns>A staged validation result containing results for each validation stage.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="message"/> or <paramref name="configure"/> is null.</exception>
    /// <exception cref="InvalidOperationException">Thrown when the configured builder does not include a signature validator.</exception>
    /// <remarks>
    /// <para>
    /// This method builds a new validator for each call. For validating multiple messages with the same
    /// configuration, consider building a validator once with <see cref="Cose.Sign1Message(ILoggerFactory?)"/>
    /// and reusing it via <see cref="Validate(CoseSign1Message, ICoseSign1Validator)"/>.
    /// </para>
    /// </remarks>
    /// <example>
    /// <code>
    /// var result = message.Validate(builder => builder
    ///     .ValidateCertificate(cert => cert
    ///         .NotExpired()
    ///         .ValidateChain())
    ///     .OverrideDefaultTrustPolicy(TrustPolicy.Claim("x509.chain.trusted")));
    /// 
    /// if (result.Overall.IsValid)
    /// {
    ///     Console.WriteLine("Valid signature from trusted certificate chain!");
    /// }
    /// </code>
    /// </example>
    public static CoseSign1ValidationResult Validate(
        this CoseSign1Message message,
        Action<ICoseSign1ValidationBuilder> configure,
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

        var builder = Cose.Sign1Message(loggerFactory);
        configure(builder);
        var validator = builder.Build();

        return validator.Validate(message);
    }
}
