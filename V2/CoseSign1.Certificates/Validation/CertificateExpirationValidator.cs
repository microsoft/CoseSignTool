// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Validation;

using System.Diagnostics.CodeAnalysis;
using CoseSign1.Certificates.Extensions;
using CoseSign1.Validation;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Validates that the signing certificate has not expired and is currently valid.
/// </summary>
public sealed partial class CertificateExpirationValidator : IValidator
{
    private static readonly IReadOnlyCollection<ValidationStage> StagesField = new[] { ValidationStage.KeyMaterialTrust };

    /// <inheritdoc/>
    public IReadOnlyCollection<ValidationStage> Stages => StagesField;

    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        // Validator name
        public static readonly string ValidatorName = nameof(CertificateExpirationValidator);

        // Error codes
        public static readonly string ErrorCodeNullInput = "NULL_INPUT";
        public static readonly string ErrorCodeCertNotFound = "CERTIFICATE_NOT_FOUND";
        public static readonly string ErrorCodeNotYetValid = "CERTIFICATE_NOT_YET_VALID";
        public static readonly string ErrorCodeExpired = "CERTIFICATE_EXPIRED";

        // Error messages
        public static readonly string ErrorMessageNullInput = "Input message is null";
        public static readonly string ErrorMessageCertNotFound = "Could not extract signing certificate from message";
        public static readonly string ErrorFormatNotYetValid = "Certificate is not yet valid. NotBefore: {0:u}, ValidationTime: {1:u}";
        public static readonly string ErrorFormatExpired = "Certificate has expired. NotAfter: {0:u}, ValidationTime: {1:u}";

        // Metadata keys
        public static readonly string MetaKeyNotBefore = "NotBefore";
        public static readonly string MetaKeyNotAfter = "NotAfter";
        public static readonly string MetaKeyValidationTime = "ValidationTime";
        public static readonly string MetaKeyCertThumbprint = "CertificateThumbprint";
    }

    private readonly DateTime? ValidationTime;
    private readonly bool AllowUnprotectedHeaders;
    private readonly ILogger<CertificateExpirationValidator> Logger;

    // Log methods using source generators for high-performance logging
    [LoggerMessage(Level = LogLevel.Debug, Message = "Validating certificate expiration. ValidationTime: {ValidationTime}")]
    private partial void LogValidatingExpiration(DateTime validationTime);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Certificate is within validity period. NotBefore: {NotBefore}, NotAfter: {NotAfter}, Thumbprint: {Thumbprint}")]
    private partial void LogCertificateValid(DateTime notBefore, DateTime notAfter, string thumbprint);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Certificate is not yet valid. NotBefore: {NotBefore}, ValidationTime: {ValidationTime}, Thumbprint: {Thumbprint}")]
    private partial void LogCertificateNotYetValid(DateTime notBefore, DateTime validationTime, string thumbprint);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Certificate has expired. NotAfter: {NotAfter}, ValidationTime: {ValidationTime}, Thumbprint: {Thumbprint}")]
    private partial void LogCertificateExpired(DateTime notAfter, DateTime validationTime, string thumbprint);

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateExpirationValidator"/> class.
    /// Validates the certificate is valid at the current time.
    /// </summary>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    public CertificateExpirationValidator(
        bool allowUnprotectedHeaders = false,
        ILogger<CertificateExpirationValidator>? logger = null)
    {
        ValidationTime = null;
        AllowUnprotectedHeaders = allowUnprotectedHeaders;
        Logger = logger ?? NullLogger<CertificateExpirationValidator>.Instance;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateExpirationValidator"/> class.
    /// Validates the certificate was valid at the specified time.
    /// </summary>
    /// <param name="validationTime">The time at which to validate the certificate.</param>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    public CertificateExpirationValidator(
        DateTime validationTime,
        bool allowUnprotectedHeaders = false,
        ILogger<CertificateExpirationValidator>? logger = null)
    {
        ValidationTime = validationTime;
        AllowUnprotectedHeaders = allowUnprotectedHeaders;
        Logger = logger ?? NullLogger<CertificateExpirationValidator>.Instance;
    }

    /// <inheritdoc/>
    public ValidationResult Validate(CoseSign1Message input, ValidationStage stage)
    {
        if (input == null)
        {
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                ClassStrings.ErrorMessageNullInput,
                ClassStrings.ErrorCodeNullInput);
        }

        if (!input.TryGetSigningCertificate(out var certificate, AllowUnprotectedHeaders))
        {
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                ClassStrings.ErrorMessageCertNotFound,
                ClassStrings.ErrorCodeCertNotFound);
        }

        DateTime checkTime = ValidationTime ?? DateTime.UtcNow;
        LogValidatingExpiration(checkTime);

        if (checkTime < certificate.NotBefore)
        {
            LogCertificateNotYetValid(certificate.NotBefore, checkTime, certificate.Thumbprint);
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                string.Format(ClassStrings.ErrorFormatNotYetValid, certificate.NotBefore, checkTime),
                ClassStrings.ErrorCodeNotYetValid);
        }

        if (checkTime > certificate.NotAfter)
        {
            LogCertificateExpired(certificate.NotAfter, checkTime, certificate.Thumbprint);
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                string.Format(ClassStrings.ErrorFormatExpired, certificate.NotAfter, checkTime),
                ClassStrings.ErrorCodeExpired);
        }

        LogCertificateValid(certificate.NotBefore, certificate.NotAfter, certificate.Thumbprint);

        var metadata = new Dictionary<string, object>
        {
            [ClassStrings.MetaKeyNotBefore] = certificate.NotBefore,
            [ClassStrings.MetaKeyNotAfter] = certificate.NotAfter,
            [ClassStrings.MetaKeyValidationTime] = checkTime,
            [ClassStrings.MetaKeyCertThumbprint] = certificate.Thumbprint
        };

        return ValidationResult.Success(ClassStrings.ValidatorName, metadata);
    }

    /// <inheritdoc/>
    public Task<ValidationResult> ValidateAsync(CoseSign1Message input, ValidationStage stage, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Validate(input, stage));
    }
}