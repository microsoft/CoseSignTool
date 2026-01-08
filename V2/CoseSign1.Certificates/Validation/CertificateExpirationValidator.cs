// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics.CodeAnalysis;
using CoseSign1.Certificates.Extensions;
using CoseSign1.Validation;

namespace CoseSign1.Certificates.Validation;

/// <summary>
/// Validates that the signing certificate has not expired and is currently valid.
/// </summary>
public sealed class CertificateExpirationValidator : IValidator
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

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateExpirationValidator"/> class.
    /// Validates the certificate is valid at the current time.
    /// </summary>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    public CertificateExpirationValidator(bool allowUnprotectedHeaders = false)
    {
        ValidationTime = null;
        AllowUnprotectedHeaders = allowUnprotectedHeaders;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateExpirationValidator"/> class.
    /// Validates the certificate was valid at the specified time.
    /// </summary>
    /// <param name="validationTime">The time at which to validate the certificate.</param>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    public CertificateExpirationValidator(DateTime validationTime, bool allowUnprotectedHeaders = false)
    {
        ValidationTime = validationTime;
        AllowUnprotectedHeaders = allowUnprotectedHeaders;
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

        if (checkTime < certificate.NotBefore)
        {
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                string.Format(ClassStrings.ErrorFormatNotYetValid, certificate.NotBefore, checkTime),
                ClassStrings.ErrorCodeNotYetValid);
        }

        if (checkTime > certificate.NotAfter)
        {
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                string.Format(ClassStrings.ErrorFormatExpired, certificate.NotAfter, checkTime),
                ClassStrings.ErrorCodeExpired);
        }

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