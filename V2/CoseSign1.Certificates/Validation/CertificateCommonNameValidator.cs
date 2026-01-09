// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Validation;

using System.Diagnostics.CodeAnalysis;
using CoseSign1.Certificates.Extensions;
using CoseSign1.Validation;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Validates that the signing certificate's subject common name matches the expected value.
/// </summary>
public sealed partial class CertificateCommonNameValidator : IValidator
{
    private static readonly IReadOnlyCollection<ValidationStage> StagesField = new[] { ValidationStage.KeyMaterialTrust };

    /// <inheritdoc/>
    public IReadOnlyCollection<ValidationStage> Stages => StagesField;

    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        // Validator name
        public static readonly string ValidatorName = nameof(CertificateCommonNameValidator);

        // Error codes
        public static readonly string ErrorCodeNullInput = "NULL_INPUT";
        public static readonly string ErrorCodeCertNotFound = "CERTIFICATE_NOT_FOUND";
        public static readonly string ErrorCodeCnNotFound = "CN_NOT_FOUND";
        public static readonly string ErrorCodeCnMismatch = "CN_MISMATCH";

        // Error messages
        public static readonly string ErrorExpectedCommonNameNull = "Expected common name cannot be null or whitespace.";
        public static readonly string ErrorMessageNullInput = "Input message is null";
        public static readonly string ErrorMessageCertNotFound = "Could not extract signing certificate from message";
        public static readonly string ErrorMessageCnNotFound = "Certificate does not have a common name";
        public static readonly string ErrorFormatCnMismatch = "Certificate common name '{0}' does not match expected '{1}'";

        // Metadata keys
        public static readonly string MetaKeyCommonName = "CommonName";
        public static readonly string MetaKeyCertThumbprint = "CertificateThumbprint";
    }

    private readonly string ExpectedCommonName;
    private readonly bool AllowUnprotectedHeaders;
    private readonly ILogger<CertificateCommonNameValidator> Logger;

    // Log methods using source generators for high-performance logging
    [LoggerMessage(Level = LogLevel.Debug, Message = "Validating certificate common name. Expected: {ExpectedCN}")]
    private partial void LogValidatingCN(string expectedCN);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Certificate common name validated: {ActualCN}")]
    private partial void LogCNMatched(string actualCN);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Certificate common name mismatch. Expected: {ExpectedCN}, Actual: {ActualCN}")]
    private partial void LogCNMismatch(string expectedCN, string actualCN);

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateCommonNameValidator"/> class.
    /// </summary>
    /// <param name="expectedCommonName">The expected common name (CN) value.</param>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="expectedCommonName"/> is null or whitespace.</exception>
    public CertificateCommonNameValidator(
        string expectedCommonName,
        bool allowUnprotectedHeaders = false,
        ILogger<CertificateCommonNameValidator>? logger = null)
    {
        if (string.IsNullOrWhiteSpace(expectedCommonName))
        {
            throw new ArgumentException(ClassStrings.ErrorExpectedCommonNameNull, nameof(expectedCommonName));
        }

        ExpectedCommonName = expectedCommonName;
        AllowUnprotectedHeaders = allowUnprotectedHeaders;
        Logger = logger ?? NullLogger<CertificateCommonNameValidator>.Instance;
    }

    /// <inheritdoc/>
    public ValidationResult Validate(CoseSign1Message input, ValidationStage stage)
    {
        LogValidatingCN(ExpectedCommonName);

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

        // Extract CN from subject name
        string? actualCN = certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false);

        if (string.IsNullOrEmpty(actualCN))
        {
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                ClassStrings.ErrorMessageCnNotFound,
                ClassStrings.ErrorCodeCnNotFound);
        }

        if (!string.Equals(actualCN, ExpectedCommonName, StringComparison.OrdinalIgnoreCase))
        {
            LogCNMismatch(ExpectedCommonName, actualCN);
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                string.Format(ClassStrings.ErrorFormatCnMismatch, actualCN, ExpectedCommonName),
                ClassStrings.ErrorCodeCnMismatch);
        }

        LogCNMatched(actualCN);

        var metadata = new Dictionary<string, object>
        {
            [ClassStrings.MetaKeyCommonName] = actualCN,
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