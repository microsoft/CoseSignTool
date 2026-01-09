// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Validation;

using System.Diagnostics.CodeAnalysis;
using CoseSign1.Certificates.Extensions;
using CoseSign1.Validation;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Validates that the signing certificate was issued by an issuer with the expected common name.
/// </summary>
public sealed partial class CertificateIssuerValidator : IValidator
{
    private static readonly IReadOnlyCollection<ValidationStage> StagesField = new[] { ValidationStage.KeyMaterialTrust };

    /// <inheritdoc/>
    public IReadOnlyCollection<ValidationStage> Stages => StagesField;

    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        // Validator name
        public static readonly string ValidatorName = nameof(CertificateIssuerValidator);

        // Error codes
        public static readonly string ErrorCodeNullInput = "NULL_INPUT";
        public static readonly string ErrorCodeCertNotFound = "CERTIFICATE_NOT_FOUND";
        public static readonly string ErrorCodeIssuerCnNotFound = "ISSUER_CN_NOT_FOUND";
        public static readonly string ErrorCodeIssuerCnMismatch = "ISSUER_CN_MISMATCH";

        // Error messages
        public static readonly string ErrorMessageNullInput = "Input message is null";
        public static readonly string ErrorMessageCertNotFound = "Could not extract signing certificate from message";
        public static readonly string ErrorMessageIssuerCnNotFound = "Certificate issuer does not contain a Common Name (CN)";
        public static readonly string ErrorFormatIssuerCnMismatch = "Certificate issuer CN '{0}' does not match expected '{1}'";

        // Metadata keys
        public static readonly string MetaKeyIssuerCn = "IssuerCN";
        public static readonly string MetaKeyCertThumbprint = "CertificateThumbprint";

        // CN parsing
        public static readonly string CnPrefix = "CN=";
    }

    private readonly string ExpectedIssuerName;
    private readonly bool AllowUnprotectedHeaders;
    private readonly ILogger<CertificateIssuerValidator> Logger;

    // Log methods using source generators for high-performance logging
    [LoggerMessage(Level = LogLevel.Debug, Message = "Validating certificate issuer. Expected: {ExpectedIssuer}")]
    private partial void LogValidatingIssuer(string expectedIssuer);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Certificate issuer validated: {ActualIssuer}")]
    private partial void LogIssuerMatched(string actualIssuer);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Certificate issuer mismatch. Expected: {ExpectedIssuer}, Actual: {ActualIssuer}")]
    private partial void LogIssuerMismatch(string expectedIssuer, string actualIssuer);

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateIssuerValidator"/> class.
    /// </summary>
    /// <param name="expectedIssuerName">The expected issuer common name (CN) value.</param>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="expectedIssuerName"/> is null.</exception>
    public CertificateIssuerValidator(
        string expectedIssuerName,
        bool allowUnprotectedHeaders = false,
        ILogger<CertificateIssuerValidator>? logger = null)
    {
        ExpectedIssuerName = expectedIssuerName ?? throw new ArgumentNullException(nameof(expectedIssuerName));
        AllowUnprotectedHeaders = allowUnprotectedHeaders;
        Logger = logger ?? NullLogger<CertificateIssuerValidator>.Instance;
    }

    /// <inheritdoc/>
    public ValidationResult Validate(CoseSign1Message input, ValidationStage stage)
    {
        LogValidatingIssuer(ExpectedIssuerName);

        if (input == null)
        {
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                ClassStrings.ErrorMessageNullInput,
                ClassStrings.ErrorCodeNullInput);
        }

        if (!input.TryGetSigningCertificate(out var signingCert, AllowUnprotectedHeaders))
        {
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                ClassStrings.ErrorMessageCertNotFound,
                ClassStrings.ErrorCodeCertNotFound);
        }

        // Extract issuer CN from certificate
        string? issuerCn = ExtractCommonName(signingCert.Issuer);

        if (string.IsNullOrEmpty(issuerCn))
        {
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                ClassStrings.ErrorMessageIssuerCnNotFound,
                ClassStrings.ErrorCodeIssuerCnNotFound);
        }

        // Compare issuer CN with expected value (case-insensitive)
        if (!string.Equals(issuerCn, ExpectedIssuerName, StringComparison.OrdinalIgnoreCase))
        {
            LogIssuerMismatch(ExpectedIssuerName, issuerCn);
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                string.Format(ClassStrings.ErrorFormatIssuerCnMismatch, issuerCn, ExpectedIssuerName),
                ClassStrings.ErrorCodeIssuerCnMismatch);
        }

        LogIssuerMatched(issuerCn);

        return ValidationResult.Success(ClassStrings.ValidatorName, new Dictionary<string, object>
        {
            [ClassStrings.MetaKeyIssuerCn] = issuerCn!,
            [ClassStrings.MetaKeyCertThumbprint] = signingCert.Thumbprint
        });
    }

    /// <inheritdoc/>
    public Task<ValidationResult> ValidateAsync(CoseSign1Message input, ValidationStage stage, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Validate(input, stage));
    }

    /// <summary>
    /// Extracts the Common Name (CN) from a distinguished name string.
    /// </summary>
    private static string? ExtractCommonName(string distinguishedName)
    {
        if (string.IsNullOrEmpty(distinguishedName))
        {
            return null;
        }

        // Parse the distinguished name to find CN
        var parts = distinguishedName.Split(',');
        foreach (var part in parts)
        {
            var trimmedPart = part.Trim();
            if (trimmedPart.StartsWith(ClassStrings.CnPrefix, StringComparison.OrdinalIgnoreCase))
            {
                return trimmedPart.Substring(3).Trim();
            }
        }

        return null;
    }
}