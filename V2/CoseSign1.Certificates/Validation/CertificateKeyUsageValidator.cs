// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics.CodeAnalysis;
using CoseSign1.Certificates.Extensions;
using CoseSign1.Validation;

namespace CoseSign1.Certificates.Validation;

/// <summary>
/// Validates that the signing certificate has the required key usage extensions.
/// </summary>
public sealed class CertificateKeyUsageValidator : IValidator
{
    private static readonly IReadOnlyCollection<ValidationStage> StagesField = new[] { ValidationStage.KeyMaterialTrust };

    /// <inheritdoc/>
    public IReadOnlyCollection<ValidationStage> Stages => StagesField;

    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        // Validator name
        public static readonly string ValidatorName = nameof(CertificateKeyUsageValidator);

        // Error codes
        public static readonly string ErrorCodeNullInput = "NULL_INPUT";
        public static readonly string ErrorCodeCertNotFound = "CERTIFICATE_NOT_FOUND";
        public static readonly string ErrorCodeNoCriteria = "NO_CRITERIA";
        public static readonly string ErrorCodeKeyUsageNotFound = "KEY_USAGE_NOT_FOUND";
        public static readonly string ErrorCodeKeyUsageMismatch = "KEY_USAGE_MISMATCH";
        public static readonly string ErrorCodeEkuNotFound = "EKU_NOT_FOUND";
        public static readonly string ErrorCodeEkuMismatch = "EKU_MISMATCH";

        // Error messages
        public static readonly string ErrorMessageNullInput = "Input message is null";
        public static readonly string ErrorMessageCertNotFound = "Could not extract signing certificate from message";
        public static readonly string ErrorMessageNoCriteria = "No key usage criteria specified";
        public static readonly string ErrorMessageKeyUsageNotFound = "Certificate does not have a key usage extension";
        public static readonly string ErrorFormatKeyUsageMismatch = "Certificate key usage '{0}' does not include required '{1}'";
        public static readonly string ErrorMessageEkuNotFound = "Certificate does not have an enhanced key usage extension";
        public static readonly string ErrorFormatEkuMismatch = "Certificate does not have required EKU '{0}'. Found: [{1}]";
        public static readonly string ErrorMessageEkuOidNull = "EKU OID cannot be null or whitespace.";

        // Metadata keys
        public static readonly string MetaKeyKeyUsage = "KeyUsage";
        public static readonly string MetaKeyEnhancedKeyUsage = "EnhancedKeyUsage";
        public static readonly string MetaKeyCertThumbprint = "CertificateThumbprint";

        // Default value
        public static readonly string MetaValueUnknown = "Unknown";

        // Separators
        public static readonly string SeparatorCommaSpace = ", ";
    }

    private readonly X509KeyUsageFlags? RequiredKeyUsage;
    private readonly Oid? RequiredEku;
    private readonly bool AllowUnprotectedHeaders;

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateKeyUsageValidator"/> class
    /// to validate key usage flags.
    /// </summary>
    /// <param name="requiredKeyUsage">The required key usage flags.</param>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    public CertificateKeyUsageValidator(X509KeyUsageFlags requiredKeyUsage, bool allowUnprotectedHeaders = false)
    {
        RequiredKeyUsage = requiredKeyUsage;
        RequiredEku = null;
        AllowUnprotectedHeaders = allowUnprotectedHeaders;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateKeyUsageValidator"/> class
    /// to validate enhanced key usage.
    /// </summary>
    /// <param name="requiredEku">The required enhanced key usage OID.</param>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="requiredEku"/> is null.</exception>
    public CertificateKeyUsageValidator(Oid requiredEku, bool allowUnprotectedHeaders = false)
    {
        RequiredKeyUsage = null;
        RequiredEku = requiredEku ?? throw new ArgumentNullException(nameof(requiredEku));
        AllowUnprotectedHeaders = allowUnprotectedHeaders;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateKeyUsageValidator"/> class
    /// to validate enhanced key usage by OID value.
    /// </summary>
    /// <param name="requiredEkuOid">The required enhanced key usage OID value.</param>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="requiredEkuOid"/> is null or whitespace.</exception>
    public CertificateKeyUsageValidator(string requiredEkuOid, bool allowUnprotectedHeaders = false)
    {
        if (string.IsNullOrWhiteSpace(requiredEkuOid))
        {
            throw new ArgumentException(ClassStrings.ErrorMessageEkuOidNull, nameof(requiredEkuOid));
        }

        RequiredKeyUsage = null;
        RequiredEku = new Oid(requiredEkuOid);
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

        if (RequiredKeyUsage.HasValue)
        {
            return ValidateKeyUsageFlags(certificate, RequiredKeyUsage.Value);
        }

        if (RequiredEku != null)
        {
            return ValidateEnhancedKeyUsage(certificate, RequiredEku);
        }

        return ValidationResult.Failure(
            ClassStrings.ValidatorName,
            ClassStrings.ErrorMessageNoCriteria,
            ClassStrings.ErrorCodeNoCriteria);
    }

    private ValidationResult ValidateKeyUsageFlags(X509Certificate2 certificate, X509KeyUsageFlags required)
    {
        var keyUsageExt = certificate.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();

        if (keyUsageExt == null)
        {
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                ClassStrings.ErrorMessageKeyUsageNotFound,
                ClassStrings.ErrorCodeKeyUsageNotFound);
        }

        if ((keyUsageExt.KeyUsages & required) != required)
        {
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                string.Format(ClassStrings.ErrorFormatKeyUsageMismatch, keyUsageExt.KeyUsages, required),
                ClassStrings.ErrorCodeKeyUsageMismatch);
        }

        return ValidationResult.Success(ClassStrings.ValidatorName, new Dictionary<string, object>
        {
            [ClassStrings.MetaKeyKeyUsage] = keyUsageExt.KeyUsages.ToString(),
            [ClassStrings.MetaKeyCertThumbprint] = certificate.Thumbprint
        });
    }

    private ValidationResult ValidateEnhancedKeyUsage(X509Certificate2 certificate, Oid requiredEku)
    {
        var ekuExt = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();

        if (ekuExt == null)
        {
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                ClassStrings.ErrorMessageEkuNotFound,
                ClassStrings.ErrorCodeEkuNotFound);
        }

        bool found = ekuExt.EnhancedKeyUsages
            .Cast<Oid>()
            .Any(oid => oid.Value == requiredEku.Value);

        if (!found)
        {
            var ekuList = string.Join(ClassStrings.SeparatorCommaSpace, ekuExt.EnhancedKeyUsages.Cast<Oid>().Select(o => o.Value ?? o.FriendlyName));
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                string.Format(ClassStrings.ErrorFormatEkuMismatch, requiredEku.Value, ekuList),
                ClassStrings.ErrorCodeEkuMismatch);
        }

        return ValidationResult.Success(ClassStrings.ValidatorName, new Dictionary<string, object>
        {
            [ClassStrings.MetaKeyEnhancedKeyUsage] = requiredEku.Value ?? requiredEku.FriendlyName ?? ClassStrings.MetaValueUnknown,
            [ClassStrings.MetaKeyCertThumbprint] = certificate.Thumbprint
        });
    }

    /// <inheritdoc/>
    public Task<ValidationResult> ValidateAsync(CoseSign1Message input, ValidationStage stage, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Validate(input, stage));
    }
}