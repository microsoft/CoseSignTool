// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Validation;

using System.Diagnostics.CodeAnalysis;
using CoseSign1.Abstractions;
using CoseSign1.Validation;
using CoseSign1.Validation.Interfaces;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Extracts assertions about the signing certificate's key usage extensions.
/// </summary>
public sealed partial class CertificateKeyUsageAssertionProvider : CertificateValidationComponentBase, ISigningKeyAssertionProvider
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        // Validator name
        public static readonly string ValidatorName = nameof(CertificateKeyUsageAssertionProvider);

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
    private readonly ILogger<CertificateKeyUsageAssertionProvider> Logger;

    // Log methods using source generators for high-performance logging
    [LoggerMessage(Level = LogLevel.Debug, Message = "Validating key usage flags. Required: {RequiredFlags}")]
    private partial void LogValidatingKeyUsage(X509KeyUsageFlags requiredFlags);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Validating enhanced key usage. Required OID: {RequiredOid}")]
    private partial void LogValidatingEku(string requiredOid);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Key usage validated successfully. Actual: {ActualFlags}, Thumbprint: {Thumbprint}")]
    private partial void LogKeyUsageValid(string actualFlags, string thumbprint);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Enhanced key usage validated successfully. OID: {Oid}, Thumbprint: {Thumbprint}")]
    private partial void LogEkuValid(string oid, string thumbprint);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Key usage mismatch. Required: {Required}, Actual: {Actual}, Thumbprint: {Thumbprint}")]
    private partial void LogKeyUsageMismatch(string required, string actual, string thumbprint);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Enhanced key usage not found. Required: {Required}, Found: [{Found}], Thumbprint: {Thumbprint}")]
    private partial void LogEkuMismatch(string required, string found, string thumbprint);

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateKeyUsageAssertionProvider"/> class
    /// to validate key usage flags.
    /// </summary>
    /// <param name="requiredKeyUsage">The required key usage flags.</param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    public CertificateKeyUsageAssertionProvider(
        X509KeyUsageFlags requiredKeyUsage,
        ILogger<CertificateKeyUsageAssertionProvider>? logger = null)
    {
        RequiredKeyUsage = requiredKeyUsage;
        RequiredEku = null;
        Logger = logger ?? NullLogger<CertificateKeyUsageAssertionProvider>.Instance;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateKeyUsageAssertionProvider"/> class
    /// to validate enhanced key usage.
    /// </summary>
    /// <param name="requiredEku">The required enhanced key usage OID.</param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="requiredEku"/> is null.</exception>
    public CertificateKeyUsageAssertionProvider(
        Oid requiredEku,
        ILogger<CertificateKeyUsageAssertionProvider>? logger = null)
    {
        RequiredKeyUsage = null;
        RequiredEku = requiredEku ?? throw new ArgumentNullException(nameof(requiredEku));
        Logger = logger ?? NullLogger<CertificateKeyUsageAssertionProvider>.Instance;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateKeyUsageAssertionProvider"/> class
    /// to validate enhanced key usage by OID value.
    /// </summary>
    /// <param name="requiredEkuOid">The required enhanced key usage OID value.</param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="requiredEkuOid"/> is null or whitespace.</exception>
    public CertificateKeyUsageAssertionProvider(
        string requiredEkuOid,
        ILogger<CertificateKeyUsageAssertionProvider>? logger = null)
    {
        if (string.IsNullOrWhiteSpace(requiredEkuOid))
        {
            throw new ArgumentException(ClassStrings.ErrorMessageEkuOidNull, nameof(requiredEkuOid));
        }

        RequiredKeyUsage = null;
        RequiredEku = new Oid(requiredEkuOid);
        Logger = logger ?? NullLogger<CertificateKeyUsageAssertionProvider>.Instance;
    }

    /// <inheritdoc/>
    public override string ComponentName => ClassStrings.ValidatorName;

    /// <inheritdoc/>
    public IReadOnlyList<ISigningKeyAssertion> ExtractAssertions(
        ISigningKey signingKey,
        CoseSign1Message message,
        CoseSign1ValidationOptions? options = null)
    {
        if (signingKey is not X509CertificateSigningKey certKey || certKey.Certificate == null)
        {
            return Array.Empty<ISigningKeyAssertion>();
        }

        var certificate = certKey.Certificate;

        if (RequiredKeyUsage.HasValue)
        {
            LogValidatingKeyUsage(RequiredKeyUsage.Value);
            return ExtractKeyUsageAssertion(certificate, RequiredKeyUsage.Value, signingKey);
        }

        if (RequiredEku != null)
        {
            LogValidatingEku(RequiredEku.Value ?? RequiredEku.FriendlyName ?? ClassStrings.MetaValueUnknown);
            return ExtractEkuAssertion(certificate, RequiredEku, signingKey);
        }

        return Array.Empty<ISigningKeyAssertion>();
    }

    private IReadOnlyList<ISigningKeyAssertion> ExtractKeyUsageAssertion(X509Certificate2 certificate, X509KeyUsageFlags required, ISigningKey signingKey)
    {
        var keyUsageExt = certificate.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();

        if (keyUsageExt == null)
        {
            return new ISigningKeyAssertion[]
            {
                new X509KeyUsageAssertion(false, ClassStrings.ErrorMessageKeyUsageNotFound) { SigningKey = signingKey }
            };
        }

        bool hasRequired = (keyUsageExt.KeyUsages & required) == required;

        if (!hasRequired)
        {
            LogKeyUsageMismatch(required.ToString(), keyUsageExt.KeyUsages.ToString(), certificate.Thumbprint);
            return new ISigningKeyAssertion[]
            {
                new X509KeyUsageAssertion(false, string.Format(ClassStrings.ErrorFormatKeyUsageMismatch, keyUsageExt.KeyUsages, required)) { SigningKey = signingKey }
            };
        }

        LogKeyUsageValid(keyUsageExt.KeyUsages.ToString(), certificate.Thumbprint);
        return new ISigningKeyAssertion[]
        {
            new X509KeyUsageAssertion(true) { SigningKey = signingKey }
        };
    }

    private IReadOnlyList<ISigningKeyAssertion> ExtractEkuAssertion(X509Certificate2 certificate, Oid requiredEku, ISigningKey signingKey)
    {
        var ekuExt = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();

        if (ekuExt == null)
        {
            return new ISigningKeyAssertion[]
            {
                new X509KeyUsageAssertion(false, ClassStrings.ErrorMessageEkuNotFound) { SigningKey = signingKey }
            };
        }

        bool found = ekuExt.EnhancedKeyUsages
            .Cast<Oid>()
            .Any(oid => oid.Value == requiredEku.Value);

        if (!found)
        {
            var ekuList = string.Join(ClassStrings.SeparatorCommaSpace, ekuExt.EnhancedKeyUsages.Cast<Oid>().Select(o => o.Value ?? o.FriendlyName));
            LogEkuMismatch(requiredEku.Value ?? ClassStrings.MetaValueUnknown, ekuList, certificate.Thumbprint);
            return new ISigningKeyAssertion[]
            {
                new X509KeyUsageAssertion(false, string.Format(ClassStrings.ErrorFormatEkuMismatch, requiredEku.Value, ekuList)) { SigningKey = signingKey }
            };
        }

        LogEkuValid(requiredEku.Value ?? requiredEku.FriendlyName ?? ClassStrings.MetaValueUnknown, certificate.Thumbprint);
        return new ISigningKeyAssertion[]
        {
            new X509KeyUsageAssertion(true) { SigningKey = signingKey }
        };
    }

    /// <inheritdoc/>
    public Task<IReadOnlyList<ISigningKeyAssertion>> ExtractAssertionsAsync(
        ISigningKey signingKey,
        CoseSign1Message message,
        CoseSign1ValidationOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(ExtractAssertions(signingKey, message, options));
    }
}
