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
/// Extracts assertions about the signing certificate's validity period.
/// </summary>
public sealed partial class CertificateExpirationAssertionProvider : ISigningKeyAssertionProvider
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        // Validator name
        public static readonly string ValidatorName = nameof(CertificateExpirationAssertionProvider);

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
    private readonly ILogger<CertificateExpirationAssertionProvider> Logger;

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
    /// Initializes a new instance of the <see cref="CertificateExpirationAssertionProvider"/> class.
    /// Validates the certificate is valid at the current time.
    /// </summary>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    public CertificateExpirationAssertionProvider(
        ILogger<CertificateExpirationAssertionProvider>? logger = null)
    {
        ValidationTime = null;
        Logger = logger ?? NullLogger<CertificateExpirationAssertionProvider>.Instance;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateExpirationAssertionProvider"/> class.
    /// Validates the certificate was valid at the specified time.
    /// </summary>
    /// <param name="validationTime">The time at which to validate the certificate.</param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    public CertificateExpirationAssertionProvider(
        DateTime validationTime,
        ILogger<CertificateExpirationAssertionProvider>? logger = null)
    {
        ValidationTime = validationTime;
        Logger = logger ?? NullLogger<CertificateExpirationAssertionProvider>.Instance;
    }

    /// <inheritdoc/>
    public string ComponentName => ClassStrings.ValidatorName;

    /// <inheritdoc/>
    public bool CanProvideAssertions(ISigningKey signingKey)
    {
        return signingKey is X509CertificateSigningKey;
    }

    /// <inheritdoc/>
    public IReadOnlyList<ISigningKeyAssertion> ExtractAssertions(
        ISigningKey signingKey,
        CoseSign1Message message)
    {
        if (signingKey is not X509CertificateSigningKey certKey || certKey.Certificate == null)
        {
            return Array.Empty<ISigningKeyAssertion>();
        }

        var certificate = certKey.Certificate;
        DateTime checkTime = ValidationTime ?? DateTime.UtcNow;
        LogValidatingExpiration(checkTime);

        if (checkTime < certificate.NotBefore)
        {
            LogCertificateNotYetValid(certificate.NotBefore, checkTime, certificate.Thumbprint);
            return new ISigningKeyAssertion[]
            {
                new SigningKeyAssertion(X509TrustClaims.NotExpired, false,
                    details: string.Format(ClassStrings.ErrorFormatNotYetValid, certificate.NotBefore, checkTime))
                { SigningKey = signingKey }
            };
        }

        if (checkTime > certificate.NotAfter)
        {
            LogCertificateExpired(certificate.NotAfter, checkTime, certificate.Thumbprint);
            return new ISigningKeyAssertion[]
            {
                new SigningKeyAssertion(X509TrustClaims.NotExpired, false,
                    details: string.Format(ClassStrings.ErrorFormatExpired, certificate.NotAfter, checkTime))
                { SigningKey = signingKey }
            };
        }

        LogCertificateValid(certificate.NotBefore, certificate.NotAfter, certificate.Thumbprint);

        return new ISigningKeyAssertion[]
        {
            new SigningKeyAssertion(X509TrustClaims.NotExpired, true) { SigningKey = signingKey }
        };
    }

    /// <inheritdoc/>
    public Task<IReadOnlyList<ISigningKeyAssertion>> ExtractAssertionsAsync(
        ISigningKey signingKey,
        CoseSign1Message message,
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(ExtractAssertions(signingKey, message));
    }
}
