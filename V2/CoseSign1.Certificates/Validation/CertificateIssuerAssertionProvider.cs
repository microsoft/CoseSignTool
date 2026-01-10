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
/// Extracts assertions about the signing certificate's issuer.
/// </summary>
public sealed partial class CertificateIssuerAssertionProvider : CertificateValidationComponentBase, ISigningKeyAssertionProvider
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        // Validator name
        public static readonly string ValidatorName = nameof(CertificateIssuerAssertionProvider);

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
    private readonly ILogger<CertificateIssuerAssertionProvider> Logger;

    // Log methods using source generators for high-performance logging
    [LoggerMessage(Level = LogLevel.Debug, Message = "Validating certificate issuer. Expected: {ExpectedIssuer}")]
    private partial void LogValidatingIssuer(string expectedIssuer);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Certificate issuer validated: {ActualIssuer}")]
    private partial void LogIssuerMatched(string actualIssuer);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Certificate issuer mismatch. Expected: {ExpectedIssuer}, Actual: {ActualIssuer}")]
    private partial void LogIssuerMismatch(string expectedIssuer, string actualIssuer);

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateIssuerAssertionProvider"/> class.
    /// </summary>
    /// <param name="expectedIssuerName">The expected issuer common name (CN) value.</param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="expectedIssuerName"/> is null.</exception>
    public CertificateIssuerAssertionProvider(
        string expectedIssuerName,
        ILogger<CertificateIssuerAssertionProvider>? logger = null)
    {
        ExpectedIssuerName = expectedIssuerName ?? throw new ArgumentNullException(nameof(expectedIssuerName));
        Logger = logger ?? NullLogger<CertificateIssuerAssertionProvider>.Instance;
    }

    /// <inheritdoc/>
    public override string ComponentName => ClassStrings.ValidatorName;

    /// <inheritdoc/>
    public IReadOnlyList<ISigningKeyAssertion> ExtractAssertions(
        ISigningKey signingKey,
        CoseSign1Message message,
        CoseSign1ValidationOptions? options = null)
    {
        LogValidatingIssuer(ExpectedIssuerName);

        if (signingKey is not X509CertificateSigningKey certKey || certKey.Certificate == null)
        {
            return Array.Empty<ISigningKeyAssertion>();
        }

        var signingCert = certKey.Certificate;

        // Extract issuer CN from certificate
        string? issuerCn = ExtractCommonName(signingCert.Issuer);

        if (string.IsNullOrEmpty(issuerCn))
        {
            return new ISigningKeyAssertion[]
            {
                new X509IssuerAssertion(false, null) { SigningKey = signingKey }
            };
        }

        // Compare issuer CN with expected value (case-insensitive)
        bool matches = string.Equals(issuerCn, ExpectedIssuerName, StringComparison.OrdinalIgnoreCase);

        if (!matches)
        {
            LogIssuerMismatch(ExpectedIssuerName, issuerCn);
        }
        else
        {
            LogIssuerMatched(issuerCn);
        }

        return new ISigningKeyAssertion[]
        {
            new X509IssuerAssertion(matches, issuerCn) { SigningKey = signingKey }
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
