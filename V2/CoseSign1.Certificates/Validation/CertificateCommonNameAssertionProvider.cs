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
/// Extracts assertions about the signing certificate's subject common name.
/// </summary>
public sealed partial class CertificateCommonNameAssertionProvider : ISigningKeyAssertionProvider
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        // Validator name
        public static readonly string ValidatorName = nameof(CertificateCommonNameAssertionProvider);

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
    private readonly ILogger<CertificateCommonNameAssertionProvider> Logger;

    // Log methods using source generators for high-performance logging
    [LoggerMessage(Level = LogLevel.Debug, Message = "Validating certificate common name. Expected: {ExpectedCN}")]
    private partial void LogValidatingCN(string expectedCN);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Certificate common name validated: {ActualCN}")]
    private partial void LogCNMatched(string actualCN);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Certificate common name mismatch. Expected: {ExpectedCN}, Actual: {ActualCN}")]
    private partial void LogCNMismatch(string expectedCN, string actualCN);

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateCommonNameAssertionProvider"/> class.
    /// </summary>
    /// <param name="expectedCommonName">The expected common name (CN) value.</param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="expectedCommonName"/> is null or whitespace.</exception>
    public CertificateCommonNameAssertionProvider(
        string expectedCommonName,
        ILogger<CertificateCommonNameAssertionProvider>? logger = null)
    {
        if (string.IsNullOrWhiteSpace(expectedCommonName))
        {
            throw new ArgumentException(ClassStrings.ErrorExpectedCommonNameNull, nameof(expectedCommonName));
        }

        ExpectedCommonName = expectedCommonName;
        Logger = logger ?? NullLogger<CertificateCommonNameAssertionProvider>.Instance;
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
        LogValidatingCN(ExpectedCommonName);

        if (signingKey is not X509CertificateSigningKey certKey || certKey.Certificate == null)
        {
            return Array.Empty<ISigningKeyAssertion>();
        }

        var certificate = certKey.Certificate;

        // Extract CN from subject name
        string? actualCN = certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false);

        if (string.IsNullOrEmpty(actualCN))
        {
            return new ISigningKeyAssertion[]
            {
                new SigningKeyAssertion(X509TrustClaims.CommonNameMatches, false, details: ClassStrings.ErrorMessageCnNotFound) { SigningKey = signingKey }
            };
        }

        bool matches = string.Equals(actualCN, ExpectedCommonName, StringComparison.OrdinalIgnoreCase);

        if (!matches)
        {
            LogCNMismatch(ExpectedCommonName, actualCN);
        }
        else
        {
            LogCNMatched(actualCN);
        }

        return new ISigningKeyAssertion[]
        {
            new SigningKeyAssertion(X509TrustClaims.CommonNameMatches, matches,
                details: matches ? actualCN : string.Format(ClassStrings.ErrorFormatCnMismatch, actualCN, ExpectedCommonName))
            { SigningKey = signingKey }
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
