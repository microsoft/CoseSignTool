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
/// Extracts assertions about a certificate using a custom predicate function.
/// </summary>
internal sealed partial class CertificatePredicateAssertionProvider : ISigningKeyAssertionProvider
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        // Validator name
        public static readonly string ValidatorName = nameof(CertificatePredicateAssertionProvider);

        // Error codes
        public static readonly string ErrorCodeNullInput = "NULL_INPUT";
        public static readonly string ErrorCodeCertNotFound = "CERTIFICATE_NOT_FOUND";
        public static readonly string ErrorCodePredicateFailed = "CERTIFICATE_PREDICATE_FAILED";

        // Error messages
        public static readonly string ErrorMessageNullInput = "Input message is null";
        public static readonly string ErrorMessageCertNotFound = "Certificate not found in message headers";
        public static readonly string ErrorMessagePredicateFailed = "Certificate does not match the specified predicate";

        // Metadata keys
        public static readonly string MetaKeyCertThumbprint = "CertificateThumbprint";
    }

    private readonly Func<X509Certificate2, bool> Predicate;
    private readonly string? FailureMessage;
    private readonly ILogger<CertificatePredicateAssertionProvider> Logger;

    // Log methods using source generators for high-performance logging
    [LoggerMessage(Level = LogLevel.Debug, Message = "Evaluating certificate predicate. Thumbprint: {Thumbprint}")]
    private partial void LogEvaluatingPredicate(string thumbprint);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Certificate predicate passed. Thumbprint: {Thumbprint}")]
    private partial void LogPredicatePassed(string thumbprint);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Certificate predicate failed. Thumbprint: {Thumbprint}, Message: {FailureMessage}")]
    private partial void LogPredicateFailed(string thumbprint, string failureMessage);

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificatePredicateAssertionProvider"/> class.
    /// </summary>
    /// <param name="predicate">The predicate function to validate the certificate.</param>
    /// <param name="failureMessage">The error message if validation fails.</param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="predicate"/> is null.</exception>
    public CertificatePredicateAssertionProvider(
        Func<X509Certificate2, bool> predicate,
        string? failureMessage = null,
        ILogger<CertificatePredicateAssertionProvider>? logger = null)
    {
        Predicate = predicate ?? throw new ArgumentNullException(nameof(predicate));
        FailureMessage = failureMessage;
        Logger = logger ?? NullLogger<CertificatePredicateAssertionProvider>.Instance;
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

        var cert = certKey.Certificate;
        LogEvaluatingPredicate(cert.Thumbprint);

        bool passed = Predicate(cert);

        if (passed)
        {
            LogPredicatePassed(cert.Thumbprint);
        }
        else
        {
            var failMsg = FailureMessage ?? ClassStrings.ErrorMessagePredicateFailed;
            LogPredicateFailed(cert.Thumbprint, failMsg);
        }

        return new ISigningKeyAssertion[]
        {
            new SigningKeyAssertion(X509TrustClaims.PredicateSatisfied, passed,
                details: passed ? null : (FailureMessage ?? ClassStrings.ErrorMessagePredicateFailed))
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
