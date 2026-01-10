// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Validation;

using System.Security.Cryptography.Cose;
using System.Diagnostics.CodeAnalysis;
using Azure.Security.CodeTransparency;
using CoseSign1.Abstractions;
using CoseSign1.Transparent.MST.Extensions;
using CoseSign1.Validation;
using CoseSign1.Validation.Interfaces;

/// <summary>
/// Validates MST receipts by first querying the configured endpoint for its current signing keys,
/// then performing full receipt proof validation using only those keys (no fallback).
/// </summary>
[ExcludeFromCodeCoverage] // Requires live MST service integration
public sealed class MstReceiptOnlineAssertionProvider : ISigningKeyAssertionProvider
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public static readonly string ValidatorName = nameof(MstReceiptOnlineAssertionProvider);

        public const string TrustDetailsNoReceipt = "NoReceipt";
        public const string TrustDetailsVerificationFailed = "VerificationFailed";
        public const string TrustDetailsException = "Exception";

        public const string MetadataKeyProviderName = "ProviderName";
        public const string MetadataKeyErrors = "Errors";
        public const string MetadataKeyIssuerHost = "IssuerHost";
        public const string MetadataKeyExceptionType = "ExceptionType";
        public const string MetadataKeyExceptionMessage = "ExceptionMessage";

        public const string DefaultProviderName = "MST";
    }

    private readonly CodeTransparencyClient Client;
    private readonly string IssuerHost;

    /// <inheritdoc/>
    public string ComponentName => ClassStrings.ValidatorName;

    /// <summary>
    /// Initializes a new instance of the <see cref="MstReceiptOnlineAssertionProvider"/> class.
    /// </summary>
    /// <param name="client">The Azure Code Transparency client.</param>
    /// <param name="issuerHost">The issuer host name used for offline key association and authorization.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="client"/> is null.</exception>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="issuerHost"/> is null or whitespace.</exception>
    public MstReceiptOnlineAssertionProvider(CodeTransparencyClient client, string issuerHost)
    {
        Client = client ?? throw new ArgumentNullException(nameof(client));
        IssuerHost = string.IsNullOrWhiteSpace(issuerHost) ? throw new ArgumentNullException(nameof(issuerHost)) : issuerHost;
    }

    /// <inheritdoc/>
    public bool CanProvideAssertions(ISigningKey signingKey)
    {
        // This provider works on message headers (MST receipts), so it can provide assertions for any signing key
        return true;
    }

    /// <inheritdoc/>
    public IReadOnlyList<ISigningKeyAssertion> ExtractAssertions(
        ISigningKey signingKey,
        CoseSign1Message message)
    {
        return ExtractAssertionsAsync(signingKey, message, CancellationToken.None).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public async Task<IReadOnlyList<ISigningKeyAssertion>> ExtractAssertionsAsync(
        ISigningKey signingKey,
        CoseSign1Message message,
        CancellationToken cancellationToken = default)
    {
        if (message == null)
        {
            return Array.Empty<ISigningKeyAssertion>();
        }

        if (!message.HasMstReceipt())
        {
            return new ISigningKeyAssertion[]
            {
                new SigningKeyAssertion(MstTrustClaims.ReceiptPresent, false),
                new SigningKeyAssertion(MstTrustClaims.ReceiptTrusted, false, details: ClassStrings.TrustDetailsNoReceipt)
            };
        }

        try
        {
            // Fetch current signing keys for the configured endpoint.
            var jwksResponse = await Client.GetPublicKeysAsync(cancellationToken).ConfigureAwait(false);
            var jwks = jwksResponse.Value;

            var offlineKeys = new CodeTransparencyOfflineKeys();
            offlineKeys.Add(IssuerHost, jwks);

            var verificationOptions = new CodeTransparencyVerificationOptions
            {
                OfflineKeys = offlineKeys,
                OfflineKeysBehavior = OfflineKeysBehavior.NoFallbackToNetwork,
                AuthorizedDomains = new[] { IssuerHost },
                UnauthorizedReceiptBehavior = UnauthorizedReceiptBehavior.FailIfPresent
            };

            var provider = new MstTransparencyProvider(Client, verificationOptions, clientOptions: null);
            var transparencyResult = await provider.VerifyTransparencyProofAsync(message, cancellationToken).ConfigureAwait(false);

            if (!transparencyResult.IsValid)
            {
                return new ISigningKeyAssertion[]
                {
                    new SigningKeyAssertion(MstTrustClaims.ReceiptPresent, true),
                    new SigningKeyAssertion(MstTrustClaims.ReceiptTrusted, false, details: ClassStrings.TrustDetailsVerificationFailed)
                };
            }

            return new ISigningKeyAssertion[]
            {
                new SigningKeyAssertion(MstTrustClaims.ReceiptPresent, true),
                new SigningKeyAssertion(MstTrustClaims.ReceiptTrusted, true)
            };
        }
        catch (Exception)
        {
            return new ISigningKeyAssertion[]
            {
                new SigningKeyAssertion(MstTrustClaims.ReceiptPresent, true),
                new SigningKeyAssertion(MstTrustClaims.ReceiptTrusted, false, details: ClassStrings.TrustDetailsException)
            };
        }
    }
}
