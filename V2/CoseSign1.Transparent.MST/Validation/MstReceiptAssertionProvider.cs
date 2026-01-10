// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Validation;

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.Cose;
using Azure.Security.CodeTransparency;
using CoseSign1.Abstractions;
using CoseSign1.Transparent.MST.Extensions;
using CoseSign1.Validation;
using CoseSign1.Validation.Interfaces;

/// <summary>
/// Validates that a COSE Sign1 message contains valid MST (Microsoft Signing Transparency) receipts.
/// </summary>
/// <remarks>
/// This validator checks for the presence of MST receipts in the message's unprotected headers
/// and verifies their validity using the Azure Code Transparency client.
/// </remarks>
public sealed class MstReceiptAssertionProvider : ISigningKeyAssertionProvider
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public static readonly string ValidatorName = nameof(MstReceiptAssertionProvider);

        public const string TrustDetailsNoReceipt = "NoReceipt";
        public const string TrustDetailsVerificationFailed = "VerificationFailed";
        public const string TrustDetailsException = "Exception";

        public const string MetadataKeyProviderName = "ProviderName";
        public const string MetadataKeyErrors = "Errors";
        public const string MetadataKeyExceptionType = "ExceptionType";
        public const string MetadataKeyExceptionMessage = "ExceptionMessage";

        public const string DefaultProviderName = "MST";
    }

    private readonly MstTransparencyProvider Provider;

    /// <inheritdoc/>
    public string ComponentName => ClassStrings.ValidatorName;

    /// <summary>
    /// Initializes a new instance of the <see cref="MstReceiptAssertionProvider"/> class.
    /// </summary>
    /// <param name="client">The CodeTransparency client for MST verification.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="client"/> is null.</exception>
    public MstReceiptAssertionProvider(CodeTransparencyClient client)
    {
        if (client == null)
        {
            throw new ArgumentNullException(nameof(client));
        }

        Provider = new MstTransparencyProvider(client);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="MstReceiptAssertionProvider"/> class with verification options.
    /// </summary>
    /// <param name="client">The CodeTransparency client for MST verification.</param>
    /// <param name="verificationOptions">Options for controlling receipt validation behavior.</param>
    /// <param name="clientOptions">Optional client options for the transparency client.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="client"/> is null.</exception>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="verificationOptions"/> is null.</exception>
    public MstReceiptAssertionProvider(
        CodeTransparencyClient client,
        CodeTransparencyVerificationOptions verificationOptions,
        CodeTransparencyClientOptions? clientOptions = null)
    {
        if (client == null)
        {
            throw new ArgumentNullException(nameof(client));
        }

        if (verificationOptions == null)
        {
            throw new ArgumentNullException(nameof(verificationOptions));
        }

        Provider = new MstTransparencyProvider(client, verificationOptions, clientOptions);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="MstReceiptAssertionProvider"/> class using an existing provider.
    /// </summary>
    /// <param name="provider">The MST transparency provider to use for validation.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="provider"/> is null.</exception>
    public MstReceiptAssertionProvider(MstTransparencyProvider provider)
    {
        Provider = provider ?? throw new ArgumentNullException(nameof(provider));
    }

    /// <inheritdoc/>
    public bool CanProvideAssertions(ISigningKey signingKey)
    {
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

        // Check if message has MST receipt
        if (!message.HasMstReceipt())
        {
            return new ISigningKeyAssertion[]
            {
                new SigningKeyAssertion(MstTrustClaims.ReceiptPresent, false),
                new SigningKeyAssertion(MstTrustClaims.ReceiptTrusted, false, details: ClassStrings.TrustDetailsNoReceipt)
            };
        }

        // Verify the receipt using the MST provider
        try
        {
            var transparencyResult = await Provider.VerifyTransparencyProofAsync(message, cancellationToken)
                .ConfigureAwait(false);

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
