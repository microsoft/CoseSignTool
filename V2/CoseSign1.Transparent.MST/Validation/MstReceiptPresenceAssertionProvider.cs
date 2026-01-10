// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Validation;

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.Cose;
using CoseSign1.Abstractions;
using CoseSign1.Transparent.MST.Extensions;
using CoseSign1.Validation;
using CoseSign1.Validation.Interfaces;

/// <summary>
/// Emits trust assertions about whether an MST receipt is present.
/// This validator does not verify receipt trust.
/// </summary>
public sealed class MstReceiptPresenceAssertionProvider : ISigningKeyAssertionProvider
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public static readonly string ValidatorName = nameof(MstReceiptPresenceAssertionProvider);

        public const string TrustDetailsNotVerified = "NotVerified";
        public const string TrustDetailsNoReceipt = "NoReceipt";
    }

    /// <inheritdoc/>
    public string ComponentName => ClassStrings.ValidatorName;

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
        if (message == null)
        {
            return Array.Empty<ISigningKeyAssertion>();
        }

        bool hasReceipt = message.HasMstReceipt();

        return new ISigningKeyAssertion[]
        {
            new SigningKeyAssertion(MstTrustClaims.ReceiptPresent, hasReceipt),
            new SigningKeyAssertion(MstTrustClaims.ReceiptTrusted, false, details: hasReceipt ? ClassStrings.TrustDetailsNotVerified : ClassStrings.TrustDetailsNoReceipt)
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
