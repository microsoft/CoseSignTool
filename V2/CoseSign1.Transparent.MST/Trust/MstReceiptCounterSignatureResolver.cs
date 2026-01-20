// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Trust;

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.Cose;
using CoseSign1.Abstractions;
using CoseSign1.Transparent.MST.Extensions;
using CoseSign1.Validation.Interfaces;

/// <summary>
/// Discovers MST receipts from the COSE Sign1 unprotected headers and exposes them as counter-signatures.
/// </summary>
/// <remarks>
/// MST receipts are stored under header label 394 and are not RFC COSE countersignatures.
/// V2 models them as counter-signatures to support subject-scoped trust evaluation.
/// </remarks>
public sealed class MstReceiptCounterSignatureResolver : ICounterSignatureResolver
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string ErrorMissingMessage = "COSE message is required";
        public const string ErrorSigningKeyNotSupported = "MST receipt counter-signatures do not expose a signing key via V2.";
    }

    private static readonly ISigningKey StubSigningKey = new UnsupportedSigningKey();

    /// <inheritdoc />
    public IReadOnlyList<CounterSignatureResolutionResult> Resolve(CoseSign1Message message)
    {
        Guard.ThrowIfNull(message, nameof(message));

        var receipts = message.GetMstReceiptBytes();
        if (receipts.Count == 0)
        {
            return Array.Empty<CounterSignatureResolutionResult>();
        }

        var results = new List<CounterSignatureResolutionResult>(capacity: receipts.Count);
        foreach (var receiptBytes in receipts)
        {
            // Each receipt is a COSE_Sign1 byte string. We treat the raw bytes as the counter-signature identifier input.
            var cs = new MstReceiptCounterSignature(receiptBytes, isProtectedHeader: false, StubSigningKey);
            results.Add(CounterSignatureResolutionResult.Success(cs));
        }

        return results;
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<CounterSignatureResolutionResult>> ResolveAsync(
        CoseSign1Message message,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(Resolve(message));
    }

    private sealed class MstReceiptCounterSignature : ICounterSignature
    {
        public MstReceiptCounterSignature(byte[] rawCounterSignatureBytes, bool isProtectedHeader, ISigningKey signingKey)
        {
            Guard.ThrowIfNull(rawCounterSignatureBytes);
            Guard.ThrowIfNull(signingKey);

            RawCounterSignatureBytes = rawCounterSignatureBytes;
            IsProtectedHeader = isProtectedHeader;
            SigningKey = signingKey;
        }

        public byte[] RawCounterSignatureBytes { get; }

        public bool IsProtectedHeader { get; }

        public ISigningKey SigningKey { get; }
    }

    private sealed class UnsupportedSigningKey : ISigningKey
    {
        public CoseKey GetCoseKey()
        {
            throw new NotSupportedException(ClassStrings.ErrorSigningKeyNotSupported);
        }

        public void Dispose()
        {
            // no-op
        }
    }
}
