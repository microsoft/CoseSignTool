// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.Ids;

using System.Security.Cryptography.Cose;
using System.Text;
using CoseSign1.Validation.Trust.Subjects;

/// <summary>
/// Helpers for computing stable trust IDs.
/// </summary>
public static class TrustIds
{
    internal static class ClassStrings
    {
        public const string PrimarySigningKeyDomain = "PrimarySigningKey";
        public const string CounterSignatureSigningKeyDomain = "CounterSignatureSigningKey";
    }

    private static readonly byte[] PrimarySigningKeyDomain = Encoding.ASCII.GetBytes(ClassStrings.PrimarySigningKeyDomain);
    private static readonly byte[] CounterSignatureSigningKeyDomain = Encoding.ASCII.GetBytes(ClassStrings.CounterSignatureSigningKeyDomain);

    /// <summary>
    /// Computes <c>MessageId</c> as SHA-256 of the entire encoded COSE_Sign1 bytes,
    /// including the unprotected header.
    /// </summary>
    /// <param name="message">The message to hash.</param>
    /// <returns>The resulting message ID.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="message"/> is null.</exception>
    public static TrustSubjectId CreateMessageId(CoseSign1Message message)
    {
        if (message == null)
        {
            throw new ArgumentNullException(nameof(message));
        }

        return CreateMessageId(message.Encode());
    }

    /// <summary>
    /// Computes <c>MessageId</c> as SHA-256 of the encoded COSE_Sign1 bytes.
    /// </summary>
    /// <param name="encodedCoseSign1">The encoded COSE_Sign1 bytes.</param>
    /// <returns>The resulting message ID.</returns>
    public static TrustSubjectId CreateMessageId(ReadOnlySpan<byte> encodedCoseSign1)
    {
        return TrustSubjectId.FromSha256OfBytes(encodedCoseSign1);
    }

    /// <summary>
    /// Computes a counter-signature ID as SHA-256 of the raw counter-signature structure bytes.
    /// </summary>
    /// <param name="rawCounterSignatureBytes">The raw bytes of the counter-signature structure.</param>
    /// <returns>The resulting counter-signature ID.</returns>
    public static TrustSubjectId CreateCounterSignatureId(ReadOnlySpan<byte> rawCounterSignatureBytes)
    {
        return TrustSubjectId.FromSha256OfBytes(rawCounterSignatureBytes);
    }

    /// <summary>
    /// Computes a primary signing key subject ID derived from the message ID.
    /// </summary>
    /// <param name="messageId">The message ID.</param>
    /// <returns>The resulting primary signing key ID.</returns>
    public static TrustSubjectId CreatePrimarySigningKeyId(TrustSubjectId messageId)
    {
        // Domain separation to avoid cross-kind collisions.
        byte[] data = new byte[PrimarySigningKeyDomain.Length + messageId.Bytes.Length];
        PrimarySigningKeyDomain.CopyTo(data, 0);
        messageId.Bytes.CopyTo(data.AsSpan(PrimarySigningKeyDomain.Length));
        return TrustSubjectId.FromSha256OfBytes(data);
    }

    /// <summary>
    /// Computes a counter-signature signing key subject ID derived from the counter-signature ID.
    /// </summary>
    /// <param name="counterSignatureId">The counter-signature ID.</param>
    /// <returns>The resulting counter-signature signing key ID.</returns>
    public static TrustSubjectId CreateCounterSignatureSigningKeyId(TrustSubjectId counterSignatureId)
    {
        // Domain separation to avoid cross-kind collisions.
        byte[] data = new byte[CounterSignatureSigningKeyDomain.Length + counterSignatureId.Bytes.Length];
        CounterSignatureSigningKeyDomain.CopyTo(data, 0);
        counterSignatureId.Bytes.CopyTo(data.AsSpan(CounterSignatureSigningKeyDomain.Length));
        return TrustSubjectId.FromSha256OfBytes(data);
    }
}
