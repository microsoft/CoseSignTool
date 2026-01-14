// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.Subjects;

using System.Security.Cryptography.Cose;
using CoseSign1.Validation.Trust.Ids;

/// <summary>
/// A subject (entity) being reasoned about during trust evaluation.
/// </summary>
public sealed class TrustSubject
{
    private TrustSubject(TrustSubjectKind kind, TrustSubjectId id, TrustSubjectId? parentId)
    {
        Kind = kind;
        Id = id;
        ParentId = parentId;
    }

    /// <summary>
    /// Gets the subject kind.
    /// </summary>
    public TrustSubjectKind Kind { get; }

    /// <summary>
    /// Gets the stable subject ID.
    /// </summary>
    public TrustSubjectId Id { get; }

    /// <summary>
    /// Gets the stable parent subject ID (if any).
    /// </summary>
    public TrustSubjectId? ParentId { get; }

    /// <summary>
    /// Creates the message subject.
    /// </summary>
    /// <param name="message">The message being evaluated.</param>
    /// <returns>The message subject.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="message"/> is null.</exception>
    public static TrustSubject Message(CoseSign1Message message)
    {
        if (message == null)
        {
            throw new ArgumentNullException(nameof(message));
        }

        return Message(TrustIds.CreateMessageId(message));
    }

    /// <summary>
    /// Creates the message subject from an already-computed message ID.
    /// </summary>
    /// <param name="messageId">The stable message ID.</param>
    /// <returns>The message subject.</returns>
    public static TrustSubject Message(TrustSubjectId messageId)
    {
        return new TrustSubject(TrustSubjectKind.Message, messageId, parentId: null);
    }

    /// <summary>
    /// Creates the primary signing key subject linked to a message subject.
    /// </summary>
    /// <param name="messageId">The message subject ID.</param>
    /// <returns>The primary signing key subject.</returns>
    public static TrustSubject PrimarySigningKey(TrustSubjectId messageId)
    {
        return new TrustSubject(
            TrustSubjectKind.PrimarySigningKey,
            TrustIds.CreatePrimarySigningKeyId(messageId),
            parentId: messageId);
    }

    /// <summary>
    /// Creates a counter-signature subject linked to a message subject.
    /// </summary>
    /// <param name="messageId">The message subject ID.</param>
    /// <param name="rawCounterSignatureBytes">The raw bytes of the counter-signature structure.</param>
    /// <returns>The counter-signature subject.</returns>
    public static TrustSubject CounterSignature(TrustSubjectId messageId, ReadOnlySpan<byte> rawCounterSignatureBytes)
    {
        return new TrustSubject(
            TrustSubjectKind.CounterSignature,
            TrustIds.CreateCounterSignatureId(rawCounterSignatureBytes),
            parentId: messageId);
    }

    /// <summary>
    /// Creates the counter-signature signing key subject linked to a counter-signature subject.
    /// </summary>
    /// <param name="counterSignatureId">The counter-signature subject ID.</param>
    /// <returns>The counter-signature signing key subject.</returns>
    public static TrustSubject CounterSignatureSigningKey(TrustSubjectId counterSignatureId)
    {
        return new TrustSubject(
            TrustSubjectKind.CounterSignatureSigningKey,
            TrustIds.CreateCounterSignatureSigningKeyId(counterSignatureId),
            parentId: counterSignatureId);
    }
}
