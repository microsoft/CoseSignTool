// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.Facts;

using CoseSign1.Validation.Trust.Subjects;

/// <summary>
/// Represents a counter-signature subject discovered on a message.
/// </summary>
public sealed class CounterSignatureSubjectFact : IMessageFact
{
    /// <inheritdoc />
    public TrustFactScope Scope => TrustFactScope.Message;

    /// <summary>
    /// Initializes a new instance of the <see cref="CounterSignatureSubjectFact"/> class.
    /// </summary>
    /// <param name="subject">The counter-signature subject.</param>
    /// <param name="isProtectedHeader">True if discovered in protected headers; otherwise, false.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="subject"/> is null.</exception>
    public CounterSignatureSubjectFact(TrustSubject subject, bool isProtectedHeader)
    {
        Subject = subject ?? throw new ArgumentNullException(nameof(subject));
        IsProtectedHeader = isProtectedHeader;
    }

    /// <summary>
    /// Gets the counter-signature subject.
    /// </summary>
    public TrustSubject Subject { get; }

    /// <summary>
    /// Gets a value indicating whether the counter-signature was discovered in protected headers.
    /// </summary>
    public bool IsProtectedHeader { get; }
}
