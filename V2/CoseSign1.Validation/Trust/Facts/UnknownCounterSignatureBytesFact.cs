// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.Facts;

using CoseSign1.Abstractions;
using CoseSign1.Validation.Trust.Subjects;

/// <summary>
/// Provides the raw bytes of a counter-signature structure when its type is unknown or unsupported.
/// </summary>
public sealed class UnknownCounterSignatureBytesFact : ICounterSignatureFact
{
    /// <inheritdoc />
    public TrustFactScope Scope => TrustFactScope.CounterSignature;

    /// <summary>
    /// Initializes a new instance of the <see cref="UnknownCounterSignatureBytesFact"/> class.
    /// </summary>
    /// <param name="counterSignatureId">The stable counter-signature ID.</param>
    /// <param name="rawCounterSignatureBytes">The raw counter-signature structure bytes.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="rawCounterSignatureBytes"/> is null.</exception>
    public UnknownCounterSignatureBytesFact(TrustSubjectId counterSignatureId, byte[] rawCounterSignatureBytes)
    {
        Guard.ThrowIfNull(rawCounterSignatureBytes);

        CounterSignatureId = counterSignatureId;
        RawCounterSignatureBytes = rawCounterSignatureBytes;
    }

    /// <summary>
    /// Gets the stable counter-signature ID.
    /// </summary>
    public TrustSubjectId CounterSignatureId { get; }

    /// <summary>
    /// Gets the raw counter-signature structure bytes.
    /// </summary>
    public byte[] RawCounterSignatureBytes { get; }
}
