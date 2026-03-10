// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.Subjects;

/// <summary>
/// Identifies the kind of entity a trust evaluation is reasoning about.
/// </summary>
public enum TrustSubjectKind
{
    /// <summary>
    /// The overall COSE_Sign1 message.
    /// </summary>
    Message,

    /// <summary>
    /// The primary signature within the message.
    /// </summary>
    PrimarySignature,

    /// <summary>
    /// The signing key used for the primary signature.
    /// </summary>
    PrimarySigningKey,

    /// <summary>
    /// A counter-signature associated with the message.
    /// </summary>
    CounterSignature,

    /// <summary>
    /// The signing key used for a counter-signature.
    /// </summary>
    CounterSignatureSigningKey
}
