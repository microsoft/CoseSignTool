// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.Facts;

/// <summary>
/// Identifies the policy scope a fact is intended to be evaluated against.
/// </summary>
public enum TrustFactScope
{
    /// <summary>
    /// Fact is evaluated on the Message subject.
    /// </summary>
    Message,

    /// <summary>
    /// Fact is evaluated on a signing-key subject (e.g., primary signing key or counter-signature signing key).
    /// </summary>
    SigningKey,

    /// <summary>
    /// Fact is evaluated on a counter-signature subject.
    /// </summary>
    CounterSignature
}
