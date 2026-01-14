// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.Facts;

/// <summary>
/// Indicates whether a COSE Sign1 message has a detached payload (no embedded content).
/// </summary>
public sealed class DetachedPayloadPresentFact : IMessageFact
{
    /// <inheritdoc />
    public TrustFactScope Scope => TrustFactScope.Message;

    /// <summary>
    /// Initializes a new instance of the <see cref="DetachedPayloadPresentFact"/> class.
    /// </summary>
    /// <param name="present">True if the message payload is detached; otherwise false.</param>
    public DetachedPayloadPresentFact(bool present)
    {
        Present = present;
    }

    /// <summary>
    /// Gets a value indicating whether the message payload is detached.
    /// </summary>
    public bool Present { get; }
}
