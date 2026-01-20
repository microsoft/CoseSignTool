// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Trust;

using CoseSign1.Validation.Trust.Facts;

/// <summary>
/// Counter-signature-scoped fact indicating whether an MST receipt header is present.
/// </summary>
public sealed record MstReceiptPresentFact(bool IsPresent) : ICounterSignatureFact
{
    /// <inheritdoc />
    public TrustFactScope Scope => TrustFactScope.CounterSignature;
}
