// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Trust;

using CoseSign1.Validation.Trust.Facts;

/// <summary>
/// Message-scoped fact indicating whether an MST receipt header is present.
/// </summary>
public sealed record MstReceiptPresentFact(bool IsPresent) : IMessageFact
{
    /// <inheritdoc />
    public TrustFactScope Scope => TrustFactScope.Message;
}
