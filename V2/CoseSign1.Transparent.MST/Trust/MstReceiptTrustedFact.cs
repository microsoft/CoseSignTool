// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Trust;

using CoseSign1.Validation.Trust.Facts;

/// <summary>
/// Message-scoped fact indicating whether MST receipts were cryptographically verified.
/// </summary>
/// <remarks>
/// When receipt verification is not enabled, this fact may be produced as "unavailable" (no values).
/// Policies should not require this fact unless verification is explicitly enabled.
/// </remarks>
public sealed record MstReceiptTrustedFact(bool IsTrusted, string? Details = null) : IMessageFact
{
    /// <inheritdoc />
    public TrustFactScope Scope => TrustFactScope.Message;
}
