// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Trust;

using CoseSign1.Validation.Trust.Facts;

/// <summary>
/// Counter-signature-scoped fact exposing candidate issuer hosts found in an MST receipt.
/// </summary>
public sealed record MstReceiptIssuerHostFact(IReadOnlyList<string> Hosts) : ICounterSignatureFact
{
    /// <inheritdoc />
    public TrustFactScope Scope => TrustFactScope.CounterSignature;
}
