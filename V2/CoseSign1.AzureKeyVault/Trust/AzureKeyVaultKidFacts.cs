// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.AzureKeyVault.Trust;

using CoseSign1.Validation.Trust.Facts;

/// <summary>
/// Message-scoped fact describing whether the message <c>kid</c> looks like an Azure Key Vault key URI.
/// </summary>
public sealed record AzureKeyVaultKidDetectedFact(bool IsAzureKeyVaultKey) : IMessageFact
{
    /// <inheritdoc />
    public TrustFactScope Scope => TrustFactScope.Message;
}

/// <summary>
/// Message-scoped fact describing whether the message <c>kid</c> matches one of the configured allowed patterns.
/// </summary>
public sealed record AzureKeyVaultKidAllowedFact(bool IsAllowed, string? Details = null) : IMessageFact
{
    /// <inheritdoc />
    public TrustFactScope Scope => TrustFactScope.Message;
}
