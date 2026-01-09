// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.AzureKeyVault.Validation;

using System.Diagnostics.CodeAnalysis;

/// <summary>
/// Well-known trust-claim IDs emitted by Azure Key Vault trust providers.
/// </summary>
public static class AkvTrustClaims
{
    /// <summary>
    /// Indicates whether the kid (key identifier) in the signature matches an allowed Azure Key Vault URI pattern.
    /// </summary>
    public const string KidAllowed = ClassStrings.KidAllowed;

    /// <summary>
    /// Indicates whether the signature was made using an Azure Key Vault key (has AKV-shaped kid).
    /// </summary>
    public const string IsAzureKeyVaultKey = ClassStrings.IsAzureKeyVaultKey;

    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string KidAllowed = "akv.kid.allowed";
        public const string IsAzureKeyVaultKey = "akv.key.detected";
    }
}
