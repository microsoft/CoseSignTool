// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.AzureKeyVault.Validation;

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.Cose;
using CoseSign1.Validation;
using CoseSign1.Validation.Abstractions;

/// <summary>
/// Abstract base class for Azure Key Vault validation components.
/// </summary>
/// <remarks>
/// <para>
/// Extends <see cref="ValidationComponentBase"/> with AKV-specific helpers.
/// Provides a default implementation of <see cref="ComputeApplicability"/> that optionally
/// checks for the presence of an Azure Key Vault key identifier (kid) in the message.
/// </para>
/// <para>
/// Derived classes can override <see cref="ComputeApplicability"/> to add additional
/// applicability checks while still leveraging the base AKV check via
/// <see cref="HasAzureKeyVaultKid"/>.
/// </para>
/// </remarks>
public abstract class AkvValidationComponentBase : ValidationComponentBase
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string KeyVaultHostSuffix = ".vault.azure.net";
        public const string KeyVaultKeysPathFragment = "/keys/";
    }

    private static readonly CoseHeaderLabel KidLabel = new(4); // kid header label

    /// <summary>
    /// Gets a value indicating whether this component requires an Azure Key Vault key identifier.
    /// </summary>
    /// <remarks>
    /// When <c>true</c>, <see cref="ComputeApplicability"/> returns <c>false</c> for messages without AKV kid.
    /// When <c>false</c>, this component is applicable to any non-null message with a kid header
    /// and will emit appropriate assertions based on whether the kid is an AKV URI.
    /// Default is <c>false</c> to allow assertion providers to emit facts about any kid.
    /// </remarks>
    protected virtual bool RequireAzureKeyVaultKid => false;

    /// <inheritdoc/>
    /// <remarks>
    /// Default implementation checks for non-null message with a kid header.
    /// If <see cref="RequireAzureKeyVaultKid"/> is true, also verifies the kid looks like an AKV URI.
    /// Override to add additional applicability checks.
    /// </remarks>
    protected override bool ComputeApplicability(CoseSign1Message message, CoseSign1ValidationOptions? options = null)
    {
        if (!TryGetKid(message, out var kid) || string.IsNullOrWhiteSpace(kid))
        {
            return false;
        }

        if (RequireAzureKeyVaultKid)
        {
            return LooksLikeAzureKeyVaultKeyId(kid);
        }

        return true;
    }

    /// <summary>
    /// Checks if the message has an Azure Key Vault key identifier in its headers.
    /// </summary>
    /// <param name="message">The message to check.</param>
    /// <returns><c>true</c> if the message has a kid that looks like an AKV key URI.</returns>
    protected static bool HasAzureKeyVaultKid(CoseSign1Message? message)
    {
        if (message == null)
        {
            return false;
        }

        return TryGetKid(message, out var kid) && LooksLikeAzureKeyVaultKeyId(kid);
    }

    /// <summary>
    /// Attempts to extract the key identifier (kid) from the message headers.
    /// </summary>
    /// <param name="message">The message to check.</param>
    /// <param name="kid">The extracted kid value, or empty string if not found.</param>
    /// <returns><c>true</c> if a kid was found.</returns>
    protected static bool TryGetKid(CoseSign1Message message, out string kid)
    {
        kid = string.Empty;

        // Try protected headers first
        if (message.ProtectedHeaders.TryGetValue(KidLabel, out var protectedKid))
        {
            var bytes = protectedKid.GetValueAsBytes();
            if (bytes.Length > 0)
            {
                kid = System.Text.Encoding.UTF8.GetString(bytes);
                return true;
            }
        }

        // Fall back to unprotected headers
        if (message.UnprotectedHeaders.TryGetValue(KidLabel, out var unprotectedKid))
        {
            var bytes = unprotectedKid.GetValueAsBytes();
            if (bytes.Length > 0)
            {
                kid = System.Text.Encoding.UTF8.GetString(bytes);
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Determines if a key identifier looks like an Azure Key Vault key URI.
    /// </summary>
    /// <param name="kid">The key identifier to check.</param>
    /// <returns><c>true</c> if the kid appears to be an AKV key URI.</returns>
    protected static bool LooksLikeAzureKeyVaultKeyId(string? kid)
    {
        if (string.IsNullOrWhiteSpace(kid))
        {
            return false;
        }

        // Check if it's a valid URI with vault.azure.net host and /keys/ path
        if (Uri.TryCreate(kid, UriKind.Absolute, out var uri))
        {
            return uri.Host.EndsWith(ClassStrings.KeyVaultHostSuffix, StringComparison.OrdinalIgnoreCase)
                   && uri.AbsolutePath.Contains(ClassStrings.KeyVaultKeysPathFragment, StringComparison.OrdinalIgnoreCase);
        }

        return false;
    }
}
