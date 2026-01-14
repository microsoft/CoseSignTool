// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.AzureKeyVault.Validation;

using System.Security.Cryptography.Cose;

internal static class AkvKidUtilities
{
    internal static class ClassStrings
    {
        public const string KeyVaultHostSuffix = ".vault.azure.net";
        public const string KeyVaultKeysPathFragment = "/keys/";
    }

    private static readonly CoseHeaderLabel KidLabel = new(4); // kid header label

    internal static bool TryGetKid(CoseSign1Message message, out string kid)
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

    internal static bool LooksLikeAzureKeyVaultKeyId(string? kid)
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
