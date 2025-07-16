// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.CTS.Plugin;

using Azure.Identity;
using Azure.Core;
using System.Text.Json;

/// <summary>
/// Helper class for creating CodeTransparencyClient instances with proper authentication.
/// </summary>
internal static class CodeTransparencyClientHelper
{
    /// <summary>
    /// Creates a CodeTransparencyClient with the specified endpoint and optional credential file.
    /// </summary>
    /// <param name="endpoint">The Azure Code Transparency Service endpoint URL.</param>
    /// <param name="credentialPath">Optional path to a JSON file containing Azure credentials.</param>
    /// <param name="cancellationToken">Cancellation token for async operations.</param>
    /// <returns>A configured CodeTransparencyClient instance.</returns>
    /// <exception cref="FileNotFoundException">Thrown when the credential file is not found.</exception>
    /// <exception cref="InvalidOperationException">Thrown when credential file format is invalid.</exception>
    public static async Task<CodeTransparencyClient> CreateClientAsync(string endpoint, string? credentialPath, CancellationToken cancellationToken = default)
    {
        var uri = new Uri(endpoint);

        if (!string.IsNullOrEmpty(credentialPath))
        {
            // Load credentials from file if specified
            if (!File.Exists(credentialPath))
            {
                throw new FileNotFoundException($"Credential file not found: {credentialPath}");
            }

            string credentialJson = await File.ReadAllTextAsync(credentialPath, cancellationToken);
            var credentialData = JsonSerializer.Deserialize<JsonElement>(credentialJson);

            // Check for access token in the credential file
            if (credentialData.TryGetProperty("token", out JsonElement tokenElement))
            {
                string token = tokenElement.GetString() ?? throw new InvalidOperationException("Invalid access token in credential file.");
                // Use AzureKeyCredential for access tokens as documented in:
                // https://github.com/Azure/azure-sdk-for-net/blob/main/sdk/confidentialledger/Azure.Security.CodeTransparency/samples/Sample3_UseYourCredentials.md
                var credential = new AzureKeyCredential(token);
                return new CodeTransparencyClient(uri, credential);
            }
            
            // Check for legacy "key" property for backward compatibility
            if (credentialData.TryGetProperty("key", out JsonElement keyElement))
            {
                string key = keyElement.GetString() ?? throw new InvalidOperationException("Invalid credential key in credential file.");
                var credential = new AzureKeyCredential(key);
                return new CodeTransparencyClient(uri, credential);
            }

            // Check for Azure credential configuration with scopes
            if (credentialData.TryGetProperty("scopes", out JsonElement scopesElement))
            {
                var scopes = scopesElement.EnumerateArray()
                    .Select(s => s.GetString())
                    .Where(s => !string.IsNullOrEmpty(s))
                    .Cast<string>()
                    .ToArray();

                if (scopes.Length > 0)
                {
                    // Use DefaultAzureCredential to get access token as documented in:
                    // https://github.com/Azure/azure-sdk-for-net/blob/main/sdk/confidentialledger/Azure.Security.CodeTransparency/samples/Sample3_UseYourCredentials.md
                    TokenCredential defaultCredential = new DefaultAzureCredential();
                    AccessToken accessToken = await defaultCredential.GetTokenAsync(new TokenRequestContext(scopes), cancellationToken);
                    var credential = new AzureKeyCredential(accessToken.Token);
                    return new CodeTransparencyClient(uri, credential);
                }
            }

            throw new InvalidOperationException("Credential file must contain either 'token', 'key', or 'scopes' property for authentication.");
        }

        // Use default Azure credential (managed identity, Azure CLI, etc.) when no credential file is specified
        // Note: CodeTransparencyClient constructor only accepts TokenCredential if using DefaultAzureCredential
        // directly, but the pattern from Azure docs uses AzureKeyCredential with retrieved tokens
        var defaultCred = new DefaultAzureCredential();
        var defaultScopes = new[] { "https://confidential-ledger.azure.com/.default" };
        var defaultToken = await defaultCred.GetTokenAsync(new TokenRequestContext(defaultScopes), cancellationToken);
        return new CodeTransparencyClient(uri, new AzureKeyCredential(defaultToken.Token));
    }
}
