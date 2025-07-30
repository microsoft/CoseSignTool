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
    /// Creates a CodeTransparencyClient with the specified endpoint and optional token environment variable.
    /// </summary>
    /// <param name="endpoint">The Azure Code Transparency Service endpoint URL.</param>
    /// <param name="tokenEnvVarName">Optional name of the environment variable containing the access token. 
    /// If not specified, defaults to "AZURE_CTS_TOKEN". If the environment variable is not set, 
    /// uses DefaultAzureCredential.</param>
    /// <param name="cancellationToken">Cancellation token for async operations.</param>
    /// <returns>A configured CodeTransparencyClient instance.</returns>
    /// <exception cref="InvalidOperationException">Thrown when token environment variable is empty or invalid.</exception>
    public static async Task<CodeTransparencyClient> CreateClientAsync(string endpoint, string? tokenEnvVarName, CancellationToken cancellationToken = default)
    {
        Uri uri = new Uri(endpoint);

        // Use the specified environment variable name or default to AZURE_CTS_TOKEN
        string envVarName = tokenEnvVarName ?? "AZURE_CTS_TOKEN";
        string? token = Environment.GetEnvironmentVariable(envVarName);

        if (!string.IsNullOrEmpty(token))
        {
            // Use the access token from the environment variable
            // Use AzureKeyCredential for access tokens as documented in:
            // https://github.com/Azure/azure-sdk-for-net/blob/main/sdk/confidentialledger/Azure.Security.CodeTransparency/samples/Sample3_UseYourCredentials.md
            AzureKeyCredential credential = new AzureKeyCredential(token);
            return new CodeTransparencyClient(uri, credential);
        }

        // Use default Azure credential (managed identity, Azure CLI, etc.) when no token is provided
        // Note: CodeTransparencyClient constructor only accepts TokenCredential if using DefaultAzureCredential
        // directly, but the pattern from Azure docs uses AzureKeyCredential with retrieved tokens
        DefaultAzureCredential defaultCred = new DefaultAzureCredential(); // CodeQL [SM05137] This is non-production testing code which is not deployed.
        string[] defaultScopes = new[] { "https://confidential-ledger.azure.com/.default" };
        AccessToken defaultToken = await defaultCred.GetTokenAsync(new TokenRequestContext(defaultScopes), cancellationToken);
        return new CodeTransparencyClient(uri, new AzureKeyCredential(defaultToken.Token));
    }
}
