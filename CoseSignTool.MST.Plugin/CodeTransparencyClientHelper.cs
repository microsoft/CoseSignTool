// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.MST.Plugin;

using Azure.Identity;
using Azure.Core;
using System.Text.Json;

/// <summary>
/// Helper class for creating CodeTransparencyClient instances with proper authentication.
/// </summary>
internal static class CodeTransparencyClientHelper
{
    /// <summary>
    /// Default scope used when acquiring an access token via DefaultAzureCredential.
    /// </summary>
    private const string DefaultAzureCredentialScope = "https://confidential-ledger.azure.com/.default";

    /// <summary>
    /// Default name of the environment variable to read for an access token when no <c>--token-env</c>
    /// override is supplied.
    /// </summary>
    private const string DefaultTokenEnvVarName = "MST_TOKEN";

    /// <summary>
    /// Pre-allocated single-element scope array for <see cref="DefaultAzureCredential"/> token requests.
    /// Hoisted to <c>static readonly</c> so the array is not re-allocated on every invocation.
    /// </summary>
    private static readonly string[] DefaultAzureCredentialScopes = new[] { DefaultAzureCredentialScope };

    /// <summary>
    /// Creates a <see cref="CodeTransparencyClient"/> with the specified endpoint and authentication mode.
    /// </summary>
    /// <param name="endpoint">The Microsoft's Signing Transparency (MST) service endpoint URL.</param>
    /// <param name="tokenEnvVarName">
    /// Optional name of the environment variable containing an access token. When the caller supplies
    /// this value explicitly (non-whitespace), the variable MUST contain a non-whitespace value or the
    /// call fails fast with <see cref="InvalidOperationException"/>. When <c>null</c> or whitespace,
    /// the helper consults <c>MST_TOKEN</c> as a non-fatal default.
    /// </param>
    /// <param name="useAzureAuth">
    /// When <c>true</c>, fall back to <see cref="DefaultAzureCredential"/> to acquire a token if no
    /// access token is found via the environment variable. When <c>false</c> (default), the client is
    /// constructed without credentials so calls reach the endpoint anonymously — appropriate for
    /// unauthenticated MST instances such as test ledgers.
    /// </param>
    /// <param name="logger">
    /// Optional logger. When supplied, the helper emits a verbose-level message indicating which
    /// authentication path was selected (token / azure-auth / anonymous). The token contents are
    /// never logged.
    /// </param>
    /// <param name="cancellationToken">Cancellation token for async operations.</param>
    /// <returns>A configured <see cref="CodeTransparencyClient"/> instance.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when <paramref name="tokenEnvVarName"/> is supplied explicitly but the named environment
    /// variable is missing, empty, or whitespace.
    /// </exception>
    public static async Task<CodeTransparencyClient> CreateClientAsync(
        string endpoint,
        string? tokenEnvVarName,
        bool useAzureAuth,
        IPluginLogger? logger = null,
        CancellationToken cancellationToken = default)
    {
        Uri uri = new(endpoint);
        CodeTransparencyClientOptions clientOptions = new();
        clientOptions.ConfigureMstPerformanceOptimizations();

        bool tokenEnvVarExplicitlyRequested = !string.IsNullOrWhiteSpace(tokenEnvVarName);
        string envVarName = tokenEnvVarExplicitlyRequested ? tokenEnvVarName! : DefaultTokenEnvVarName;
        string? token = Environment.GetEnvironmentVariable(envVarName);

        if (!string.IsNullOrWhiteSpace(token))
        {
            // Use the access token from the environment variable.
            // AzureKeyCredential is the documented pattern for static tokens, see:
            // https://github.com/Azure/azure-sdk-for-net/blob/main/sdk/confidentialledger/Azure.Security.CodeTransparency/samples/Sample3_UseYourCredentials.md
            logger?.LogVerbose($"MST auth: using access token from environment variable '{envVarName}'");
            AzureKeyCredential credential = new(token);
            return new CodeTransparencyClient(uri, credential, clientOptions);
        }

        if (tokenEnvVarExplicitlyRequested)
        {
            throw new InvalidOperationException(
                $"--token-env was set to '{envVarName}' but the environment variable is missing, empty, or whitespace.");
        }

        if (useAzureAuth)
        {
            // Acquire a token via the Azure default credential chain (CLI, MSI, VS, etc.).
            logger?.LogVerbose("MST auth: using Azure DefaultAzureCredential (--azure-auth)");
            DefaultAzureCredential defaultCred = new(); // CodeQL [SM05137] This is non-production testing code which is not deployed.
            AccessToken defaultToken = await defaultCred.GetTokenAsync(new TokenRequestContext(DefaultAzureCredentialScopes), cancellationToken).ConfigureAwait(false);
            return new CodeTransparencyClient(uri, new AzureKeyCredential(defaultToken.Token), clientOptions);
        }

        // No credential supplied — construct an anonymous client. Appropriate for unauthenticated
        // MST instances (e.g., test ledgers). The SDK omits the bearer auth policy when no
        // credential is provided, so no Authorization header is sent.
        logger?.LogVerbose("MST auth: anonymous (no credentials sent). Pass --token-env or --azure-auth if the endpoint requires auth.");
        return new CodeTransparencyClient(uri, clientOptions);
    }
}

