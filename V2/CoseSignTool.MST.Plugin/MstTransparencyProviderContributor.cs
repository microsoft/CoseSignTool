// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Azure;
using Azure.Security.CodeTransparency;
using CoseSign1.Abstractions.Transparency;
using CoseSign1.Transparent.MST;
using CoseSignTool.Plugins;

namespace CoseSignTool.MST.Plugin;

/// <summary>
/// Transparency provider contributor for Microsoft Signing Transparency (MST).
/// Enables signing commands to automatically include MST receipts.
/// </summary>
public class MstTransparencyProviderContributor : ITransparencyProviderContributor
{
    /// <inheritdoc/>
    public string ProviderName => "Microsoft Signing Transparency";

    /// <inheritdoc/>
    public string ProviderDescription => "Add Microsoft Signing Transparency (MST) receipts to signed messages";

    /// <inheritdoc/>
    public Task<ITransparencyProvider> CreateTransparencyProviderAsync(
        IDictionary<string, object?> options,
        CancellationToken cancellationToken = default)
    {
        // Get MST endpoint from options (optional - uses default if not provided)
        string? endpoint = options.TryGetValue("mst-endpoint", out var endpointValue)
            ? endpointValue as string
            : null;

        // Create MST client
        CodeTransparencyClient client;
        if (!string.IsNullOrEmpty(endpoint))
        {
            if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var endpointUri))
            {
                throw new ArgumentException($"Invalid MST endpoint URL: {endpoint}");
            }

            client = new CodeTransparencyClient(endpointUri);
        }
        else
        {
            // Use default public MST service endpoint
            client = new CodeTransparencyClient(new Uri("https://dataplane.codetransparency.azure.net"));
        }

        // Note: SkipEmbedding is not currently supported by CodeTransparencyVerificationOptions
        // Create the transparency provider
        var provider = new MstTransparencyProvider(client, null, null);

        return Task.FromResult<ITransparencyProvider>(provider);
    }
}