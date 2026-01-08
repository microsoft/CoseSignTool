// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics.CodeAnalysis;
using Azure;
using Azure.Security.CodeTransparency;
using CoseSign1.Abstractions.Transparency;
using CoseSign1.Transparent.MST;
using CoseSignTool.Abstractions;

namespace CoseSignTool.MST.Plugin;

/// <summary>
/// Transparency provider contributor for Microsoft Signing Transparency (MST).
/// Enables signing commands to automatically include MST receipts.
/// </summary>
public class MstTransparencyProviderContributor : ITransparencyProviderContributor
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string ProviderName = "Microsoft Signing Transparency";
        public const string ProviderDescription = "Add Microsoft Signing Transparency (MST) receipts to signed messages";

        public const string OptionKeyMstEndpoint = "mst-endpoint";

        public const string ErrorFormatInvalidEndpoint = "Invalid MST endpoint URL: {0}";
        public const string DefaultEndpointUrl = "https://dataplane.codetransparency.azure.net";
    }

    /// <inheritdoc/>
    public string ProviderName => ClassStrings.ProviderName;

    /// <inheritdoc/>
    public string ProviderDescription => ClassStrings.ProviderDescription;

    /// <inheritdoc/>
    public Task<ITransparencyProvider> CreateTransparencyProviderAsync(
        IDictionary<string, object?> options,
        CancellationToken cancellationToken = default)
    {
        // Get MST endpoint from options (optional - uses default if not provided)
        string? endpoint = options.TryGetValue(ClassStrings.OptionKeyMstEndpoint, out var endpointValue)
            ? endpointValue as string
            : null;

        // Create MST client
        CodeTransparencyClient client;
        if (!string.IsNullOrEmpty(endpoint))
        {
            client = new CodeTransparencyClient(ParseEndpointOrThrow(endpoint));
        }
        else
        {
            // Use default public MST service endpoint
            client = new CodeTransparencyClient(new Uri(ClassStrings.DefaultEndpointUrl));
        }

        // Note: SkipEmbedding is not currently supported by CodeTransparencyVerificationOptions
        // Create the transparency provider
        var provider = new MstTransparencyProvider(client, null, null);

        return Task.FromResult<ITransparencyProvider>(provider);
    }

    private static Uri ParseEndpointOrThrow(string endpoint)
    {
        if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var endpointUri))
        {
            ThrowInvalidEndpoint(endpoint);
        }

        return endpointUri;
    }

    private static void ThrowInvalidEndpoint(string endpoint)
    {
        throw new ArgumentException(string.Format(ClassStrings.ErrorFormatInvalidEndpoint, endpoint));
    }
}