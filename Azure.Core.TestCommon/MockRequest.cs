// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics.CodeAnalysis;

namespace Azure.Core.TestCommon;

/// <summary>
/// Mock HTTP request for testing Azure SDK clients.
/// </summary>
/// <remarks>
/// From https://github.com/Azure/azure-sdk-for-net/blob/main/sdk/core/Azure.Core.TestFramework/src/MockRequest.cs
/// </remarks>
[ExcludeFromCodeCoverage]
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
public class MockRequest : Request
{
    private readonly DictionaryHeaders _headers = new();

    /// <summary>
    /// Creates a new instance.
    /// </summary>
    public MockRequest()
    {
        ClientRequestId = Guid.NewGuid().ToString();
    }

    /// <summary>
    /// Gets whether this request has been disposed.
    /// </summary>
    public bool IsDisposed { get; private set; }

    /// <inheritdoc/>
    public override RequestContent? Content
    {
        get => base.Content;
        set => base.Content = value;
    }

    /// <inheritdoc/>
    protected override void SetHeader(string name, string value) => _headers.SetHeader(name, value);

    /// <inheritdoc/>
    protected override void AddHeader(string name, string value) => _headers.AddHeader(name, value);

    /// <inheritdoc/>
    protected override bool TryGetHeader(string name, [NotNullWhen(true)] out string? value) => _headers.TryGetHeader(name, out value);

    /// <inheritdoc/>
    protected override bool TryGetHeaderValues(string name, [NotNullWhen(true)] out IEnumerable<string>? values) => _headers.TryGetHeaderValues(name, out values);

    /// <inheritdoc/>
    protected override bool ContainsHeader(string name) => _headers.TryGetHeaderValues(name, out _);

    /// <inheritdoc/>
    protected override bool RemoveHeader(string name) => _headers.RemoveHeader(name);

    /// <inheritdoc/>
    protected override IEnumerable<HttpHeader> EnumerateHeaders() => _headers.EnumerateHeaders();

    /// <inheritdoc/>
    public override string ClientRequestId { get; set; }

    /// <inheritdoc/>
    public override string ToString() => $"{Method} {Uri}";

    /// <inheritdoc/>
    public override void Dispose()
    {
        IsDisposed = true;
    }
}
#pragma warning restore CS1591
