// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Azure.Core.TestCommon;

/// <summary>
/// Mock HTTP response for testing Azure SDK clients.
/// </summary>
/// <remarks>
/// From https://github.com/Azure/azure-sdk-for-net/blob/main/sdk/core/Azure.Core.TestFramework/src/MockResponse.cs
/// </remarks>
[ExcludeFromCodeCoverage]
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
public class MockResponse : Response
{
    private readonly Dictionary<string, List<string>> _headers = new(StringComparer.OrdinalIgnoreCase);
    private bool? _isError;

    /// <summary>
    /// Creates a new instance with the specified status code.
    /// </summary>
    public MockResponse(int status, string? reasonPhrase = null)
    {
        Status = status;
        ReasonPhrase = reasonPhrase ?? string.Empty;
        ContentStream = new MemoryStream();
        ClientRequestId = Guid.NewGuid().ToString();
    }

    /// <inheritdoc/>
    public override int Status { get; }

    /// <inheritdoc/>
    public override string ReasonPhrase { get; }

    /// <inheritdoc/>
    public override Stream? ContentStream { get; set; }

    /// <inheritdoc/>
    public override string ClientRequestId { get; set; }

    /// <inheritdoc/>
    public override bool IsError => _isError ?? base.IsError;

    /// <summary>
    /// Gets whether this response has been disposed.
    /// </summary>
    public bool IsDisposed { get; private set; }

    /// <summary>
    /// Sets the IsError value explicitly.
    /// </summary>
    public void SetIsError(bool value) => _isError = value;

    /// <summary>
    /// Sets the response content from a byte array.
    /// </summary>
    public void SetContent(byte[] content)
    {
        ContentStream = new MemoryStream(content, 0, content.Length, false, true);
    }

    /// <summary>
    /// Sets the response content from a string.
    /// </summary>
    public MockResponse SetContent(string content)
    {
        SetContent(Encoding.UTF8.GetBytes(content));
        return this;
    }

    /// <summary>
    /// Adds a header to the response.
    /// </summary>
    public MockResponse AddHeader(string name, string value)
    {
        return AddHeader(new HttpHeader(name, value));
    }

    /// <summary>
    /// Adds a header to the response.
    /// </summary>
    public MockResponse AddHeader(HttpHeader header)
    {
        if (!_headers.TryGetValue(header.Name, out List<string>? values))
        {
            _headers[header.Name] = values = new List<string>();
        }

        values.Add(header.Value);
        return this;
    }

    /// <inheritdoc/>
    protected override bool TryGetHeader(string name, [NotNullWhen(true)] out string? value)
    {
        if (_headers.TryGetValue(name, out List<string>? values))
        {
            value = JoinHeaderValue(values);
            return true;
        }

        value = null;
        return false;
    }

    /// <inheritdoc/>
    protected override bool TryGetHeaderValues(string name, [NotNullWhen(true)] out IEnumerable<string>? values)
    {
        bool result = _headers.TryGetValue(name, out List<string>? valuesList);
        values = valuesList;
        return result;
    }

    /// <inheritdoc/>
    protected override bool ContainsHeader(string name)
    {
        return TryGetHeaderValues(name, out _);
    }

    /// <inheritdoc/>
    protected override IEnumerable<HttpHeader> EnumerateHeaders()
        => _headers.Select(h => new HttpHeader(h.Key, JoinHeaderValue(h.Value)));

    /// <inheritdoc/>
    public override void Dispose()
    {
        IsDisposed = true;
        GC.SuppressFinalize(this);
    }

    private static string JoinHeaderValue(IEnumerable<string> values) => string.Join(",", values);
}
#pragma warning restore CS1591
