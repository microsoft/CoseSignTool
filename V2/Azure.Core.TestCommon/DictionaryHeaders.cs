// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics.CodeAnalysis;

namespace Azure.Core.TestCommon;

/// <summary>
/// An implementation for manipulating headers on Request.
/// </summary>
[ExcludeFromCodeCoverage]
internal class DictionaryHeaders
{
    private readonly Dictionary<string, object> _headers = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Adds a header value to the header collection.
    /// </summary>
    public void AddHeader(string name, string value)
    {
        if (!_headers.TryGetValue(name, out object? objValue))
        {
            _headers[name] = value;
        }
        else
        {
            if (objValue is List<string> values)
            {
                values.Add(value);
            }
            else
            {
                _headers[name] = new List<string> { (objValue as string)!, value };
            }
        }
    }

    /// <summary>
    /// Sets a header value, replacing any existing values.
    /// </summary>
    public void SetHeader(string name, string value)
    {
        _headers[name] = value;
    }

    /// <summary>
    /// Returns header value if the header is stored in the collection.
    /// </summary>
    public bool TryGetHeader(string name, out string? value)
    {
        if (_headers.TryGetValue(name, out object? objValue))
        {
            value = objValue is List<string> values ? JoinHeaderValue(values) : objValue as string;
            return true;
        }

        value = null;
        return false;
    }

    /// <summary>
    /// Returns header values if the header is stored in the collection.
    /// </summary>
    public bool TryGetHeaderValues(string name, out IEnumerable<string>? values)
    {
        if (_headers.TryGetValue(name, out object? objValue))
        {
            values = objValue is List<string> valuesList
                ? valuesList
                : new List<string> { (objValue as string)! };
            return true;
        }

        values = null;
        return false;
    }

    /// <summary>
    /// Removes a header from the collection.
    /// </summary>
    public bool RemoveHeader(string name)
    {
        return _headers.Remove(name);
    }

    /// <summary>
    /// Enumerates all headers in the collection.
    /// </summary>
    public IEnumerable<HttpHeader> EnumerateHeaders()
    {
        foreach (var kvp in _headers)
        {
            if (kvp.Value is List<string> values)
            {
                yield return new HttpHeader(kvp.Key, JoinHeaderValue(values));
            }
            else
            {
                yield return new HttpHeader(kvp.Key, (kvp.Value as string)!);
            }
        }
    }

    private static string JoinHeaderValue(IEnumerable<string> values) => string.Join(",", values);
}