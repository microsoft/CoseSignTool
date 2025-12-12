// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace DIDx509.Models;

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;

/// <summary>
/// Represents an X.509 Name (Subject or Issuer) according to the DID:X509 JSON data model.
/// Maps X.509 distinguished name attributes to key-value pairs.
/// </summary>
public sealed class X509Name
{
    private readonly Dictionary<string, string> _attributes;

    /// <summary>
    /// Gets the attributes dictionary (key is label or OID, value is UTF-8 string).
    /// </summary>
    public IReadOnlyDictionary<string, string> Attributes { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="X509Name"/> class.
    /// </summary>
    public X509Name(IDictionary<string, string> attributes)
    {
        _attributes = new Dictionary<string, string>(attributes ?? throw new ArgumentNullException(nameof(attributes)), StringComparer.OrdinalIgnoreCase);
        Attributes = new ReadOnlyDictionary<string, string>(_attributes);
    }

    /// <summary>
    /// Gets an attribute value by key (label or OID).
    /// </summary>
    public string? GetAttribute(string key)
    {
        return _attributes.TryGetValue(key, out var value) ? value : null;
    }

    /// <summary>
    /// Checks if the name contains all attributes from another name with matching values.
    /// </summary>
    public bool ContainsAll(X509Name other)
    {
        if (other == null)
        {
            throw new ArgumentNullException(nameof(other));
        }

        foreach (var kvp in other.Attributes)
        {
            if (!_attributes.TryGetValue(kvp.Key, out var value) || !string.Equals(value, kvp.Value, StringComparison.Ordinal))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Common Name (CN).
    /// </summary>
    public string? CN => GetAttribute(DidX509Constants.AttributeCN);

    /// <summary>
    /// Locality (L).
    /// </summary>
    public string? L => GetAttribute(DidX509Constants.AttributeL);

    /// <summary>
    /// State or Province (ST).
    /// </summary>
    public string? ST => GetAttribute(DidX509Constants.AttributeST);

    /// <summary>
    /// Organization (O).
    /// </summary>
    public string? O => GetAttribute(DidX509Constants.AttributeO);

    /// <summary>
    /// Organizational Unit (OU).
    /// </summary>
    public string? OU => GetAttribute(DidX509Constants.AttributeOU);

    /// <summary>
    /// Country (C).
    /// </summary>
    public string? C => GetAttribute(DidX509Constants.AttributeC);

    /// <summary>
    /// Street Address (STREET).
    /// </summary>
    public string? STREET => GetAttribute(DidX509Constants.AttributeSTREET);
}