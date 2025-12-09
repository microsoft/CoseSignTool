// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace DIDx509.Models;

using System;

/// <summary>
/// Represents an X.509 Subject Alternative Name (SAN) entry.
/// </summary>
public sealed class SubjectAlternativeName
{
    /// <summary>
    /// Gets the SAN type (email, dns, uri, dn).
    /// </summary>
    public string Type { get; }

    /// <summary>
    /// Gets the SAN value (UTF-8 string or X509Name for DirectoryName).
    /// </summary>
    public object Value { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="SubjectAlternativeName"/> class.
    /// </summary>
    public SubjectAlternativeName(string type, object value)
    {
        Type = type ?? throw new ArgumentNullException(nameof(type));
        Value = value ?? throw new ArgumentNullException(nameof(value));
        
        // Validate type and value combination
        switch (type.ToLowerInvariant())
        {
            case DidX509Constants.SanTypeEmail:
            case DidX509Constants.SanTypeDns:
            case DidX509Constants.SanTypeUri:
                if (!(value is string))
                {
                    throw new ArgumentException($"SAN type '{type}' requires string value", nameof(value));
                }
                break;
            case DidX509Constants.SanTypeDn:
                if (!(value is X509Name))
                {
                    throw new ArgumentException($"SAN type '{type}' requires X509Name value", nameof(value));
                }
                break;
            default:
                throw new ArgumentException($"Unknown SAN type: {type}", nameof(type));
        }
    }

    /// <summary>
    /// Gets the value as a string (for email, dns, uri types).
    /// </summary>
    public string? ValueAsString => Value as string;

    /// <summary>
    /// Gets the value as X509Name (for dn type).
    /// </summary>
    public X509Name? ValueAsName => Value as X509Name;

    /// <summary>
    /// Checks if this SAN matches another SAN.
    /// </summary>
    public bool Matches(SubjectAlternativeName other)
    {
        if (other == null)
        {
            return false;
        }

        if (!string.Equals(Type, other.Type, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (Value is string strValue && other.Value is string otherStrValue)
        {
            return string.Equals(strValue, otherStrValue, StringComparison.Ordinal);
        }

        if (Value is X509Name nameValue && other.Value is X509Name otherNameValue)
        {
            return nameValue.ContainsAll(otherNameValue) && otherNameValue.ContainsAll(nameValue);
        }

        return false;
    }

    /// <inheritdoc/>
    public override string ToString()
    {
        return $"{Type}:{Value}";
    }
}
