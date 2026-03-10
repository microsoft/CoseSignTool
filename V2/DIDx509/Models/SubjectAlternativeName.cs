// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace DIDx509.Models;

using System;
using System.Diagnostics.CodeAnalysis;

/// <summary>
/// Represents an X.509 Subject Alternative Name (SAN) entry.
/// </summary>
public sealed class SubjectAlternativeName
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string ErrorSanTypeRequiresStringValue = "SAN type '{0}' requires string value";
        public const string ErrorSanTypeRequiresX509NameValue = "SAN type '{0}' requires X509Name value";
        public const string ErrorUnknownSanType = "Unknown SAN type: {0}";
    }

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
    /// <param name="type">The SAN type.</param>
    /// <param name="value">The SAN value.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="type"/> or <paramref name="value"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown when the <paramref name="type"/> and <paramref name="value"/> combination is invalid.</exception>
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
                    throw new ArgumentException(string.Format(ClassStrings.ErrorSanTypeRequiresStringValue, type), nameof(value));
                }
                break;
            case DidX509Constants.SanTypeDn:
                if (!(value is X509Name))
                {
                    throw new ArgumentException(string.Format(ClassStrings.ErrorSanTypeRequiresX509NameValue, type), nameof(value));
                }
                break;
            default:
                throw new ArgumentException(string.Format(ClassStrings.ErrorUnknownSanType, type), nameof(type));
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
    /// <param name="other">The SAN to compare against.</param>
    /// <returns><see langword="true"/> if the SANs match; otherwise, <see langword="false"/>.</returns>
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
        return string.Concat(Type, DidX509Constants.ValueSeparator, Value);
    }
}