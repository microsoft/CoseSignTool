// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace DIDx509.Models;

using System;

/// <summary>
/// Represents a single policy in a DID:X509 identifier.
/// </summary>
public sealed class DidX509Policy
{
    /// <summary>
    /// Gets the policy name (e.g., "subject", "san", "eku", "fulcio-issuer").
    /// </summary>
    public string Name { get; }

    /// <summary>
    /// Gets the raw policy value (unparsed).
    /// </summary>
    public string RawValue { get; }

    /// <summary>
    /// Gets the parsed policy value (type depends on policy).
    /// </summary>
    public object? ParsedValue { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="DidX509Policy"/> class.
    /// </summary>
    public DidX509Policy(string name, string rawValue, object? parsedValue = null)
    {
        Name = name ?? throw new ArgumentNullException(nameof(name));
        RawValue = rawValue ?? throw new ArgumentNullException(nameof(rawValue));
        ParsedValue = parsedValue;
    }
}