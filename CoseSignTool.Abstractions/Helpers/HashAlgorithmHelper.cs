// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Abstractions.Helpers;

using System.Security.Cryptography;
using Microsoft.Extensions.Configuration;

/// <summary>
/// Shared helper for parsing and validating the signing hash algorithm supplied on the command line.
/// </summary>
/// <remarks>
/// Only the SHA-2 family members that COSE defines signature algorithms for are accepted. Restricting
/// the set here keeps the signing path aligned with the allow-list already applied to indirect
/// signatures, so an unsupported algorithm fails during argument parsing rather than mid-sign.
/// </remarks>
public static class HashAlgorithmHelper
{
    /// <summary>
    /// The hash algorithm used when the caller does not specify one.
    /// </summary>
    public static readonly HashAlgorithmName DefaultHashAlgorithm = HashAlgorithmName.SHA256;

    /// <summary>
    /// The set of hash algorithm names accepted by <see cref="Parse(string?)"/>, in documentation order.
    /// </summary>
    public static readonly IReadOnlyList<string> SupportedHashAlgorithms = new[] { "SHA256", "SHA384", "SHA512" };

    /// <summary>
    /// Parses a hash algorithm name such as "SHA384" into a <see cref="HashAlgorithmName"/>.
    /// </summary>
    /// <param name="value">
    /// The algorithm name. Case is ignored and an optional separating dash is allowed, so "sha-384"
    /// and "SHA384" are equivalent. A null or whitespace value yields <see cref="DefaultHashAlgorithm"/>.
    /// </param>
    /// <returns>The parsed <see cref="HashAlgorithmName"/>.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="value"/> is not a supported algorithm.</exception>
    /// <example>
    /// <code>
    /// HashAlgorithmName algorithm = HashAlgorithmHelper.Parse("SHA384");
    /// </code>
    /// </example>
    public static HashAlgorithmName Parse(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return DefaultHashAlgorithm;
        }

        string normalized = value.Trim().Replace("-", string.Empty).ToUpperInvariant();

        return normalized switch
        {
            "SHA256" => HashAlgorithmName.SHA256,
            "SHA384" => HashAlgorithmName.SHA384,
            "SHA512" => HashAlgorithmName.SHA512,
            _ => throw new ArgumentException(
                $"'{value}' is not a supported hash algorithm. Supported values are: {string.Join(", ", SupportedHashAlgorithms)}.",
                nameof(value)),
        };
    }

    /// <summary>
    /// Reads a hash algorithm from configuration, falling back to <see cref="DefaultHashAlgorithm"/> when absent.
    /// </summary>
    /// <param name="configuration">The configuration to read from.</param>
    /// <param name="key">The configuration key holding the algorithm name.</param>
    /// <returns>The parsed <see cref="HashAlgorithmName"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="configuration"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when the configured value is not a supported algorithm.</exception>
    public static HashAlgorithmName Parse(IConfiguration configuration, string key)
    {
        if (configuration is null)
        {
            throw new ArgumentNullException(nameof(configuration));
        }

        return Parse(configuration[key]);
    }
}
