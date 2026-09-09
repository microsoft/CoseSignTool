// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Abstractions.Helpers;

using System.Security.Cryptography;
using Microsoft.Extensions.Configuration;

/// <summary>
/// Shared helper for parsing the RSA signature padding supplied on the command line.
/// </summary>
/// <remarks>
/// The padding selects the COSE algorithm family rather than just an implementation detail:
/// PKCS#1 v1.5 produces RS256/RS384/RS512 while PSS produces PS256/PS384/PS512. Services and
/// verifiers that only accept the RS family therefore need this to be selectable.
/// </remarks>
public static class RsaSignaturePaddingHelper
{
    /// <summary>
    /// The padding used when the caller does not specify one.
    /// </summary>
    public static readonly RSASignaturePadding DefaultPadding = RSASignaturePadding.Pss;

    /// <summary>
    /// The set of padding names accepted by <see cref="Parse(string?)"/>, in documentation order.
    /// </summary>
    public static readonly IReadOnlyList<string> SupportedPaddings = new[] { "PSS", "PKCS1" };

    /// <summary>
    /// Parses a padding name into an <see cref="RSASignaturePadding"/>.
    /// </summary>
    /// <param name="value">
    /// The padding name. Case is ignored. "PSS" and the COSE algorithm prefix "PS" select
    /// <see cref="RSASignaturePadding.Pss"/>; "PKCS1", "PKCS1V15" and the COSE algorithm prefix "RS"
    /// select <see cref="RSASignaturePadding.Pkcs1"/>. A null or whitespace value yields
    /// <see cref="DefaultPadding"/>.
    /// </param>
    /// <returns>The parsed <see cref="RSASignaturePadding"/>.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="value"/> is not a supported padding.</exception>
    /// <example>
    /// <code>
    /// // Both select PKCS#1 v1.5, which produces RS256/RS384/RS512.
    /// RSASignaturePadding padding = RsaSignaturePaddingHelper.Parse("PKCS1");
    /// RSASignaturePadding same = RsaSignaturePaddingHelper.Parse("RS");
    /// </code>
    /// </example>
    public static RSASignaturePadding Parse(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return DefaultPadding;
        }

        string normalized = value.Trim().Replace("-", string.Empty).ToUpperInvariant();

        return normalized switch
        {
            "PSS" or "PS" => RSASignaturePadding.Pss,
            "PKCS1" or "PKCS1V15" or "RS" => RSASignaturePadding.Pkcs1,
            _ => throw new ArgumentException(
                $"'{value}' is not a supported RSA signature padding. Supported values are: {string.Join(", ", SupportedPaddings)}.",
                nameof(value)),
        };
    }

    /// <summary>
    /// Reads an RSA signature padding from configuration, falling back to <see cref="DefaultPadding"/> when absent.
    /// </summary>
    /// <param name="configuration">The configuration to read from.</param>
    /// <param name="key">The configuration key holding the padding name.</param>
    /// <returns>The parsed <see cref="RSASignaturePadding"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="configuration"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when the configured value is not a supported padding.</exception>
    public static RSASignaturePadding Parse(IConfiguration configuration, string key)
    {
        if (configuration is null)
        {
            throw new ArgumentNullException(nameof(configuration));
        }

        return Parse(configuration[key]);
    }

    /// <summary>
    /// Gets the COSE algorithm name produced by a hash algorithm and padding combination.
    /// </summary>
    /// <param name="hashAlgorithm">The hash algorithm.</param>
    /// <param name="padding">The RSA signature padding.</param>
    /// <returns>The COSE algorithm name, such as "RS384".</returns>
    /// <exception cref="ArgumentException">Thrown when the combination has no COSE algorithm.</exception>
    public static string GetCoseAlgorithmName(HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        string prefix = padding == RSASignaturePadding.Pkcs1 ? "RS" : "PS";

        string suffix = hashAlgorithm.Name switch
        {
            "SHA256" => "256",
            "SHA384" => "384",
            "SHA512" => "512",
            _ => throw new ArgumentException(
                $"'{hashAlgorithm.Name}' has no corresponding COSE RSA algorithm.",
                nameof(hashAlgorithm)),
        };

        return prefix + suffix;
    }
}
