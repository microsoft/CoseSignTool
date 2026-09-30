// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Abstractions.Helpers;

using System.Security.Cryptography;
using CoseSign1.Abstractions.Interfaces;
using CoseX509;
using Microsoft.Extensions.Configuration;

/// <summary>
/// Shared parsing for provider-independent COSE signing algorithm options.
/// </summary>
public static class CoseSigningAlgorithmHelper
{
    private const string DefaultContentType = "application/cose";

    /// <summary>
    /// Signing algorithm options that can be exposed by plugin commands.
    /// </summary>
    public static readonly Dictionary<string, string> SigningOptions = new()
    {
        { "hash-algorithm", "The hash algorithm to use (SHA256, SHA384, or SHA512; default: SHA256)" },
        { "rsa-signature-padding", "The RSA signature padding to use (PSS or PKCS1; default: PSS)" },
    };

    /// <summary>
    /// Gets the hash algorithm from configuration.
    /// </summary>
    /// <param name="configuration">The command configuration.</param>
    /// <returns>The parsed hash algorithm.</returns>
    public static HashAlgorithmName GetHashAlgorithm(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        return ParseHashAlgorithm(configuration["hash-algorithm"]);
    }

    /// <summary>
    /// Gets the RSA signature padding from configuration.
    /// </summary>
    /// <param name="configuration">The command configuration.</param>
    /// <returns>The parsed RSA signature padding.</returns>
    public static RSASignaturePadding GetRsaSignaturePadding(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        return ParseRsaSignaturePadding(configuration["rsa-signature-padding"]);
    }

    /// <summary>
    /// Parses a hash algorithm name.
    /// </summary>
    /// <param name="hashAlgorithm">The hash algorithm name.</param>
    /// <returns>The parsed hash algorithm.</returns>
    public static HashAlgorithmName ParseHashAlgorithm(string? hashAlgorithm)
    {
        return (hashAlgorithm ?? HashAlgorithmName.SHA256.Name).ToUpperInvariant() switch
        {
            "SHA256" => HashAlgorithmName.SHA256,
            "SHA384" => HashAlgorithmName.SHA384,
            "SHA512" => HashAlgorithmName.SHA512,
            _ => throw new InvalidOperationException(
                $"Unsupported hash algorithm '{hashAlgorithm}'. Supported values are SHA256, SHA384, and SHA512."),
        };
    }

    /// <summary>
    /// Parses an RSA signature padding name.
    /// </summary>
    /// <param name="rsaSignaturePadding">The RSA signature padding name.</param>
    /// <returns>The parsed RSA signature padding.</returns>
    public static RSASignaturePadding ParseRsaSignaturePadding(string? rsaSignaturePadding)
    {
        string normalizedPadding = (rsaSignaturePadding ?? "PSS").Replace("-", string.Empty).ToUpperInvariant();
        return normalizedPadding switch
        {
            "PSS" or "PS" => RSASignaturePadding.Pss,
            "PKCS1" or "PKCS1V15" or "RS" => RSASignaturePadding.Pkcs1,
            _ => throw new InvalidOperationException(
                $"Unsupported RSA signature padding '{rsaSignaturePadding}'. Supported values are PSS and PKCS1."),
        };
    }

    /// <summary>
    /// Signs a payload using the shared generic COSE signing implementation.
    /// </summary>
    /// <param name="payload">The payload stream.</param>
    /// <param name="signingKeyProvider">The signing key provider.</param>
    /// <param name="embedPayload">Whether to embed the payload in the statement.</param>
    /// <param name="headerExtender">Optional custom header provider.</param>
    /// <param name="hashAlgorithm">The hash algorithm for this signing operation.</param>
    /// <param name="rsaSignaturePadding">The RSA padding for this signing operation.</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    /// <param name="contentType">The payload MIME type.</param>
    /// <returns>The encoded COSE Sign1 statement.</returns>
    public static Task<ReadOnlyMemory<byte>> SignPayloadAsync(
        Stream payload,
        ICoseSigningKeyProvider signingKeyProvider,
        bool embedPayload,
        ICoseHeaderExtender? headerExtender,
        HashAlgorithmName hashAlgorithm,
        RSASignaturePadding rsaSignaturePadding,
        CancellationToken cancellationToken = default,
        string contentType = DefaultContentType)
    {
        return CoseHandler.SignAsync(
            payload,
            signingKeyProvider,
            embedPayload,
            contentType,
            headerExtender,
            hashAlgorithm,
            rsaSignaturePadding,
            cancellationToken);
    }
}
