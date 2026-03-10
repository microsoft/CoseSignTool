// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Trust;

using System.Diagnostics.CodeAnalysis;
using CoseSign1.Abstractions;

/// <summary>
/// Builder for configuring MST trust-pack registrations.
/// </summary>
public sealed class MstTrustBuilder
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string ErrorIssuerHostRequired = "Issuer host is required";
        public const string ErrorJwksJsonRequired = "JWKS JSON is required";
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="MstTrustBuilder"/> class.
    /// </summary>
    public MstTrustBuilder()
    {
    }

    /// <summary>
    /// Gets the configured trust options.
    /// </summary>
    public MstTrustOptions Options { get; } = new();

    /// <summary>
    /// Enables receipt verification.
    /// </summary>
    /// <returns>The same builder instance.</returns>
    public MstTrustBuilder VerifyReceipts()
    {
        Options.VerifyReceipts = true;
        return this;
    }

    /// <summary>
    /// Enables receipt verification using the specified MST endpoint.
    /// </summary>
    /// <param name="endpoint">The MST service endpoint URL.</param>
    /// <returns>The same builder instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="endpoint"/> is null.</exception>
    public MstTrustBuilder VerifyReceipts(Uri endpoint)
    {
        Guard.ThrowIfNull(endpoint);

        Options.VerifyReceipts = true;
        Options.Endpoint = endpoint;
        return this;
    }

    /// <summary>
    /// Requires that receipts are issued by a specific ledger/issuer host.
    /// </summary>
    /// <param name="issuerHost">The expected issuer host (for example, <c>esrp-cts-cp.confidential-ledger.azure.com</c>).</param>
    /// <returns>The same builder instance.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="issuerHost"/> is null or whitespace.</exception>
    public MstTrustBuilder RequireIssuerHost(string issuerHost)
    {
        Guard.ThrowIfNullOrWhiteSpace(issuerHost, ClassStrings.ErrorIssuerHostRequired, nameof(issuerHost));

        Options.AuthorizedDomains = new[] { issuerHost };
        return this;
    }

    /// <summary>
    /// Configures offline-only receipt verification using a pinned JWKS JSON payload.
    /// </summary>
    /// <param name="jwksJson">The JWKS JSON (for example, <c>{\"keys\":[...]}</c>).</param>
    /// <returns>The same builder instance.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="jwksJson"/> is null or whitespace.</exception>
    public MstTrustBuilder UseOfflineTrustedJwksJson(string jwksJson)
    {
        Guard.ThrowIfNullOrWhiteSpace(jwksJson, ClassStrings.ErrorJwksJsonRequired, nameof(jwksJson));

        // Offline keys only make sense when receipt verification is enabled.
        Options.VerifyReceipts = true;
        Options.OfflineOnly = true;
        Options.HasOfflineKeys = true;
        Options.OfflineTrustedJwksJson = jwksJson;
        return this;
    }

    /// <summary>
    /// Configures the trust pack for offline-only behavior.
    /// </summary>
    /// <returns>The same builder instance.</returns>
    public MstTrustBuilder OfflineOnly()
    {
        Options.OfflineOnly = true;
        return this;
    }
}

/// <summary>
/// Configuration options for the MST trust pack.
/// </summary>
[ExcludeFromCodeCoverage]
public sealed class MstTrustOptions
{
    /// <summary>
    /// Gets or sets a value indicating whether receipt verification is enabled.
    /// When false, <see cref="MstReceiptTrustedFact"/> will be produced as "unavailable".
    /// </summary>
    public bool VerifyReceipts { get; set; }

    /// <summary>
    /// Gets or sets the MST service endpoint used for receipt verification.
    /// Required when <see cref="VerifyReceipts"/> is true.
    /// </summary>
    public Uri? Endpoint { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the trust pack must operate in offline-only mode.
    /// </summary>
    public bool OfflineOnly { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether offline MST signing keys were provided.
    /// </summary>
    /// <remarks>
    /// This option is a compatibility bridge for callers that want to distinguish
    /// "offline requested but no keys provided" (missing) vs "offline keys were provided" (available).
    /// The current implementation does not yet perform full offline receipt verification.
    /// </remarks>
    public bool HasOfflineKeys { get; set; }

    /// <summary>
    /// Gets or sets the authorized receipt issuer domains.
    /// </summary>
    /// <remarks>
    /// When set, verification will only accept receipts whose issuer domain matches one of these values.
    /// If null/empty, the default is derived from <see cref="Endpoint"/>.
    /// </remarks>
    public IReadOnlyList<string>? AuthorizedDomains { get; set; }

    /// <summary>
    /// Gets or sets pinned JWKS JSON content used for offline verification.
    /// </summary>
    /// <remarks>
    /// This is intended for tests and air-gapped environments. When set alongside <see cref="OfflineOnly"/>,
    /// verification should not need to fetch signing keys from the network.
    /// </remarks>
    public string? OfflineTrustedJwksJson { get; set; }
}
