// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Headers;

using System;
using System.Diagnostics;
using System.Security.Cryptography.Cose;
using CoseSign1.Abstractions;
using CoseSign1.Headers.Extensions;

/// <summary>
/// Specifies where CWT claims should be placed in COSE headers.
/// </summary>
public enum CwtClaimsHeaderPlacement
{
    /// <summary>
    /// Add CWT claims to protected headers only (default, recommended for SCITT compliance).
    /// </summary>
    ProtectedOnly,

    /// <summary>
    /// Add CWT claims to unprotected headers only (not recommended for SCITT).
    /// </summary>
    UnprotectedOnly,

    /// <summary>
    /// Add CWT claims to both protected and unprotected headers.
    /// </summary>
    Both
}

/// <summary>
/// A strongly-typed implementation of <see cref="IHeaderContributor"/> for managing CWT (CBOR Web Token) Claims
/// in COSE Sign1 messages. This class enables customization of CWT claims in the protected header (label 15)
/// as required by SCITT (Supply Chain Integrity, Transparency, and Trust) specifications.
/// </summary>
/// <remarks>
/// <para>
/// This contributor adds CWT Claims to the protected headers as a CBOR map under label 15 (per RFC 9597).
/// CWT Claims are defined in RFC 8392 and include standard claims such as issuer (iss),
/// subject (sub), audience (aud), and timestamp claims (iat, nbf, exp).
/// </para>
/// <para>
/// For SCITT compliance, the issuer and subject claims are typically required at minimum.
/// The iat (Issued At) and nbf (Not Before) claims are automatically populated with the current
/// Unix timestamp when any claim is set, unless explicitly provided.
/// See: https://ietf-wg-scitt.github.io/draft-ietf-scitt-architecture/
/// </para>
/// </remarks>
public class CwtClaimsHeaderContributor : IHeaderContributor
{
    private readonly CwtClaims _claims;
    private readonly CwtClaimsHeaderPlacement _headerPlacement;
    private readonly CoseHeaderLabel _customHeaderLabel;
    private readonly bool _autoPopulateTimestamps;

    /// <summary>
    /// Gets the issuer claim value if set, otherwise null.
    /// </summary>
    public string? Issuer => _claims.Issuer;

    /// <summary>
    /// Gets the subject claim value if set, otherwise null.
    /// </summary>
    public string? Subject => _claims.Subject;

    /// <summary>
    /// Gets the audience claim value if set, otherwise null.
    /// </summary>
    public string? Audience => _claims.Audience;

    /// <summary>
    /// Gets the expiration time claim value if set, otherwise null.
    /// </summary>
    public DateTimeOffset? ExpirationTime => _claims.ExpirationTime;

    /// <summary>
    /// Gets the not before claim value if set, otherwise null.
    /// </summary>
    public DateTimeOffset? NotBefore => _claims.NotBefore;

    /// <summary>
    /// Gets the issued at claim value if set, otherwise null.
    /// </summary>
    public DateTimeOffset? IssuedAt => _claims.IssuedAt;

    /// <summary>
    /// Gets the CWT ID claim value if set, otherwise null.
    /// </summary>
    public byte[]? CWTID => _claims.CwtId;

    /// <summary>
    /// Gets the merge strategy for handling conflicts when headers already exist.
    /// Uses Replace strategy to allow user-provided claims to override defaults.
    /// </summary>
    public HeaderMergeStrategy MergeStrategy => HeaderMergeStrategy.Replace;

    /// <summary>
    /// Initializes a new instance of the <see cref="CwtClaimsHeaderContributor"/> class with no claims.
    /// </summary>
    /// <param name="headerPlacement">Specifies where to place the CWT claims (protected, unprotected, or both). Default is protected only.</param>
    /// <param name="customHeaderLabel">Optional custom header label to use instead of the default CWT Claims label (15).</param>
    /// <param name="autoPopulateTimestamps">If true (default), automatically populates iat and nbf claims with current time if not set.</param>
    public CwtClaimsHeaderContributor(
        CwtClaimsHeaderPlacement headerPlacement = CwtClaimsHeaderPlacement.ProtectedOnly,
        CoseHeaderLabel? customHeaderLabel = null,
        bool autoPopulateTimestamps = true)
    {
        _claims = new CwtClaims();
        _headerPlacement = headerPlacement;
        _customHeaderLabel = customHeaderLabel ?? CWTClaimsHeaderLabels.CWTClaims;
        _autoPopulateTimestamps = autoPopulateTimestamps;
        Trace.TraceInformation($"CwtClaimsHeaderContributor: Initialized with no claims (placement={headerPlacement}, label={_customHeaderLabel}).");
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CwtClaimsHeaderContributor"/> class with the specified claims.
    /// </summary>
    /// <param name="claims">A CwtClaims object containing the initial claims.</param>
    /// <param name="headerPlacement">Specifies where to place the CWT claims (protected, unprotected, or both). Default is protected only.</param>
    /// <param name="customHeaderLabel">Optional custom header label to use instead of the default CWT Claims label (15).</param>
    /// <param name="autoPopulateTimestamps">If true (default), automatically populates iat and nbf claims with current time if not set.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="claims"/> is null.</exception>
    public CwtClaimsHeaderContributor(
        CwtClaims claims,
        CwtClaimsHeaderPlacement headerPlacement = CwtClaimsHeaderPlacement.ProtectedOnly,
        CoseHeaderLabel? customHeaderLabel = null,
        bool autoPopulateTimestamps = true)
    {
        if (claims == null)
        {
            throw new ArgumentNullException(nameof(claims));
        }

        _claims = new CwtClaims(claims);
        _headerPlacement = headerPlacement;
        _customHeaderLabel = customHeaderLabel ?? CWTClaimsHeaderLabels.CWTClaims;
        _autoPopulateTimestamps = autoPopulateTimestamps;
        Trace.TraceInformation($"CwtClaimsHeaderContributor: Initialized with claims from CwtClaims object (placement={headerPlacement}, label={_customHeaderLabel}).");
    }

    /// <summary>
    /// Sets the issuer (iss) claim.
    /// </summary>
    /// <param name="issuer">The issuer string. Must not be null or empty.</param>
    /// <returns>The current instance for method chaining.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="issuer"/> is null or whitespace.</exception>
    public CwtClaimsHeaderContributor SetIssuer(string issuer)
    {
        if (string.IsNullOrWhiteSpace(issuer))
        {
            throw new ArgumentException("Issuer cannot be null or whitespace.", nameof(issuer));
        }

        _claims.Issuer = issuer;
        Trace.TraceInformation($"CwtClaimsHeaderContributor: Set issuer to '{issuer}'.");
        return this;
    }

    /// <summary>
    /// Sets the subject (sub) claim.
    /// </summary>
    /// <param name="subject">The subject string. Must not be null or empty.</param>
    /// <returns>The current instance for method chaining.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="subject"/> is null or whitespace.</exception>
    public CwtClaimsHeaderContributor SetSubject(string subject)
    {
        if (string.IsNullOrWhiteSpace(subject))
        {
            throw new ArgumentException("Subject cannot be null or whitespace.", nameof(subject));
        }

        _claims.Subject = subject;
        Trace.TraceInformation($"CwtClaimsHeaderContributor: Set subject to '{subject}'.");
        return this;
    }

    /// <summary>
    /// Sets the audience (aud) claim.
    /// </summary>
    /// <param name="audience">The audience string. Must not be null or empty.</param>
    /// <returns>The current instance for method chaining.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="audience"/> is null or whitespace.</exception>
    public CwtClaimsHeaderContributor SetAudience(string audience)
    {
        if (string.IsNullOrWhiteSpace(audience))
        {
            throw new ArgumentException("Audience cannot be null or whitespace.", nameof(audience));
        }

        _claims.Audience = audience;
        Trace.TraceInformation($"CwtClaimsHeaderContributor: Set audience to '{audience}'.");
        return this;
    }

    /// <summary>
    /// Sets the expiration time (exp) claim from a DateTimeOffset.
    /// </summary>
    /// <param name="expirationTime">The expiration time as a DateTimeOffset.</param>
    /// <returns>The current instance for method chaining.</returns>
    public CwtClaimsHeaderContributor SetExpirationTime(DateTimeOffset expirationTime)
    {
        _claims.ExpirationTime = expirationTime;
        Trace.TraceInformation($"CwtClaimsHeaderContributor: Set expiration time to {expirationTime.ToUnixTimeSeconds()}.");
        return this;
    }

    /// <summary>
    /// Sets the not before (nbf) claim from a DateTimeOffset.
    /// </summary>
    /// <param name="notBefore">The not before time as a DateTimeOffset.</param>
    /// <returns>The current instance for method chaining.</returns>
    public CwtClaimsHeaderContributor SetNotBefore(DateTimeOffset notBefore)
    {
        _claims.NotBefore = notBefore;
        Trace.TraceInformation($"CwtClaimsHeaderContributor: Set not before time to {notBefore.ToUnixTimeSeconds()}.");
        return this;
    }

    /// <summary>
    /// Sets the issued at (iat) claim from a DateTimeOffset.
    /// </summary>
    /// <param name="issuedAt">The issued at time as a DateTimeOffset.</param>
    /// <returns>The current instance for method chaining.</returns>
    public CwtClaimsHeaderContributor SetIssuedAt(DateTimeOffset issuedAt)
    {
        _claims.IssuedAt = issuedAt;
        Trace.TraceInformation($"CwtClaimsHeaderContributor: Set issued at time to {issuedAt.ToUnixTimeSeconds()}.");
        return this;
    }

    /// <summary>
    /// Sets the CWT ID (cti) claim.
    /// </summary>
    /// <param name="cwtId">The CWT ID as a byte array. Must not be null or empty.</param>
    /// <returns>The current instance for method chaining.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="cwtId"/> is null or empty.</exception>
    public CwtClaimsHeaderContributor SetCWTID(byte[] cwtId)
    {
        if (cwtId == null || cwtId.Length == 0)
        {
            throw new ArgumentException("CWT ID cannot be null or empty.", nameof(cwtId));
        }

        _claims.CwtId = cwtId;
        Trace.TraceInformation($"CwtClaimsHeaderContributor: Set CWT ID (length: {cwtId.Length} bytes).");
        return this;
    }

    /// <summary>
    /// Sets a custom claim with the specified label and value.
    /// </summary>
    /// <param name="label">The claim label (integer key).</param>
    /// <param name="value">The claim value (must be a supported type: string, long, int, byte[], bool, double).</param>
    /// <returns>The current instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="value"/> is null.</exception>
    public CwtClaimsHeaderContributor SetCustomClaim(int label, object value)
    {
        if (value == null)
        {
            throw new ArgumentNullException(nameof(value));
        }

        _claims.CustomClaims[label] = value;
        Trace.TraceInformation($"CwtClaimsHeaderContributor: Set custom claim {label} with value type {value.GetType().Name}.");
        return this;
    }

    /// <summary>
    /// Sets timestamp claims (iat, nbf, exp) in one call for convenience.
    /// </summary>
    /// <param name="issuedAt">The issued at time. If null, will be auto-populated if autoPopulateTimestamps is enabled.</param>
    /// <param name="notBefore">The not before time. If null, will be auto-populated if autoPopulateTimestamps is enabled.</param>
    /// <param name="expirationTime">The expiration time. Optional.</param>
    /// <returns>The current instance for method chaining.</returns>
    public CwtClaimsHeaderContributor WithTimestamps(
        DateTimeOffset? issuedAt = null,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? expirationTime = null)
    {
        if (issuedAt.HasValue)
        {
            _claims.IssuedAt = issuedAt.Value;
            Trace.TraceInformation($"CwtClaimsHeaderContributor: Set issued at time to {issuedAt.Value.ToUnixTimeSeconds()}.");
        }

        if (notBefore.HasValue)
        {
            _claims.NotBefore = notBefore.Value;
            Trace.TraceInformation($"CwtClaimsHeaderContributor: Set not before time to {notBefore.Value.ToUnixTimeSeconds()}.");
        }

        if (expirationTime.HasValue)
        {
            _claims.ExpirationTime = expirationTime.Value;
            Trace.TraceInformation($"CwtClaimsHeaderContributor: Set expiration time to {expirationTime.Value.ToUnixTimeSeconds()}.");
        }

        return this;
    }

    /// <summary>
    /// Sets the audience claim if provided.
    /// </summary>
    /// <param name="audience">The audience string, or null to skip setting.</param>
    /// <returns>The current instance for method chaining.</returns>
    public CwtClaimsHeaderContributor WithAudience(string? audience)
    {
        if (!string.IsNullOrWhiteSpace(audience))
        {
            _claims.Audience = audience;
            Trace.TraceInformation($"CwtClaimsHeaderContributor: Set audience to '{audience}'.");
        }

        return this;
    }

    /// <summary>
    /// Sets the CWT ID claim if provided.
    /// </summary>
    /// <param name="cwtId">The CWT ID byte array, or null to skip setting.</param>
    /// <returns>The current instance for method chaining.</returns>
    public CwtClaimsHeaderContributor WithCwtId(byte[]? cwtId)
    {
        if (cwtId != null && cwtId.Length > 0)
        {
            _claims.CwtId = cwtId;
            Trace.TraceInformation($"CwtClaimsHeaderContributor: Set CWT ID (length: {cwtId.Length} bytes).");
        }

        return this;
    }

    /// <summary>
    /// Configures this contributor to use protected headers only (recommended for SCITT).
    /// This method returns a new instance with the updated placement.
    /// </summary>
    /// <returns>A new CwtClaimsHeaderContributor configured for protected headers.</returns>
    public CwtClaimsHeaderContributor UseProtectedHeaders()
    {
        if (_headerPlacement == CwtClaimsHeaderPlacement.ProtectedOnly)
        {
            return this; // Already configured correctly
        }

        return new CwtClaimsHeaderContributor(
            _claims,
            CwtClaimsHeaderPlacement.ProtectedOnly,
            _customHeaderLabel,
            _autoPopulateTimestamps);
    }

    /// <summary>
    /// Configures this contributor to use unprotected headers only.
    /// This method returns a new instance with the updated placement.
    /// </summary>
    /// <returns>A new CwtClaimsHeaderContributor configured for unprotected headers.</returns>
    public CwtClaimsHeaderContributor UseUnprotectedHeaders()
    {
        if (_headerPlacement == CwtClaimsHeaderPlacement.UnprotectedOnly)
        {
            return this; // Already configured correctly
        }

        return new CwtClaimsHeaderContributor(
            _claims,
            CwtClaimsHeaderPlacement.UnprotectedOnly,
            _customHeaderLabel,
            _autoPopulateTimestamps);
    }

    /// <summary>
    /// Configures this contributor to use both protected and unprotected headers.
    /// This method returns a new instance with the updated placement.
    /// </summary>
    /// <returns>A new CwtClaimsHeaderContributor configured for both header types.</returns>
    public CwtClaimsHeaderContributor UseBothHeaders()
    {
        if (_headerPlacement == CwtClaimsHeaderPlacement.Both)
        {
            return this; // Already configured correctly
        }

        return new CwtClaimsHeaderContributor(
            _claims,
            CwtClaimsHeaderPlacement.Both,
            _customHeaderLabel,
            _autoPopulateTimestamps);
    }

    /// <inheritdoc/>
    public void ContributeProtectedHeaders(CoseHeaderMap headers, HeaderContributorContext context)
    {
        if (headers == null)
        {
            throw new ArgumentNullException(nameof(headers));
        }

        // Skip if this placement doesn't include protected headers
        if (_headerPlacement == CwtClaimsHeaderPlacement.UnprotectedOnly)
        {
            Trace.TraceInformation("CwtClaimsHeaderContributor: Skipping protected headers (placement=UnprotectedOnly).");
            return;
        }

        ContributeToHeaders(headers);
    }

    /// <inheritdoc/>
    public void ContributeUnprotectedHeaders(CoseHeaderMap headers, HeaderContributorContext context)
    {
        if (headers == null)
        {
            throw new ArgumentNullException(nameof(headers));
        }

        // Skip if this placement doesn't include unprotected headers
        if (_headerPlacement == CwtClaimsHeaderPlacement.ProtectedOnly)
        {
            Trace.TraceInformation("CwtClaimsHeaderContributor: Skipping unprotected headers (placement=ProtectedOnly).");
            return;
        }

        ContributeToHeaders(headers);
    }

    private void ContributeToHeaders(CoseHeaderMap headers)
    {
        // Get existing claims if any
        headers.TryGetCwtClaims(out CwtClaims? existingClaims, _customHeaderLabel);

        // Build final claims with auto-population
        CwtClaims finalClaims = BuildFinalClaims();

        // Merge with existing if present (user claims win)
        if (existingClaims != null)
        {
            Trace.TraceInformation("CwtClaimsHeaderContributor: Merging with existing CWT claims.");
            finalClaims = existingClaims.Merge(finalClaims);
        }

        // Only set if we have non-default claims
        if (!finalClaims.IsDefault())
        {
            headers.SetCwtClaims(finalClaims, _customHeaderLabel);
            Trace.TraceInformation("CwtClaimsHeaderContributor: Added CWT claims to headers.");
        }
        else
        {
            Trace.TraceWarning("CwtClaimsHeaderContributor: No claims to add to headers.");
        }
    }

    private CwtClaims BuildFinalClaims()
    {
        var claims = new CwtClaims(_claims);

        // Auto-populate iat (issued at) and nbf (not before) if enabled and not already set
        if (_autoPopulateTimestamps && !claims.IsDefault())
        {
            DateTimeOffset currentTime = DateTimeOffset.UtcNow;
            
            if (!claims.IssuedAt.HasValue)
            {
                claims.IssuedAt = currentTime;
                Trace.TraceInformation($"CwtClaimsHeaderContributor: Auto-populated IssuedAt to {currentTime.ToUnixTimeSeconds()}.");
            }

            if (!claims.NotBefore.HasValue)
            {
                claims.NotBefore = currentTime;
                Trace.TraceInformation($"CwtClaimsHeaderContributor: Auto-populated NotBefore to {currentTime.ToUnixTimeSeconds()}.");
            }
        }

        return claims;
    }
}
