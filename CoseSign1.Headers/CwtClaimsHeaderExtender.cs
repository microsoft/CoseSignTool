// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Headers;

using System.Diagnostics;

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
/// A strongly-typed implementation of <see cref="ICoseHeaderExtender"/> for managing CWT (CBOR Web Token) Claims
/// in COSE Sign1 messages. This class enables customization of CWT claims in the protected header (label 15)
/// as required by SCITT (Supply Chain Integrity, Transparency, and Trust) specifications.
/// </summary>
/// <remarks>
/// <para>
/// This extender adds CWT Claims to the protected headers as a CBOR map under label 15 (per RFC 9597).
/// CWT Claims are defined in RFC 8392 and include standard claims such as issuer (iss),
/// subject (sub), audience (aud), and timestamp claims (iat, nbf, exp).
/// </para>
/// <para>
/// For SCITT compliance, the issuer and subject claims are typically required at minimum.
/// The iat (Issued At) and nbf (Not Before) claims are automatically populated with the current
/// Unix timestamp when issuer or subject is set, unless explicitly provided.
/// See: https://ietf-wg-scitt.github.io/draft-ietf-scitt-architecture/
/// </para>
/// <para>
/// This class supports all claim types including negative labels per the IANA CWT Claims Registry.
/// Negative labels -256 to -1 are unassigned, -65536 to -257 require specification, and < -65536 are for private use.
/// </para>
/// <para>
/// This class is designed to be chainable with other header extenders using <see cref="ChainedCoseHeaderExtender"/>.
/// </para>
/// </remarks>
public class CWTClaimsHeaderExtender : ICoseHeaderExtender
{
    private readonly CwtClaims Claims = new();
    private readonly bool preventMerge;
    private readonly CwtClaimsHeaderPlacement headerPlacement;
    private readonly CoseHeaderLabel customHeaderLabel;

    /// <summary>
    /// Gets the issuer claim value if set, otherwise null.
    /// </summary>
    public string? Issuer => Claims.Issuer;

    /// <summary>
    /// Gets the subject claim value if set, otherwise null.
    /// </summary>
    public string? Subject => Claims.Subject;

    /// <summary>
    /// Gets the audience claim value if set, otherwise null.
    /// </summary>
    public string? Audience => Claims.Audience;

    /// <summary>
    /// Gets the expiration time claim value if set, otherwise null.
    /// </summary>
    public DateTimeOffset? ExpirationTime => Claims.ExpirationTime;

    /// <summary>
    /// Gets the not before claim value if set, otherwise null.
    /// </summary>
    public DateTimeOffset? NotBefore => Claims.NotBefore;

    /// <summary>
    /// Gets the issued at claim value if set, otherwise null.
    /// </summary>
    public DateTimeOffset? IssuedAt => Claims.IssuedAt;

    /// <summary>
    /// Gets the CWT ID claim value if set, otherwise null.
    /// </summary>
    public byte[]? CWTID => Claims.CwtId;

    /// <summary>
    /// Gets a read-only view of all custom claims currently set in this extender.
    /// </summary>
    public Dictionary<int, object> CustomClaims => Claims.CustomClaims;

    /// <summary>
    /// Initializes a new instance of the <see cref="CWTClaimsHeaderExtender"/> class with no claims.
    /// </summary>
    /// <param name="preventMerge">If true, prevents merging with existing CWT claims and throws an exception if they exist. Default is false.</param>
    /// <param name="headerPlacement">Specifies where to place the CWT claims (protected, unprotected, or both). Default is protected only.</param>
    /// <param name="customHeaderLabel">Optional custom header label to use instead of the default CWT Claims label (15). If not specified, uses CWTClaimsHeaderLabels.CWTClaims.</param>
    public CWTClaimsHeaderExtender(bool preventMerge = false, CwtClaimsHeaderPlacement headerPlacement = CwtClaimsHeaderPlacement.ProtectedOnly, CoseHeaderLabel? customHeaderLabel = null)
    {
        this.preventMerge = preventMerge;
        this.headerPlacement = headerPlacement;
        this.customHeaderLabel = customHeaderLabel ?? CWTClaimsHeaderLabels.CWTClaims;
        Trace.TraceInformation($"CWTClaimsHeaderExtender: Initialized with no claims (preventMerge={preventMerge}, placement={headerPlacement}, label={this.customHeaderLabel}).");
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CWTClaimsHeaderExtender"/> class with the specified claims.
    /// </summary>
    /// <param name="claims">A CwtClaims object containing the initial claims.</param>
    /// <param name="preventMerge">If true, prevents merging with existing CWT claims and throws an exception if they exist. Default is false.</param>
    /// <param name="headerPlacement">Specifies where to place the CWT claims (protected, unprotected, or both). Default is protected only.</param>
    /// <param name="customHeaderLabel">Optional custom header label to use instead of the default CWT Claims label (15). If not specified, uses CWTClaimsHeaderLabels.CWTClaims.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="claims"/> is null.</exception>
    public CWTClaimsHeaderExtender(CwtClaims claims, bool preventMerge = false, CwtClaimsHeaderPlacement headerPlacement = CwtClaimsHeaderPlacement.ProtectedOnly, CoseHeaderLabel? customHeaderLabel = null)
    {
        if (claims == null)
        {
            throw new ArgumentNullException(nameof(claims));
        }
        Claims = new CwtClaims(claims);
        this.preventMerge = preventMerge;
        this.headerPlacement = headerPlacement;
        this.customHeaderLabel = customHeaderLabel ?? CWTClaimsHeaderLabels.CWTClaims;
        Trace.TraceInformation($"CWTClaimsHeaderExtender: Initialized with claims from CwtClaims object (preventMerge={preventMerge}, placement={headerPlacement}, label={this.customHeaderLabel}).");
    }

    /// <summary>
    /// Sets the issuer (iss) claim.
    /// </summary>
    /// <param name="issuer">The issuer string. Must not be null or empty.</param>
    /// <returns>The current instance for method chaining.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="issuer"/> is null or whitespace.</exception>
    public CWTClaimsHeaderExtender SetIssuer(string issuer)
    {
        if (string.IsNullOrWhiteSpace(issuer))
        {
            throw new ArgumentException("Issuer cannot be null or whitespace.", nameof(issuer));
        }

        Claims.Issuer = issuer;
        Trace.TraceInformation($"CWTClaimsHeaderExtender: Set issuer to '{issuer}'.");
        return this;
    }

    /// <summary>
    /// Sets the subject (sub) claim.
    /// </summary>
    /// <param name="subject">The subject string. Must not be null or empty.</param>
    /// <returns>The current instance for method chaining.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="subject"/> is null or whitespace.</exception>
    public CWTClaimsHeaderExtender SetSubject(string subject)
    {
        if (string.IsNullOrWhiteSpace(subject))
        {
            throw new ArgumentException("Subject cannot be null or whitespace.", nameof(subject));
        }

        Claims.Subject = subject;
        Trace.TraceInformation($"CWTClaimsHeaderExtender: Set subject to '{subject}'.");
        return this;
    }

    /// <summary>
    /// Sets the audience (aud) claim.
    /// </summary>
    /// <param name="audience">The audience string. Must not be null or empty.</param>
    /// <returns>The current instance for method chaining.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="audience"/> is null or whitespace.</exception>
    public CWTClaimsHeaderExtender SetAudience(string audience)
    {
        if (string.IsNullOrWhiteSpace(audience))
        {
            throw new ArgumentException("Audience cannot be null or whitespace.", nameof(audience));
        }

        Claims.Audience = audience;
        Trace.TraceInformation($"CWTClaimsHeaderExtender: Set audience to '{audience}'.");
        return this;
    }

    /// <summary>
    /// Sets the expiration time (exp) claim as a Unix timestamp.
    /// </summary>
    /// <param name="expirationTime">The expiration time as a Unix timestamp (seconds since epoch).</param>
    /// <returns>The current instance for method chaining.</returns>
    public CWTClaimsHeaderExtender SetExpirationTime(long expirationTime)
    {
        Claims.ExpirationTime = DateTimeOffset.FromUnixTimeSeconds(expirationTime);
        Trace.TraceInformation($"CWTClaimsHeaderExtender: Set expiration time to {expirationTime}.");
        return this;
    }

    /// <summary>
    /// Sets the expiration time (exp) claim from a DateTimeOffset.
    /// </summary>
    /// <param name="expirationTime">The expiration time as a DateTimeOffset. Will be converted to Unix timestamp (seconds since epoch).</param>
    /// <returns>The current instance for method chaining.</returns>
    public CWTClaimsHeaderExtender SetExpirationTime(DateTimeOffset expirationTime)
    {
        Claims.ExpirationTime = expirationTime;
        Trace.TraceInformation($"CWTClaimsHeaderExtender: Set expiration time to {expirationTime.ToUnixTimeSeconds()}.");
        return this;
    }

    /// <summary>
    /// Sets the not before (nbf) claim as a Unix timestamp.
    /// </summary>
    /// <param name="notBefore">The not before time as a Unix timestamp (seconds since epoch).</param>
    /// <returns>The current instance for method chaining.</returns>
    public CWTClaimsHeaderExtender SetNotBefore(long notBefore)
    {
        Claims.NotBefore = DateTimeOffset.FromUnixTimeSeconds(notBefore);
        Trace.TraceInformation($"CWTClaimsHeaderExtender: Set not before time to {notBefore}.");
        return this;
    }

    /// <summary>
    /// Sets the not before (nbf) claim from a DateTimeOffset.
    /// </summary>
    /// <param name="notBefore">The not before time as a DateTimeOffset. Will be converted to Unix timestamp (seconds since epoch).</param>
    /// <returns>The current instance for method chaining.</returns>
    public CWTClaimsHeaderExtender SetNotBefore(DateTimeOffset notBefore)
    {
        Claims.NotBefore = notBefore;
        Trace.TraceInformation($"CWTClaimsHeaderExtender: Set not before time to {notBefore.ToUnixTimeSeconds()}.");
        return this;
    }

    /// <summary>
    /// Sets the issued at (iat) claim as a Unix timestamp.
    /// </summary>
    /// <param name="issuedAt">The issued at time as a Unix timestamp (seconds since epoch).</param>
    /// <returns>The current instance for method chaining.</returns>
    public CWTClaimsHeaderExtender SetIssuedAt(long issuedAt)
    {
        Claims.IssuedAt = DateTimeOffset.FromUnixTimeSeconds(issuedAt);
        Trace.TraceInformation($"CWTClaimsHeaderExtender: Set issued at time to {issuedAt}.");
        return this;
    }

    /// <summary>
    /// Sets the issued at (iat) claim from a DateTimeOffset.
    /// </summary>
    /// <param name="issuedAt">The issued at time as a DateTimeOffset. Will be converted to Unix timestamp (seconds since epoch).</param>
    /// <returns>The current instance for method chaining.</returns>
    public CWTClaimsHeaderExtender SetIssuedAt(DateTimeOffset issuedAt)
    {
        Claims.IssuedAt = issuedAt;
        Trace.TraceInformation($"CWTClaimsHeaderExtender: Set issued at time to {issuedAt.ToUnixTimeSeconds()}.");
        return this;
    }

    /// <summary>
    /// Sets the CWT ID (cti) claim.
    /// </summary>
    /// <param name="cwtId">The CWT ID as a byte array. Must not be null or empty.</param>
    /// <returns>The current instance for method chaining.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="cwtId"/> is null or empty.</exception>
    public CWTClaimsHeaderExtender SetCWTID(byte[] cwtId)
    {
        if (cwtId == null || cwtId.Length == 0)
        {
            throw new ArgumentException("CWT ID cannot be null or empty.", nameof(cwtId));
        }

        Claims.CwtId = cwtId;
        Trace.TraceInformation($"CWTClaimsHeaderExtender: Set CWT ID (length: {cwtId.Length} bytes).");
        return this;
    }

    /// <summary>
    /// Sets a custom claim with the specified label and value.
    /// </summary>
    /// <param name="label">The claim label (integer key).</param>
    /// <param name="value">The claim value (must be a supported CBOR type: string, long, byte[], etc.).</param>
    /// <returns>The current instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="value"/> is null.</exception>
    public CWTClaimsHeaderExtender SetCustomClaim(int label, object value)
    {
        if (value == null)
        {
            throw new ArgumentNullException(nameof(value));
        }

        Claims.CustomClaims[label] = value;
        Trace.TraceInformation($"CWTClaimsHeaderExtender: Set custom claim {label} with value type {value.GetType().Name}.");
        return this;
    }

    /// <summary>
    /// Removes a claim by its label.
    /// </summary>
    /// <param name="label">The claim label to remove.</param>
    /// <returns>True if the claim was removed; false if the claim was not found.</returns>
    public bool RemoveClaim(int label)
    {
        bool removed = Claims.CustomClaims.Remove(label);
        if (removed)
        {
            Trace.TraceInformation($"CWTClaimsHeaderExtender: Removed claim {label}.");
        }
        else
        {
            Trace.TraceWarning($"CWTClaimsHeaderExtender: Attempted to remove non-existent claim {label}.");
        }
        return removed;
    }

    /// <inheritdoc/>
    public CoseHeaderMap ExtendProtectedHeaders(CoseHeaderMap protectedHeaders)
    {
        if (protectedHeaders == null)
        {
            throw new ArgumentNullException(nameof(protectedHeaders));
        }

        // Skip if this placement doesn't include protected headers
        if (headerPlacement == CwtClaimsHeaderPlacement.UnprotectedOnly)
        {
            Trace.TraceInformation("CWTClaimsHeaderExtender: Skipping protected headers (placement=UnprotectedOnly).");
            return protectedHeaders;
        }

        // Build a CwtClaims object from our internal state (applies auto-population)
        CwtClaims? currentClaims = BuildCwtClaims();
        
        // Extract any existing CWT claims from the protected headers (from certificate provider defaults)
        protectedHeaders.TryGetCwtClaims(out CwtClaims? existingClaims, customHeaderLabel);
        
        if (currentClaims == null && existingClaims == null)
        {
            Trace.TraceWarning("CWTClaimsHeaderExtender: No claims to add to protected headers.");
            return protectedHeaders;
        }

        if (existingClaims != null)
        {
            if (preventMerge)
            {
                throw new InvalidOperationException("CWT claims already exist in protected headers and preventMerge is enabled. Cannot add claims.");
            }
            Trace.TraceInformation($"CWTClaimsHeaderExtender: Found existing CWT claims from provider defaults.");
        }

        // Merge: existing claims as base, current claims override (only if merge is allowed)
        CwtClaims finalClaims = existingClaims?.Merge(currentClaims, logOverrides: true) ?? currentClaims!;

        // Set the final merged claims
        protectedHeaders.SetCwtClaims(finalClaims, customHeaderLabel);

        Trace.TraceInformation($"CWTClaimsHeaderExtender: Added CWT claims to protected headers (merged from defaults and user-provided).");
        return protectedHeaders;
    }

    /// <inheritdoc/>
    public CoseHeaderMap ExtendUnProtectedHeaders(CoseHeaderMap? unProtectedHeaders)
    {
        unProtectedHeaders ??= new CoseHeaderMap();

        // Skip if this placement doesn't include unprotected headers
        if (headerPlacement == CwtClaimsHeaderPlacement.ProtectedOnly)
        {
            Trace.TraceInformation("CWTClaimsHeaderExtender: No modifications to unprotected headers (CWT Claims are protected only).");
            return unProtectedHeaders;
        }

        // Build a CwtClaims object from our internal state (applies auto-population)
        CwtClaims? currentClaims = BuildCwtClaims();
        
        // Extract any existing CWT claims from the unprotected headers
        unProtectedHeaders.TryGetCwtClaims(out CwtClaims? existingClaims, customHeaderLabel);
        
        if (currentClaims == null && existingClaims == null)
        {
            Trace.TraceWarning("CWTClaimsHeaderExtender: No claims to add to unprotected headers.");
            return unProtectedHeaders;
        }

        if (existingClaims != null)
        {
            if (preventMerge)
            {
                throw new InvalidOperationException("CWT claims already exist in unprotected headers and preventMerge is enabled. Cannot add claims.");
            }
            Trace.TraceInformation($"CWTClaimsHeaderExtender: Found existing CWT claims in unprotected headers.");
        }

        // Merge: existing claims as base, current claims override (only if merge is allowed)
        CwtClaims finalClaims = existingClaims?.Merge(currentClaims, logOverrides: true) ?? currentClaims!;

        // Set the final merged claims
        unProtectedHeaders.SetCwtClaims(finalClaims, customHeaderLabel);

        Trace.TraceInformation($"CWTClaimsHeaderExtender: Added CWT claims to unprotected headers.");
        return unProtectedHeaders;
    }

    /// <summary>
    /// Builds a CwtClaims object from the current internal state, auto-populating iat and nbf if needed.
    /// </summary>
    /// <returns>A CwtClaims object, or null if no claims are set.</returns>
    private CwtClaims? BuildCwtClaims()
    {
        // Check if we have any claims at all
        if (Claims.IsDefault())
        {
            return null;
        }

        // Auto-populate iat (issued at) and nbf (not before) claims if not already present
        DateTimeOffset currentTime = DateTimeOffset.UtcNow;
        Claims.IssuedAt ??= currentTime;
        Claims.NotBefore ??= currentTime;

        return Claims;
    }
}
