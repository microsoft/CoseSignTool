// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics;

namespace CoseSign1.Headers;

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
    private readonly Dictionary<int, object> Claims;

    /// <summary>
    /// Gets the issuer claim value if set, otherwise null.
    /// </summary>
    public string? Issuer => Claims.TryGetValue(CWTClaimsHeaderLabels.Issuer, out object? value) ? value as string : null;

    /// <summary>
    /// Gets the subject claim value if set, otherwise null.
    /// </summary>
    public string? Subject => Claims.TryGetValue(CWTClaimsHeaderLabels.Subject, out object? value) ? value as string : null;

    /// <summary>
    /// Gets the audience claim value if set, otherwise null.
    /// </summary>
    public string? Audience => Claims.TryGetValue(CWTClaimsHeaderLabels.Audience, out object? value) ? value as string : null;

    /// <summary>
    /// Gets the expiration time claim value if set, otherwise null.
    /// </summary>
    public long? ExpirationTime => Claims.TryGetValue(CWTClaimsHeaderLabels.ExpirationTime, out object? value) ? value as long? : null;

    /// <summary>
    /// Gets the not before claim value if set, otherwise null.
    /// </summary>
    public long? NotBefore => Claims.TryGetValue(CWTClaimsHeaderLabels.NotBefore, out object? value) ? value as long? : null;

    /// <summary>
    /// Gets the issued at claim value if set, otherwise null.
    /// </summary>
    public long? IssuedAt => Claims.TryGetValue(CWTClaimsHeaderLabels.IssuedAt, out object? value) ? value as long? : null;

    /// <summary>
    /// Gets the CWT ID claim value if set, otherwise null.
    /// </summary>
    public byte[]? CWTID => Claims.TryGetValue(CWTClaimsHeaderLabels.CWTID, out object? value) ? value as byte[] : null;

    /// <summary>
    /// Gets a read-only view of all claims currently set in this extender.
    /// </summary>
    public IReadOnlyDictionary<int, object> AllClaims => Claims;

    /// <summary>
    /// Initializes a new instance of the <see cref="CWTClaimsHeaderExtender"/> class with no claims.
    /// </summary>
    public CWTClaimsHeaderExtender()
    {
        Claims = new Dictionary<int, object>();
        Trace.TraceInformation("CWTClaimsHeaderExtender: Initialized with no claims.");
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CWTClaimsHeaderExtender"/> class with the specified claims.
    /// </summary>
    /// <param name="claims">A dictionary of claim labels (integers) to claim values (objects).</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="claims"/> is null.</exception>
    public CWTClaimsHeaderExtender(Dictionary<int, object> claims)
    {
        Claims = claims ?? throw new ArgumentNullException(nameof(claims));
        Trace.TraceInformation($"CWTClaimsHeaderExtender: Initialized with {Claims.Count} claims.");
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

        Claims[CWTClaimsHeaderLabels.Issuer] = issuer;
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

        Claims[CWTClaimsHeaderLabels.Subject] = subject;
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

        Claims[CWTClaimsHeaderLabels.Audience] = audience;
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
        Claims[CWTClaimsHeaderLabels.ExpirationTime] = expirationTime;
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
        long unixTimestamp = expirationTime.ToUnixTimeSeconds();
        return SetExpirationTime(unixTimestamp);
    }

    /// <summary>
    /// Sets the not before (nbf) claim as a Unix timestamp.
    /// </summary>
    /// <param name="notBefore">The not before time as a Unix timestamp (seconds since epoch).</param>
    /// <returns>The current instance for method chaining.</returns>
    public CWTClaimsHeaderExtender SetNotBefore(long notBefore)
    {
        Claims[CWTClaimsHeaderLabels.NotBefore] = notBefore;
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
        long unixTimestamp = notBefore.ToUnixTimeSeconds();
        return SetNotBefore(unixTimestamp);
    }

    /// <summary>
    /// Sets the issued at (iat) claim as a Unix timestamp.
    /// </summary>
    /// <param name="issuedAt">The issued at time as a Unix timestamp (seconds since epoch).</param>
    /// <returns>The current instance for method chaining.</returns>
    public CWTClaimsHeaderExtender SetIssuedAt(long issuedAt)
    {
        Claims[CWTClaimsHeaderLabels.IssuedAt] = issuedAt;
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
        long unixTimestamp = issuedAt.ToUnixTimeSeconds();
        return SetIssuedAt(unixTimestamp);
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

        Claims[CWTClaimsHeaderLabels.CWTID] = cwtId;
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

        Claims[label] = value;
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
        bool removed = Claims.Remove(label);
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

        if (Claims.Count == 0)
        {
            Trace.TraceWarning("CWTClaimsHeaderExtender: No claims to add to protected headers.");
            return protectedHeaders;
        }

        // Auto-populate iat (issued at) and nbf (not before) claims if not already present and if issuer or subject are set
        // This ensures these claims are only added when CWT claims are being actively used
        if (Claims.ContainsKey(CWTClaimsHeaderLabels.Issuer) || Claims.ContainsKey(CWTClaimsHeaderLabels.Subject))
        {
            long currentTimestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            
            if (!Claims.ContainsKey(CWTClaimsHeaderLabels.IssuedAt))
            {
                Claims[CWTClaimsHeaderLabels.IssuedAt] = currentTimestamp;
                Trace.TraceInformation($"CWTClaimsHeaderExtender: Auto-populated iat (issued at) claim with current timestamp: {currentTimestamp}");
            }
            
            if (!Claims.ContainsKey(CWTClaimsHeaderLabels.NotBefore))
            {
                Claims[CWTClaimsHeaderLabels.NotBefore] = currentTimestamp;
                Trace.TraceInformation($"CWTClaimsHeaderExtender: Auto-populated nbf (not before) claim with current timestamp: {currentTimestamp}");
            }
        }

        // Encode the claims as a CBOR map
        CborWriter writer = new();
        writer.WriteStartMap(Claims.Count);

        foreach (KeyValuePair<int, object> claim in Claims)
        {
            writer.WriteInt32(claim.Key);

            // Encode the value based on its type
            switch (claim.Value)
            {
                case string stringValue:
                    writer.WriteTextString(stringValue);
                    break;
                case long longValue:
                    writer.WriteInt64(longValue);
                    break;
                case int intValue:
                    writer.WriteInt32(intValue);
                    break;
                case byte[] byteArrayValue:
                    writer.WriteByteString(byteArrayValue);
                    break;
                case bool boolValue:
                    writer.WriteBoolean(boolValue);
                    break;
                case double doubleValue:
                    writer.WriteDouble(doubleValue);
                    break;
                default:
                    Trace.TraceError($"CWTClaimsHeaderExtender: Unsupported claim value type {claim.Value.GetType().Name} for claim {claim.Key}.");
                    throw new InvalidOperationException($"Unsupported claim value type: {claim.Value.GetType().Name}");
            }
        }

        writer.WriteEndMap();

        // Add the encoded claims to the protected headers under label 13
        CoseHeaderValue cwtClaimsValue = CoseHeaderValue.FromEncodedValue(writer.Encode());
        protectedHeaders[CWTClaimsHeaderLabels.CWTClaims] = cwtClaimsValue;

        Trace.TraceInformation($"CWTClaimsHeaderExtender: Added {Claims.Count} CWT claims to protected headers.");
        return protectedHeaders;
    }

    /// <inheritdoc/>
    public CoseHeaderMap ExtendUnProtectedHeaders(CoseHeaderMap? unProtectedHeaders)
    {
        // CWT Claims should only be in protected headers per SCITT specification
        unProtectedHeaders ??= new CoseHeaderMap();
        Trace.TraceInformation("CWTClaimsHeaderExtender: No modifications to unprotected headers (CWT Claims are protected only).");
        return unProtectedHeaders;
    }
}
