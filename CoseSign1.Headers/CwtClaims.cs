// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Headers;

using System.Linq;

/// <summary>
/// Represents CWT (CBOR Web Token) Claims extracted from a COSE signature.
/// </summary>
public sealed class CwtClaims
{
    /// <summary>
    /// Default value for the subject claim (sub, label 2) when not explicitly set.
    /// </summary>
    public static readonly string DefaultSubject = "unknown.intent";

    /// <summary>
    /// Gets the issuer claim (iss, label 1).
    /// </summary>
    public string? Issuer { get; internal set; }

    /// <summary>
    /// Gets the subject claim (sub, label 2).
    /// Default value is "unknown.intent" when not explicitly set.
    /// </summary>
    public string? Subject { get; internal set; } = DefaultSubject;

    /// <summary>
    /// Gets the audience claim (aud, label 3).
    /// </summary>
    public string? Audience { get; internal set; }

    /// <summary>
    /// Gets the expiration time claim (exp, label 4) as a DateTimeOffset.
    /// </summary>
    public DateTimeOffset? ExpirationTime { get; internal set; }

    /// <summary>
    /// Gets the not-before time claim (nbf, label 5) as a DateTimeOffset.
    /// </summary>
    public DateTimeOffset? NotBefore { get; internal set; }

    /// <summary>
    /// Gets the issued-at time claim (iat, label 6) as a DateTimeOffset.
    /// </summary>
    public DateTimeOffset? IssuedAt { get; internal set; }

    /// <summary>
    /// Gets the CWT ID claim (cti, label 7).
    /// </summary>
    public byte[]? CwtId { get; internal set; }

    /// <summary>
    /// Gets custom claims with integer labels not in the standard set.
    /// The key is the claim label, and the value is the claim value.
    /// Simple types (string, long, bool, byte[]) are parsed directly.
    /// Complex types (maps, arrays) are stored as raw CBOR-encoded bytes.
    /// </summary>
    public Dictionary<int, object> CustomClaims { get; internal set; } = new Dictionary<int, object>();

    #region Constructors

    /// <summary>
    /// Internal constructor for CwtClaims.
    /// </summary>
    internal CwtClaims()
    {
    }

    /// <summary>
    /// Copy constructor for CwtClaims.
    /// </summary>
    internal CwtClaims(CwtClaims other)
    {
        Issuer = other.Issuer;
        Subject = other.Subject;
        Audience = other.Audience;
        ExpirationTime = other.ExpirationTime;
        NotBefore = other.NotBefore;
        IssuedAt = other.IssuedAt;
        CwtId = other.CwtId != null ? (byte[])other.CwtId.Clone() : null;
        CustomClaims = new Dictionary<int, object>(other.CustomClaims);
    }

    #endregion

    #region CBOR Serialization

    /// <summary>
    /// Parses CWT Claims from CBOR-encoded bytes.
    /// </summary>
    /// <param name="cborBytes">The CBOR-encoded CWT claims map.</param>
    /// <returns>A CwtClaims object containing the parsed claims.</returns>
    /// <exception cref="ArgumentNullException">Thrown when cborBytes is null.</exception>
    /// <exception cref="CborContentException">Thrown when the CBOR data is malformed.</exception>
    public static CwtClaims FromCborBytes(byte[] cborBytes)
    {
        if (cborBytes == null)
        {
            throw new ArgumentNullException(nameof(cborBytes));
        }

        var reader = new CborReader(cborBytes);
        reader.ReadStartMap();

        string? issuer = null;
        string? subject = null;
        string? audience = null;
        DateTimeOffset? expirationTime = null;
        DateTimeOffset? notBefore = null;
        DateTimeOffset? issuedAt = null;
        byte[]? cwtId = null;
        var customClaims = new Dictionary<int, object>();

        while (reader.PeekState() != CborReaderState.EndMap)
        {
            int label = reader.ReadInt32();

            switch (label)
            {
                case CWTClaimsHeaderLabels.Issuer:
                    issuer = reader.ReadTextString();
                    break;

                case CWTClaimsHeaderLabels.Subject:
                    subject = reader.ReadTextString();
                    break;

                case CWTClaimsHeaderLabels.Audience:
                    audience = reader.ReadTextString();
                    break;

                case CWTClaimsHeaderLabels.ExpirationTime:
                    long exp = reader.ReadInt64();
                    expirationTime = DateTimeOffset.FromUnixTimeSeconds(exp);
                    break;

                case CWTClaimsHeaderLabels.NotBefore:
                    long nbf = reader.ReadInt64();
                    notBefore = DateTimeOffset.FromUnixTimeSeconds(nbf);
                    break;

                case CWTClaimsHeaderLabels.IssuedAt:
                    long iat = reader.ReadInt64();
                    issuedAt = DateTimeOffset.FromUnixTimeSeconds(iat);
                    break;

                case CWTClaimsHeaderLabels.CWTID:
                    cwtId = reader.ReadByteString();
                    break;

                default:
                    // Handle custom claims based on CBOR type
                    var state = reader.PeekState();
                    object? customValue;

                    switch (state)
                    {
                        case CborReaderState.TextString:
                            customValue = reader.ReadTextString();
                            break;
                        case CborReaderState.UnsignedInteger:
                            customValue = reader.ReadInt64();
                            break;
                        case CborReaderState.NegativeInteger:
                            customValue = reader.ReadInt64();
                            break;
                        case CborReaderState.ByteString:
                            customValue = reader.ReadByteString();
                            break;
                        case CborReaderState.Boolean:
                            customValue = reader.ReadBoolean();
                            break;
                        case CborReaderState.HalfPrecisionFloat:
                        case CborReaderState.SinglePrecisionFloat:
                        case CborReaderState.DoublePrecisionFloat:
                            customValue = reader.ReadDouble();
                            break;
                        default:
                            // For complex types (maps, arrays, etc), store as raw CBOR bytes
                            // so the caller can process them externally if needed
                            customValue = reader.ReadEncodedValue().ToArray();
                            break;
                    }

                    if (customValue != null)
                    {
                        customClaims[label] = customValue;
                    }
                    break;
            }
        }

        reader.ReadEndMap();

        return new CwtClaims
        {
            Issuer = issuer,
            Subject = subject,
            Audience = audience,
            ExpirationTime = expirationTime,
            NotBefore = notBefore,
            IssuedAt = issuedAt,
            CwtId = cwtId,
            CustomClaims = customClaims
        };
    }

    /// <summary>
    /// Converts the CWT claims to CBOR-encoded bytes.
    /// </summary>
    /// <returns>CBOR-encoded bytes representing the claims map.</returns>
    public byte[] ToCborBytes()
    {
        var writer = new CborWriter();
        
        // Count all non-null claims
        int claimCount = CustomClaims.Count;
        if (Issuer != null)
        {
            claimCount++;
        }
        if (Subject != null)
        {
            claimCount++;
        }
        if (Audience != null)
        {
            claimCount++;
        }
        if (ExpirationTime.HasValue)
        {
            claimCount++;
        }
        if (NotBefore.HasValue)
        {
            claimCount++;
        }
        if (IssuedAt.HasValue)
        {
            claimCount++;
        }
        if (CwtId != null)
        {
            claimCount++;
        }

        writer.WriteStartMap(claimCount);

        // Write standard claims
        if (Issuer != null)
        {
            writer.WriteInt32(CWTClaimsHeaderLabels.Issuer);
            writer.WriteTextString(Issuer);
        }

        if (Subject != null)
        {
            writer.WriteInt32(CWTClaimsHeaderLabels.Subject);
            writer.WriteTextString(Subject);
        }

        if (Audience != null)
        {
            writer.WriteInt32(CWTClaimsHeaderLabels.Audience);
            writer.WriteTextString(Audience);
        }

        if (ExpirationTime.HasValue)
        {
            writer.WriteInt32(CWTClaimsHeaderLabels.ExpirationTime);
            writer.WriteInt64(ExpirationTime.Value.ToUnixTimeSeconds());
        }

        if (NotBefore.HasValue)
        {
            writer.WriteInt32(CWTClaimsHeaderLabels.NotBefore);
            writer.WriteInt64(NotBefore.Value.ToUnixTimeSeconds());
        }

        if (IssuedAt.HasValue)
        {
            writer.WriteInt32(CWTClaimsHeaderLabels.IssuedAt);
            writer.WriteInt64(IssuedAt.Value.ToUnixTimeSeconds());
        }

        if (CwtId != null)
        {
            writer.WriteInt32(CWTClaimsHeaderLabels.CWTID);
            writer.WriteByteString(CwtId);
        }

        // Write custom claims
        foreach (var claim in CustomClaims)
        {
            writer.WriteInt32(claim.Key);

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
                    throw new InvalidOperationException($"Unsupported CWT claim value type: {claim.Value.GetType().Name}");
            }
        }

        writer.WriteEndMap();
        return writer.Encode();
    }

    #endregion

    #region Public Methods

    /// <summary>
    /// Determines whether this CwtClaims instance is in its default state (no claims set).
    /// </summary>
    /// <returns>True if this instance has no claims set; otherwise, false.</returns>
    public bool IsDefault()
    {
        return Issuer == null &&
               (Subject == null || string.Equals(Subject, DefaultSubject, StringComparison.Ordinal)) &&
               Audience == null &&
               ExpirationTime == null &&
               NotBefore == null &&
               IssuedAt == null &&
               CwtId == null &&
               CustomClaims.Count == 0;
    }

    /// <summary>
    /// Returns a string representation of the CWT claims.
    /// </summary>
    public override string ToString()
    {
        var parts = new List<string>();

        if (Issuer != null)
        {
            parts.Add($"Issuer: {Issuer}");
        }

        if (Subject != null)
        {
            parts.Add($"Subject: {Subject}");
        }

        if (Audience != null)
        {
            parts.Add($"Audience: {Audience}");
        }

        if (ExpirationTime.HasValue)
        {
            parts.Add($"Expires: {ExpirationTime.Value:o}");
        }

        if (NotBefore.HasValue)
        {
            parts.Add($"Not Before: {NotBefore.Value:o}");
        }

        if (IssuedAt.HasValue)
        {
            parts.Add($"Issued At: {IssuedAt.Value:o}");
        }

        if (CwtId != null)
        {
            parts.Add($"CWT ID: {BitConverter.ToString(CwtId)}");
        }

        if (CustomClaims.Count > 0)
        {
            parts.Add($"Custom Claims: {CustomClaims.Count}");
            foreach (var kvp in CustomClaims)
            {
                string valueStr = kvp.Value switch
                {
                    byte[] bytes => $"[{bytes.Length} bytes]",
                    _ => kvp.Value.ToString() ?? "[null]"
                };
                parts.Add($"  [{kvp.Key}]: {valueStr}");
            }
        }

        return string.Join(Environment.NewLine, parts);
    }

    /// <summary>
    /// Merges this CwtClaims with another, creating a new CwtClaims instance.
    /// Values from the other claims take precedence over values from this instance.
    /// </summary>
    /// <param name="other">The claims to merge with. If null, returns this instance.</param>
    /// <param name="logOverrides">Whether to log when values are overridden.</param>
    /// <returns>A new CwtClaims instance with merged values.</returns>
    public CwtClaims Merge(CwtClaims? other, bool logOverrides = true)
    {
        if (other == null)
        {
            // No merging needed, return this instance
            return this;
        }

        // Create a new instance starting with values from this instance
        var merged = new CwtClaims(this);

        // Overlay with values from other (other wins)
        if (other.Issuer != null)
        {
            if (logOverrides && merged.Issuer != null && !string.Equals(merged.Issuer, other.Issuer, StringComparison.Ordinal))
            {
                System.Diagnostics.Trace.TraceInformation($"CwtClaims.Merge: Overriding issuer claim with new value.");
            }
            merged.Issuer = other.Issuer;
        }

        if (other.Subject != null)
        {
            // Special handling for subject: prefer non-default value over "unknown.intent"
            bool thisIsDefault = string.Equals(merged.Subject, DefaultSubject, StringComparison.Ordinal);
            bool otherIsDefault = string.Equals(other.Subject, DefaultSubject, StringComparison.Ordinal);
            
            if (!otherIsDefault || thisIsDefault)
            {
                // Use other.Subject if:
                // 1. other is not the default value, OR
                // 2. both are default (in which case no change, but we set it anyway for consistency)
                if (logOverrides && merged.Subject != null && !string.Equals(merged.Subject, other.Subject, StringComparison.Ordinal) && !thisIsDefault)
                {
                    System.Diagnostics.Trace.TraceInformation($"CwtClaims.Merge: Overriding subject claim with new value.");
                }
                merged.Subject = other.Subject;
            }
            // else: other is default and this is not, so keep this value
        }

        if (other.Audience != null)
        {
            if (logOverrides && merged.Audience != null && !string.Equals(merged.Audience, other.Audience, StringComparison.Ordinal))
            {
                System.Diagnostics.Trace.TraceInformation($"CwtClaims.Merge: Overriding audience claim with new value.");
            }
            merged.Audience = other.Audience;
        }

        if (other.ExpirationTime.HasValue)
        {
            if (logOverrides && merged.ExpirationTime.HasValue && merged.ExpirationTime != other.ExpirationTime)
            {
                System.Diagnostics.Trace.TraceInformation($"CwtClaims.Merge: Overriding expiration time claim with new value.");
            }
            merged.ExpirationTime = other.ExpirationTime;
        }

        if (other.NotBefore.HasValue)
        {
            if (logOverrides && merged.NotBefore.HasValue && merged.NotBefore != other.NotBefore)
            {
                System.Diagnostics.Trace.TraceInformation($"CwtClaims.Merge: Overriding not-before claim with new value.");
            }
            merged.NotBefore = other.NotBefore;
        }

        if (other.IssuedAt.HasValue)
        {
            if (logOverrides && merged.IssuedAt.HasValue && merged.IssuedAt != other.IssuedAt)
            {
                System.Diagnostics.Trace.TraceInformation($"CwtClaims.Merge: Overriding issued-at claim with new value.");
            }
            merged.IssuedAt = other.IssuedAt;
        }

        if (other.CwtId != null)
        {
            if (logOverrides && merged.CwtId != null && !merged.CwtId.SequenceEqual(other.CwtId))
            {
                System.Diagnostics.Trace.TraceInformation($"CwtClaims.Merge: Overriding CWT ID claim with new value.");
            }
            merged.CwtId = (byte[])other.CwtId.Clone();
        }

        // Merge custom claims (other wins)
        var mergedCustomClaims = new Dictionary<int, object>(merged.CustomClaims);
        foreach (var claim in other.CustomClaims)
        {
            if (logOverrides && mergedCustomClaims.ContainsKey(claim.Key))
            {
                System.Diagnostics.Trace.TraceInformation($"CwtClaims.Merge: Overriding custom claim {claim.Key} with new value.");
            }
            mergedCustomClaims[claim.Key] = claim.Value;
        }
        merged.CustomClaims = mergedCustomClaims;

        return merged;
    }

    #endregion
}
