// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Headers;

using System;
using System.Collections.Generic;
using System.Formats.Cbor;

/// <summary>
/// Represents CWT (CBOR Web Token) Claims extracted from or to be added to a COSE signature.
/// </summary>
public sealed class CwtClaims
{
    /// <summary>
    /// Default value for the subject claim (sub, label 2) when not explicitly set.
    /// </summary>
    public const string DefaultSubject = ClassStrings.DefaultSubject;

    /// <summary>
    /// Gets or sets the issuer claim (iss, label 1).
    /// </summary>
    public string? Issuer { get; set; }

    /// <summary>
    /// Gets or sets the subject claim (sub, label 2).
    /// Default value is "unknown.intent" when not explicitly set.
    /// </summary>
    public string? Subject { get; set; }

    /// <summary>
    /// Gets or sets the audience claim (aud, label 3).
    /// </summary>
    public string? Audience { get; set; }

    /// <summary>
    /// Gets or sets the expiration time claim (exp, label 4) as a DateTimeOffset.
    /// </summary>
    public DateTimeOffset? ExpirationTime { get; set; }

    /// <summary>
    /// Gets or sets the not-before time claim (nbf, label 5) as a DateTimeOffset.
    /// </summary>
    public DateTimeOffset? NotBefore { get; set; }

    /// <summary>
    /// Gets or sets the issued-at time claim (iat, label 6) as a DateTimeOffset.
    /// </summary>
    public DateTimeOffset? IssuedAt { get; set; }

    /// <summary>
    /// Gets or sets the CWT ID claim (cti, label 7).
    /// </summary>
    public byte[]? CwtId { get; set; }

    /// <summary>
    /// Gets or sets custom claims with integer labels not in the standard set.
    /// The key is the claim label, and the value is the claim value.
    /// Supported types: string, long, int, byte[], bool, double.
    /// </summary>
    public Dictionary<int, object> CustomClaims { get; set; } = new Dictionary<int, object>();

    /// <summary>
    /// Initializes a new instance of the <see cref="CwtClaims"/> class.
    /// </summary>
    public CwtClaims()
    {
    }

    /// <summary>
    /// Copy constructor for CwtClaims.
    /// </summary>
    /// <param name="other">The instance to copy.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="other"/> is null.</exception>
    public CwtClaims(CwtClaims other)
    {
        if (other == null)
        {
            throw new ArgumentNullException(nameof(other));
        }

        Issuer = other.Issuer;
        Subject = other.Subject;
        Audience = other.Audience;
        ExpirationTime = other.ExpirationTime;
        NotBefore = other.NotBefore;
        IssuedAt = other.IssuedAt;
        CwtId = other.CwtId != null ? (byte[])other.CwtId.Clone() : null;
        CustomClaims = new Dictionary<int, object>(other.CustomClaims);
    }

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
    /// <exception cref="InvalidOperationException">Thrown when a custom claim value has an unsupported type.</exception>
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
                    throw new InvalidOperationException(
                        string.Format(
                            System.Globalization.CultureInfo.InvariantCulture,
                            ClassStrings.UnsupportedCwtClaimValueType,
                            claim.Value.GetType().Name));
            }
        }

        writer.WriteEndMap();
        return writer.Encode();
    }

    /// <summary>
    /// Determines whether this CwtClaims instance is in its default state (no meaningful claims set).
    /// </summary>
    /// <returns>True if this instance has no meaningful claims set; otherwise, false.</returns>
    public bool IsDefault()
    {
        return Issuer == null &&
               Subject == null &&
               Audience == null &&
               ExpirationTime == null &&
               NotBefore == null &&
               IssuedAt == null &&
               CwtId == null &&
               CustomClaims.Count == 0;
    }

    /// <summary>
    /// Merges this CwtClaims with another, creating a new CwtClaims instance.
    /// Values from the other claims take precedence over values from this instance.
    /// </summary>
    /// <param name="other">The claims to merge with. If null, returns a copy of this instance.</param>
    /// <returns>A new CwtClaims instance with merged values.</returns>
    public CwtClaims Merge(CwtClaims? other)
    {
        if (other == null)
        {
            return new CwtClaims(this);
        }

        var merged = new CwtClaims(this);

        // Overlay with values from other (other wins)
        if (other.Issuer != null)
        {
            merged.Issuer = other.Issuer;
        }

        if (other.Subject != null)
        {
            merged.Subject = other.Subject;
        }

        if (other.Audience != null)
        {
            merged.Audience = other.Audience;
        }

        if (other.ExpirationTime.HasValue)
        {
            merged.ExpirationTime = other.ExpirationTime;
        }

        if (other.NotBefore.HasValue)
        {
            merged.NotBefore = other.NotBefore;
        }

        if (other.IssuedAt.HasValue)
        {
            merged.IssuedAt = other.IssuedAt;
        }

        if (other.CwtId != null)
        {
            merged.CwtId = (byte[])other.CwtId.Clone();
        }

        // Merge custom claims (other wins)
        foreach (var claim in other.CustomClaims)
        {
            merged.CustomClaims[claim.Key] = claim.Value;
        }

        return merged;
    }

    /// <summary>
    /// Returns a string representation of the CWT claims.
    /// </summary>
    /// <returns>A string representation of the CWT claims.</returns>
    public override string ToString()
    {
        var parts = new List<string>();

        if (Issuer != null)
        {
            parts.Add(string.Format(ClassStrings.ToStringIssuerFormat, Issuer));
        }

        if (Subject != null)
        {
            parts.Add(string.Format(ClassStrings.ToStringSubjectFormat, Subject));
        }

        if (Audience != null)
        {
            parts.Add(string.Format(ClassStrings.ToStringAudienceFormat, Audience));
        }

        if (ExpirationTime.HasValue)
        {
            parts.Add(string.Format(ClassStrings.ToStringExpiresFormat, ExpirationTime.Value));
        }

        if (NotBefore.HasValue)
        {
            parts.Add(string.Format(ClassStrings.ToStringNotBeforeFormat, NotBefore.Value));
        }

        if (IssuedAt.HasValue)
        {
            parts.Add(string.Format(ClassStrings.ToStringIssuedAtFormat, IssuedAt.Value));
        }

        if (CwtId != null)
        {
            parts.Add(string.Format(ClassStrings.ToStringCwtIdFormat, BitConverter.ToString(CwtId)));
        }

        if (CustomClaims.Count > 0)
        {
            parts.Add(string.Format(ClassStrings.ToStringCustomClaimsCountFormat, CustomClaims.Count));
            foreach (var kvp in CustomClaims)
            {
                string valueStr = kvp.Value switch
                {
                    byte[] bytes => string.Format(ClassStrings.ToStringByteArraySummaryFormat, bytes.Length),
                    _ => kvp.Value.ToString() ?? ClassStrings.ToStringNullPlaceholder
                };
                parts.Add(string.Format(ClassStrings.ToStringCustomClaimEntryFormat, kvp.Key, valueStr));
            }
        }

        return string.Join(Environment.NewLine, parts);
    }
}