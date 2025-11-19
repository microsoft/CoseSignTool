// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Formats.Cbor;

namespace CoseSign1.Headers;

/// <summary>
/// Represents CWT (CBOR Web Token) Claims extracted from a COSE signature.
/// </summary>
public class CwtClaims
{
    /// <summary>
    /// Gets the issuer claim (iss, label 1).
    /// </summary>
    public string? Issuer { get; private set; }

    /// <summary>
    /// Gets the subject claim (sub, label 2).
    /// </summary>
    public string? Subject { get; private set; }

    /// <summary>
    /// Gets the audience claim (aud, label 3).
    /// </summary>
    public string? Audience { get; private set; }

    /// <summary>
    /// Gets the expiration time claim (exp, label 4) as a DateTimeOffset.
    /// </summary>
    public DateTimeOffset? ExpirationTime { get; private set; }

    /// <summary>
    /// Gets the not-before time claim (nbf, label 5) as a DateTimeOffset.
    /// </summary>
    public DateTimeOffset? NotBefore { get; private set; }

    /// <summary>
    /// Gets the issued-at time claim (iat, label 6) as a DateTimeOffset.
    /// </summary>
    public DateTimeOffset? IssuedAt { get; private set; }

    /// <summary>
    /// Gets the CWT ID claim (cti, label 7).
    /// </summary>
    public byte[]? CwtId { get; private set; }

    /// <summary>
    /// Gets custom claims with integer labels not in the standard set.
    /// The key is the claim label, and the value is the claim value.
    /// Simple types (string, long, bool, byte[]) are parsed directly.
    /// Complex types (maps, arrays) are stored as raw CBOR-encoded bytes.
    /// </summary>
    public IReadOnlyDictionary<int, object> CustomClaims { get; private set; } = new Dictionary<int, object>();

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
                    object? customValue = null;

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
}
