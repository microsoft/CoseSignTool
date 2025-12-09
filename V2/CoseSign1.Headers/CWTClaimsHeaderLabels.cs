// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Headers;

using System.Security.Cryptography.Cose;

/// <summary>
/// <see cref="CoseHeaderLabel"/> objects representing CBOR Web Token (CWT) Claims as defined in RFC 8392.
/// These labels are used in the CWT Claims Set (label 15) according to RFC 9597 and the IANA COSE Header Parameters registry.
/// </summary>
/// <remarks>
/// CWT Claims are defined in RFC 8392, and the CWT Claims header parameter (label 15) is defined in RFC 9597.
/// See: https://www.rfc-editor.org/rfc/rfc9597.html
/// IANA registries:
/// https://www.iana.org/assignments/cose/cose.xhtml#header-parameters
/// https://www.iana.org/assignments/cwt/cwt.xhtml
/// </remarks>
public static class CWTClaimsHeaderLabels
{
    /// <summary>
    /// The CWT Claims Set header label (label 15) as defined in RFC 9597.
    /// This protected header contains a CBOR map of CWT claims.
    /// </summary>
    /// <remarks>
    /// This header is required by SCITT (Supply Chain Integrity, Transparency, and Trust) for submission
    /// to transparency services. See: https://ietf-wg-scitt.github.io/draft-ietf-scitt-architecture/
    /// RFC 9597: https://www.rfc-editor.org/rfc/rfc9597.html
    /// </remarks>
    public static readonly CoseHeaderLabel CWTClaims = new(15);

    // Standard CWT Claim keys from RFC 8392
    // https://www.iana.org/assignments/cwt/cwt.xhtml

    /// <summary>
    /// Issuer claim (label 1): Identifies the principal that issued the JWT/CWT.
    /// </summary>
    /// <remarks>
    /// The "iss" (issuer) claim identifies the principal that issued the CWT.
    /// The processing of this claim is generally application specific.
    /// The value is a case-sensitive string.
    /// </remarks>
    public const int Issuer = 1;

    /// <summary>
    /// Subject claim (label 2): Identifies the principal that is the subject of the JWT/CWT.
    /// </summary>
    /// <remarks>
    /// The "sub" (subject) claim identifies the principal that is the subject of the CWT.
    /// The value is a case-sensitive string.
    /// </remarks>
    public const int Subject = 2;

    /// <summary>
    /// Audience claim (label 3): Identifies the recipients that the JWT/CWT is intended for.
    /// </summary>
    /// <remarks>
    /// The "aud" (audience) claim identifies the recipients that the CWT is intended for.
    /// The value is either a case-sensitive string or an array of case-sensitive strings.
    /// </remarks>
    public const int Audience = 3;

    /// <summary>
    /// Expiration Time claim (label 4): Identifies the expiration time on or after which the JWT/CWT MUST NOT be accepted.
    /// </summary>
    /// <remarks>
    /// The "exp" (expiration time) claim identifies the expiration time on or after which
    /// the CWT MUST NOT be accepted for processing. The value is a NumericDate.
    /// </remarks>
    public const int ExpirationTime = 4;

    /// <summary>
    /// Not Before claim (label 5): Identifies the time before which the JWT/CWT MUST NOT be accepted.
    /// </summary>
    /// <remarks>
    /// The "nbf" (not before) claim identifies the time before which the CWT MUST NOT be
    /// accepted for processing. The value is a NumericDate.
    /// </remarks>
    public const int NotBefore = 5;

    /// <summary>
    /// Issued At claim (label 6): Identifies the time at which the JWT/CWT was issued.
    /// </summary>
    /// <remarks>
    /// The "iat" (issued at) claim identifies the time at which the CWT was issued.
    /// The value is a NumericDate.
    /// </remarks>
    public const int IssuedAt = 6;

    /// <summary>
    /// CWT ID claim (label 7): Provides a unique identifier for the JWT/CWT.
    /// </summary>
    /// <remarks>
    /// The "cti" (CWT ID) claim provides a unique identifier for the CWT.
    /// The value is a byte string.
    /// </remarks>
    public const int CWTID = 7;
}
