// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Formats.Cbor;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using CoseSign1.Abstractions;

namespace CoseSign1.AzureKeyVault;

/// <summary>
/// Header contributor that embeds the public key as a COSE_Key structure in the COSE message headers.
/// This enables self-contained verification when the verifier cannot fetch the public key from Key Vault.
/// </summary>
/// <remarks>
/// <para>
/// RFC 9052 defines the COSE_Key structure (Section 7) but does not define a standard header label
/// for embedding it in COSE_Sign1 messages. This contributor uses a private-use header label
/// (negative integer) as allowed by RFC 9052 Section 3.1 for application-specific headers.
/// </para>
/// <para>
/// The COSE_Key structure is encoded according to RFC 9052 Section 7:
/// <list type="bullet">
/// <item><description>Key Type (kty, label 1): EC2 (2) or RSA (3)</description></item>
/// <item><description>Algorithm (alg, label 3): COSE algorithm identifier</description></item>
/// <item><description>Key ID (kid, label 2): Optional key identifier</description></item>
/// <item><description>Key-specific parameters (curve, x, y for EC; n, e for RSA)</description></item>
/// </list>
/// </para>
/// <para>
/// <strong>Security Note:</strong> The public key is placed in <em>unprotected</em> headers by default
/// because:
/// <list type="bullet">
/// <item><description>The signature already cryptographically binds the public key (only the correct key can verify)</description></item>
/// <item><description>Protected headers increase signature size and require AAD computation</description></item>
/// <item><description>The kid in protected headers identifies the key; this is supplementary data</description></item>
/// </list>
/// Set <see cref="UseProtectedHeader"/> to true if you need the public key in protected headers.
/// </para>
/// </remarks>
public sealed class CoseKeyHeaderContributor : IHeaderContributor
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public static readonly string ErrorRsaParametersMustNotIncludePrivateKeyComponents = "RSA parameters must not include private key components.";
        public static readonly string ErrorEcParametersMustNotIncludePrivateKey = "EC parameters must not include private key (D parameter).";

        public const string CurveFriendlyNameEcdsaP256 = "ECDSA_P256";
        public const string CurveFriendlyNameNistP256 = "nistP256";
        public const string CurveFriendlyNameEcdsaP384 = "ECDSA_P384";
        public const string CurveFriendlyNameNistP384 = "nistP384";
        public const string CurveFriendlyNameEcdsaP521 = "ECDSA_P521";
        public const string CurveFriendlyNameNistP521 = "nistP521";

        public const string Unknown = "unknown";
        public const string ErrorUnsupportedEcCurveFormat = "Unsupported EC curve: {0}";
    }

    /// <summary>
    /// Private-use header label for embedding COSE_Key.
    /// Using -65537 which is in the private-use range (less than -65536 per RFC 9052).
    /// This follows the pattern of other private headers while avoiding collision with
    /// commonly used negative labels.
    /// </summary>
    /// <remarks>
    /// Per RFC 9052 Section 3.1: "Labels in the range -65536 to -1 are designated as
    /// private use and are not managed by IANA."
    /// We use a value below this range to ensure no conflicts.
    /// </remarks>
    public static readonly CoseHeaderLabel CoseKeyHeaderLabel = new(-65537);

    /// <summary>
    /// COSE_Key parameter labels per RFC 9052 Section 7.1.
    /// </summary>
    public static class CoseKeyLabels
    {
        /// <summary>Key Type (kty) - Label 1</summary>
        public const int KeyType = 1;

        /// <summary>Key ID (kid) - Label 2</summary>
        public const int KeyId = 2;

        /// <summary>Algorithm (alg) - Label 3</summary>
        public const int Algorithm = 3;

        /// <summary>Key Operations (key_ops) - Label 4</summary>
        public const int KeyOps = 4;

        /// <summary>Base IV (Base_IV) - Label 5</summary>
        public const int BaseIV = 5;
    }

    /// <summary>
    /// COSE Key Type values per RFC 9052 Section 7.1.
    /// </summary>
    public static class CoseKeyTypes
    {
        /// <summary>Octet Key Pair (OKP) - Value 1</summary>
        public const int OKP = 1;

        /// <summary>Elliptic Curve Keys w/ x- and y-coordinate pair (EC2) - Value 2</summary>
        public const int EC2 = 2;

        /// <summary>RSA Key - Value 3</summary>
        public const int RSA = 3;

        /// <summary>Symmetric Key - Value 4</summary>
        public const int Symmetric = 4;
    }

    /// <summary>
    /// EC2 key parameter labels per RFC 9052 Section 7.1.1.
    /// </summary>
    public static class EC2Labels
    {
        /// <summary>Curve identifier - Label -1</summary>
        public const int Curve = -1;

        /// <summary>X coordinate - Label -2</summary>
        public const int X = -2;

        /// <summary>Y coordinate - Label -3</summary>
        public const int Y = -3;

        /// <summary>Private key (d) - Label -4 (not used for public keys)</summary>
        public const int D = -4;
    }

    /// <summary>
    /// RSA key parameter labels per RFC 9052 Section 7.1.2.
    /// </summary>
    public static class RSALabels
    {
        /// <summary>Modulus (n) - Label -1</summary>
        public const int N = -1;

        /// <summary>Public Exponent (e) - Label -2</summary>
        public const int E = -2;
    }

    /// <summary>
    /// COSE Elliptic Curve identifiers per RFC 9053.
    /// </summary>
    public static class CoseEllipticCurves
    {
        /// <summary>NIST P-256 (secp256r1) - Value 1</summary>
        public const int P256 = 1;

        /// <summary>NIST P-384 (secp384r1) - Value 2</summary>
        public const int P384 = 2;

        /// <summary>NIST P-521 (secp521r1) - Value 3</summary>
        public const int P521 = 3;
    }

    private readonly byte[] EncodedCoseKey;

    /// <summary>
    /// Gets the key ID associated with this public key (optional).
    /// </summary>
    public string? KeyId { get; }

    /// <summary>
    /// Gets the COSE algorithm identifier for this key.
    /// </summary>
    public int CoseAlgorithm { get; }

    /// <summary>
    /// Gets or sets whether to place the COSE_Key in protected headers.
    /// Default is false (unprotected headers).
    /// </summary>
    public bool UseProtectedHeader { get; set; }

    /// <summary>
    /// Initializes a new instance of the <see cref="CoseKeyHeaderContributor"/> class with RSA public key parameters.
    /// </summary>
    /// <param name="rsaParameters">The RSA public key parameters (must not include private key).</param>
    /// <param name="coseAlgorithm">The COSE algorithm identifier (e.g., -37 for PS256, -38 for PS384, -39 for PS512).</param>
    /// <param name="keyId">Optional key identifier to embed in the COSE_Key.</param>
    /// <exception cref="ArgumentException">Thrown if private key parameters are included.</exception>
    public CoseKeyHeaderContributor(RSAParameters rsaParameters, int coseAlgorithm, string? keyId = null)
    {
        if (rsaParameters.D != null || rsaParameters.P != null || rsaParameters.Q != null)
        {
            throw new ArgumentException(ClassStrings.ErrorRsaParametersMustNotIncludePrivateKeyComponents, nameof(rsaParameters));
        }

        ArgumentNullException.ThrowIfNull(rsaParameters.Modulus);
        ArgumentNullException.ThrowIfNull(rsaParameters.Exponent);

        KeyId = keyId;
        CoseAlgorithm = coseAlgorithm;
        EncodedCoseKey = EncodeRsaCoseKey(rsaParameters, coseAlgorithm, keyId);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CoseKeyHeaderContributor"/> class with EC public key parameters.
    /// </summary>
    /// <param name="ecParameters">The EC public key parameters (must not include private key).</param>
    /// <param name="coseAlgorithm">The COSE algorithm identifier (e.g., -7 for ES256, -35 for ES384, -36 for ES512).</param>
    /// <param name="keyId">Optional key identifier to embed in the COSE_Key.</param>
    /// <exception cref="ArgumentException">Thrown if private key parameters are included.</exception>
    public CoseKeyHeaderContributor(ECParameters ecParameters, int coseAlgorithm, string? keyId = null)
    {
        if (ecParameters.D != null)
        {
            throw new ArgumentException(ClassStrings.ErrorEcParametersMustNotIncludePrivateKey, nameof(ecParameters));
        }

        ArgumentNullException.ThrowIfNull(ecParameters.Q.X);
        ArgumentNullException.ThrowIfNull(ecParameters.Q.Y);

        KeyId = keyId;
        CoseAlgorithm = coseAlgorithm;
        EncodedCoseKey = EncodeEcCoseKey(ecParameters, coseAlgorithm, keyId);
    }

    /// <inheritdoc/>
    public HeaderMergeStrategy MergeStrategy => HeaderMergeStrategy.Replace;

    /// <inheritdoc/>
    public void ContributeProtectedHeaders(CoseHeaderMap headers, HeaderContributorContext context)
    {
        if (UseProtectedHeader)
        {
            AddCoseKeyHeader(headers);
        }
    }

    /// <inheritdoc/>
    public void ContributeUnprotectedHeaders(CoseHeaderMap headers, HeaderContributorContext context)
    {
        if (!UseProtectedHeader)
        {
            AddCoseKeyHeader(headers);
        }
    }

    private void AddCoseKeyHeader(CoseHeaderMap headers)
    {
        var headerValue = CoseHeaderValue.FromEncodedValue(EncodedCoseKey);

        if (headers.ContainsKey(CoseKeyHeaderLabel))
        {
            headers[CoseKeyHeaderLabel] = headerValue;
        }
        else
        {
            headers.Add(CoseKeyHeaderLabel, headerValue);
        }
    }

    /// <summary>
    /// Encodes an RSA public key as a COSE_Key structure per RFC 9052 Section 7.1.2.
    /// </summary>
    private static byte[] EncodeRsaCoseKey(RSAParameters rsaParams, int algorithm, string? keyId)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);

        // Count map entries: kty, alg, n, e, and optionally kid
        int mapSize = keyId != null ? 5 : 4;
        writer.WriteStartMap(mapSize);

        // kty (1): RSA (3)
        writer.WriteInt32(CoseKeyLabels.KeyType);
        writer.WriteInt32(CoseKeyTypes.RSA);

        // kid (2): Key ID (optional)
        if (keyId != null)
        {
            writer.WriteInt32(CoseKeyLabels.KeyId);
            writer.WriteTextString(keyId);
        }

        // alg (3): Algorithm
        writer.WriteInt32(CoseKeyLabels.Algorithm);
        writer.WriteInt32(algorithm);

        // n (-1): Modulus
        writer.WriteInt32(RSALabels.N);
        writer.WriteByteString(rsaParams.Modulus!);

        // e (-2): Exponent
        writer.WriteInt32(RSALabels.E);
        writer.WriteByteString(rsaParams.Exponent!);

        writer.WriteEndMap();
        return writer.Encode();
    }

    /// <summary>
    /// Encodes an EC public key as a COSE_Key structure per RFC 9052 Section 7.1.1.
    /// </summary>
    private static byte[] EncodeEcCoseKey(ECParameters ecParams, int algorithm, string? keyId)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);

        // Count map entries: kty, alg, crv, x, y, and optionally kid
        int mapSize = keyId != null ? 6 : 5;
        writer.WriteStartMap(mapSize);

        // kty (1): EC2 (2)
        writer.WriteInt32(CoseKeyLabels.KeyType);
        writer.WriteInt32(CoseKeyTypes.EC2);

        // kid (2): Key ID (optional)
        if (keyId != null)
        {
            writer.WriteInt32(CoseKeyLabels.KeyId);
            writer.WriteTextString(keyId);
        }

        // alg (3): Algorithm
        writer.WriteInt32(CoseKeyLabels.Algorithm);
        writer.WriteInt32(algorithm);

        // crv (-1): Curve
        writer.WriteInt32(EC2Labels.Curve);
        writer.WriteInt32(GetCoseCurveId(ecParams.Curve));

        // x (-2): X coordinate
        writer.WriteInt32(EC2Labels.X);
        writer.WriteByteString(ecParams.Q.X!);

        // y (-3): Y coordinate
        writer.WriteInt32(EC2Labels.Y);
        writer.WriteByteString(ecParams.Q.Y!);

        writer.WriteEndMap();
        return writer.Encode();
    }

    /// <summary>
    /// Maps .NET ECCurve to COSE curve identifier.
    /// </summary>
    private static int GetCoseCurveId(ECCurve curve)
    {
        // Compare by OID since ECCurve comparison by name can be unreliable
        if (curve.Oid?.Value == ECCurve.NamedCurves.nistP256.Oid?.Value ||
            curve.Oid?.FriendlyName == ClassStrings.CurveFriendlyNameEcdsaP256 ||
            curve.Oid?.FriendlyName == ClassStrings.CurveFriendlyNameNistP256)
        {
            return CoseEllipticCurves.P256;
        }
        if (curve.Oid?.Value == ECCurve.NamedCurves.nistP384.Oid?.Value ||
            curve.Oid?.FriendlyName == ClassStrings.CurveFriendlyNameEcdsaP384 ||
            curve.Oid?.FriendlyName == ClassStrings.CurveFriendlyNameNistP384)
        {
            return CoseEllipticCurves.P384;
        }
        if (curve.Oid?.Value == ECCurve.NamedCurves.nistP521.Oid?.Value ||
            curve.Oid?.FriendlyName == ClassStrings.CurveFriendlyNameEcdsaP521 ||
            curve.Oid?.FriendlyName == ClassStrings.CurveFriendlyNameNistP521)
        {
            return CoseEllipticCurves.P521;
        }

        var curveName = curve.Oid?.FriendlyName ?? curve.Oid?.Value ?? ClassStrings.Unknown;
        throw new NotSupportedException(string.Format(ClassStrings.ErrorUnsupportedEcCurveFormat, curveName));
    }
}
