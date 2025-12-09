// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace DIDx509;

/// <summary>
/// Static string constants for DID:X509 to reduce memory allocations.
/// Contains all string literals used throughout the DID:X509 implementation.
/// </summary>
public static class DidX509Constants
{
    // DID prefixes and separators
    public const string DidMethod = "did";
    public const string MethodName = "x509";
    public const string Version = "0";
    public const string DidPrefix = "did:x509";
    public const string FullDidPrefix = "did:x509:0";
    public const string PolicySeparator = "::";
    public const string ValueSeparator = ":";
    public const string ChainSeparator = ",";

    // Hash algorithm names
    public const string HashAlgorithmSha256 = "sha256";
    public const string HashAlgorithmSha384 = "sha384";
    public const string HashAlgorithmSha512 = "sha512";

    // Policy names
    public const string PolicySubject = "subject";
    public const string PolicySan = "san";
    public const string PolicyEku = "eku";
    public const string PolicyFulcioIssuer = "fulcio-issuer";

    // SAN types
    public const string SanTypeEmail = "email";
    public const string SanTypeDns = "dns";
    public const string SanTypeUri = "uri";
    public const string SanTypeDn = "dn";

    // X.509 Name attribute labels (RFC 4514)
    public const string AttributeCN = "CN";        // Common Name
    public const string AttributeL = "L";          // Locality
    public const string AttributeST = "ST";        // State or Province
    public const string AttributeO = "O";          // Organization
    public const string AttributeOU = "OU";        // Organizational Unit
    public const string AttributeC = "C";          // Country
    public const string AttributeSTREET = "STREET"; // Street Address

    // Well-known OIDs
    public const string OidCommonName = "2.5.4.3";
    public const string OidLocalityName = "2.5.4.7";
    public const string OidStateOrProvinceName = "2.5.4.8";
    public const string OidOrganizationName = "2.5.4.10";
    public const string OidOrganizationalUnitName = "2.5.4.11";
    public const string OidCountryName = "2.5.4.6";
    public const string OidStreetAddress = "2.5.4.9";
    
    // Fulcio extension OID
    public const string OidFulcioIssuer = "1.3.6.1.4.1.57264.1.1";

    // X.509 Extension OIDs
    public const string OidExtendedKeyUsage = "2.5.29.37";
    public const string OidSubjectAlternativeName = "2.5.29.17";
    public const string OidBasicConstraints = "2.5.29.19";
    public const string OidKeyUsage = "2.5.29.15";

    // DID Document constants
    public const string DidContextUrl = "https://www.w3.org/ns/did/v1";
    public const string JsonKeyContext = "@context";
    public const string JsonKeyId = "id";
    public const string JsonKeyType = "type";
    public const string JsonKeyController = "controller";
    public const string JsonKeyVerificationMethod = "verificationMethod";
    public const string JsonKeyAssertionMethod = "assertionMethod";
    public const string JsonKeyKeyAgreement = "keyAgreement";
    public const string JsonKeyPublicKeyJwk = "publicKeyJwk";
    public const string VerificationMethodType = "JsonWebKey2020";
    public const string VerificationMethodSuffix = "#key-1";

    // Certificate chain JSON model keys
    public const string JsonKeyFingerprint = "fingerprint";
    public const string JsonKeyIssuer = "issuer";
    public const string JsonKeySubject = "subject";
    public const string JsonKeyExtensions = "extensions";
    public const string JsonKeyEku = "eku";
    public const string JsonKeySan = "san";
    public const string JsonKeyFulcioIssuer = "fulcio_issuer";

    // JWK keys
    public const string JwkKeyKty = "kty";
    public const string JwkKeyN = "n";
    public const string JwkKeyE = "e";
    public const string JwkKeyCrv = "crv";
    public const string JwkKeyX = "x";
    public const string JwkKeyY = "y";
    public const string JwkKeyUse = "use";
    public const string JwkKeyAlg = "alg";
    public const string JwkKtyRsa = "RSA";
    public const string JwkKtyEc = "EC";
    public const string JwkUseSignature = "sig";
    public const string JwkUseEncryption = "enc";

    // EC curve names
    public const string CurveP256 = "P-256";
    public const string CurveP384 = "P-384";
    public const string CurveP521 = "P-521";

    // Protocol prefixes
    public const string ProtocolHttps = "https://";

    // Percent encoding
    public const char PercentChar = '%';
    public const char ColonChar = ':';
    public const char CommaChar = ',';
    public const char EqualChar = '=';
    public const char BackslashChar = '\\';
    public const char HyphenChar = '-';
    public const char UnderscoreChar = '_';
    public const char PeriodChar = '.';
    public const char TildeChar = '~';
    public const char PlusChar = '+';
    public const char SlashChar = '/';

    // DID resolution option name
    public const string ResolutionOptionX509Chain = "x509chain";

    /// <summary>
    /// Known X.509 Name attribute labels from the DID:X509 specification.
    /// </summary>
    public static readonly HashSet<string> KnownLabels = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        AttributeCN,
        AttributeL,
        AttributeST,
        AttributeO,
        AttributeOU,
        AttributeC,
        AttributeSTREET
    };

    // Error messages
    public const string ErrorInvalidDid = "Invalid DID:X509 format";
    public const string ErrorInvalidChain = "Invalid or empty certificate chain";
    public const string ErrorChainValidationFailed = "Certificate chain validation failed";
    public const string ErrorPolicyValidationFailed = "Policy validation failed";
    public const string ErrorNoCaMatch = "No CA certificate matches the specified fingerprint";
    public const string ErrorInvalidKeyUsage = "Certificate does not have valid key usage";
    public const string ErrorUnsupportedHashAlgorithm = "Unsupported hash algorithm";
    public const string ErrorInvalidSubjectPolicy = "Invalid subject policy format";
    public const string ErrorInvalidSanPolicy = "Invalid SAN policy format";
    public const string ErrorInvalidEkuPolicy = "Invalid EKU policy format";
    public const string ErrorInvalidFulcioPolicy = "Invalid Fulcio issuer policy format";
}
