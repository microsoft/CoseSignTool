// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace DIDx509;

/// <summary>
/// Static string constants for DID:X509 to reduce memory allocations.
/// Contains all string literals used throughout the DID:X509 implementation.
/// </summary>
public static class DidX509Constants
{
    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        internal const string DidMethod = "did";
        internal const string MethodName = "x509";
        internal const string Version = "0";
        internal const string DidPrefix = "did:x509";
        internal const string FullDidPrefix = "did:x509:0";
        internal const string PolicySeparator = "::";
        internal const string ValueSeparator = ":";
        internal const string ChainSeparator = ",";

        internal const string HashAlgorithmSha256 = "sha256";
        internal const string HashAlgorithmSha384 = "sha384";
        internal const string HashAlgorithmSha512 = "sha512";

        internal const string PolicySubject = "subject";
        internal const string PolicySan = "san";
        internal const string PolicyEku = "eku";
        internal const string PolicyFulcioIssuer = "fulcio-issuer";

        internal const string SanTypeEmail = "email";
        internal const string SanTypeDns = "dns";
        internal const string SanTypeUri = "uri";
        internal const string SanTypeDn = "dn";

        internal const string AttributeCN = "CN";
        internal const string AttributeL = "L";
        internal const string AttributeST = "ST";
        internal const string AttributeO = "O";
        internal const string AttributeOU = "OU";
        internal const string AttributeC = "C";
        internal const string AttributeSTREET = "STREET";

        internal const string OidCommonName = "2.5.4.3";
        internal const string OidLocalityName = "2.5.4.7";
        internal const string OidStateOrProvinceName = "2.5.4.8";
        internal const string OidOrganizationName = "2.5.4.10";
        internal const string OidOrganizationalUnitName = "2.5.4.11";
        internal const string OidCountryName = "2.5.4.6";
        internal const string OidStreetAddress = "2.5.4.9";

        internal const string OidFulcioIssuer = "1.3.6.1.4.1.57264.1.1";

        internal const string OidExtendedKeyUsage = "2.5.29.37";
        internal const string OidSubjectAlternativeName = "2.5.29.17";
        internal const string OidBasicConstraints = "2.5.29.19";
        internal const string OidKeyUsage = "2.5.29.15";

        internal const string DidContextUrl = "https://www.w3.org/ns/did/v1";
        internal const string JsonKeyContext = "@context";
        internal const string JsonKeyId = "id";
        internal const string JsonKeyType = "type";
        internal const string JsonKeyController = "controller";
        internal const string JsonKeyVerificationMethod = "verificationMethod";
        internal const string JsonKeyAssertionMethod = "assertionMethod";
        internal const string JsonKeyKeyAgreement = "keyAgreement";
        internal const string JsonKeyPublicKeyJwk = "publicKeyJwk";
        internal const string VerificationMethodType = "JsonWebKey2020";
        internal const string VerificationMethodSuffix = "#key-1";

        internal const string JsonKeyFingerprint = "fingerprint";
        internal const string JsonKeyIssuer = "issuer";
        internal const string JsonKeySubject = "subject";
        internal const string JsonKeyExtensions = "extensions";
        internal const string JsonKeyEku = "eku";
        internal const string JsonKeySan = "san";
        internal const string JsonKeyFulcioIssuer = "fulcio_issuer";

        internal const string JwkKeyKty = "kty";
        internal const string JwkKeyN = "n";
        internal const string JwkKeyE = "e";
        internal const string JwkKeyCrv = "crv";
        internal const string JwkKeyX = "x";
        internal const string JwkKeyY = "y";
        internal const string JwkKeyUse = "use";
        internal const string JwkKeyAlg = "alg";

        internal const string JwkKtyRsa = "RSA";
        internal const string JwkKtyEc = "EC";
        internal const string JwkUseSignature = "sig";
        internal const string JwkUseEncryption = "enc";

        internal const string CurveP256 = "P-256";
        internal const string CurveP384 = "P-384";
        internal const string CurveP521 = "P-521";

        internal const string ProtocolHttps = "https://";
        internal const string ResolutionOptionX509Chain = "x509chain";

        internal const string ErrorInvalidDid = "Invalid DID:X509 format";
        internal const string ErrorInvalidChain = "Invalid or empty certificate chain";
        internal const string ErrorChainValidationFailed = "Certificate chain validation failed";
        internal const string ErrorPolicyValidationFailed = "Policy validation failed";
        internal const string ErrorNoCaMatch = "No CA certificate matches the specified fingerprint";
        internal const string ErrorInvalidKeyUsage = "Certificate does not have valid key usage";
        internal const string ErrorUnsupportedHashAlgorithm = "Unsupported hash algorithm";
        internal const string ErrorInvalidSubjectPolicy = "Invalid subject policy format";
        internal const string ErrorInvalidSanPolicy = "Invalid SAN policy format";
        internal const string ErrorInvalidEkuPolicy = "Invalid EKU policy format";
        internal const string ErrorInvalidFulcioPolicy = "Invalid Fulcio issuer policy format";
    }

    // DID prefixes and separators
    /// <summary>
    /// DID method prefix.
    /// </summary>
    public const string DidMethod = ClassStrings.DidMethod;

    /// <summary>
    /// DID method name for DID:X509.
    /// </summary>
    public const string MethodName = ClassStrings.MethodName;

    /// <summary>
    /// DID:X509 method version.
    /// </summary>
    public const string Version = ClassStrings.Version;

    /// <summary>
    /// DID:X509 prefix without version.
    /// </summary>
    public const string DidPrefix = ClassStrings.DidPrefix;

    /// <summary>
    /// Full DID:X509 prefix including version.
    /// </summary>
    public const string FullDidPrefix = ClassStrings.FullDidPrefix;

    /// <summary>
    /// Separator used between policy segments.
    /// </summary>
    public const string PolicySeparator = ClassStrings.PolicySeparator;

    /// <summary>
    /// Separator used between a key and value.
    /// </summary>
    public const string ValueSeparator = ClassStrings.ValueSeparator;

    /// <summary>
    /// Separator used between certificates in a chain.
    /// </summary>
    public const string ChainSeparator = ClassStrings.ChainSeparator;

    // Hash algorithm names
    /// <summary>
    /// Hash algorithm name for SHA-256.
    /// </summary>
    public const string HashAlgorithmSha256 = ClassStrings.HashAlgorithmSha256;

    /// <summary>
    /// Hash algorithm name for SHA-384.
    /// </summary>
    public const string HashAlgorithmSha384 = ClassStrings.HashAlgorithmSha384;

    /// <summary>
    /// Hash algorithm name for SHA-512.
    /// </summary>
    public const string HashAlgorithmSha512 = ClassStrings.HashAlgorithmSha512;

    // Policy names
    /// <summary>
    /// Policy name for X.509 subject matching.
    /// </summary>
    public const string PolicySubject = ClassStrings.PolicySubject;

    /// <summary>
    /// Policy name for subject alternative name matching.
    /// </summary>
    public const string PolicySan = ClassStrings.PolicySan;

    /// <summary>
    /// Policy name for extended key usage matching.
    /// </summary>
    public const string PolicyEku = ClassStrings.PolicyEku;

    /// <summary>
    /// Policy name for Fulcio issuer matching.
    /// </summary>
    public const string PolicyFulcioIssuer = ClassStrings.PolicyFulcioIssuer;

    // SAN types
    /// <summary>
    /// SAN type label for email addresses.
    /// </summary>
    public const string SanTypeEmail = ClassStrings.SanTypeEmail;

    /// <summary>
    /// SAN type label for DNS names.
    /// </summary>
    public const string SanTypeDns = ClassStrings.SanTypeDns;

    /// <summary>
    /// SAN type label for URIs.
    /// </summary>
    public const string SanTypeUri = ClassStrings.SanTypeUri;

    /// <summary>
    /// SAN type label for distinguished names.
    /// </summary>
    public const string SanTypeDn = ClassStrings.SanTypeDn;

    // X.509 Name attribute labels (RFC 4514)
    /// <summary>
    /// X.509 Name attribute label for Common Name.
    /// </summary>
    public const string AttributeCN = ClassStrings.AttributeCN;        // Common Name

    /// <summary>
    /// X.509 Name attribute label for Locality.
    /// </summary>
    public const string AttributeL = ClassStrings.AttributeL;          // Locality

    /// <summary>
    /// X.509 Name attribute label for State or Province.
    /// </summary>
    public const string AttributeST = ClassStrings.AttributeST;        // State or Province

    /// <summary>
    /// X.509 Name attribute label for Organization.
    /// </summary>
    public const string AttributeO = ClassStrings.AttributeO;          // Organization

    /// <summary>
    /// X.509 Name attribute label for Organizational Unit.
    /// </summary>
    public const string AttributeOU = ClassStrings.AttributeOU;        // Organizational Unit

    /// <summary>
    /// X.509 Name attribute label for Country.
    /// </summary>
    public const string AttributeC = ClassStrings.AttributeC;          // Country

    /// <summary>
    /// X.509 Name attribute label for Street Address.
    /// </summary>
    public const string AttributeSTREET = ClassStrings.AttributeSTREET; // Street Address

    // Well-known OIDs
    /// <summary>
    /// OID for X.509 Common Name.
    /// </summary>
    public const string OidCommonName = ClassStrings.OidCommonName;

    /// <summary>
    /// OID for X.509 Locality Name.
    /// </summary>
    public const string OidLocalityName = ClassStrings.OidLocalityName;

    /// <summary>
    /// OID for X.509 State or Province Name.
    /// </summary>
    public const string OidStateOrProvinceName = ClassStrings.OidStateOrProvinceName;

    /// <summary>
    /// OID for X.509 Organization Name.
    /// </summary>
    public const string OidOrganizationName = ClassStrings.OidOrganizationName;

    /// <summary>
    /// OID for X.509 Organizational Unit Name.
    /// </summary>
    public const string OidOrganizationalUnitName = ClassStrings.OidOrganizationalUnitName;

    /// <summary>
    /// OID for X.509 Country Name.
    /// </summary>
    public const string OidCountryName = ClassStrings.OidCountryName;

    /// <summary>
    /// OID for X.509 Street Address.
    /// </summary>
    public const string OidStreetAddress = ClassStrings.OidStreetAddress;

    // Fulcio extension OID
    /// <summary>
    /// OID for the Fulcio issuer extension.
    /// </summary>
    public const string OidFulcioIssuer = ClassStrings.OidFulcioIssuer;

    // X.509 Extension OIDs
    /// <summary>
    /// OID for X.509 Extended Key Usage.
    /// </summary>
    public const string OidExtendedKeyUsage = ClassStrings.OidExtendedKeyUsage;

    /// <summary>
    /// OID for X.509 Subject Alternative Name.
    /// </summary>
    public const string OidSubjectAlternativeName = ClassStrings.OidSubjectAlternativeName;

    /// <summary>
    /// OID for X.509 Basic Constraints.
    /// </summary>
    public const string OidBasicConstraints = ClassStrings.OidBasicConstraints;

    /// <summary>
    /// OID for X.509 Key Usage.
    /// </summary>
    public const string OidKeyUsage = ClassStrings.OidKeyUsage;

    // DID Document constants
    /// <summary>
    /// DID document @context URL.
    /// </summary>
    public const string DidContextUrl = ClassStrings.DidContextUrl;

    /// <summary>
    /// JSON key for the DID document @context property.
    /// </summary>
    public const string JsonKeyContext = ClassStrings.JsonKeyContext;

    /// <summary>
    /// JSON key for an object's id.
    /// </summary>
    public const string JsonKeyId = ClassStrings.JsonKeyId;

    /// <summary>
    /// JSON key for an object's type.
    /// </summary>
    public const string JsonKeyType = ClassStrings.JsonKeyType;

    /// <summary>
    /// JSON key for a controller value.
    /// </summary>
    public const string JsonKeyController = ClassStrings.JsonKeyController;

    /// <summary>
    /// JSON key for verificationMethod.
    /// </summary>
    public const string JsonKeyVerificationMethod = ClassStrings.JsonKeyVerificationMethod;

    /// <summary>
    /// JSON key for assertionMethod.
    /// </summary>
    public const string JsonKeyAssertionMethod = ClassStrings.JsonKeyAssertionMethod;

    /// <summary>
    /// JSON key for keyAgreement.
    /// </summary>
    public const string JsonKeyKeyAgreement = ClassStrings.JsonKeyKeyAgreement;

    /// <summary>
    /// JSON key for publicKeyJwk.
    /// </summary>
    public const string JsonKeyPublicKeyJwk = ClassStrings.JsonKeyPublicKeyJwk;

    /// <summary>
    /// Verification method type used in DID documents.
    /// </summary>
    public const string VerificationMethodType = ClassStrings.VerificationMethodType;

    /// <summary>
    /// Suffix used to build the verification method id.
    /// </summary>
    public const string VerificationMethodSuffix = ClassStrings.VerificationMethodSuffix;

    // Certificate chain JSON model keys
    /// <summary>
    /// JSON key for a certificate fingerprint.
    /// </summary>
    public const string JsonKeyFingerprint = ClassStrings.JsonKeyFingerprint;

    /// <summary>
    /// JSON key for a certificate issuer.
    /// </summary>
    public const string JsonKeyIssuer = ClassStrings.JsonKeyIssuer;

    /// <summary>
    /// JSON key for a certificate subject.
    /// </summary>
    public const string JsonKeySubject = ClassStrings.JsonKeySubject;

    /// <summary>
    /// JSON key for certificate extensions.
    /// </summary>
    public const string JsonKeyExtensions = ClassStrings.JsonKeyExtensions;

    /// <summary>
    /// JSON key for extended key usages.
    /// </summary>
    public const string JsonKeyEku = ClassStrings.JsonKeyEku;

    /// <summary>
    /// JSON key for subject alternative names.
    /// </summary>
    public const string JsonKeySan = ClassStrings.JsonKeySan;

    /// <summary>
    /// JSON key for the Fulcio issuer extension value.
    /// </summary>
    public const string JsonKeyFulcioIssuer = ClassStrings.JsonKeyFulcioIssuer;

    // JWK keys
    /// <summary>
    /// JWK key for the key type.
    /// </summary>
    public const string JwkKeyKty = ClassStrings.JwkKeyKty;

    /// <summary>
    /// JWK key for RSA modulus.
    /// </summary>
    public const string JwkKeyN = ClassStrings.JwkKeyN;

    /// <summary>
    /// JWK key for RSA exponent.
    /// </summary>
    public const string JwkKeyE = ClassStrings.JwkKeyE;

    /// <summary>
    /// JWK key for elliptic curve name.
    /// </summary>
    public const string JwkKeyCrv = ClassStrings.JwkKeyCrv;

    /// <summary>
    /// JWK key for EC X coordinate.
    /// </summary>
    public const string JwkKeyX = ClassStrings.JwkKeyX;

    /// <summary>
    /// JWK key for EC Y coordinate.
    /// </summary>
    public const string JwkKeyY = ClassStrings.JwkKeyY;

    /// <summary>
    /// JWK key for key use.
    /// </summary>
    public const string JwkKeyUse = ClassStrings.JwkKeyUse;

    /// <summary>
    /// JWK key for algorithm.
    /// </summary>
    public const string JwkKeyAlg = ClassStrings.JwkKeyAlg;

    /// <summary>
    /// JWK key type value for RSA.
    /// </summary>
    public const string JwkKtyRsa = ClassStrings.JwkKtyRsa;

    /// <summary>
    /// JWK key type value for EC.
    /// </summary>
    public const string JwkKtyEc = ClassStrings.JwkKtyEc;

    /// <summary>
    /// JWK use value for signing.
    /// </summary>
    public const string JwkUseSignature = ClassStrings.JwkUseSignature;

    /// <summary>
    /// JWK use value for encryption.
    /// </summary>
    public const string JwkUseEncryption = ClassStrings.JwkUseEncryption;

    // EC curve names
    /// <summary>
    /// JWK curve name for P-256.
    /// </summary>
    public const string CurveP256 = ClassStrings.CurveP256;

    /// <summary>
    /// JWK curve name for P-384.
    /// </summary>
    public const string CurveP384 = ClassStrings.CurveP384;

    /// <summary>
    /// JWK curve name for P-521.
    /// </summary>
    public const string CurveP521 = ClassStrings.CurveP521;

    // Protocol prefixes
    /// <summary>
    /// HTTPS URL prefix.
    /// </summary>
    public const string ProtocolHttps = ClassStrings.ProtocolHttps;

    // Percent encoding
    /// <summary>
    /// Percent character used for percent-encoding.
    /// </summary>
    public const char PercentChar = '%';

    /// <summary>
    /// Colon character used in DID formatting.
    /// </summary>
    public const char ColonChar = ':';

    /// <summary>
    /// Comma character used for certificate chain separation.
    /// </summary>
    public const char CommaChar = ',';

    /// <summary>
    /// Equals character used in name/value pairs.
    /// </summary>
    public const char EqualChar = '=';

    /// <summary>
    /// Backslash character used for escaping.
    /// </summary>
    public const char BackslashChar = '\\';

    /// <summary>
    /// Hyphen character.
    /// </summary>
    public const char HyphenChar = '-';

    /// <summary>
    /// Underscore character.
    /// </summary>
    public const char UnderscoreChar = '_';

    /// <summary>
    /// Period character.
    /// </summary>
    public const char PeriodChar = '.';

    /// <summary>
    /// Tilde character.
    /// </summary>
    public const char TildeChar = '~';

    /// <summary>
    /// Plus character.
    /// </summary>
    public const char PlusChar = '+';

    /// <summary>
    /// Forward slash character.
    /// </summary>
    public const char SlashChar = '/';

    // DID resolution option name
    /// <summary>
    /// DID resolution option name for requesting an x509 chain.
    /// </summary>
    public const string ResolutionOptionX509Chain = ClassStrings.ResolutionOptionX509Chain;

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
    /// <summary>
    /// Error message used when a DID:X509 value cannot be parsed.
    /// </summary>
    public const string ErrorInvalidDid = ClassStrings.ErrorInvalidDid;

    /// <summary>
    /// Error message used when a certificate chain is missing or invalid.
    /// </summary>
    public const string ErrorInvalidChain = ClassStrings.ErrorInvalidChain;

    /// <summary>
    /// Error message used when chain validation fails.
    /// </summary>
    public const string ErrorChainValidationFailed = ClassStrings.ErrorChainValidationFailed;

    /// <summary>
    /// Error message used when a policy cannot be satisfied.
    /// </summary>
    public const string ErrorPolicyValidationFailed = ClassStrings.ErrorPolicyValidationFailed;

    /// <summary>
    /// Error message used when no CA matches a specified fingerprint.
    /// </summary>
    public const string ErrorNoCaMatch = ClassStrings.ErrorNoCaMatch;

    /// <summary>
    /// Error message used when a certificate does not contain required key usage.
    /// </summary>
    public const string ErrorInvalidKeyUsage = ClassStrings.ErrorInvalidKeyUsage;

    /// <summary>
    /// Error message used when an unsupported hash algorithm is requested.
    /// </summary>
    public const string ErrorUnsupportedHashAlgorithm = ClassStrings.ErrorUnsupportedHashAlgorithm;

    /// <summary>
    /// Error message used when a subject policy string is malformed.
    /// </summary>
    public const string ErrorInvalidSubjectPolicy = ClassStrings.ErrorInvalidSubjectPolicy;

    /// <summary>
    /// Error message used when a SAN policy string is malformed.
    /// </summary>
    public const string ErrorInvalidSanPolicy = ClassStrings.ErrorInvalidSanPolicy;

    /// <summary>
    /// Error message used when an EKU policy string is malformed.
    /// </summary>
    public const string ErrorInvalidEkuPolicy = ClassStrings.ErrorInvalidEkuPolicy;

    /// <summary>
    /// Error message used when a Fulcio issuer policy string is malformed.
    /// </summary>
    public const string ErrorInvalidFulcioPolicy = ClassStrings.ErrorInvalidFulcioPolicy;
}