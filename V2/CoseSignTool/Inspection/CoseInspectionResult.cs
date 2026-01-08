// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics.CodeAnalysis;
using System.Text.Json.Serialization;

namespace CoseSignTool.Inspection;

/// <summary>
/// Represents the fully decoded result of inspecting a COSE Sign1 message.
/// </summary>
public class CoseInspectionResult
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string JsonPropertyFile = "file";
        public const string JsonPropertyProtectedHeaders = "protectedHeaders";
        public const string JsonPropertyUnprotectedHeaders = "unprotectedHeaders";
        public const string JsonPropertyCwtClaims = "cwtClaims";
        public const string JsonPropertyPayload = "payload";
        public const string JsonPropertySignature = "signature";
        public const string JsonPropertyCertificates = "certificates";
    }

    /// <summary>
    /// File information.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyFile)]
    public FileInformation? File { get; set; }

    /// <summary>
    /// Protected headers from the COSE message.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyProtectedHeaders)]
    public ProtectedHeadersInfo? ProtectedHeaders { get; set; }

    /// <summary>
    /// Unprotected headers from the COSE message.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyUnprotectedHeaders)]
    public List<HeaderInfo>? UnprotectedHeaders { get; set; }

    /// <summary>
    /// CWT Claims if present in the signature.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyCwtClaims)]
    public CwtClaimsInfo? CwtClaims { get; set; }

    /// <summary>
    /// Payload information.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyPayload)]
    public PayloadInfo? Payload { get; set; }

    /// <summary>
    /// Signature information.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertySignature)]
    public SignatureInfo? Signature { get; set; }

    /// <summary>
    /// Certificate information extracted from the signature.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyCertificates)]
    public List<CertificateInfo>? Certificates { get; set; }
}

/// <summary>
/// File information for the inspected COSE message.
/// </summary>
public class FileInformation
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string JsonPropertyPath = "path";
        public const string JsonPropertySizeBytes = "sizeBytes";
    }

    /// <summary>
    /// The path that was inspected.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyPath)]
    public string? Path { get; set; }

    /// <summary>
    /// The size of the inspected input in bytes.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertySizeBytes)]
    public long SizeBytes { get; set; }
}

/// <summary>
/// Protected headers information with decoded values.
/// </summary>
public class ProtectedHeadersInfo
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string JsonPropertyAlgorithm = "algorithm";
        public const string JsonPropertyContentType = "contentType";
        public const string JsonPropertyCriticalHeaders = "criticalHeaders";
        public const string JsonPropertyCertificateThumbprint = "certificateThumbprint";
        public const string JsonPropertyCertificateChainLength = "certificateChainLength";
        public const string JsonPropertyPayloadHashAlgorithm = "payloadHashAlgorithm";
        public const string JsonPropertyPreimageContentType = "preimageContentType";
        public const string JsonPropertyPayloadLocation = "payloadLocation";
        public const string JsonPropertyOtherHeaders = "otherHeaders";
    }

    /// <summary>
    /// The signature algorithm from protected headers.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyAlgorithm)]
    public AlgorithmInfo? Algorithm { get; set; }

    /// <summary>
    /// The protected content type, if present.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyContentType)]
    public string? ContentType { get; set; }

    /// <summary>
    /// Critical header labels, if present.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyCriticalHeaders)]
    public List<string>? CriticalHeaders { get; set; }

    /// <summary>
    /// Certificate thumbprint information (x5t), if present.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyCertificateThumbprint)]
    public CertificateThumbprintInfo? CertificateThumbprint { get; set; }

    /// <summary>
    /// The number of certificates in the embedded chain (x5chain), if present.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyCertificateChainLength)]
    public int? CertificateChainLength { get; set; }

    /// <summary>
    /// Payload hash algorithm used by indirect signatures, if present.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyPayloadHashAlgorithm)]
    public AlgorithmInfo? PayloadHashAlgorithm { get; set; }

    /// <summary>
    /// The content type of the preimage used for payload hashing, if present.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyPreimageContentType)]
    public string? PreimageContentType { get; set; }

    /// <summary>
    /// The payload location (embedded/detached) if present.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyPayloadLocation)]
    public string? PayloadLocation { get; set; }

    /// <summary>
    /// Any additional protected headers not mapped to explicit fields.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyOtherHeaders)]
    public List<HeaderInfo>? OtherHeaders { get; set; }
}

/// <summary>
/// Algorithm information with ID and name.
/// </summary>
public class AlgorithmInfo
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string JsonPropertyId = "id";
        public const string JsonPropertyName = "name";
    }

    /// <summary>
    /// The numeric algorithm identifier.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyId)]
    public int Id { get; set; }

    /// <summary>
    /// The algorithm name, if known.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyName)]
    public string? Name { get; set; }
}

/// <summary>
/// Certificate thumbprint information.
/// </summary>
public class CertificateThumbprintInfo
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string JsonPropertyAlgorithm = "algorithm";
        public const string JsonPropertyValue = "value";
    }

    /// <summary>
    /// The thumbprint algorithm name (e.g. SHA-256).
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyAlgorithm)]
    public string? Algorithm { get; set; }

    /// <summary>
    /// The thumbprint value.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyValue)]
    public string? Value { get; set; }
}

/// <summary>
/// Generic header information for custom headers.
/// </summary>
public class HeaderInfo
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string JsonPropertyLabel = "label";
        public const string JsonPropertyLabelId = "labelId";
        public const string JsonPropertyValue = "value";
        public const string JsonPropertyValueType = "valueType";
        public const string JsonPropertyLengthBytes = "lengthBytes";
    }

    /// <summary>
    /// The header label as a string, if available.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyLabel)]
    public string? Label { get; set; }

    /// <summary>
    /// The header label as an integer, if available.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyLabelId)]
    public int? LabelId { get; set; }

    /// <summary>
    /// The decoded header value.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyValue)]
    public object? Value { get; set; }

    /// <summary>
    /// The decoded value type name.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyValueType)]
    public string? ValueType { get; set; }

    /// <summary>
    /// Approximate length of the encoded value, if available.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyLengthBytes)]
    public int? LengthBytes { get; set; }
}

/// <summary>
/// CWT Claims information (SCITT compliance).
/// </summary>
public class CwtClaimsInfo
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string JsonPropertyIssuer = "issuer";
        public const string JsonPropertySubject = "subject";
        public const string JsonPropertyAudience = "audience";
        public const string JsonPropertyIssuedAt = "issuedAt";
        public const string JsonPropertyIssuedAtUnix = "issuedAtUnix";
        public const string JsonPropertyNotBefore = "notBefore";
        public const string JsonPropertyNotBeforeUnix = "notBeforeUnix";
        public const string JsonPropertyExpirationTime = "expirationTime";
        public const string JsonPropertyExpirationTimeUnix = "expirationTimeUnix";
        public const string JsonPropertyIsExpired = "isExpired";
        public const string JsonPropertyCwtId = "cwtId";
        public const string JsonPropertyCustomClaimsCount = "customClaimsCount";
    }

    /// <summary>
    /// Issuer claim (iss).
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyIssuer)]
    public string? Issuer { get; set; }

    /// <summary>
    /// Subject claim (sub).
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertySubject)]
    public string? Subject { get; set; }

    /// <summary>
    /// Audience claim (aud).
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyAudience)]
    public string? Audience { get; set; }

    /// <summary>
    /// Issued-at claim (iat) formatted as a string.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyIssuedAt)]
    public string? IssuedAt { get; set; }

    /// <summary>
    /// Issued-at claim (iat) as Unix time, if available.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyIssuedAtUnix)]
    public long? IssuedAtUnix { get; set; }

    /// <summary>
    /// Not-before claim (nbf) formatted as a string.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyNotBefore)]
    public string? NotBefore { get; set; }

    /// <summary>
    /// Not-before claim (nbf) as Unix time, if available.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyNotBeforeUnix)]
    public long? NotBeforeUnix { get; set; }

    /// <summary>
    /// Expiration time claim (exp) formatted as a string.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyExpirationTime)]
    public string? ExpirationTime { get; set; }

    /// <summary>
    /// Expiration time claim (exp) as Unix time, if available.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyExpirationTimeUnix)]
    public long? ExpirationTimeUnix { get; set; }

    /// <summary>
    /// Indicates whether the token is expired at inspection time, if available.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyIsExpired)]
    public bool? IsExpired { get; set; }

    /// <summary>
    /// CWT identifier (cti), if present.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyCwtId)]
    public string? CwtId { get; set; }

    /// <summary>
    /// The number of custom claims in the token.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyCustomClaimsCount)]
    public int? CustomClaimsCount { get; set; }
}

/// <summary>
/// Payload information.
/// </summary>
public class PayloadInfo
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string JsonPropertyIsEmbedded = "isEmbedded";
        public const string JsonPropertySizeBytes = "sizeBytes";
        public const string JsonPropertyContentType = "contentType";
        public const string JsonPropertyIsText = "isText";
        public const string JsonPropertyPreview = "preview";
        public const string JsonPropertySha256 = "sha256";
    }

    /// <summary>
    /// Indicates whether the payload is embedded in the COSE message.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyIsEmbedded)]
    public bool IsEmbedded { get; set; }

    /// <summary>
    /// The payload size in bytes, if available.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertySizeBytes)]
    public int? SizeBytes { get; set; }

    /// <summary>
    /// The payload content type, if available.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyContentType)]
    public string? ContentType { get; set; }

    /// <summary>
    /// Indicates whether the payload appears to be text.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyIsText)]
    public bool? IsText { get; set; }

    /// <summary>
    /// A short preview of the payload, if produced.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyPreview)]
    public string? Preview { get; set; }

    /// <summary>
    /// The SHA-256 hash of the payload, if produced.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertySha256)]
    public string? Sha256 { get; set; }
}

/// <summary>
/// Signature information.
/// </summary>
public class SignatureInfo
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string JsonPropertyTotalSizeBytes = "totalSizeBytes";
        public const string JsonPropertyCertificateChainLocation = "certificateChainLocation";
    }

    /// <summary>
    /// The total signature size in bytes.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyTotalSizeBytes)]
    public int TotalSizeBytes { get; set; }

    /// <summary>
    /// Indicates where the certificate chain was located (protected/unprotected), if known.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyCertificateChainLocation)]
    public string? CertificateChainLocation { get; set; }
}

/// <summary>
/// Certificate information extracted from the chain.
/// </summary>
public class CertificateInfo
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string JsonPropertySubject = "subject";
        public const string JsonPropertyIssuer = "issuer";
        public const string JsonPropertySerialNumber = "serialNumber";
        public const string JsonPropertyThumbprint = "thumbprint";
        public const string JsonPropertyNotBefore = "notBefore";
        public const string JsonPropertyNotAfter = "notAfter";
        public const string JsonPropertyIsExpired = "isExpired";
        public const string JsonPropertyKeyAlgorithm = "keyAlgorithm";
        public const string JsonPropertySignatureAlgorithm = "signatureAlgorithm";
    }

    /// <summary>
    /// Certificate subject distinguished name.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertySubject)]
    public string? Subject { get; set; }

    /// <summary>
    /// Certificate issuer distinguished name.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyIssuer)]
    public string? Issuer { get; set; }

    /// <summary>
    /// Certificate serial number.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertySerialNumber)]
    public string? SerialNumber { get; set; }

    /// <summary>
    /// Certificate thumbprint.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyThumbprint)]
    public string? Thumbprint { get; set; }

    /// <summary>
    /// Certificate validity start time.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyNotBefore)]
    public string? NotBefore { get; set; }

    /// <summary>
    /// Certificate validity end time.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyNotAfter)]
    public string? NotAfter { get; set; }

    /// <summary>
    /// Indicates whether the certificate is expired at inspection time, if computed.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyIsExpired)]
    public bool? IsExpired { get; set; }

    /// <summary>
    /// Public key algorithm name.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyKeyAlgorithm)]
    public string? KeyAlgorithm { get; set; }

    /// <summary>
    /// Certificate signature algorithm name.
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertySignatureAlgorithm)]
    public string? SignatureAlgorithm { get; set; }
}