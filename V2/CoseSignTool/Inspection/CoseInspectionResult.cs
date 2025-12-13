// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json.Serialization;

namespace CoseSignTool.Inspection;

/// <summary>
/// Represents the fully decoded result of inspecting a COSE Sign1 message.
/// </summary>
public class CoseInspectionResult
{
    /// <summary>
    /// File information.
    /// </summary>
    [JsonPropertyName("file")]
    public FileInformation? File { get; set; }

    /// <summary>
    /// Protected headers from the COSE message.
    /// </summary>
    [JsonPropertyName("protectedHeaders")]
    public ProtectedHeadersInfo? ProtectedHeaders { get; set; }

    /// <summary>
    /// Unprotected headers from the COSE message.
    /// </summary>
    [JsonPropertyName("unprotectedHeaders")]
    public List<HeaderInfo>? UnprotectedHeaders { get; set; }

    /// <summary>
    /// CWT Claims if present in the signature.
    /// </summary>
    [JsonPropertyName("cwtClaims")]
    public CwtClaimsInfo? CwtClaims { get; set; }

    /// <summary>
    /// Payload information.
    /// </summary>
    [JsonPropertyName("payload")]
    public PayloadInfo? Payload { get; set; }

    /// <summary>
    /// Signature information.
    /// </summary>
    [JsonPropertyName("signature")]
    public SignatureInfo? Signature { get; set; }

    /// <summary>
    /// Certificate information extracted from the signature.
    /// </summary>
    [JsonPropertyName("certificates")]
    public List<CertificateInfo>? Certificates { get; set; }
}

/// <summary>
/// File information for the inspected COSE message.
/// </summary>
public class FileInformation
{
    [JsonPropertyName("path")]
    public string? Path { get; set; }

    [JsonPropertyName("sizeBytes")]
    public long SizeBytes { get; set; }
}

/// <summary>
/// Protected headers information with decoded values.
/// </summary>
public class ProtectedHeadersInfo
{
    [JsonPropertyName("algorithm")]
    public AlgorithmInfo? Algorithm { get; set; }

    [JsonPropertyName("contentType")]
    public string? ContentType { get; set; }

    [JsonPropertyName("criticalHeaders")]
    public List<string>? CriticalHeaders { get; set; }

    [JsonPropertyName("certificateThumbprint")]
    public CertificateThumbprintInfo? CertificateThumbprint { get; set; }

    [JsonPropertyName("certificateChainLength")]
    public int? CertificateChainLength { get; set; }

    [JsonPropertyName("payloadHashAlgorithm")]
    public AlgorithmInfo? PayloadHashAlgorithm { get; set; }

    [JsonPropertyName("preimageContentType")]
    public string? PreimageContentType { get; set; }

    [JsonPropertyName("payloadLocation")]
    public string? PayloadLocation { get; set; }

    [JsonPropertyName("otherHeaders")]
    public List<HeaderInfo>? OtherHeaders { get; set; }
}

/// <summary>
/// Algorithm information with ID and name.
/// </summary>
public class AlgorithmInfo
{
    [JsonPropertyName("id")]
    public int Id { get; set; }

    [JsonPropertyName("name")]
    public string? Name { get; set; }
}

/// <summary>
/// Certificate thumbprint information.
/// </summary>
public class CertificateThumbprintInfo
{
    [JsonPropertyName("algorithm")]
    public string? Algorithm { get; set; }

    [JsonPropertyName("value")]
    public string? Value { get; set; }
}

/// <summary>
/// Generic header information for custom headers.
/// </summary>
public class HeaderInfo
{
    [JsonPropertyName("label")]
    public string? Label { get; set; }

    [JsonPropertyName("labelId")]
    public int? LabelId { get; set; }

    [JsonPropertyName("value")]
    public object? Value { get; set; }

    [JsonPropertyName("valueType")]
    public string? ValueType { get; set; }

    [JsonPropertyName("lengthBytes")]
    public int? LengthBytes { get; set; }
}

/// <summary>
/// CWT Claims information (SCITT compliance).
/// </summary>
public class CwtClaimsInfo
{
    [JsonPropertyName("issuer")]
    public string? Issuer { get; set; }

    [JsonPropertyName("subject")]
    public string? Subject { get; set; }

    [JsonPropertyName("audience")]
    public string? Audience { get; set; }

    [JsonPropertyName("issuedAt")]
    public string? IssuedAt { get; set; }

    [JsonPropertyName("issuedAtUnix")]
    public long? IssuedAtUnix { get; set; }

    [JsonPropertyName("notBefore")]
    public string? NotBefore { get; set; }

    [JsonPropertyName("notBeforeUnix")]
    public long? NotBeforeUnix { get; set; }

    [JsonPropertyName("expirationTime")]
    public string? ExpirationTime { get; set; }

    [JsonPropertyName("expirationTimeUnix")]
    public long? ExpirationTimeUnix { get; set; }

    [JsonPropertyName("isExpired")]
    public bool? IsExpired { get; set; }

    [JsonPropertyName("cwtId")]
    public string? CwtId { get; set; }

    [JsonPropertyName("customClaimsCount")]
    public int? CustomClaimsCount { get; set; }
}

/// <summary>
/// Payload information.
/// </summary>
public class PayloadInfo
{
    [JsonPropertyName("isEmbedded")]
    public bool IsEmbedded { get; set; }

    [JsonPropertyName("sizeBytes")]
    public int? SizeBytes { get; set; }

    [JsonPropertyName("contentType")]
    public string? ContentType { get; set; }

    [JsonPropertyName("isText")]
    public bool? IsText { get; set; }

    [JsonPropertyName("preview")]
    public string? Preview { get; set; }

    [JsonPropertyName("sha256")]
    public string? Sha256 { get; set; }
}

/// <summary>
/// Signature information.
/// </summary>
public class SignatureInfo
{
    [JsonPropertyName("totalSizeBytes")]
    public int TotalSizeBytes { get; set; }

    [JsonPropertyName("certificateChainLocation")]
    public string? CertificateChainLocation { get; set; }
}

/// <summary>
/// Certificate information extracted from the chain.
/// </summary>
public class CertificateInfo
{
    [JsonPropertyName("subject")]
    public string? Subject { get; set; }

    [JsonPropertyName("issuer")]
    public string? Issuer { get; set; }

    [JsonPropertyName("serialNumber")]
    public string? SerialNumber { get; set; }

    [JsonPropertyName("thumbprint")]
    public string? Thumbprint { get; set; }

    [JsonPropertyName("notBefore")]
    public string? NotBefore { get; set; }

    [JsonPropertyName("notAfter")]
    public string? NotAfter { get; set; }

    [JsonPropertyName("isExpired")]
    public bool? IsExpired { get; set; }

    [JsonPropertyName("keyAlgorithm")]
    public string? KeyAlgorithm { get; set; }

    [JsonPropertyName("signatureAlgorithm")]
    public string? SignatureAlgorithm { get; set; }
}
