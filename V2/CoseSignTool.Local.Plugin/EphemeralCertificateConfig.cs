// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Local.Plugin;

using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Serialization;

/// <summary>
/// Configuration model for ephemeral certificate generation.
/// Can be loaded from a JSON file or created programmatically.
/// </summary>
/// <remarks>
/// <para>
/// Example JSON configuration:
/// </para>
/// <code>
/// {
///   "subject": "CN=My Test Signer, O=My Organization",
///   "algorithm": "RSA",
///   "keySize": 4096,
///   "validityDays": 365,
///   "generateChain": true,
///   "chain": {
///     "rootSubject": "CN=Test Root CA, O=My Organization",
///     "intermediateSubject": "CN=Test Intermediate CA, O=My Organization",
///     "rootValidityDays": 3650,
///     "intermediateValidityDays": 1825
///   },
///   "enhancedKeyUsages": ["CodeSigning", "LifetimeSigning"]
/// }
/// </code>
/// </remarks>
public class EphemeralCertificateConfig
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        // JSON property names
        public const string JsonPropertySubject = "subject";
        public const string JsonPropertyAlgorithm = "algorithm";
        public const string JsonPropertyKeySize = "keySize";
        public const string JsonPropertyValidityDays = "validityDays";
        public const string JsonPropertyGenerateChain = "generateChain";
        public const string JsonPropertyChain = "chain";
        public const string JsonPropertyEnhancedKeyUsages = "enhancedKeyUsages";
        public const string JsonPropertyHashAlgorithm = "hashAlgorithm";

        // Well-known values
        public const string AlgorithmRsa = "RSA";
        public const string AlgorithmEcdsa = "ECDSA";
        public const string AlgorithmMldsa = "MLDSA";

        public const string HashAlgorithmSha256 = "SHA256";

        public const string EkuCodeSigning = "CodeSigning";

        // Default values
        public const string DefaultSubject = "CN=CoseSignTool Test Signer, O=Test Organization";
        public const string DefaultPqcSubject = "CN=CoseSignTool PQC Test Signer, O=Test Organization";

        // Error formats
        public const string ErrorFormatConfigNotFound = "Configuration file not found: {0}";
    }

    /// <summary>
    /// The subject distinguished name for the signing certificate.
    /// Default: "CN=CoseSignTool Test Signer, O=Test Organization"
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertySubject)]
    public string Subject { get; set; } = ClassStrings.DefaultSubject;

    /// <summary>
    /// The cryptographic algorithm to use. Options: RSA, ECDSA, MLDSA.
    /// Default: RSA (most widely supported)
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyAlgorithm)]
    public string Algorithm { get; set; } = ClassStrings.AlgorithmRsa;

    /// <summary>
    /// Key size in bits.
    /// RSA: 2048, 3072, 4096 (default: 4096 for security)
    /// ECDSA: 256, 384, 521 (default: 384)
    /// MLDSA: 44, 65, 87 (default: 65)
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyKeySize)]
    public int? KeySize { get; set; }

    /// <summary>
    /// Certificate validity period in days.
    /// Default: 365 days
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyValidityDays)]
    public int ValidityDays { get; set; } = 365;

    /// <summary>
    /// Whether to generate a full certificate chain (Root → Intermediate → Leaf).
    /// Default: true (recommended for realistic testing)
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyGenerateChain)]
    public bool GenerateChain { get; set; } = true;

    /// <summary>
    /// Certificate chain configuration (used when GenerateChain is true).
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyChain)]
    public ChainConfig? Chain { get; set; }

    /// <summary>
    /// Enhanced Key Usages (EKUs) to add to the certificate.
    /// Supported values: CodeSigning, LifetimeSigning, ServerAuth, ClientAuth, TimeStamping
    /// Default: ["CodeSigning"] for COSE signing
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyEnhancedKeyUsages)]
    public List<string>? EnhancedKeyUsages { get; set; }

    /// <summary>
    /// Hash algorithm for certificate signing.
    /// Options: SHA256, SHA384, SHA512
    /// Default: SHA256
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyHashAlgorithm)]
    public string HashAlgorithm { get; set; } = ClassStrings.HashAlgorithmSha256;

    /// <summary>
    /// Gets the effective key size based on algorithm defaults.
    /// </summary>
    [JsonIgnore]
    public int EffectiveKeySize => KeySize ?? Algorithm?.ToUpperInvariant() switch
    {
        ClassStrings.AlgorithmRsa => 4096,      // Strong default for RSA
        ClassStrings.AlgorithmEcdsa => 384,     // P-384 curve
        ClassStrings.AlgorithmMldsa => 65,      // ML-DSA-65
        _ => 4096
    };

    /// <summary>
    /// Gets the effective EKUs, defaulting to CodeSigning if not specified.
    /// </summary>
    [JsonIgnore]
    public IReadOnlyList<string> EffectiveEnhancedKeyUsages =>
        EnhancedKeyUsages?.Count > 0
            ? EnhancedKeyUsages
            : new List<string> { ClassStrings.EkuCodeSigning };

    /// <summary>
    /// Gets the effective chain configuration with defaults.
    /// </summary>
    [JsonIgnore]
    public ChainConfig EffectiveChainConfig => Chain ?? new ChainConfig();

    /// <summary>
    /// Loads configuration from a JSON file.
    /// </summary>
    /// <param name="filePath">Path to the JSON configuration file.</param>
    /// <returns>The loaded configuration.</returns>
    /// <exception cref="FileNotFoundException">If the file doesn't exist.</exception>
    /// <exception cref="JsonException">If the JSON is invalid.</exception>
    public static EphemeralCertificateConfig LoadFromFile(string filePath)
    {
        if (!File.Exists(filePath))
        {
            throw new FileNotFoundException(string.Format(ClassStrings.ErrorFormatConfigNotFound, filePath), filePath);
        }

        var json = File.ReadAllText(filePath);
        return LoadFromJson(json);
    }

    /// <summary>
    /// Loads configuration from a JSON string.
    /// </summary>
    /// <param name="json">JSON configuration string.</param>
    /// <returns>The loaded configuration.</returns>
    /// <exception cref="JsonException">If the JSON is invalid.</exception>
    public static EphemeralCertificateConfig LoadFromJson(string json)
    {
        var options = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            ReadCommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true
        };

        return JsonSerializer.Deserialize<EphemeralCertificateConfig>(json, options)
            ?? new EphemeralCertificateConfig();
    }

    /// <summary>
    /// Creates a default configuration optimized for COSE signing tests.
    /// Uses RSA-4096 with a full certificate chain and CodeSigning EKU.
    /// </summary>
    /// <returns>A new default configuration.</returns>
    public static EphemeralCertificateConfig CreateDefault() => new();

    /// <summary>
    /// Creates a minimal configuration for quick testing.
    /// Uses a self-signed RSA-2048 certificate.
    /// </summary>
    /// <returns>A new minimal configuration.</returns>
    public static EphemeralCertificateConfig CreateMinimal() => new()
    {
        Algorithm = ClassStrings.AlgorithmRsa,
        KeySize = 2048,
        ValidityDays = 1,
        GenerateChain = false
    };

    /// <summary>
    /// Creates a configuration for post-quantum testing with ML-DSA.
    /// </summary>
    /// <returns>A new post-quantum configuration.</returns>
    public static EphemeralCertificateConfig CreatePostQuantum() => new()
    {
        Subject = ClassStrings.DefaultPqcSubject,
        Algorithm = ClassStrings.AlgorithmMldsa,
        KeySize = 65,
        ValidityDays = 365,
        GenerateChain = true
    };

    /// <summary>
    /// Serializes this configuration to JSON.
    /// </summary>
    /// <returns>A JSON representation of this configuration.</returns>
    public string ToJson()
    {
        var options = new JsonSerializerOptions
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };
        return JsonSerializer.Serialize(this, options);
    }
}

/// <summary>
/// Configuration for certificate chain generation.
/// </summary>
public class ChainConfig
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string JsonPropertyRootSubject = "rootSubject";
        public const string JsonPropertyIntermediateSubject = "intermediateSubject";
        public const string JsonPropertyRootValidityDays = "rootValidityDays";
        public const string JsonPropertyIntermediateValidityDays = "intermediateValidityDays";

        public const string DefaultRootSubject = "CN=CoseSignTool Test Root CA, O=Test Organization";
        public const string DefaultIntermediateSubject = "CN=CoseSignTool Test Intermediate CA, O=Test Organization";
    }

    /// <summary>
    /// Subject name for the root CA certificate.
    /// Default: "CN=CoseSignTool Test Root CA, O=Test Organization"
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyRootSubject)]
    public string RootSubject { get; set; } = ClassStrings.DefaultRootSubject;

    /// <summary>
    /// Subject name for the intermediate CA certificate.
    /// Default: "CN=CoseSignTool Test Intermediate CA, O=Test Organization"
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyIntermediateSubject)]
    public string IntermediateSubject { get; set; } = ClassStrings.DefaultIntermediateSubject;

    /// <summary>
    /// Validity period for the root CA in days.
    /// Default: 3650 (10 years)
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyRootValidityDays)]
    public int RootValidityDays { get; set; } = 3650;

    /// <summary>
    /// Validity period for the intermediate CA in days.
    /// Default: 1825 (5 years)
    /// </summary>
    [JsonPropertyName(ClassStrings.JsonPropertyIntermediateValidityDays)]
    public int IntermediateValidityDays { get; set; } = 1825;
}