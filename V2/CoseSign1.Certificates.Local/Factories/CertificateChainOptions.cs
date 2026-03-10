// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Local;

/// <summary>
/// Configuration options for certificate chain creation.
/// </summary>
public class CertificateChainOptions
{
    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string DefaultRootName = "CN=Ephemeral Root CA";
        public const string DefaultIntermediateName = "CN=Ephemeral Intermediate CA";
        public const string DefaultLeafName = "CN=Ephemeral Leaf Certificate";
    }

    /// <summary>
    /// Gets or sets the subject name for the root CA certificate.
    /// Default: "CN=Ephemeral Root CA"
    /// </summary>
    public string RootName { get; set; } = ClassStrings.DefaultRootName;

    /// <summary>
    /// Gets or sets the subject name for the intermediate CA certificate.
    /// If null, no intermediate CA is created (2-tier chain).
    /// Default: "CN=Ephemeral Intermediate CA"
    /// </summary>
    public string? IntermediateName { get; set; } = ClassStrings.DefaultIntermediateName;

    /// <summary>
    /// Gets or sets the subject name for the leaf (end-entity) certificate.
    /// Default: "CN=Ephemeral Leaf Certificate"
    /// </summary>
    public string LeafName { get; set; } = ClassStrings.DefaultLeafName;

    /// <summary>
    /// Gets or sets the cryptographic algorithm for all certificates in the chain.
    /// Default: RSA
    /// </summary>
    public KeyAlgorithm KeyAlgorithm { get; set; } = KeyAlgorithm.RSA;

    /// <summary>
    /// Gets or sets the key size for all certificates in the chain.
    /// If null, uses algorithm defaults.
    /// </summary>
    public int? KeySize { get; set; }

    /// <summary>
    /// Gets or sets the validity duration for the root CA.
    /// Default: 10 years
    /// </summary>
    public TimeSpan RootValidity { get; set; } = TimeSpan.FromDays(3650);

    /// <summary>
    /// Gets or sets the validity duration for the intermediate CA.
    /// Default: 5 years
    /// </summary>
    public TimeSpan IntermediateValidity { get; set; } = TimeSpan.FromDays(1825);

    /// <summary>
    /// Gets or sets the validity duration for the leaf certificate.
    /// Default: 1 year
    /// </summary>
    public TimeSpan LeafValidity { get; set; } = TimeSpan.FromDays(365);

    /// <summary>
    /// Gets or sets whether only the leaf certificate should have a private key.
    /// Root and intermediate will only contain public keys.
    /// Useful for PFX export scenarios.
    /// Default: false
    /// </summary>
    public bool LeafOnlyPrivateKey { get; set; }

    /// <summary>
    /// Gets or sets whether to return certificates in leaf-first order.
    /// If false, returns root-first order.
    /// Default: false (root first)
    /// </summary>
    public bool LeafFirst { get; set; }

    /// <summary>
    /// Gets or sets the Enhanced Key Usage OIDs for the leaf certificate.
    /// If null, uses default code signing EKU.
    /// </summary>
    public IList<string>? LeafEnhancedKeyUsages { get; set; }
}