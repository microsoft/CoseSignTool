// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics.CodeAnalysis;

namespace CoseSign1.Certificates;

/// <summary>
/// Shared certificate signing key implementation that works for both local and remote scenarios.
/// Uses ICertificateSource for certificate management and ISigningKeyProvider for signing operations.
/// </summary>
public class CertificateSigningKey : ICertificateSigningKey
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string MldsaOidPrefix = "2.16.840.1.101.3.4.3.";
        public const string Mldsa44Oid = "2.16.840.1.101.3.4.3.17";
        public const string Mldsa65Oid = "2.16.840.1.101.3.4.3.18";
        public const string Mldsa87Oid = "2.16.840.1.101.3.4.3.19";

        public const string MetadataKeyPublicKeyAlgorithmOid = "PublicKeyAlgorithmOid";
        public const string MetadataKeyWarning = "Warning";
        public const string MetadataValueUnknown = "unknown";

        public const string WarningUnableToDetermineKeyTypeFromCertificate = "Unable to determine key type from certificate";
    }

    private readonly ICertificateSource CertificateSourceField;
    private readonly ISigningKeyProvider SigningKeyProviderField;
    private readonly ISigningService<SigningOptions> SigningServiceField;
    private CoseKey? CoseKeyField;
    private readonly object CoseKeyLock = new();
    private bool Disposed;

    /// <summary>
    /// Initializes a new instance of CertificateSigningKey.
    /// </summary>
    /// <param name="certificateSource">Source for the signing certificate</param>
    /// <param name="signingKeyProvider">Provider for signing operations</param>
    /// <param name="signingService">The signing service that owns this key</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="certificateSource"/> is null.</exception>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="signingKeyProvider"/> is null.</exception>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="signingService"/> is null.</exception>
    public CertificateSigningKey(
        ICertificateSource certificateSource,
        ISigningKeyProvider signingKeyProvider,
        ISigningService<SigningOptions> signingService)
    {
        CertificateSourceField = certificateSource ?? throw new ArgumentNullException(nameof(certificateSource));
        SigningKeyProviderField = signingKeyProvider ?? throw new ArgumentNullException(nameof(signingKeyProvider));
        SigningServiceField = signingService ?? throw new ArgumentNullException(nameof(signingService));
    }

    /// <inheritdoc/>
    public CoseKey GetCoseKey()
    {
        if (CoseKeyField != null)
        {
            return CoseKeyField;
        }

        lock (CoseKeyLock)
        {
            if (CoseKeyField != null)
            {
                return CoseKeyField;
            }

            CoseKeyField = SigningKeyProviderField.GetCoseKey();
            return CoseKeyField;
        }
    }

    /// <inheritdoc/>
    public X509Certificate2 GetSigningCertificate()
    {
        return CertificateSourceField.GetSigningCertificate();
    }

    /// <inheritdoc/>
    public IEnumerable<X509Certificate2> GetCertificateChain(X509ChainSortOrder sortOrder)
    {
        var chainBuilder = CertificateSourceField.GetChainBuilder();
        var cert = CertificateSourceField.GetSigningCertificate();

        chainBuilder.Build(cert);

        var chainElements = sortOrder == X509ChainSortOrder.LeafFirst
            ? chainBuilder.ChainElements
            : chainBuilder.ChainElements.Reverse();

        return chainElements;
    }

    /// <inheritdoc/>
    public SigningKeyMetadata Metadata => GetMetadata();

    /// <inheritdoc/>
    public ISigningService<SigningOptions> SigningService => SigningServiceField;

    private SigningKeyMetadata GetMetadata()
    {
        var cert = CertificateSourceField.GetSigningCertificate();

        // Detect key type and algorithm from certificate
        var keyType = CryptographicKeyType.RSA;
        int coseAlgorithmId = -37; // Default to PS256
        HashAlgorithmName hashAlgorithm = HashAlgorithmName.SHA256;
        int? keySizeInBits = null;

        // Try RSA first
        using var rsa = cert.GetRSAPublicKey();
        if (rsa != null)
        {
            keyType = CryptographicKeyType.RSA;
            keySizeInBits = rsa.KeySize;

            // Determine COSE algorithm based on key size
            // -37: PS256 (RSA-PSS with SHA-256)
            // -38: PS384 (RSA-PSS with SHA-384)
            // -39: PS512 (RSA-PSS with SHA-512)
            coseAlgorithmId = keySizeInBits switch
            {
                >= 4096 => -39, // PS512
                >= 3072 => -38, // PS384
                _ => -37        // PS256
            };

            hashAlgorithm = coseAlgorithmId switch
            {
                -39 => HashAlgorithmName.SHA512,
                -38 => HashAlgorithmName.SHA384,
                _ => HashAlgorithmName.SHA256
            };

            return new SigningKeyMetadata(
                coseAlgorithmId: coseAlgorithmId,
                keyType: keyType,
                isRemote: SigningKeyProviderField.IsRemote,
                hashAlgorithm: hashAlgorithm,
                keySizeInBits: keySizeInBits,
                additionalMetadata: null);
        }

        // Try ECDSA
        using var ecdsa = cert.GetECDsaPublicKey();
        if (ecdsa != null)
        {
            keyType = CryptographicKeyType.ECDsa;
            keySizeInBits = ecdsa.KeySize;

            // Determine COSE algorithm based on curve
            // -7: ES256 (ECDSA with SHA-256, P-256 curve)
            // -35: ES384 (ECDSA with SHA-384, P-384 curve)
            // -36: ES512 (ECDSA with SHA-512, P-521 curve)
            coseAlgorithmId = keySizeInBits switch
            {
                521 => -36, // ES512 (P-521)
                384 => -35, // ES384 (P-384)
                _ => -7     // ES256 (P-256)
            };

            hashAlgorithm = coseAlgorithmId switch
            {
                -36 => HashAlgorithmName.SHA512,
                -35 => HashAlgorithmName.SHA384,
                _ => HashAlgorithmName.SHA256
            };

            return new SigningKeyMetadata(
                coseAlgorithmId: coseAlgorithmId,
                keyType: keyType,
                isRemote: SigningKeyProviderField.IsRemote,
                hashAlgorithm: hashAlgorithm,
                keySizeInBits: keySizeInBits,
                additionalMetadata: null);
        }

        // Try ML-DSA (Post-Quantum)
        // ML-DSA uses different OIDs that are supported in .NET 10.0+
        // Check for ML-DSA by examining the public key algorithm OID
        var publicKeyOid = cert.PublicKey.Oid.Value;

        // ML-DSA OIDs (NIST standardized):
        // 2.16.840.1.101.3.4.3.17 - ML-DSA-44
        // 2.16.840.1.101.3.4.3.18 - ML-DSA-65
        // 2.16.840.1.101.3.4.3.19 - ML-DSA-87
        if (publicKeyOid?.StartsWith(ClassStrings.MldsaOidPrefix) == true)
        {
            keyType = CryptographicKeyType.MLDSA;

            // Determine COSE algorithm and security level based on ML-DSA variant
            // TBD: COSE algorithm IDs for ML-DSA (these are provisional)
            // -48: ML-DSA-44 (128-bit security)
            // -49: ML-DSA-65 (192-bit security)
            // -50: ML-DSA-87 (256-bit security)
            (coseAlgorithmId, keySizeInBits, hashAlgorithm) = publicKeyOid switch
            {
                ClassStrings.Mldsa44Oid => (-48, (int?)44, HashAlgorithmName.SHA256),  // ML-DSA-44
                ClassStrings.Mldsa65Oid => (-49, (int?)65, HashAlgorithmName.SHA384),  // ML-DSA-65
                ClassStrings.Mldsa87Oid => (-50, (int?)87, HashAlgorithmName.SHA512),  // ML-DSA-87
                _ => (-48, (int?)null, HashAlgorithmName.SHA256) // Default to ML-DSA-44 equivalent
            };

            return new SigningKeyMetadata(
                coseAlgorithmId: coseAlgorithmId,
                keyType: keyType,
                isRemote: SigningKeyProviderField.IsRemote,
                hashAlgorithm: hashAlgorithm,
                keySizeInBits: keySizeInBits,
                additionalMetadata: new Dictionary<string, object>
                {
                    [ClassStrings.MetadataKeyPublicKeyAlgorithmOid] = publicKeyOid ?? ClassStrings.MetadataValueUnknown
                });
        }

        // Fallback: Unknown key type
        return new SigningKeyMetadata(
            coseAlgorithmId: -37, // Default to PS256
            keyType: CryptographicKeyType.RSA,
            isRemote: SigningKeyProviderField.IsRemote,
            hashAlgorithm: HashAlgorithmName.SHA256,
            keySizeInBits: null,
            additionalMetadata: new Dictionary<string, object>
            {
                [ClassStrings.MetadataKeyWarning] = ClassStrings.WarningUnableToDetermineKeyTypeFromCertificate
            });
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (Disposed)
        {
            return;
        }

        SigningKeyProviderField?.Dispose();
        CertificateSourceField?.Dispose();
        Disposed = true;
        GC.SuppressFinalize(this);
    }
}