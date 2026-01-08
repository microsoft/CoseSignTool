// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics.CodeAnalysis;
using CoseSign1.Certificates.ChainBuilders;

namespace CoseSign1.Certificates.Remote;

/// <summary>
/// Abstract base class for remote certificate sources that perform signing operations
/// via a remote service (e.g., Azure Key Vault, Azure Trusted Signing, HSM, etc.).
/// </summary>
/// <remarks>
/// Remote signing services must implement the signing operations for RSA, ECDSA, and ML-DSA algorithms.
/// Authentication, service connection, and service-specific configuration are the responsibility of the derived class.
/// </remarks>
public abstract class RemoteCertificateSource : CertificateSourceBase
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string Mldsa44Oid = "2.16.840.1.101.3.4.3.17";
        public const string Mldsa65Oid = "2.16.840.1.101.3.4.3.18";
        public const string Mldsa87Oid = "2.16.840.1.101.3.4.3.19";

        public const string ErrorFormatUnableToDetermineKeySizeForAlgorithm = "Unable to determine key size for certificate with algorithm {0}";
        public const string ErrorCertificateDoesNotContainRsaPublicKey = "Certificate does not contain an RSA public key.";
        public const string ErrorCertificateDoesNotContainEcdsaPublicKey = "Certificate does not contain an ECDsa public key.";
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="RemoteCertificateSource"/> class.
    /// </summary>
    /// <param name="chainBuilder">Optional custom chain builder. If null, uses X509ChainBuilder for automatic chain building.</param>
    protected RemoteCertificateSource(ICertificateChainBuilder? chainBuilder = null)
        : base(chainBuilder ?? new X509ChainBuilder())
    {
    }

    /// <inheritdoc/>
    public override bool HasPrivateKey => true; // Remote services always have access to private key operations

    /// <summary>
    /// Signs data using RSA with the specified hash algorithm and padding.
    /// </summary>
    /// <param name="data">The data to sign.</param>
    /// <param name="hashAlgorithm">The hash algorithm to use.</param>
    /// <param name="padding">The RSA signature padding mode.</param>
    /// <returns>The signature bytes.</returns>
    /// <exception cref="NotSupportedException">Thrown if the remote service does not support RSA signing.</exception>
    public abstract byte[] SignDataWithRsa(byte[] data, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding);

    /// <summary>
    /// Signs data using RSA with the specified hash algorithm and padding asynchronously.
    /// </summary>
    /// <param name="data">The data to sign.</param>
    /// <param name="hashAlgorithm">The hash algorithm to use.</param>
    /// <param name="padding">The RSA signature padding mode.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task that represents the asynchronous operation. The task result contains the signature bytes.</returns>
    /// <exception cref="NotSupportedException">Thrown if the remote service does not support RSA signing.</exception>
    public abstract Task<byte[]> SignDataWithRsaAsync(byte[] data, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding, CancellationToken cancellationToken = default);

    /// <summary>
    /// Signs a hash using RSA with the specified hash algorithm and padding.
    /// </summary>
    /// <param name="hash">The hash to sign.</param>
    /// <param name="hashAlgorithm">The hash algorithm that was used to create the hash.</param>
    /// <param name="padding">The RSA signature padding mode.</param>
    /// <returns>The signature bytes.</returns>
    /// <exception cref="NotSupportedException">Thrown if the remote service does not support RSA signing.</exception>
    public abstract byte[] SignHashWithRsa(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding);

    /// <summary>
    /// Signs a hash using RSA with the specified hash algorithm and padding asynchronously.
    /// </summary>
    /// <param name="hash">The hash to sign.</param>
    /// <param name="hashAlgorithm">The hash algorithm that was used to create the hash.</param>
    /// <param name="padding">The RSA signature padding mode.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task that represents the asynchronous operation. The task result contains the signature bytes.</returns>
    /// <exception cref="NotSupportedException">Thrown if the remote service does not support RSA signing.</exception>
    public abstract Task<byte[]> SignHashWithRsaAsync(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding, CancellationToken cancellationToken = default);

    /// <summary>
    /// Signs data using ECDSA with the specified hash algorithm.
    /// </summary>
    /// <param name="data">The data to sign.</param>
    /// <param name="hashAlgorithm">The hash algorithm to use.</param>
    /// <returns>The signature bytes in IEEE P1363 format.</returns>
    /// <exception cref="NotSupportedException">Thrown if the remote service does not support ECDSA signing.</exception>
    public abstract byte[] SignDataWithEcdsa(byte[] data, HashAlgorithmName hashAlgorithm);

    /// <summary>
    /// Signs data using ECDSA with the specified hash algorithm asynchronously.
    /// </summary>
    /// <param name="data">The data to sign.</param>
    /// <param name="hashAlgorithm">The hash algorithm to use.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task that represents the asynchronous operation. The task result contains the signature bytes in IEEE P1363 format.</returns>
    /// <exception cref="NotSupportedException">Thrown if the remote service does not support ECDSA signing.</exception>
    public abstract Task<byte[]> SignDataWithEcdsaAsync(byte[] data, HashAlgorithmName hashAlgorithm, CancellationToken cancellationToken = default);

    /// <summary>
    /// Signs a hash using ECDSA.
    /// </summary>
    /// <param name="hash">The hash to sign.</param>
    /// <returns>The signature bytes in IEEE P1363 format.</returns>
    /// <exception cref="NotSupportedException">Thrown if the remote service does not support ECDSA signing.</exception>
    public abstract byte[] SignHashWithEcdsa(byte[] hash);

    /// <summary>
    /// Signs a hash using ECDSA asynchronously.
    /// </summary>
    /// <param name="hash">The hash to sign.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task that represents the asynchronous operation. The task result contains the signature bytes in IEEE P1363 format.</returns>
    /// <exception cref="NotSupportedException">Thrown if the remote service does not support ECDSA signing.</exception>
    public abstract Task<byte[]> SignHashWithEcdsaAsync(byte[] hash, CancellationToken cancellationToken = default);

    /// <summary>
    /// Signs data using ML-DSA (Module-Lattice-Based Digital Signature Algorithm).
    /// </summary>
    /// <param name="data">The data to sign.</param>
    /// <param name="hashAlgorithm">The hash algorithm to use for pre-hashing (optional, depending on ML-DSA variant).</param>
    /// <returns>The signature bytes.</returns>
    /// <exception cref="NotSupportedException">Thrown if the remote service does not support ML-DSA signing.</exception>
    /// <remarks>
    /// ML-DSA (FIPS 204) is a post-quantum signature algorithm.
    /// </remarks>
    public abstract byte[] SignDataWithMLDsa(byte[] data, HashAlgorithmName? hashAlgorithm = null);

    /// <summary>
    /// Signs data using ML-DSA (Module-Lattice-Based Digital Signature Algorithm) asynchronously.
    /// </summary>
    /// <param name="data">The data to sign.</param>
    /// <param name="hashAlgorithm">The hash algorithm to use for pre-hashing (optional, depending on ML-DSA variant).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task that represents the asynchronous operation. The task result contains the signature bytes.</returns>
    /// <exception cref="NotSupportedException">Thrown if the remote service does not support ML-DSA signing.</exception>
    /// <remarks>
    /// ML-DSA (FIPS 204) is a post-quantum signature algorithm.
    /// </remarks>
    public abstract Task<byte[]> SignDataWithMLDsaAsync(byte[] data, HashAlgorithmName? hashAlgorithm = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets the public key algorithm identifier for the signing certificate.
    /// This is used to determine which signing method to use.
    /// </summary>
    /// <returns>The OID string for the public key algorithm (e.g., "1.2.840.113549.1.1.1" for RSA).</returns>
    protected string GetPublicKeyAlgorithm()
    {
        var cert = GetSigningCertificate();
        return cert.GetKeyAlgorithm();
    }

    /// <summary>
    /// Gets the key size in bits for the signing certificate.
    /// </summary>
    /// <returns>The key size in bits.</returns>
    protected int GetKeySize()
    {
        var cert = GetSigningCertificate();

        // Try to get the public key and determine its size
        using var rsa = cert.GetRSAPublicKey();
        if (rsa != null)
        {
            return rsa.KeySize;
        }

        using var ecdsa = cert.GetECDsaPublicKey();
        if (ecdsa != null)
        {
            return ecdsa.KeySize;
        }

#pragma warning disable SYSLIB5006 // ML-DSA APIs are marked as preview in .NET 10
        try
        {
            using var mldsa = cert.GetMLDsaPublicKey();
            if (mldsa != null)
            {
                // ML-DSA KeySize property doesn't exist, use OID-based sizing
                var publicKeyOid = cert.PublicKey.Oid.Value;
                return publicKeyOid switch
                {
                    ClassStrings.Mldsa44Oid => 44,  // ML-DSA-44
                    ClassStrings.Mldsa65Oid => 65,  // ML-DSA-65
                    ClassStrings.Mldsa87Oid => 87,  // ML-DSA-87
                    _ => 65 // Default to ML-DSA-65
                };
            }
        }
        catch
        {
            // ML-DSA might not be available or supported
        }
#pragma warning restore SYSLIB5006

        throw new NotSupportedException(string.Format(ClassStrings.ErrorFormatUnableToDetermineKeySizeForAlgorithm, cert.GetKeyAlgorithm()));
    }

    /// <summary>
    /// Creates a RemoteRsa instance for COSE signing operations.
    /// This wraps the public key but delegates signing to abstract remote methods.
    /// </summary>
    /// <returns>A RemoteRsa instance configured for this certificate.</returns>
    internal RSA GetRemoteRsa()
    {
        var cert = GetSigningCertificate();
        using var publicRsa = cert.GetRSAPublicKey();

        if (publicRsa == null)
        {
            throw new InvalidOperationException(ClassStrings.ErrorCertificateDoesNotContainRsaPublicKey);
        }

        var parameters = publicRsa.ExportParameters(includePrivateParameters: false);
        return new RemoteRsa(this, parameters);
    }

    /// <summary>
    /// Creates a RemoteECDsa instance for COSE signing operations.
    /// This wraps the public key but delegates signing to abstract remote methods.
    /// </summary>
    /// <returns>A RemoteECDsa instance configured for this certificate.</returns>
    internal ECDsa GetRemoteECDsa()
    {
        var cert = GetSigningCertificate();
        using var publicEcdsa = cert.GetECDsaPublicKey();

        if (publicEcdsa == null)
        {
            throw new InvalidOperationException(ClassStrings.ErrorCertificateDoesNotContainEcdsaPublicKey);
        }

        var parameters = publicEcdsa.ExportParameters(includePrivateParameters: false);
        return new RemoteECDsa(this, parameters);
    }

#if NET10_0_OR_GREATER
    /// <summary>
    /// Creates a RemoteMLDsa instance for COSE signing operations.
    /// This wraps the public key but delegates signing to abstract remote methods.
    /// </summary>
    /// <returns>A RemoteMLDsa instance configured for this certificate.</returns>
#pragma warning disable SYSLIB5006 // ML-DSA APIs are marked as preview
    internal MLDsa GetRemoteMLDsa()
    {
        var cert = GetSigningCertificate();

        // Determine security level from OID first
        var oid = cert.PublicKey.Oid.Value;
        var securityLevel = oid switch
        {
            ClassStrings.Mldsa44Oid => 44,
            ClassStrings.Mldsa65Oid => 65,
            ClassStrings.Mldsa87Oid => 87,
            _ => 44 // Default
        };

        // Get the public key size based on security level (in bytes)
        var publicKeySize = securityLevel switch
        {
            44 => 1312,  // ML-DSA-44 public key size
            65 => 1952,  // ML-DSA-65 public key size
            87 => 2592,  // ML-DSA-87 public key size
            _ => 1952
        };

        // Export public key from certificate
        var publicKey = new byte[publicKeySize];
        var publicKeyData = cert.PublicKey.EncodedKeyValue.RawData;
        Array.Copy(publicKeyData, publicKey, Math.Min(publicKeyData.Length, publicKeySize));

        return new RemoteMLDsa(this, publicKey, securityLevel);
    }
#pragma warning restore SYSLIB5006
#endif
}
