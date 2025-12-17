// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Azure.Developer.TrustedSigning.CryptoProvider;
using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Certificates.Interfaces;
using CoseSign1.Certificates.Remote;

namespace CoseSign1.Certificates.AzureTrustedSigning;

/// <summary>
/// Provides certificate and signing operations using Azure Trusted Signing service.
/// Implements the RemoteCertificateSource pattern for V2 architecture.
/// </summary>
/// <remarks>
/// Azure Trusted Signing is a Microsoft-managed cloud service that provides:
/// - Certificate lifecycle management
/// - Secure key storage in FIPS 140-2 Level 3 HSMs
/// - Remote signing operations for RSA and ML-DSA algorithms (ECDSA not currently supported)
/// - Compliance with industry standards (e.g., SCITT)
/// 
/// This class wraps the Azure Developer Trusted Signing SDK (AzSignContext) and adapts it
/// to the V2 RemoteCertificateSource pattern.
/// </remarks>
public class AzureTrustedSigningCertificateSource : RemoteCertificateSource
{
    private readonly AzSignContext SignContext;
    private X509Certificate2? SigningCertificate;
    private readonly object CertificateLock = new();
    private RSA? RsaInstance;

    /// <summary>
    /// Initializes a new instance of the <see cref="AzureTrustedSigningCertificateSource"/> class.
    /// </summary>
    /// <param name="signContext">The Azure Trusted Signing context from the SDK.</param>
    /// <param name="chainBuilder">Optional custom chain builder. If null, creates a chain builder with Azure certs.</param>
    public AzureTrustedSigningCertificateSource(
        AzSignContext signContext,
        ICertificateChainBuilder? chainBuilder = null)
        : base(chainBuilder ?? CreateAzureChainBuilder(signContext))
    {
        SignContext = signContext ?? throw new ArgumentNullException(nameof(signContext));
    }

    private static ICertificateChainBuilder CreateAzureChainBuilder(AzSignContext signContext)
    {
        var chain = signContext.GetCertChain()
            ?? throw new InvalidOperationException(
                "Azure Trusted Signing did not return a certificate chain. " +
                "Please check the Azure Trusted Signing configuration and ensure the signing profile is valid.");

        if (chain.Count == 0)
        {
            throw new InvalidOperationException(
                "Azure Trusted Signing returned an empty certificate chain. " +
                "Please check the Azure Trusted Signing configuration.");
        }

        return new ExplicitCertificateChainBuilder(chain);
    }

    /// <inheritdoc/>
    public override X509Certificate2 GetSigningCertificate()
    {
        if (SigningCertificate != null)
        {
            return SigningCertificate;
        }

        lock (CertificateLock)
        {
            if (SigningCertificate != null)
            {
                return SigningCertificate;
            }

            // Get the certificate from Azure Trusted Signing SDK
            SigningCertificate = SignContext.GetSigningCertificate()
                ?? throw new InvalidOperationException("Azure Trusted Signing did not return a signing certificate.");

            return SigningCertificate;
        }
    }

    #region RSA Signing Operations

    /// <inheritdoc/>
    public override byte[] SignDataWithRsa(byte[] data, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        if (data == null) { throw new ArgumentNullException(nameof(data)); }

        var rsa = RsaInstance ??= new RSAAzSign(SignContext);
        return rsa.SignData(data, hashAlgorithm, padding);
    }

    /// <inheritdoc/>
    public override async Task<byte[]> SignDataWithRsaAsync(byte[] data, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding, CancellationToken cancellationToken = default)
    {
        if (data == null) { throw new ArgumentNullException(nameof(data)); }

        var rsa = RsaInstance ??= new RSAAzSign(SignContext);
        // Note: RSA.SignData is synchronous, but we wrap it for async pattern consistency
        return await Task.Run(() => rsa.SignData(data, hashAlgorithm, padding), cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public override byte[] SignHashWithRsa(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        if (hash == null) { throw new ArgumentNullException(nameof(hash)); }

        var rsa = RsaInstance ??= new RSAAzSign(SignContext);
        return rsa.SignHash(hash, hashAlgorithm, padding);
    }

    /// <inheritdoc/>
    public override async Task<byte[]> SignHashWithRsaAsync(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding, CancellationToken cancellationToken = default)
    {
        if (hash == null) { throw new ArgumentNullException(nameof(hash)); }

        var rsa = RsaInstance ??= new RSAAzSign(SignContext);
        return await Task.Run(() => rsa.SignHash(hash, hashAlgorithm, padding), cancellationToken).ConfigureAwait(false);
    }

    #endregion

    #region ECDSA Signing Operations

    /// <inheritdoc/>
    /// <remarks>
    /// ECDSA is not currently supported by Azure Trusted Signing CryptoProvider SDK.
    /// </remarks>
    public override byte[] SignDataWithEcdsa(byte[] data, HashAlgorithmName hashAlgorithm)
    {
        throw new NotSupportedException(
            "ECDSA signing is not currently supported by Azure Trusted Signing CryptoProvider. " +
            "Use RSA signing operations instead.");
    }

    /// <inheritdoc/>
    /// <remarks>
    /// ECDSA is not currently supported by Azure Trusted Signing CryptoProvider SDK.
    /// </remarks>
    public override Task<byte[]> SignDataWithEcdsaAsync(byte[] data, HashAlgorithmName hashAlgorithm, CancellationToken cancellationToken = default)
    {
        throw new NotSupportedException(
            "ECDSA signing is not currently supported by Azure Trusted Signing CryptoProvider. " +
            "Use RSA signing operations instead.");
    }

    /// <inheritdoc/>
    /// <remarks>
    /// ECDSA is not currently supported by Azure Trusted Signing CryptoProvider SDK.
    /// </remarks>
    public override byte[] SignHashWithEcdsa(byte[] hash)
    {
        throw new NotSupportedException(
            "ECDSA signing is not currently supported by Azure Trusted Signing CryptoProvider. " +
            "Use RSA signing operations instead.");
    }

    /// <inheritdoc/>
    /// <remarks>
    /// ECDSA is not currently supported by Azure Trusted Signing CryptoProvider SDK.
    /// </remarks>
    public override Task<byte[]> SignHashWithEcdsaAsync(byte[] hash, CancellationToken cancellationToken = default)
    {
        throw new NotSupportedException(
            "ECDSA signing is not currently supported by Azure Trusted Signing CryptoProvider. " +
            "Use RSA signing operations instead.");
    }

    #endregion

    #region ML-DSA (Post-Quantum) Signing Operations

    /// <inheritdoc/>
    public override byte[] SignDataWithMLDsa(byte[] data, HashAlgorithmName? hashAlgorithm = null)
    {
        throw new NotSupportedException(
            "Azure Trusted Signing does not currently support ML-DSA (post-quantum) signing operations. " +
            "This feature may be available in future versions of the service.");
    }

    /// <inheritdoc/>
    public override Task<byte[]> SignDataWithMLDsaAsync(byte[] data, HashAlgorithmName? hashAlgorithm = null, CancellationToken cancellationToken = default)
    {
        throw new NotSupportedException(
            "Azure Trusted Signing does not currently support ML-DSA (post-quantum) signing operations. " +
            "This feature may be available in future versions of the service.");
    }

    #endregion

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            SigningCertificate?.Dispose();
            SigningCertificate = null;

            RsaInstance?.Dispose();
            RsaInstance = null;

            // Note: We don't dispose _signContext as it's owned by the service and may be reused
        }

        base.Dispose(disposing);
    }
}