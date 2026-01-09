// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.AzureTrustedSigning;

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Azure.Developer.TrustedSigning.CryptoProvider;
using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Certificates.Interfaces;
using CoseSign1.Certificates.Remote;

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
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string ErrorAzTrustedSigningDidNotReturnCertificateChain = "Azure Trusted Signing did not return a certificate chain. Please check the Azure Trusted Signing configuration and ensure the signing profile is valid.";
        public const string ErrorAzTrustedSigningReturnedEmptyCertificateChain = "Azure Trusted Signing returned an empty certificate chain. Please check the Azure Trusted Signing configuration.";
        public const string ErrorAzTrustedSigningDidNotReturnSigningCertificate = "Azure Trusted Signing did not return a signing certificate.";

        public const string ErrorEcdsaNotSupportedUseRsa = "ECDSA signing is not currently supported by Azure Trusted Signing CryptoProvider. Use RSA signing operations instead.";
        public const string ErrorMldsaNotSupportedMayBeAvailableFuture = "Azure Trusted Signing does not currently support ML-DSA (post-quantum) signing operations. This feature may be available in future versions of the service.";
    }

    private readonly AzSignContext SignContext;
    private X509Certificate2? SigningCertificate;
    private readonly object CertificateLock = new();
    private RSA? RsaInstance;

    /// <summary>
    /// Initializes a new instance of the <see cref="AzureTrustedSigningCertificateSource"/> class.
    /// </summary>
    /// <param name="signContext">The Azure Trusted Signing context from the SDK.</param>
    /// <param name="chainBuilder">Optional custom chain builder. If null, creates a chain builder with Azure certs.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="signContext"/> is null.</exception>
    /// <exception cref="InvalidOperationException">Thrown when Azure Trusted Signing does not provide a usable certificate chain.</exception>
    public AzureTrustedSigningCertificateSource(
        AzSignContext signContext,
        ICertificateChainBuilder? chainBuilder = null)
        : base(chainBuilder ?? CreateAzureChainBuilder(EnsureNotNull(signContext)))
    {
        SignContext = signContext;
    }

    private static AzSignContext EnsureNotNull(AzSignContext signContext)
    {
        return signContext ?? throw new ArgumentNullException(nameof(signContext));
    }

    private static ICertificateChainBuilder CreateAzureChainBuilder(AzSignContext signContext)
    {
        var chain = signContext.GetCertChain()
            ?? throw new InvalidOperationException(
                ClassStrings.ErrorAzTrustedSigningDidNotReturnCertificateChain);

        if (chain.Count == 0)
        {
            throw new InvalidOperationException(ClassStrings.ErrorAzTrustedSigningReturnedEmptyCertificateChain);
        }

        return new ExplicitCertificateChainBuilder(chain);
    }

    /// <inheritdoc/>
    /// <exception cref="InvalidOperationException">Thrown when Azure Trusted Signing does not return a signing certificate.</exception>
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
                ?? throw new InvalidOperationException(ClassStrings.ErrorAzTrustedSigningDidNotReturnSigningCertificate);

            return SigningCertificate;
        }
    }

    #region RSA Signing Operations

    /// <inheritdoc/>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="data"/> is null.</exception>
    public override byte[] SignDataWithRsa(byte[] data, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        if (data == null) { throw new ArgumentNullException(nameof(data)); }

        var rsa = RsaInstance ??= new RSAAzSign(SignContext);
        return rsa.SignData(data, hashAlgorithm, padding);
    }

    /// <inheritdoc/>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="data"/> is null.</exception>
    public override async Task<byte[]> SignDataWithRsaAsync(byte[] data, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding, CancellationToken cancellationToken = default)
    {
        if (data == null) { throw new ArgumentNullException(nameof(data)); }

        var rsa = RsaInstance ??= new RSAAzSign(SignContext);
        // Note: RSA.SignData is synchronous, but we wrap it for async pattern consistency
        return await Task.Run(() => rsa.SignData(data, hashAlgorithm, padding), cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="hash"/> is null.</exception>
    public override byte[] SignHashWithRsa(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        if (hash == null) { throw new ArgumentNullException(nameof(hash)); }

        var rsa = RsaInstance ??= new RSAAzSign(SignContext);
        return rsa.SignHash(hash, hashAlgorithm, padding);
    }

    /// <inheritdoc/>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="hash"/> is null.</exception>
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
    /// <exception cref="NotSupportedException">Always thrown because ECDSA is not supported.</exception>
    public override byte[] SignDataWithEcdsa(byte[] data, HashAlgorithmName hashAlgorithm)
    {
        throw new NotSupportedException(ClassStrings.ErrorEcdsaNotSupportedUseRsa);
    }

    /// <inheritdoc/>
    /// <remarks>
    /// ECDSA is not currently supported by Azure Trusted Signing CryptoProvider SDK.
    /// </remarks>
    /// <exception cref="NotSupportedException">Always thrown because ECDSA is not supported.</exception>
    public override Task<byte[]> SignDataWithEcdsaAsync(byte[] data, HashAlgorithmName hashAlgorithm, CancellationToken cancellationToken = default)
    {
        throw new NotSupportedException(ClassStrings.ErrorEcdsaNotSupportedUseRsa);
    }

    /// <inheritdoc/>
    /// <remarks>
    /// ECDSA is not currently supported by Azure Trusted Signing CryptoProvider SDK.
    /// </remarks>
    /// <exception cref="NotSupportedException">Always thrown because ECDSA is not supported.</exception>
    public override byte[] SignHashWithEcdsa(byte[] hash)
    {
        throw new NotSupportedException(ClassStrings.ErrorEcdsaNotSupportedUseRsa);
    }

    /// <inheritdoc/>
    /// <remarks>
    /// ECDSA is not currently supported by Azure Trusted Signing CryptoProvider SDK.
    /// </remarks>
    /// <exception cref="NotSupportedException">Always thrown because ECDSA is not supported.</exception>
    public override Task<byte[]> SignHashWithEcdsaAsync(byte[] hash, CancellationToken cancellationToken = default)
    {
        throw new NotSupportedException(ClassStrings.ErrorEcdsaNotSupportedUseRsa);
    }

    #endregion

    #region ML-DSA (Post-Quantum) Signing Operations

    /// <inheritdoc/>
    /// <exception cref="NotSupportedException">Always thrown because ML-DSA signing is not supported.</exception>
    public override byte[] SignDataWithMLDsa(byte[] data, HashAlgorithmName? hashAlgorithm = null)
    {
        throw new NotSupportedException(ClassStrings.ErrorMldsaNotSupportedMayBeAvailableFuture);
    }

    /// <inheritdoc/>
    /// <exception cref="NotSupportedException">Always thrown because ML-DSA signing is not supported.</exception>
    public override Task<byte[]> SignDataWithMLDsaAsync(byte[] data, HashAlgorithmName? hashAlgorithm = null, CancellationToken cancellationToken = default)
    {
        throw new NotSupportedException(ClassStrings.ErrorMldsaNotSupportedMayBeAvailableFuture);
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