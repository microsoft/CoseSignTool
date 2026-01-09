// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Remote;

using System.Diagnostics.CodeAnalysis;

/// <summary>
/// ML-DSA implementation that delegates signing operations to a remote service.
/// This class wraps ML-DSA public key information but performs signing through RemoteCertificateSource.
/// </summary>
/// <remarks>
/// Note: ML-DSA API differs between Windows and Linux in .NET 10 preview.
/// This class uses conditional compilation to handle these differences.
/// </remarks>
#pragma warning disable SYSLIB5006 // ML-DSA APIs are marked as preview in .NET 10
internal sealed class RemoteMLDsa : MLDsa
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string HashAlgorithmSha256 = "SHA-256";
        public const string HashAlgorithmSha384 = "SHA-384";
        public const string HashAlgorithmSha512 = "SHA-512";

        public const string ErrorVerificationShouldUsePublicKeyDirectly = "Verification should be performed using public key directly, not through remote service.";
        public const string ErrorPrivateKeyExportNotSupported = "Private key export is not supported for remote signing.";
        public const string ErrorPrivateSeedExportNotSupported = "Private seed export is not supported for remote signing.";
    }

    private readonly RemoteCertificateSource CertificateSource;
    private readonly byte[] PublicKey;
    private bool Disposed;

    public RemoteMLDsa(RemoteCertificateSource certificateSource, byte[] publicKey, int securityLevel)
        : base(securityLevel switch
        {
            44 => MLDsaAlgorithm.MLDsa44,
            65 => MLDsaAlgorithm.MLDsa65,
            87 => MLDsaAlgorithm.MLDsa87,
            _ => MLDsaAlgorithm.MLDsa65
        })
    {
        CertificateSource = certificateSource ?? throw new ArgumentNullException(nameof(certificateSource));
        PublicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
    }

    #region Core Abstract Methods - Must implement for ML-DSA base class

    protected override void SignDataCore(ReadOnlySpan<byte> data, ReadOnlySpan<byte> context, Span<byte> destination)
    {
        var signature = CertificateSource.SignDataWithMLDsa(data.ToArray(), hashAlgorithm: null);
        signature.CopyTo(destination);
    }

    protected override void SignPreHashCore(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> context, string hashAlgorithm, Span<byte> destination)
    {
        // For pre-hashed signing, we need to use the hash directly
        var hashAlgName = hashAlgorithm switch
        {
            ClassStrings.HashAlgorithmSha256 => HashAlgorithmName.SHA256,
            ClassStrings.HashAlgorithmSha384 => HashAlgorithmName.SHA384,
            ClassStrings.HashAlgorithmSha512 => HashAlgorithmName.SHA512,
            _ => HashAlgorithmName.SHA256
        };

        var signature = CertificateSource.SignDataWithMLDsa(hash.ToArray(), hashAlgName);
        signature.CopyTo(destination);
    }

#if WINDOWS
    // Windows-specific ML-DSA API methods (different from Linux in .NET 10 preview)
    protected override void SignMuCore(ReadOnlySpan<byte> mu, Span<byte> destination)
    {
        // ML-DSA pure mode signing (no pre-hashing)
        var signature = CertificateSource.SignDataWithMLDsa(mu.ToArray(), hashAlgorithm: null);
        signature.CopyTo(destination);
    }
#endif

    protected override bool VerifyDataCore(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> context)
    {
        throw new NotSupportedException(ClassStrings.ErrorVerificationShouldUsePublicKeyDirectly);
    }

    protected override bool VerifyPreHashCore(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature, string hashAlgorithm, ReadOnlySpan<byte> context)
    {
        throw new NotSupportedException(ClassStrings.ErrorVerificationShouldUsePublicKeyDirectly);
    }

#if WINDOWS
    // Windows-specific ML-DSA API methods (different from Linux in .NET 10 preview)
    protected override bool VerifyMuCore(ReadOnlySpan<byte> mu, ReadOnlySpan<byte> signature)
    {
        throw new NotSupportedException(ClassStrings.ErrorVerificationShouldUsePublicKeyDirectly);
    }
#endif

    protected override void ExportMLDsaPublicKeyCore(Span<byte> destination)
    {
        PublicKey.CopyTo(destination);
    }

#if WINDOWS
    // Windows uses ExportMLDsaPrivateKeyCore
    protected override void ExportMLDsaPrivateKeyCore(Span<byte> destination)
    {
        throw new CryptographicException(ClassStrings.ErrorPrivateKeyExportNotSupported);
    }
#else
    // Linux/macOS uses ExportMLDsaSecretKeyCore
    protected override void ExportMLDsaSecretKeyCore(Span<byte> destination)
    {
        throw new CryptographicException(ClassStrings.ErrorPrivateKeyExportNotSupported);
    }
#endif

    protected override void ExportMLDsaPrivateSeedCore(Span<byte> destination)
    {
        throw new CryptographicException(ClassStrings.ErrorPrivateSeedExportNotSupported);
    }

    protected override bool TryExportPkcs8PrivateKeyCore(Span<byte> destination, out int bytesWritten)
    {
        throw new CryptographicException(ClassStrings.ErrorPrivateKeyExportNotSupported);
    }

    #endregion

    protected override void Dispose(bool disposing)
    {
        if (!Disposed)
        {
            Disposed = true;
            base.Dispose(disposing);
        }
    }
}
#pragma warning restore SYSLIB5006