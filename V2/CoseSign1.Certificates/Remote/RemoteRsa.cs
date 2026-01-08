// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics.CodeAnalysis;

namespace CoseSign1.Certificates.Remote;

/// <summary>
/// RSA implementation that delegates signing operations to a remote service.
/// This class wraps RSA public key information but performs signing through RemoteCertificateSource.
/// </summary>
internal sealed class RemoteRsa : RSA
{
    private readonly RemoteCertificateSource CertificateSource;
    private readonly RSAParameters PublicParameters;
    private bool Disposed;

    public RemoteRsa(RemoteCertificateSource certificateSource, RSAParameters publicParameters)
    {
        CertificateSource = certificateSource ?? throw new ArgumentNullException(nameof(certificateSource));
        PublicParameters = publicParameters;
        KeySizeValue = PublicParameters.Modulus?.Length * 8 ?? 0;
    }

    public override RSAParameters ExportParameters(bool includePrivateParameters)
    {
        if (includePrivateParameters)
        {
            throw new CryptographicException(ClassStrings.ErrorPrivateKeyExportNotSupported);
        }

        return PublicParameters;
    }

    public override void ImportParameters(RSAParameters parameters)
    {
        throw new NotSupportedException(ClassStrings.ErrorParameterImportNotSupported);
    }

    public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        if (padding != RSASignaturePadding.Pss)
        {
            throw new CryptographicException(ClassStrings.ErrorOnlyPssPaddingSupportedForRemoteRsaSigning);
        }

        return CertificateSource.SignHashWithRsa(hash, hashAlgorithm, padding);
    }

    protected override void Dispose(bool disposing)
    {
        if (!Disposed)
        {
            Disposed = true;
            base.Dispose(disposing);
        }
    }

    #region Not Implemented - Encryption/Decryption not needed for COSE signing

    public override byte[] Decrypt(byte[] data, RSAEncryptionPadding padding)
    {
        throw new NotSupportedException(ClassStrings.ErrorDecryptionNotSupportedForRemoteSigning);
    }

    public override byte[] Encrypt(byte[] data, RSAEncryptionPadding padding)
    {
        throw new NotSupportedException(ClassStrings.ErrorEncryptionNotSupportedForRemoteSigning);
    }

    #endregion

    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string ErrorPrivateKeyExportNotSupported = "Private key export is not supported for remote signing.";
        public const string ErrorParameterImportNotSupported = "Parameter import is not supported for remote signing.";
        public const string ErrorOnlyPssPaddingSupportedForRemoteRsaSigning = "Only PSS padding is supported for remote RSA signing.";
        public const string ErrorDecryptionNotSupportedForRemoteSigning = "Decryption is not supported for remote signing.";
        public const string ErrorEncryptionNotSupportedForRemoteSigning = "Encryption is not supported for remote signing.";
    }
}