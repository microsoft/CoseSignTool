// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.AzureKeyVault;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Diagnostics.CodeAnalysis;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Secrets;
using CoseSign1.Abstractions;
using CoseSign1.AzureKeyVault.Common;
using CoseSign1.Certificates.Remote;

/// <summary>
/// Indicates how the private key for an Azure Key Vault certificate is accessed.
/// </summary>
public enum KeyVaultCertificateKeyMode
{
    /// <summary>
    /// Private key operations are performed remotely via the /keys plane.
    /// This includes HSM-backed keys and non-exportable software keys.
    /// </summary>
    Remote,

    /// <summary>
    /// Private key material is downloaded via the /secrets plane.
    /// </summary>
    Local
}

/// <summary>
/// Retrieves an Azure Key Vault certificate and exposes it as a <see cref="RemoteCertificateSource"/>.
/// The source auto-detects exportability (local vs remote signing) and can optionally refresh.
/// </summary>
/// <remarks>
/// Usage is intentionally simple:
/// <list type="bullet">
/// <item><description>Construct with an <see cref="IKeyVaultClientFactory"/> and certificate name.</description></item>
/// <item><description>Call <see cref="InitializeAsync"/> once.</description></item>
/// <item><description>Use signing methods and/or <see cref="GetSigningCertificate"/>.</description></item>
/// </list>
/// </remarks>
public sealed class AzureKeyVaultCertificateSource : RemoteCertificateSource
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string ErrorCertificateDoesNotHaveRsaPrivateKey = "Certificate does not have an RSA private key.";
        public const string ErrorCertificateDoesNotHaveEcdsaPrivateKey = "Certificate does not have an ECDSA private key.";
        public const string ErrorRemoteSigningRequiresCryptographyClientWrapper = "Remote signing requires a CryptographyClient wrapper.";
        public const string ErrorAzureKeyVaultDoesNotSupportMldsaSigning = "Azure Key Vault does not currently support ML-DSA (post-quantum) signing.";
        public const string ErrorCannotRefreshPinnedCertificateVersion = "Cannot refresh a pinned certificate version.";
        public const string ErrorNotInitializedCallInitializeAsyncBeforeUse = "AzureKeyVaultCertificateSource has not been initialized. Call InitializeAsync() before use.";
        public const string ErrorKeyVaultReturnedCertificateWithoutVersion = "Key Vault returned a certificate without a version.";
        public const string ErrorCertificateDataFromKeyVaultInvalid = "Certificate data retrieved from Key Vault is invalid.";
        public const string ErrorKeyVaultSecretDidNotContainCertificateWithPrivateKey = "Key Vault secret did not contain a certificate with a private key.";
        public const string ErrorInvalidPemFormat = "Invalid PEM format: could not find certificate data.";

        public const string ContentTypePkcs12 = "application/x-pkcs12";
        public const string ContentTypePemFile = "application/x-pem-file";

        public const string PemCertificateHeader = "-----BEGIN CERTIFICATE-----";
        public const string PemCertificateFooter = "-----END CERTIFICATE-----";
    }

    private sealed class State
    {
        public State(
            X509Certificate2 certificate,
            string version,
            KeyVaultCertificateKeyMode keyMode,
            KeyVaultCryptoClientWrapper? cryptoWrapper)
        {
            Certificate = certificate;
            Version = version;
            KeyMode = keyMode;
            CryptoWrapper = cryptoWrapper;
        }

        public X509Certificate2 Certificate { get; }

        public string Version { get; }

        public KeyVaultCertificateKeyMode KeyMode { get; }

        public KeyVaultCryptoClientWrapper? CryptoWrapper { get; }
    }

    private readonly IKeyVaultClientFactory ClientFactory;
    private readonly CertificateClient CertificateClient;
    private readonly SecretClient SecretClient;
    private readonly KeyClient KeyClient;
    private readonly string CertificateName;
    private readonly string? PinnedVersion;
    private readonly TimeSpan? RefreshInterval;
    private readonly bool ForceRemoteMode;

    private readonly SemaphoreSlim InitGate = new(1, 1);
    private readonly SemaphoreSlim UseGate = new(1, 1);
    private Timer? RefreshTimer;
    private int RefreshInProgress;
    private bool Disposed;

    private State? Current;

    /// <summary>
    /// Gets the Key Vault URI.
    /// </summary>
    public Uri VaultUri => ClientFactory.VaultUri;

    /// <summary>
    /// Gets the certificate name in Key Vault.
    /// </summary>
    public string Name => CertificateName;

    /// <summary>
    /// Gets the current certificate version being used.
    /// </summary>
    public string Version => GetRequiredState().Version;

    /// <summary>
    /// Gets whether this source is using a pinned certificate version (no auto-refresh).
    /// </summary>
    public bool IsPinnedVersion => PinnedVersion != null;

    /// <summary>
    /// Gets the refresh interval, or null if auto-refresh is disabled.
    /// </summary>
    public TimeSpan? AutoRefreshInterval => RefreshInterval;

    /// <summary>
    /// Gets the key access mode (Remote for HSM/non-exportable, Local for exportable).
    /// </summary>
    public KeyVaultCertificateKeyMode KeyMode => GetRequiredState().KeyMode;

    /// <summary>
    /// Gets whether this certificate requires remote signing.
    /// </summary>
    public bool RequiresRemoteSigning => GetRequiredState().KeyMode == KeyVaultCertificateKeyMode.Remote;

    /// <summary>
    /// Gets whether the backing Key Vault key is HSM-protected.
    /// Returns false for local/exportable mode.
    /// </summary>
    public bool IsHsmProtected => GetRequiredState().CryptoWrapper?.IsHsmProtected ?? false;

    /// <summary>
    /// Creates a new Azure Key Vault certificate source.
    /// Call <see cref="InitializeAsync"/> before use.
    /// </summary>
    /// <param name="clientFactory">Factory providing Key Vault SDK clients.</param>
    /// <param name="certificateName">The name of the certificate in Key Vault.</param>
    /// <param name="certificateVersion">Optional pinned certificate version. When set, auto-refresh is disabled.</param>
    /// <param name="refreshInterval">Optional auto-refresh interval. Default is 15 minutes when not pinned.</param>
    /// <param name="forceRemoteMode">If true, always use remote signing even if the key is exportable.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="clientFactory"/> or <paramref name="certificateName"/> is null.</exception>
    public AzureKeyVaultCertificateSource(
        IKeyVaultClientFactory clientFactory,
        string certificateName,
        string? certificateVersion = null,
        TimeSpan? refreshInterval = null,
        bool forceRemoteMode = false)
    {
        Guard.ThrowIfNull(clientFactory);
        Guard.ThrowIfNull(certificateName);

        ClientFactory = clientFactory;
        CertificateClient = clientFactory.CertificateClient;
        SecretClient = clientFactory.SecretClient;
        KeyClient = clientFactory.KeyClient;

        CertificateName = certificateName;
        PinnedVersion = certificateVersion;
        ForceRemoteMode = forceRemoteMode;

        RefreshInterval = certificateVersion != null
            ? null
            : (refreshInterval ?? TimeSpan.FromMinutes(15));
    }

    /// <summary>
    /// Initializes the instance by loading the certificate and (optionally) starting auto-refresh.
    /// Safe to call multiple times.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task that represents the asynchronous initialization operation.</returns>
    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        if (Current != null)
        {
            return;
        }

        await InitGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (Current != null)
            {
                return;
            }

            var state = await LoadStateAsync(PinnedVersion, cancellationToken).ConfigureAwait(false);

            await UseGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                Current = state;
            }
            finally
            {
                UseGate.Release();
            }

            if (RefreshInterval.HasValue)
            {
                RefreshTimer?.Dispose();
                RefreshTimer = new Timer(OnRefreshTimerTick, null, RefreshInterval.Value, RefreshInterval.Value);
            }
        }
        finally
        {
            InitGate.Release();
        }
    }

    /// <inheritdoc/>
    public override X509Certificate2 GetSigningCertificate()
    {
        ThrowIfDisposed();
        return GetRequiredState().Certificate;
    }

    #region RSA Signing

    /// <inheritdoc/>
    /// <exception cref="InvalidOperationException">Thrown when the certificate does not have the required private key for signing.</exception>
    /// <exception cref="InvalidOperationException">Thrown when remote signing is required but the cryptography client wrapper is unavailable.</exception>
    public override byte[] SignDataWithRsa(byte[] data, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        ThrowIfDisposed();
        UseGate.Wait();
        try
        {
            var state = GetRequiredState();
            if (state.KeyMode == KeyVaultCertificateKeyMode.Local)
            {
                using var rsa = state.Certificate.GetRSAPrivateKey()
                    ?? throw new InvalidOperationException(ClassStrings.ErrorCertificateDoesNotHaveRsaPrivateKey);
                return rsa.SignData(data, hashAlgorithm, padding);
            }

            var wrapper = state.CryptoWrapper
                ?? throw new InvalidOperationException(ClassStrings.ErrorRemoteSigningRequiresCryptographyClientWrapper);
            return wrapper.SignDataWithRsa(data, hashAlgorithm, padding);
        }
        finally
        {
            UseGate.Release();
        }
    }

    /// <inheritdoc/>
    /// <exception cref="InvalidOperationException">Thrown when the certificate does not have the required private key for signing.</exception>
    /// <exception cref="InvalidOperationException">Thrown when remote signing is required but the cryptography client wrapper is unavailable.</exception>
    public override async Task<byte[]> SignDataWithRsaAsync(
        byte[] data,
        HashAlgorithmName hashAlgorithm,
        RSASignaturePadding padding,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        await UseGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var state = GetRequiredState();
            if (state.KeyMode == KeyVaultCertificateKeyMode.Local)
            {
                using var rsa = state.Certificate.GetRSAPrivateKey()
                    ?? throw new InvalidOperationException(ClassStrings.ErrorCertificateDoesNotHaveRsaPrivateKey);
                return rsa.SignData(data, hashAlgorithm, padding);
            }

            var wrapper = state.CryptoWrapper
                ?? throw new InvalidOperationException(ClassStrings.ErrorRemoteSigningRequiresCryptographyClientWrapper);
            return await wrapper.SignDataWithRsaAsync(data, hashAlgorithm, padding, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            UseGate.Release();
        }
    }

    /// <inheritdoc/>
    /// <exception cref="InvalidOperationException">Thrown when the certificate does not have the required private key for signing.</exception>
    /// <exception cref="InvalidOperationException">Thrown when remote signing is required but the cryptography client wrapper is unavailable.</exception>
    public override byte[] SignHashWithRsa(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        ThrowIfDisposed();
        UseGate.Wait();
        try
        {
            var state = GetRequiredState();
            if (state.KeyMode == KeyVaultCertificateKeyMode.Local)
            {
                using var rsa = state.Certificate.GetRSAPrivateKey()
                    ?? throw new InvalidOperationException(ClassStrings.ErrorCertificateDoesNotHaveRsaPrivateKey);
                return rsa.SignHash(hash, hashAlgorithm, padding);
            }

            var wrapper = state.CryptoWrapper
                ?? throw new InvalidOperationException(ClassStrings.ErrorRemoteSigningRequiresCryptographyClientWrapper);
            return wrapper.SignHashWithRsa(hash, hashAlgorithm, padding);
        }
        finally
        {
            UseGate.Release();
        }
    }

    /// <inheritdoc/>
    /// <exception cref="InvalidOperationException">Thrown when the certificate does not have the required private key for signing.</exception>
    /// <exception cref="InvalidOperationException">Thrown when remote signing is required but the cryptography client wrapper is unavailable.</exception>
    public override async Task<byte[]> SignHashWithRsaAsync(
        byte[] hash,
        HashAlgorithmName hashAlgorithm,
        RSASignaturePadding padding,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        await UseGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var state = GetRequiredState();
            if (state.KeyMode == KeyVaultCertificateKeyMode.Local)
            {
                using var rsa = state.Certificate.GetRSAPrivateKey()
                    ?? throw new InvalidOperationException(ClassStrings.ErrorCertificateDoesNotHaveRsaPrivateKey);
                return rsa.SignHash(hash, hashAlgorithm, padding);
            }

            var wrapper = state.CryptoWrapper
                ?? throw new InvalidOperationException(ClassStrings.ErrorRemoteSigningRequiresCryptographyClientWrapper);
            return await wrapper.SignHashWithRsaAsync(hash, hashAlgorithm, padding, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            UseGate.Release();
        }
    }

    #endregion

    #region ECDSA Signing

    /// <inheritdoc/>
    /// <exception cref="InvalidOperationException">Thrown when the certificate does not have the required private key for signing.</exception>
    /// <exception cref="InvalidOperationException">Thrown when remote signing is required but the cryptography client wrapper is unavailable.</exception>
    public override byte[] SignDataWithEcdsa(byte[] data, HashAlgorithmName hashAlgorithm)
    {
        ThrowIfDisposed();
        UseGate.Wait();
        try
        {
            var state = GetRequiredState();
            if (state.KeyMode == KeyVaultCertificateKeyMode.Local)
            {
                using var ecdsa = state.Certificate.GetECDsaPrivateKey()
                    ?? throw new InvalidOperationException(ClassStrings.ErrorCertificateDoesNotHaveEcdsaPrivateKey);
                return ecdsa.SignData(data, hashAlgorithm);
            }

            var wrapper = state.CryptoWrapper
                ?? throw new InvalidOperationException(ClassStrings.ErrorRemoteSigningRequiresCryptographyClientWrapper);
            return wrapper.SignDataWithEcdsa(data, hashAlgorithm);
        }
        finally
        {
            UseGate.Release();
        }
    }

    /// <inheritdoc/>
    /// <exception cref="InvalidOperationException">Thrown when the certificate does not have the required private key for signing.</exception>
    /// <exception cref="InvalidOperationException">Thrown when remote signing is required but the cryptography client wrapper is unavailable.</exception>
    public override async Task<byte[]> SignDataWithEcdsaAsync(
        byte[] data,
        HashAlgorithmName hashAlgorithm,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        await UseGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var state = GetRequiredState();
            if (state.KeyMode == KeyVaultCertificateKeyMode.Local)
            {
                using var ecdsa = state.Certificate.GetECDsaPrivateKey()
                    ?? throw new InvalidOperationException(ClassStrings.ErrorCertificateDoesNotHaveEcdsaPrivateKey);
                return ecdsa.SignData(data, hashAlgorithm);
            }

            var wrapper = state.CryptoWrapper
                ?? throw new InvalidOperationException(ClassStrings.ErrorRemoteSigningRequiresCryptographyClientWrapper);
            return await wrapper.SignDataWithEcdsaAsync(data, hashAlgorithm, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            UseGate.Release();
        }
    }

    /// <inheritdoc/>
    /// <exception cref="InvalidOperationException">Thrown when the certificate does not have the required private key for signing.</exception>
    /// <exception cref="InvalidOperationException">Thrown when remote signing is required but the cryptography client wrapper is unavailable.</exception>
    public override byte[] SignHashWithEcdsa(byte[] hash)
    {
        ThrowIfDisposed();
        UseGate.Wait();
        try
        {
            var state = GetRequiredState();
            if (state.KeyMode == KeyVaultCertificateKeyMode.Local)
            {
                using var ecdsa = state.Certificate.GetECDsaPrivateKey()
                    ?? throw new InvalidOperationException(ClassStrings.ErrorCertificateDoesNotHaveEcdsaPrivateKey);
                return ecdsa.SignHash(hash);
            }

            var wrapper = state.CryptoWrapper
                ?? throw new InvalidOperationException(ClassStrings.ErrorRemoteSigningRequiresCryptographyClientWrapper);
            return wrapper.SignHashWithEcdsa(hash);
        }
        finally
        {
            UseGate.Release();
        }
    }

    /// <inheritdoc/>
    /// <exception cref="InvalidOperationException">Thrown when the certificate does not have the required private key for signing.</exception>
    /// <exception cref="InvalidOperationException">Thrown when remote signing is required but the cryptography client wrapper is unavailable.</exception>
    public override async Task<byte[]> SignHashWithEcdsaAsync(byte[] hash, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        await UseGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var state = GetRequiredState();
            if (state.KeyMode == KeyVaultCertificateKeyMode.Local)
            {
                using var ecdsa = state.Certificate.GetECDsaPrivateKey()
                    ?? throw new InvalidOperationException(ClassStrings.ErrorCertificateDoesNotHaveEcdsaPrivateKey);
                return ecdsa.SignHash(hash);
            }

            var wrapper = state.CryptoWrapper
                ?? throw new InvalidOperationException(ClassStrings.ErrorRemoteSigningRequiresCryptographyClientWrapper);
            return await wrapper.SignHashWithEcdsaAsync(hash, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            UseGate.Release();
        }
    }

    #endregion

    #region ML-DSA Signing (Post-Quantum)

    /// <inheritdoc/>
    /// <exception cref="NotSupportedException">Always thrown because ML-DSA signing is not supported.</exception>
    public override byte[] SignDataWithMLDsa(byte[] data, HashAlgorithmName? hashAlgorithm = null)
    {
        throw new NotSupportedException(ClassStrings.ErrorAzureKeyVaultDoesNotSupportMldsaSigning);
    }

    /// <inheritdoc/>
    /// <exception cref="NotSupportedException">Always thrown because ML-DSA signing is not supported.</exception>
    public override Task<byte[]> SignDataWithMLDsaAsync(
        byte[] data,
        HashAlgorithmName? hashAlgorithm = null,
        CancellationToken cancellationToken = default)
    {
        throw new NotSupportedException(ClassStrings.ErrorAzureKeyVaultDoesNotSupportMldsaSigning);
    }

    #endregion

    #region Refresh

    /// <summary>
    /// Manually triggers a refresh check.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>True if the certificate changed and was reloaded.</returns>
    /// <exception cref="InvalidOperationException">Thrown when a pinned certificate version is in use.</exception>
    public async Task<bool> RefreshCertificateAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        if (PinnedVersion != null)
        {
            throw new InvalidOperationException(ClassStrings.ErrorCannotRefreshPinnedCertificateVersion);
        }

        await EnsureInitializedAsync(cancellationToken).ConfigureAwait(false);
        return await TryRefreshCertificateAsync(cancellationToken).ConfigureAwait(false);
    }


    private void OnRefreshTimerTick(object? state)
    {
        _ = TryRefreshFromTimerAsync();
    }

    private async Task TryRefreshFromTimerAsync()
    {
        try
        {
            if (PinnedVersion != null)
            {
                return;
            }

            await EnsureInitializedAsync(CancellationToken.None).ConfigureAwait(false);
            await TryRefreshCertificateAsync(CancellationToken.None).ConfigureAwait(false);
        }
        catch
        {
            // Background refresh should not throw.
        }
    }

    private async Task<bool> TryRefreshCertificateAsync(CancellationToken cancellationToken)
    {
        if (Interlocked.Exchange(ref RefreshInProgress, 1) == 1)
        {
            return false;
        }

        try
        {
            var latest = await CertificateClient.GetCertificateAsync(CertificateName, cancellationToken).ConfigureAwait(false);
            var latestVersion = latest.Value.Properties.Version;
            if (string.IsNullOrEmpty(latestVersion))
            {
                return false;
            }

            var currentVersion = GetRequiredState().Version;
            if (string.Equals(currentVersion, latestVersion, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            var newState = await LoadStateAsync(requestedVersion: null, cancellationToken).ConfigureAwait(false);

            await UseGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var existing = Current;
                if (existing == null)
                {
                    Current = newState;
                    return true;
                }

                if (string.Equals(existing.Version, newState.Version, StringComparison.OrdinalIgnoreCase))
                {
                    newState.Certificate.Dispose();
                    newState.CryptoWrapper?.Dispose();
                    return false;
                }

                Current = newState;
                existing.Certificate.Dispose();
                existing.CryptoWrapper?.Dispose();
                return true;
            }
            finally
            {
                UseGate.Release();
            }
        }
        finally
        {
            Interlocked.Exchange(ref RefreshInProgress, 0);
        }
    }

    #endregion

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if (!disposing)
        {
            return;
        }

        if (Disposed)
        {
            return;
        }

        Disposed = true;

        RefreshTimer?.Dispose();
        RefreshTimer = null;

        InitGate.Dispose();
        UseGate.Dispose();

        var state = Current;
        Current = null;
        state?.Certificate.Dispose();
        state?.CryptoWrapper?.Dispose();

        base.Dispose(disposing);
    }

    private async Task EnsureInitializedAsync(CancellationToken cancellationToken)
    {
        if (Current != null)
        {
            return;
        }

        await InitializeAsync(cancellationToken).ConfigureAwait(false);
    }

    private State GetRequiredState()
    {
        var state = Current;
        if (state == null)
        {
            throw new InvalidOperationException(ClassStrings.ErrorNotInitializedCallInitializeAsyncBeforeUse);
        }

        return state;
    }

    private async Task<State> LoadStateAsync(string? requestedVersion, CancellationToken cancellationToken)
    {
        var certWithPolicy = await CertificateClient.GetCertificateAsync(CertificateName, cancellationToken).ConfigureAwait(false);
        var version = requestedVersion ?? certWithPolicy.Value.Properties.Version;
        if (string.IsNullOrEmpty(version))
        {
            throw new InvalidOperationException(ClassStrings.ErrorKeyVaultReturnedCertificateWithoutVersion);
        }

        var exportable = certWithPolicy.Value.Policy?.Exportable ?? false;
        var keyMode = (exportable && !ForceRemoteMode)
            ? KeyVaultCertificateKeyMode.Local
            : KeyVaultCertificateKeyMode.Remote;

        if (keyMode == KeyVaultCertificateKeyMode.Local)
        {
            var cert = await DownloadCertificateWithPrivateKeyAsync(version, cancellationToken).ConfigureAwait(false);
            return new State(cert, version, keyMode, cryptoWrapper: null);
        }

        var certBytes = await DownloadPublicCertificateBytesAsync(requestedVersion, version, certWithPolicy.Value, cancellationToken).ConfigureAwait(false);
        var publicCert = X509CertificateLoader.LoadCertificate(certBytes);

        var key = await KeyClient.GetKeyAsync(CertificateName, version, cancellationToken).ConfigureAwait(false);
        var cryptoClient = ClientFactory.CreateCryptographyClient(key.Value.Id);
        var wrapper = new KeyVaultCryptoClientWrapper(key.Value, cryptoClient);

        return new State(publicCert, version, keyMode, wrapper);
    }

    private async Task<byte[]> DownloadPublicCertificateBytesAsync(
        string? requestedVersion,
        string resolvedVersion,
        KeyVaultCertificateWithPolicy currentCertificate,
        CancellationToken cancellationToken)
    {
        byte[]? bytes;
        if (requestedVersion == null)
        {
            bytes = currentCertificate.Cer;
        }
        else
        {
            var versionResponse = await CertificateClient
                .GetCertificateVersionAsync(CertificateName, resolvedVersion, cancellationToken)
                .ConfigureAwait(false);
            bytes = versionResponse.Value.Cer;
        }

        if (bytes == null || bytes.Length == 0)
        {
            throw new InvalidOperationException(ClassStrings.ErrorCertificateDataFromKeyVaultInvalid);
        }

        return bytes;
    }

    private async Task<X509Certificate2> DownloadCertificateWithPrivateKeyAsync(string version, CancellationToken cancellationToken)
    {
        var secretResponse = await SecretClient
            .GetSecretAsync(CertificateName, version, cancellationToken)
            .ConfigureAwait(false);

        var secret = secretResponse.Value;
        var contentType = secret.Properties.ContentType;
        var value = secret.Value;

        X509Certificate2 cert;
        if (string.Equals(contentType, ClassStrings.ContentTypePkcs12, StringComparison.OrdinalIgnoreCase))
        {
            cert = X509CertificateLoader.LoadPkcs12(
                Convert.FromBase64String(value),
                password: null,
                X509KeyStorageFlags.Exportable);
        }
        else if (string.Equals(contentType, ClassStrings.ContentTypePemFile, StringComparison.OrdinalIgnoreCase))
        {
            cert = CreateCertificateFromPem(value);
        }
        else
        {
            try
            {
                cert = X509CertificateLoader.LoadPkcs12(
                    Convert.FromBase64String(value),
                    password: null,
                    X509KeyStorageFlags.Exportable);
            }
            catch
            {
                cert = CreateCertificateFromPem(value);
            }
        }

        if (!cert.HasPrivateKey)
        {
            cert.Dispose();
            throw new InvalidOperationException(ClassStrings.ErrorKeyVaultSecretDidNotContainCertificateWithPrivateKey);
        }

        return cert;
    }

    /// <summary>
    /// Creates an X509Certificate2 from PEM-encoded data.
    /// Uses the native API on .NET 5+ and a polyfill implementation on netstandard2.0.
    /// </summary>
    /// <param name="pem">The PEM-encoded certificate (and optionally key) data.</param>
    /// <returns>An X509Certificate2 instance.</returns>
    private static X509Certificate2 CreateCertificateFromPem(string pem)
    {
#if NET5_0_OR_GREATER
        return X509Certificate2.CreateFromPem(pem);
#else
        // For netstandard2.0, we need to extract the certificate from PEM format
        // This handles the case where the PEM contains just a certificate (no private key)
        var startIndex = pem.IndexOf(ClassStrings.PemCertificateHeader, StringComparison.Ordinal);
        if (startIndex < 0)
        {
            throw new ArgumentException(ClassStrings.ErrorInvalidPemFormat, nameof(pem));
        }

        var endIndex = pem.IndexOf(ClassStrings.PemCertificateFooter, startIndex, StringComparison.Ordinal);
        if (endIndex < 0)
        {
            throw new ArgumentException(ClassStrings.ErrorInvalidPemFormat, nameof(pem));
        }

        var base64Start = startIndex + ClassStrings.PemCertificateHeader.Length;
        var base64Builder = new System.Text.StringBuilder();
        for (int i = base64Start; i < endIndex; i++)
        {
            char c = pem[i];
            if (c != '\r' && c != '\n' && c != ' ')
            {
                base64Builder.Append(c);
            }
        }

        var certBytes = Convert.FromBase64String(base64Builder.ToString());
        return new X509Certificate2(certBytes);
#endif
    }

    private void ThrowIfDisposed()
    {
        Guard.ThrowIfDisposed(Disposed, this);
    }
}
