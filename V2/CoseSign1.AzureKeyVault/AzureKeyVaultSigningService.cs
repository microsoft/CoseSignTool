// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using Azure.Core;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Azure.Security.KeyVault.Secrets;
using CoseSign1.Abstractions;
using CoseSign1.AzureKeyVault.Common;

namespace CoseSign1.AzureKeyVault;

/// <summary>
/// An <see cref="ISigningService{TSigningOptions}"/> implementation for Azure Key Vault keys (non-certificate).
/// Signs using Key Vault keys directly without X.509 certificate chain embedding.
/// </summary>
/// <remarks>
/// <para>
/// This service is for signing with standalone Key Vault keys that don't have associated certificates.
/// The signature includes a <c>kid</c> (Key ID) header per RFC 9052 to identify the signing key.
/// </para>
/// <para>
/// For certificate-based signing with X.509 chain embedding, use
/// <c>AzureKeyVaultCertificateSource</c> from <c>CoseSign1.Certificates.AzureKeyVault</c> with
/// <c>RemoteCertificateSigningService</c> instead.
/// </para>
/// <para>
/// <strong>Key Identification Headers (RFC 9052 Section 3.1):</strong>
/// <list type="bullet">
/// <item><description><c>kid</c> (header 4): Key Vault key URI identifying the exact key version</description></item>
/// <item><description><c>alg</c> (header 1): COSE algorithm identifier (automatically set)</description></item>
/// </list>
/// </para>
/// </remarks>
/// <example>
/// <code>
/// // Create the signing service
/// var service = await AzureKeyVaultSigningService.CreateAsync(
///     new Uri("https://myvault.vault.azure.net"),
///     "my-signing-key",
///     new DefaultAzureCredential());
/// 
/// // Sign a message
/// var context = new SigningContext(payload, "application/json");
/// var signer = service.GetCoseSigner(context);
/// var signature = CoseSign1Message.SignDetached(payload, signer);
/// </code>
/// </example>
public sealed class AzureKeyVaultSigningService : ISigningService<SigningOptions>, IDisposable
{
    private readonly string KeyName;
    private readonly string? PinnedVersion;
    private readonly TimeSpan? RefreshInterval;
    private readonly IKeyVaultClientFactory ClientFactory;
    private readonly SemaphoreSlim InitGate = new(1, 1);
    private readonly SemaphoreSlim UseGate = new(1, 1);
    private Timer? RefreshTimer;
    private int RefreshInProgress;

    private SigningServiceMetadata? ServiceMetadataField;

    private KeyVaultCryptoClientWrapper? CryptoWrapper;
    private AzureKeyVaultSigningKey? SigningKey;
    private KeyIdHeaderContributor? KeyIdContributor;
    private CoseKeyHeaderContributor? PublicKeyContributor;
    private string? CurrentVersion;
    private bool Disposed;

    /// <summary>
    /// Gets the Key Vault URI.
    /// </summary>
    public Uri VaultUri => ClientFactory.VaultUri;

    /// <summary>
    /// Gets the key name in Key Vault.
    /// </summary>
    public string Name => KeyName;

    /// <summary>
    /// Gets the current key version being used.
    /// </summary>
    public string Version => GetRequiredState().Version;

    /// <summary>
    /// Gets whether this service is using a pinned key version (no auto-refresh).
    /// </summary>
    public bool IsPinnedVersion => PinnedVersion != null;

    /// <summary>
    /// Gets the auto-refresh interval if enabled.
    /// </summary>
    public TimeSpan? AutoRefreshInterval => IsPinnedVersion ? null : RefreshInterval;

    /// <summary>
    /// Gets the Key ID (kid) that will be included in signatures.
    /// This is the full Key Vault key URI.
    /// </summary>
    public string KeyId => GetRequiredState().CryptoWrapper.KeyId;

    /// <summary>
    /// Gets the type of the key (RSA, EC, etc.).
    /// </summary>
    public string KeyType => GetRequiredState().CryptoWrapper.KeyType.ToString();

    /// <summary>
    /// Gets whether the key is HSM-protected.
    /// </summary>
    public bool IsHsmProtected => GetRequiredState().CryptoWrapper.IsHsmProtected;

    /// <summary>
    /// Gets the header contributor that adds the Key ID (kid) header to signatures.
    /// This can be used to add the same kid header to other signing operations.
    /// </summary>
    public KeyIdHeaderContributor HeaderContributor => GetRequiredState().KeyIdContributor;

    /// <summary>
    /// Gets a header contributor that embeds the public key as a COSE_Key structure.
    /// This enables self-contained verification without fetching the key from Key Vault.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The public key is encoded as a COSE_Key per RFC 9052 Section 7 and placed in a
    /// private-use header label (-65537). This is allowed by RFC 9052 for application-specific headers.
    /// </para>
    /// <para>
    /// By default, the public key is placed in unprotected headers since the signature
    /// already cryptographically binds the public key. Set <see cref="CoseKeyHeaderContributor.UseProtectedHeader"/>
    /// to true if you need the public key in protected headers.
    /// </para>
    /// </remarks>
    public CoseKeyHeaderContributor PublicKeyHeaderContributor
    {
        get
        {
            ThrowIfDisposed();
            if (PublicKeyContributor == null)
            {
                PublicKeyContributor = CreatePublicKeyContributor();
            }
            return PublicKeyContributor;
        }
    }

    /// <inheritdoc/>
    public bool IsRemote => true;

    /// <inheritdoc/>
    public SigningServiceMetadata ServiceMetadata => ServiceMetadataField ?? throw new InvalidOperationException(
        "AzureKeyVaultSigningService has not been initialized. Call InitializeAsync() before use.");

    /// <summary>
    /// Creates a new Azure Key Vault signing service.
    /// Call <see cref="InitializeAsync"/> before use.
    /// </summary>
    /// <param name="clientFactory">Factory providing Key Vault SDK clients.</param>
    /// <param name="keyName">The name of the key in Key Vault.</param>
    /// <param name="keyVersion">Optional pinned key version. When set, auto-refresh is disabled.</param>
    /// <param name="refreshInterval">Optional auto-refresh interval. Use null to disable.</param>
    public AzureKeyVaultSigningService(
        IKeyVaultClientFactory clientFactory,
        string keyName,
        string? keyVersion = null,
        TimeSpan? refreshInterval = null)
    {
        ArgumentNullException.ThrowIfNull(clientFactory);
        ArgumentNullException.ThrowIfNull(keyName);

        ClientFactory = clientFactory;
        KeyName = keyName;
        PinnedVersion = keyVersion;
        RefreshInterval = keyVersion != null ? null : refreshInterval;
    }

    /// <summary>
    /// Creates a new Azure Key Vault signing service asynchronously.
    /// </summary>
    /// <param name="vaultUri">The URI of the Key Vault (e.g., https://myvault.vault.azure.net).</param>
    /// <param name="keyName">The name of the key in Key Vault.</param>
    /// <param name="credential">The Azure credential for authentication.</param>
    /// <param name="keyVersion">
    /// Optional specific key version. If provided, auto-refresh is disabled and this exact
    /// version will always be used. If null, the latest version is retrieved.
    /// </param>
    /// <param name="refreshInterval">
    /// Optional interval for auto-refreshing the key. If null, auto-refresh is disabled.
    /// Ignored if <paramref name="keyVersion"/> is specified.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A configured AzureKeyVaultSigningService ready for signing.</returns>
    public static async Task<AzureKeyVaultSigningService> CreateAsync(
        Uri vaultUri,
        string keyName,
        TokenCredential credential,
        string? keyVersion = null,
        TimeSpan? refreshInterval = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(vaultUri);
        ArgumentNullException.ThrowIfNull(keyName);
        ArgumentNullException.ThrowIfNull(credential);

        var factory = new KeyVaultClientFactory(vaultUri, credential);
        var service = new AzureKeyVaultSigningService(factory, keyName, keyVersion, refreshInterval);
        await service.InitializeAsync(cancellationToken).ConfigureAwait(false);
        return service;
    }

    /// <summary>
    /// Creates a new Azure Key Vault signing service with pre-created dependencies.
    /// </summary>
    /// <remarks>
    /// This factory method enables dependency injection for testing scenarios.
    /// For production use, prefer the <see cref="CreateAsync"/> method.
    /// </remarks>
    public static AzureKeyVaultSigningService Create(
        Uri vaultUri,
        KeyClient keyClient,
        TokenCredential credential,
        KeyVaultCryptoClientWrapper cryptoWrapper,
        string? pinnedVersion = null,
        TimeSpan? refreshInterval = null)
    {
        ArgumentNullException.ThrowIfNull(vaultUri);
        ArgumentNullException.ThrowIfNull(keyClient);
        ArgumentNullException.ThrowIfNull(credential);
        ArgumentNullException.ThrowIfNull(cryptoWrapper);

        var factory = new FixedKeyVaultClientFactory(vaultUri, credential, keyClient);
        var service = new AzureKeyVaultSigningService(factory, cryptoWrapper.Name, pinnedVersion, refreshInterval);
        service.SetCurrentState(cryptoWrapper);
        service.StartAutoRefreshIfEnabled();
        return service;
    }

    /// <summary>
    /// Initializes the instance by loading the key and (optionally) starting auto-refresh.
    /// Safe to call multiple times.
    /// </summary>
    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        if (CryptoWrapper != null)
        {
            return;
        }

        await InitGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (CryptoWrapper != null)
            {
                return;
            }

            var wrapper = await LoadWrapperAsync(PinnedVersion, cancellationToken).ConfigureAwait(false);

            await UseGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                SetCurrentState(wrapper);
            }
            finally
            {
                UseGate.Release();
            }

            StartAutoRefreshIfEnabled();
        }
        finally
        {
            InitGate.Release();
        }
    }

    /// <inheritdoc/>
    public CoseSigner GetCoseSigner(SigningContext context)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(context);

        var state = GetRequiredState();
        var coseKey = state.SigningKey.GetCoseKey();

        // Build protected headers
        var protectedHeaders = new CoseHeaderMap();
        var unprotectedHeaders = new CoseHeaderMap();

        // Create contributor context for header contributors
        var contributorContext = new HeaderContributorContext(context, state.SigningKey);

        // Add kid (Key ID) header using our header contributor
        // This ensures the Azure Key Vault key URI is embedded for verification
        state.KeyIdContributor.ContributeProtectedHeaders(protectedHeaders, contributorContext);

        // Add content type if specified
        if (!string.IsNullOrEmpty(context.ContentType))
        {
            protectedHeaders.Add(CoseHeaderLabel.ContentType, CoseHeaderValue.FromString(context.ContentType));
        }

        // Apply any additional header contributors from context
        if (context.AdditionalHeaderContributors != null)
        {
            foreach (var contributor in context.AdditionalHeaderContributors)
            {
                contributor.ContributeProtectedHeaders(protectedHeaders, contributorContext);
                contributor.ContributeUnprotectedHeaders(unprotectedHeaders, contributorContext);
            }
        }

        return new CoseSigner(
            coseKey,
            protectedHeaders: protectedHeaders,
            unprotectedHeaders: unprotectedHeaders.Count > 0 ? unprotectedHeaders : null);
    }

    /// <inheritdoc/>
    public SigningOptions CreateSigningOptions()
    {
        return new SigningOptions();
    }

    /// <summary>
    /// Manually triggers a key refresh check.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>True if the key was updated, false if it was already current.</returns>
    /// <exception cref="InvalidOperationException">Thrown if using a pinned version.</exception>
    public async Task<bool> RefreshKeyAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        if (PinnedVersion != null)
        {
            throw new InvalidOperationException("Cannot refresh a pinned key version.");
        }

        await EnsureInitializedAsync(cancellationToken).ConfigureAwait(false);
        return await TryRefreshKeyAsync(cancellationToken).ConfigureAwait(false);
    }

    private void OnRefreshTimerCallback(object? state)
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
            await TryRefreshKeyAsync(CancellationToken.None).ConfigureAwait(false);
        }
        catch
        {
            // Swallow exceptions during background refresh
        }
    }

    private async Task<bool> TryRefreshKeyAsync(CancellationToken cancellationToken)
    {
        if (Interlocked.Exchange(ref RefreshInProgress, 1) == 1)
        {
            return false;
        }

        try
        {
            var existing = GetRequiredState();
            var newWrapper = await LoadWrapperAsync(requestedVersion: null, cancellationToken).ConfigureAwait(false);
            var latestVersion = newWrapper.Version;

            if (string.Equals(latestVersion, existing.Version, StringComparison.OrdinalIgnoreCase))
            {
                newWrapper.Dispose();
                return false;
            }

            await UseGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var current = GetRequiredState();

                if (string.Equals(current.Version, latestVersion, StringComparison.OrdinalIgnoreCase))
                {
                    newWrapper.Dispose();
                    return false;
                }

                var oldSigningKey = current.SigningKey;
                SetCurrentState(newWrapper);
                PublicKeyContributor = null;
                oldSigningKey.Dispose();
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

    /// <inheritdoc/>
    public void Dispose()
    {
        if (Disposed)
        {
            return;
        }

        RefreshTimer?.Dispose();
        RefreshTimer = null;

        InitGate.Dispose();
        UseGate.Dispose();

        SigningKey?.Dispose();
        SigningKey = null;
        CryptoWrapper = null;
        KeyIdContributor = null;
        PublicKeyContributor = null;
        ServiceMetadataField = null;
        Disposed = true;
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(Disposed, this);
    }

    private sealed class State
    {
        public required KeyVaultCryptoClientWrapper CryptoWrapper { get; init; }
        public required AzureKeyVaultSigningKey SigningKey { get; init; }
        public required KeyIdHeaderContributor KeyIdContributor { get; init; }
        public required string Version { get; init; }
    }

    private State GetRequiredState()
    {
        var wrapper = CryptoWrapper;
        var signingKey = SigningKey;
        var keyIdContributor = KeyIdContributor;
        var version = CurrentVersion;

        if (wrapper == null || signingKey == null || keyIdContributor == null || string.IsNullOrEmpty(version))
        {
            throw new InvalidOperationException(
                "AzureKeyVaultSigningService has not been initialized. Call InitializeAsync() before use.");
        }

        return new State
        {
            CryptoWrapper = wrapper,
            SigningKey = signingKey,
            KeyIdContributor = keyIdContributor,
            Version = version
        };
    }

    private async Task EnsureInitializedAsync(CancellationToken cancellationToken)
    {
        if (CryptoWrapper != null)
        {
            return;
        }

        await InitializeAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task<KeyVaultCryptoClientWrapper> LoadWrapperAsync(string? requestedVersion, CancellationToken cancellationToken)
    {
        var response = await ClientFactory.KeyClient
            .GetKeyAsync(KeyName, requestedVersion, cancellationToken)
            .ConfigureAwait(false);

        var key = response.Value;
        var version = key.Properties.Version;
        if (string.IsNullOrEmpty(version))
        {
            throw new InvalidOperationException("Key Vault returned a key without a version.");
        }

        var cryptoClient = ClientFactory.CreateCryptographyClient(key.Id);
        return new KeyVaultCryptoClientWrapper(key, cryptoClient);
    }

    private void SetCurrentState(KeyVaultCryptoClientWrapper wrapper)
    {
        CryptoWrapper = wrapper;
        CurrentVersion = wrapper.Version;

        SigningKey = new AzureKeyVaultSigningKey(this, wrapper);
        KeyIdContributor = new KeyIdHeaderContributor(wrapper.KeyId, wrapper.IsHsmProtected);
        ServiceMetadataField = new SigningServiceMetadata(
            "AzureKeyVault",
            $"Azure Key Vault signing service using key: {wrapper.KeyId}");
    }

    private void StartAutoRefreshIfEnabled()
    {
        if (PinnedVersion != null)
        {
            return;
        }

        if (!RefreshInterval.HasValue)
        {
            return;
        }

        RefreshTimer?.Dispose();
        RefreshTimer = new Timer(
            OnRefreshTimerCallback,
            null,
            RefreshInterval.Value,
            RefreshInterval.Value);
    }

    private sealed class FixedKeyVaultClientFactory : IKeyVaultClientFactory
    {
        private readonly TokenCredential Credential;

        public Uri VaultUri { get; }

        public CertificateClient CertificateClient { get; }

        public SecretClient SecretClient { get; }

        public KeyClient KeyClient { get; }

        public FixedKeyVaultClientFactory(Uri vaultUri, TokenCredential credential, KeyClient keyClient)
        {
            ArgumentNullException.ThrowIfNull(vaultUri);
            ArgumentNullException.ThrowIfNull(credential);
            ArgumentNullException.ThrowIfNull(keyClient);

            VaultUri = vaultUri;
            Credential = credential;
            KeyClient = keyClient;

            CertificateClient = new CertificateClient(vaultUri, credential);
            SecretClient = new SecretClient(vaultUri, credential);
        }

        public CryptographyClient CreateCryptographyClient(Uri keyId)
        {
            ArgumentNullException.ThrowIfNull(keyId);
            return new CryptographyClient(keyId, Credential);
        }
    }

    /// <summary>
    /// Creates a CoseKeyHeaderContributor with the public key from the current Key Vault key.
    /// </summary>
    private CoseKeyHeaderContributor CreatePublicKeyContributor()
    {
        var state = GetRequiredState();
        var key = state.CryptoWrapper.KeyVaultKey;
        var kvKeyType = state.CryptoWrapper.KeyType;
        var metadata = state.SigningKey.Metadata;
        var coseAlgorithm = metadata.CoseAlgorithmId;

        if (kvKeyType == Azure.Security.KeyVault.Keys.KeyType.Rsa ||
            kvKeyType == Azure.Security.KeyVault.Keys.KeyType.RsaHsm)
        {
            var rsaParams = new RSAParameters
            {
                Modulus = key.Key.N,
                Exponent = key.Key.E
            };
            return new CoseKeyHeaderContributor(rsaParams, coseAlgorithm, KeyId);
        }
        else if (kvKeyType == Azure.Security.KeyVault.Keys.KeyType.Ec ||
                 kvKeyType == Azure.Security.KeyVault.Keys.KeyType.EcHsm)
        {
            var curveName = key.Key.CurveName?.ToString() ?? "P-256";
            ECCurve curve = curveName switch
            {
                "P-521" => ECCurve.NamedCurves.nistP521,
                "P-384" => ECCurve.NamedCurves.nistP384,
                _ => ECCurve.NamedCurves.nistP256
            };

            var ecParams = new ECParameters
            {
                Curve = curve,
                Q = new ECPoint
                {
                    X = key.Key.X,
                    Y = key.Key.Y
                }
            };
            return new CoseKeyHeaderContributor(ecParams, coseAlgorithm, KeyId);
        }

        throw new NotSupportedException($"Key type {kvKeyType} is not supported for public key embedding.");
    }
}
