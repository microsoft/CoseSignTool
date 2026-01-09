// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.AzureKeyVault.Tests;

using System.Reflection;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;

/// <summary>
/// Tests for <see cref="AzureKeyVaultSigningService"/>.
/// Uses mocked Azure SDK clients following Azure SDK mocking guidelines.
/// </summary>
[TestFixture]
public class AzureKeyVaultSigningServiceTests
{
    private const string TestKeyName = "test-signing-key";
    private const string TestKeyVersion = "v1";
    private readonly Uri TestVaultUri = new("https://test-vault.vault.azure.net");
    private readonly Uri TestKeyId = new("https://test-vault.vault.azure.net/keys/test-signing-key/v1");

    #region CreateAsync Parameter Validation Tests

    [Test]
    public void CreateAsync_WithNullVaultUri_ThrowsArgumentNullException()
    {
        // Arrange
        var mockCredential = new Mock<TokenCredential>();

        // Act & Assert
        var ex = Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await AzureKeyVaultSigningService.CreateAsync(
                null!,
                TestKeyName,
                mockCredential.Object));

        Assert.That(ex.ParamName, Is.EqualTo("vaultUri"));
    }

    [Test]
    public void CreateAsync_WithNullKeyName_ThrowsArgumentNullException()
    {
        // Arrange
        var mockCredential = new Mock<TokenCredential>();

        // Act & Assert
        var ex = Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await AzureKeyVaultSigningService.CreateAsync(
                TestVaultUri,
                null!,
                mockCredential.Object));

        Assert.That(ex.ParamName, Is.EqualTo("keyName"));
    }

    [Test]
    public void CreateAsync_WithNullCredential_ThrowsArgumentNullException()
    {
        // Act & Assert
        var ex = Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await AzureKeyVaultSigningService.CreateAsync(
                TestVaultUri,
                TestKeyName,
                null!));

        Assert.That(ex.ParamName, Is.EqualTo("credential"));
    }

    #endregion

    #region DI / Initialization Tests

    [Test]
    public void Constructor_WithNullClientFactory_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new AzureKeyVaultSigningService(null!, TestKeyName));
    }

    [Test]
    public void GetCoseSigner_BeforeInitialize_ThrowsInvalidOperationException()
    {
        var mockFactory = CreateMockClientFactory(CreateKeyVaultRsaKey(TestKeyId, TestKeyVersion));
        using var service = new AzureKeyVaultSigningService(mockFactory.Object, TestKeyName);

        var context = new SigningContext("test"u8.ToArray(), "text/plain");
        Assert.That(() => service.GetCoseSigner(context), Throws.TypeOf<InvalidOperationException>());
    }

    [Test]
    public async Task InitializeAsync_WithFactory_LoadsKeyAndSetsProperties()
    {
        var key = CreateKeyVaultRsaKey(TestKeyId, TestKeyVersion);
        var mockFactory = CreateMockClientFactory(key);

        using var service = new AzureKeyVaultSigningService(mockFactory.Object, TestKeyName);
        await service.InitializeAsync();

        Assert.Multiple(() =>
        {
            Assert.That(service.VaultUri, Is.EqualTo(TestVaultUri));
            Assert.That(service.Name, Is.EqualTo(TestKeyName));
            Assert.That(service.Version, Is.EqualTo(TestKeyVersion));
            Assert.That(service.KeyId, Is.EqualTo(TestKeyId.ToString()));
            Assert.That(service.ServiceMetadata.ServiceName, Is.EqualTo("AzureKeyVault"));
            Assert.That(service.ServiceMetadata.Description, Does.Contain(TestKeyId.ToString()));
        });

        mockFactory.Verify(f => f.CreateCryptographyClient(It.Is<Uri>(u => u == TestKeyId)), Times.Once);
    }

    [Test]
    public async Task InitializeAsync_CalledTwice_DoesNotFetchKeyTwice()
    {
        var key = CreateKeyVaultRsaKey(TestKeyId, TestKeyVersion);
        var mockKeyClient = new Mock<KeyClient>(MockBehavior.Strict);
        var mockCryptoClient = CreateMockCryptographyClient();

        mockKeyClient
            .Setup(k => k.GetKeyAsync(TestKeyName, It.Is<string?>(v => v == null), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(key, new Mock<Response>().Object));

        var mockFactory = new Mock<CoseSign1.AzureKeyVault.Common.IKeyVaultClientFactory>(MockBehavior.Strict);
        mockFactory.SetupGet(f => f.VaultUri).Returns(TestVaultUri);
        mockFactory.SetupGet(f => f.KeyClient).Returns(mockKeyClient.Object);
        mockFactory.SetupGet(f => f.CertificateClient).Returns(new Mock<CertificateClient>().Object);
        mockFactory.SetupGet(f => f.SecretClient).Returns(new Mock<SecretClient>().Object);
        mockFactory.Setup(f => f.CreateCryptographyClient(It.IsAny<Uri>())).Returns(mockCryptoClient.Object);

        using var service = new AzureKeyVaultSigningService(mockFactory.Object, TestKeyName);
        await service.InitializeAsync();
        await service.InitializeAsync();

        mockKeyClient.Verify(
            k => k.GetKeyAsync(TestKeyName, It.Is<string?>(v => v == null), It.IsAny<CancellationToken>()),
            Times.Once);
    }

    #endregion

    #region Create (DI Factory) Parameter Validation Tests

    [Test]
    public void Create_WithNullVaultUri_ThrowsArgumentNullException()
    {
        // Arrange
        var mockKeyClient = new Mock<KeyClient>();
        var mockCredential = new Mock<TokenCredential>();
        var wrapper = CreateTestWrapper();

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() =>
            AzureKeyVaultSigningService.Create(
                null!,
                mockKeyClient.Object,
                mockCredential.Object,
                wrapper));

        Assert.That(ex.ParamName, Is.EqualTo("vaultUri"));
    }

    [Test]
    public void Create_WithNullKeyClient_ThrowsArgumentNullException()
    {
        // Arrange
        var mockCredential = new Mock<TokenCredential>();
        var wrapper = CreateTestWrapper();

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() =>
            AzureKeyVaultSigningService.Create(
                TestVaultUri,
                null!,
                mockCredential.Object,
                wrapper));

        Assert.That(ex.ParamName, Is.EqualTo("keyClient"));
    }

    [Test]
    public void Create_WithNullCredential_ThrowsArgumentNullException()
    {
        // Arrange
        var mockKeyClient = new Mock<KeyClient>();
        var wrapper = CreateTestWrapper();

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() =>
            AzureKeyVaultSigningService.Create(
                TestVaultUri,
                mockKeyClient.Object,
                null!,
                wrapper));

        Assert.That(ex.ParamName, Is.EqualTo("credential"));
    }

    [Test]
    public void Create_WithNullCryptoWrapper_ThrowsArgumentNullException()
    {
        // Arrange
        var mockKeyClient = new Mock<KeyClient>();
        var mockCredential = new Mock<TokenCredential>();

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() =>
            AzureKeyVaultSigningService.Create(
                TestVaultUri,
                mockKeyClient.Object,
                mockCredential.Object,
                null!));

        Assert.That(ex.ParamName, Is.EqualTo("cryptoWrapper"));
    }

    #endregion

    #region Service Creation and Properties Tests

    [Test]
    public void Create_WithValidParameters_ReturnsConfiguredService()
    {
        // Arrange
        var mockKeyClient = new Mock<KeyClient>();
        var mockCredential = new Mock<TokenCredential>();
        var wrapper = CreateTestWrapper();

        // Act
        using var service = AzureKeyVaultSigningService.Create(
            TestVaultUri,
            mockKeyClient.Object,
            mockCredential.Object,
            wrapper);

        // Assert
        Assert.Multiple(() =>
        {
            Assert.That(service.VaultUri, Is.EqualTo(TestVaultUri));
            Assert.That(service.Name, Is.EqualTo(TestKeyName));
            Assert.That(service.Version, Is.EqualTo(TestKeyVersion));
            Assert.That(service.IsRemote, Is.True);
            Assert.That(service.KeyId, Is.EqualTo(TestKeyId.ToString()));
        });
    }

    [Test]
    public void Create_WithPinnedVersion_SetsPinnedVersionCorrectly()
    {
        // Arrange
        var mockKeyClient = new Mock<KeyClient>();
        var mockCredential = new Mock<TokenCredential>();
        var wrapper = CreateTestWrapper();

        // Act
        using var service = AzureKeyVaultSigningService.Create(
            TestVaultUri,
            mockKeyClient.Object,
            mockCredential.Object,
            wrapper,
            pinnedVersion: "v1");

        // Assert
        Assert.Multiple(() =>
        {
            Assert.That(service.IsPinnedVersion, Is.True);
            Assert.That(service.AutoRefreshInterval, Is.Null);
        });
    }

    [Test]
    public async Task BackgroundRefresh_WhenPinned_ReturnsWithoutCallingKeyClient()
    {
        // Arrange
        var mockKeyClient = new Mock<KeyClient>(MockBehavior.Strict);
        var mockCredential = new Mock<TokenCredential>();
        var wrapper = CreateTestWrapper();

        using var service = AzureKeyVaultSigningService.Create(
            TestVaultUri,
            mockKeyClient.Object,
            mockCredential.Object,
            wrapper,
            pinnedVersion: TestKeyVersion,
            refreshInterval: TimeSpan.FromSeconds(1));

        var method = typeof(AzureKeyVaultSigningService)
            .GetMethod("TryRefreshFromTimerAsync", BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.That(method, Is.Not.Null);

        // Act & Assert
        Assert.DoesNotThrowAsync(async () => await (Task)method!.Invoke(service, null)!);
        mockKeyClient.VerifyNoOtherCalls();
    }

    [Test]
    public async Task BackgroundRefresh_WhenInitializationThrows_SwallowsException()
    {
        // Arrange
        var mockKeyClient = new Mock<KeyClient>(MockBehavior.Strict);
        var mockFactory = new Mock<CoseSign1.AzureKeyVault.Common.IKeyVaultClientFactory>(MockBehavior.Strict);
        var mockCredential = new Mock<TokenCredential>();

        mockFactory.SetupGet(f => f.VaultUri).Returns(TestVaultUri);
        mockFactory.SetupGet(f => f.KeyClient).Returns(mockKeyClient.Object);
        mockFactory.SetupGet(f => f.CertificateClient).Returns(new Mock<CertificateClient>().Object);
        mockFactory.SetupGet(f => f.SecretClient).Returns(new Mock<SecretClient>().Object);

        mockKeyClient
            .Setup(k => k.GetKeyAsync(TestKeyName, It.Is<string?>(v => v == null), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new RequestFailedException(500, "boom"));

        using var service = new AzureKeyVaultSigningService(
            mockFactory.Object,
            TestKeyName,
            keyVersion: null,
            refreshInterval: null);

        var method = typeof(AzureKeyVaultSigningService)
            .GetMethod("TryRefreshFromTimerAsync", BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.That(method, Is.Not.Null);

        // Act & Assert (should swallow)
        Assert.DoesNotThrowAsync(async () => await (Task)method!.Invoke(service, null)!);
    }

    [Test]
    public async Task TryRefreshKeyAsync_WhenRefreshAlreadyInProgress_ReturnsFalse()
    {
        // Arrange
        var key = CreateKeyVaultRsaKey(TestKeyId, TestKeyVersion);
        var mockFactory = CreateMockClientFactory(key);

        using var service = new AzureKeyVaultSigningService(mockFactory.Object, TestKeyName);
        await service.InitializeAsync();

        var field = typeof(AzureKeyVaultSigningService)
            .GetField("RefreshInProgress", BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.That(field, Is.Not.Null);
        field!.SetValue(service, 1);

        var method = typeof(AzureKeyVaultSigningService)
            .GetMethod("TryRefreshKeyAsync", BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.That(method, Is.Not.Null);

        try
        {
            // Act
            var task = (Task<bool>)method!.Invoke(service, new object[] { CancellationToken.None })!;
            var refreshed = await task;

            // Assert
            Assert.That(refreshed, Is.False);
        }
        finally
        {
            field.SetValue(service, 0);
        }
    }

    [Test]
    public void Create_WithoutPinnedVersion_AllowsRefresh()
    {
        // Arrange
        var mockKeyClient = new Mock<KeyClient>();
        var mockCredential = new Mock<TokenCredential>();
        var wrapper = CreateTestWrapper();

        // Act
        using var service = AzureKeyVaultSigningService.Create(
            TestVaultUri,
            mockKeyClient.Object,
            mockCredential.Object,
            wrapper,
            pinnedVersion: null,
            refreshInterval: TimeSpan.FromMinutes(5));

        // Assert
        Assert.Multiple(() =>
        {
            Assert.That(service.IsPinnedVersion, Is.False);
            Assert.That(service.AutoRefreshInterval, Is.EqualTo(TimeSpan.FromMinutes(5)));
        });
    }

    [Test]
    public void ServiceMetadata_ContainsAzureKeyVaultProvider()
    {
        // Arrange
        var mockKeyClient = new Mock<KeyClient>();
        var mockCredential = new Mock<TokenCredential>();
        var wrapper = CreateTestWrapper();

        // Act
        using var service = AzureKeyVaultSigningService.Create(
            TestVaultUri,
            mockKeyClient.Object,
            mockCredential.Object,
            wrapper);

        // Assert
        Assert.Multiple(() =>
        {
            Assert.That(service.ServiceMetadata.ServiceName, Is.EqualTo("AzureKeyVault"));
            Assert.That(service.ServiceMetadata.Description, Does.Contain(TestKeyId.ToString()));
        });
    }

    [Test]
    public void KeyType_ReturnsCorrectKeyType()
    {
        // Arrange - RSA key
        var mockKeyClient = new Mock<KeyClient>();
        var mockCredential = new Mock<TokenCredential>();
        var rsaWrapper = CreateTestWrapper(KeyType.Rsa);

        // Act
        using var service = AzureKeyVaultSigningService.Create(
            TestVaultUri,
            mockKeyClient.Object,
            mockCredential.Object,
            rsaWrapper);

        // Assert - KeyType returns uppercase "RSA" from KeyVaultKey.KeyType.ToString()
        Assert.That(service.KeyType, Is.EqualTo("RSA"));
    }

    [Test]
    public void IsHsmProtected_ReturnsFalseForSoftwareKey()
    {
        // Arrange
        var mockKeyClient = new Mock<KeyClient>();
        var mockCredential = new Mock<TokenCredential>();
        var wrapper = CreateTestWrapper(KeyType.Rsa);

        // Act
        using var service = AzureKeyVaultSigningService.Create(
            TestVaultUri,
            mockKeyClient.Object,
            mockCredential.Object,
            wrapper);

        // Assert
        Assert.That(service.IsHsmProtected, Is.False);
    }

    [Test]
    public void IsHsmProtected_ReturnsTrueForHsmKey()
    {
        // Arrange
        var mockKeyClient = new Mock<KeyClient>();
        var mockCredential = new Mock<TokenCredential>();
        var wrapper = CreateTestWrapper(KeyType.RsaHsm);

        // Act
        using var service = AzureKeyVaultSigningService.Create(
            TestVaultUri,
            mockKeyClient.Object,
            mockCredential.Object,
            wrapper);

        // Assert
        Assert.That(service.IsHsmProtected, Is.True);
    }

    #endregion

    #region GetCoseSigner Tests

    [Test]
    public void GetCoseSigner_WithNullContext_ThrowsArgumentNullException()
    {
        // Arrange
        var mockKeyClient = new Mock<KeyClient>();
        var mockCredential = new Mock<TokenCredential>();
        var wrapper = CreateTestWrapper();

        using var service = AzureKeyVaultSigningService.Create(
            TestVaultUri,
            mockKeyClient.Object,
            mockCredential.Object,
            wrapper);

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() => service.GetCoseSigner(null!));
        Assert.That(ex.ParamName, Is.EqualTo("context"));
    }

    [Test]
    public void GetCoseSigner_AfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        var mockKeyClient = new Mock<KeyClient>();
        var mockCredential = new Mock<TokenCredential>();
        var wrapper = CreateTestWrapper();

        var service = AzureKeyVaultSigningService.Create(
            TestVaultUri,
            mockKeyClient.Object,
            mockCredential.Object,
            wrapper);

        service.Dispose();
        var context = new SigningContext("test"u8.ToArray(), "text/plain");

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => service.GetCoseSigner(context));
    }

    #endregion

    #region CreateSigningOptions Tests

    [Test]
    public void CreateSigningOptions_ReturnsNewInstance()
    {
        // Arrange
        var mockKeyClient = new Mock<KeyClient>();
        var mockCredential = new Mock<TokenCredential>();
        var wrapper = CreateTestWrapper();

        using var service = AzureKeyVaultSigningService.Create(
            TestVaultUri,
            mockKeyClient.Object,
            mockCredential.Object,
            wrapper);

        // Act
        var options1 = service.CreateSigningOptions();
        var options2 = service.CreateSigningOptions();

        // Assert
        Assert.Multiple(() =>
        {
            Assert.That(options1, Is.Not.Null);
            Assert.That(options2, Is.Not.Null);
            Assert.That(options1, Is.Not.SameAs(options2));
        });
    }

    #endregion

    #region RefreshKeyAsync Tests

    [Test]
    public void RefreshKeyAsync_WhenPinned_ThrowsInvalidOperationException()
    {
        // Arrange
        var mockKeyClient = new Mock<KeyClient>();
        var mockCredential = new Mock<TokenCredential>();
        var wrapper = CreateTestWrapper();

        using var service = AzureKeyVaultSigningService.Create(
            TestVaultUri,
            mockKeyClient.Object,
            mockCredential.Object,
            wrapper,
            pinnedVersion: "v1");

        // Act & Assert
        Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await service.RefreshKeyAsync());
    }

    [Test]
    public async Task RefreshKeyAsync_WhenVersionUnchanged_ReturnsFalseAndKeepsState()
    {
        // Arrange
        var mockKeyClient = new Mock<KeyClient>(MockBehavior.Strict);
        var mockCredential = new Mock<TokenCredential>(MockBehavior.Strict);

        var wrapper = CreateTestWrapper();
        var currentKeyId = new Uri(TestKeyId.ToString());
        var latestKey = CreateKeyVaultRsaKey(id: currentKeyId, version: TestKeyVersion);

        mockKeyClient
            .Setup(k => k.GetKeyAsync(TestKeyName, It.Is<string?>(v => v == null), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(latestKey, new Mock<Response>().Object));

        using var service = AzureKeyVaultSigningService.Create(
            TestVaultUri,
            mockKeyClient.Object,
            mockCredential.Object,
            wrapper,
            pinnedVersion: null,
            refreshInterval: null);

        var originalVersion = service.Version;
        var originalKeyId = service.KeyId;

        // Act
        var changed = await service.RefreshKeyAsync();

        // Assert
        Assert.That(changed, Is.False);
        Assert.That(service.Version, Is.EqualTo(originalVersion));
        Assert.That(service.KeyId, Is.EqualTo(originalKeyId));
    }

    [Test]
    public async Task RefreshKeyAsync_WhenVersionChanges_ReturnsTrueAndUpdatesVersionAndContributorCache()
    {
        // Arrange
        var mockKeyClient = new Mock<KeyClient>(MockBehavior.Strict);
        var mockCredential = new Mock<TokenCredential>(MockBehavior.Strict);

        const string v2 = "v2";
        var wrapper = CreateTestWrapper();

        var keyIdV2 = new Uri($"{TestVaultUri}keys/{TestKeyName}/{v2}");
        var latestKey = CreateKeyVaultRsaKey(id: keyIdV2, version: v2);

        mockKeyClient
            .Setup(k => k.GetKeyAsync(TestKeyName, It.Is<string?>(v => v == null), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(latestKey, new Mock<Response>().Object));

        using var service = AzureKeyVaultSigningService.Create(
            TestVaultUri,
            mockKeyClient.Object,
            mockCredential.Object,
            wrapper,
            pinnedVersion: null,
            refreshInterval: null);

        var contributor1 = service.PublicKeyHeaderContributor;

        // Act
        var changed = await service.RefreshKeyAsync();

        // Assert
        Assert.That(changed, Is.True);
        Assert.That(service.Version, Is.EqualTo(v2));
        Assert.That(service.KeyId, Is.EqualTo(keyIdV2.ToString()));

        var contributor2 = service.PublicKeyHeaderContributor;
        Assert.That(contributor2, Is.Not.SameAs(contributor1));
    }

    [Test]
    public async Task RefreshKeyAsync_WhenAlreadyRefreshing_ReturnsFalse()
    {
        // Arrange
        var mockKeyClient = new Mock<KeyClient>(MockBehavior.Strict);
        var mockCredential = new Mock<TokenCredential>(MockBehavior.Strict);
        var wrapper = CreateTestWrapper();

        var enteredGetKey = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var allowGetKeyToReturn = new TaskCompletionSource<Response<KeyVaultKey>>(TaskCreationOptions.RunContinuationsAsynchronously);

        mockKeyClient
            .Setup(k => k.GetKeyAsync(TestKeyName, It.Is<string?>(v => v == null), It.IsAny<CancellationToken>()))
            .Returns(() =>
            {
                enteredGetKey.TrySetResult();
                return allowGetKeyToReturn.Task;
            });

        using var service = AzureKeyVaultSigningService.Create(
            TestVaultUri,
            mockKeyClient.Object,
            mockCredential.Object,
            wrapper,
            pinnedVersion: null,
            refreshInterval: null);

        // Act
        var refresh1 = service.RefreshKeyAsync();
        await enteredGetKey.Task;

        var refresh2 = await service.RefreshKeyAsync();

        // Let the first refresh complete
        var latestKey = CreateKeyVaultRsaKey(id: new Uri(TestKeyId.ToString()), version: TestKeyVersion);
        allowGetKeyToReturn.SetResult(Response.FromValue(latestKey, new Mock<Response>().Object));
        var refresh1Result = await refresh1;

        // Assert
        Assert.That(refresh2, Is.False);
        Assert.That(refresh1Result, Is.False);
    }

    #endregion

    private KeyVaultKey CreateKeyVaultRsaKey(Uri id, string version)
    {
        using var rsa = RSA.Create(2048);
        var jsonWebKey = new JsonWebKey(rsa, includePrivateParameters: false);

        return KeyModelFactory.KeyVaultKey(
            properties: KeyModelFactory.KeyProperties(
                id: id,
                vaultUri: TestVaultUri,
                name: TestKeyName,
                version: version),
            key: jsonWebKey);
    }

    #region HeaderContributor Tests

    [Test]
    public void HeaderContributor_ReturnsKeyIdHeaderContributor()
    {
        // Arrange
        var mockKeyClient = new Mock<KeyClient>();
        var mockCredential = new Mock<TokenCredential>();
        var wrapper = CreateTestWrapper();

        using var service = AzureKeyVaultSigningService.Create(
            TestVaultUri,
            mockKeyClient.Object,
            mockCredential.Object,
            wrapper);

        // Act
        var contributor = service.HeaderContributor;

        // Assert
        Assert.That(contributor, Is.Not.Null);
        Assert.That(contributor, Is.TypeOf<KeyIdHeaderContributor>());
    }

    [Test]
    public void PublicKeyHeaderContributor_ReturnsLazyInitializedContributor()
    {
        // Arrange
        var mockKeyClient = new Mock<KeyClient>();
        var mockCredential = new Mock<TokenCredential>();
        var wrapper = CreateTestWrapper();

        using var service = AzureKeyVaultSigningService.Create(
            TestVaultUri,
            mockKeyClient.Object,
            mockCredential.Object,
            wrapper);

        // Act
        var contributor1 = service.PublicKeyHeaderContributor;
        var contributor2 = service.PublicKeyHeaderContributor;

        // Assert
        Assert.Multiple(() =>
        {
            Assert.That(contributor1, Is.Not.Null);
            Assert.That(contributor1, Is.TypeOf<CoseKeyHeaderContributor>());
            Assert.That(contributor2, Is.SameAs(contributor1)); // Should be cached
        });
    }

    [Test]
    public void PublicKeyHeaderContributor_WithEcKey_ReturnsContributor()
    {
        // Arrange
        var mockKeyClient = new Mock<KeyClient>();
        var mockCredential = new Mock<TokenCredential>();
        var wrapper = CreateEcKeyWrapper();

        using var service = AzureKeyVaultSigningService.Create(
            TestVaultUri,
            mockKeyClient.Object,
            mockCredential.Object,
            wrapper);

        // Act
        var contributor = service.PublicKeyHeaderContributor;

        // Assert
        Assert.That(contributor, Is.Not.Null);
        Assert.That(contributor, Is.TypeOf<CoseKeyHeaderContributor>());
    }

    [Test]
    public void PublicKeyHeaderContributor_WithEcHsmKey_ReturnsContributor()
    {
        // Arrange
        var mockKeyClient = new Mock<KeyClient>();
        var mockCredential = new Mock<TokenCredential>();
        var wrapper = CreateEcHsmKeyWrapper();

        using var service = AzureKeyVaultSigningService.Create(
            TestVaultUri,
            mockKeyClient.Object,
            mockCredential.Object,
            wrapper);

        // Act
        var contributor = service.PublicKeyHeaderContributor;

        // Assert
        Assert.That(contributor, Is.Not.Null);
    }

    [Test]
    public void PublicKeyHeaderContributor_WithP384Curve_ReturnsContributor()
    {
        // Arrange
        var mockKeyClient = new Mock<KeyClient>();
        var mockCredential = new Mock<TokenCredential>();
        var wrapper = CreateEcKeyWrapper(KeyCurveName.P384);

        using var service = AzureKeyVaultSigningService.Create(
            TestVaultUri,
            mockKeyClient.Object,
            mockCredential.Object,
            wrapper);

        // Act
        var contributor = service.PublicKeyHeaderContributor;

        // Assert
        Assert.That(contributor, Is.Not.Null);
    }

    [Test]
    public void PublicKeyHeaderContributor_WithP521Curve_ReturnsContributor()
    {
        // Arrange
        var mockKeyClient = new Mock<KeyClient>();
        var mockCredential = new Mock<TokenCredential>();
        var wrapper = CreateEcKeyWrapper(KeyCurveName.P521);

        using var service = AzureKeyVaultSigningService.Create(
            TestVaultUri,
            mockKeyClient.Object,
            mockCredential.Object,
            wrapper);

        // Act
        var contributor = service.PublicKeyHeaderContributor;

        // Assert
        Assert.That(contributor, Is.Not.Null);
    }

    [Test]
    public void PublicKeyHeaderContributor_WithUnsupportedKeyType_ThrowsNotSupportedException()
    {
        // Arrange
        var mockKeyClient = new Mock<KeyClient>();
        var mockCredential = new Mock<TokenCredential>();
        var mockCryptoClient = CreateMockCryptographyClient();

        // Create a KeyVaultKey with a non-RSA/non-EC key type.
        var key = CreateMockRsaKey(2048);
        key.Key.KeyType = KeyType.Oct;
        var wrapper = new KeyVaultCryptoClientWrapper(key, mockCryptoClient.Object);

        using var service = AzureKeyVaultSigningService.Create(
            TestVaultUri,
            mockKeyClient.Object,
            mockCredential.Object,
            wrapper);

        // Act & Assert
        Assert.That(() => _ = service.PublicKeyHeaderContributor,
            Throws.TypeOf<NotSupportedException>());
    }

    #endregion

    #region GetCoseSigner Detailed Tests

    [Test]
    public void GetCoseSigner_WithContentType_ReturnsNonNullSigner()
    {
        // Arrange
        var mockKeyClient = new Mock<KeyClient>();
        var mockCredential = new Mock<TokenCredential>();
        var wrapper = CreateTestWrapper();

        using var service = AzureKeyVaultSigningService.Create(
            TestVaultUri,
            mockKeyClient.Object,
            mockCredential.Object,
            wrapper);

        var context = new SigningContext("test"u8.ToArray(), "application/json");

        // Act
        var signer = service.GetCoseSigner(context);

        // Assert
        Assert.That(signer, Is.Not.Null);
    }

    [Test]
    public void GetCoseSigner_WithEmptyContentType_DoesNotAddContentTypeHeader()
    {
        // Arrange
        var mockKeyClient = new Mock<KeyClient>();
        var mockCredential = new Mock<TokenCredential>();
        var wrapper = CreateTestWrapper();

        using var service = AzureKeyVaultSigningService.Create(
            TestVaultUri,
            mockKeyClient.Object,
            mockCredential.Object,
            wrapper);

        var context = new SigningContext("test"u8.ToArray(), "");

        // Act
        var signer = service.GetCoseSigner(context);

        // Assert
        Assert.That(signer, Is.Not.Null);
    }

    [Test]
    public void GetCoseSigner_WithAdditionalHeaderContributors_AppliesContributors()
    {
        // Arrange
        var mockKeyClient = new Mock<KeyClient>();
        var mockCredential = new Mock<TokenCredential>();
        var wrapper = CreateTestWrapper();

        using var service = AzureKeyVaultSigningService.Create(
            TestVaultUri,
            mockKeyClient.Object,
            mockCredential.Object,
            wrapper);

        var mockContributor = new Mock<IHeaderContributor>();
        var context = new SigningContext("test"u8.ToArray(), "text/plain", [mockContributor.Object]);

        // Act
        _ = service.GetCoseSigner(context);

        // Assert
        mockContributor.Verify(c => c.ContributeProtectedHeaders(It.IsAny<CoseHeaderMap>(), It.IsAny<HeaderContributorContext>()), Times.Once);
        mockContributor.Verify(c => c.ContributeUnprotectedHeaders(It.IsAny<CoseHeaderMap>(), It.IsAny<HeaderContributorContext>()), Times.Once);
    }

    [Test]
    public void GetCoseSigner_WithNullAdditionalHeaderContributors_DoesNotThrowBeforeKidHeader()
    {
        // Arrange
        var mockKeyClient = new Mock<KeyClient>();
        var mockCredential = new Mock<TokenCredential>();
        var wrapper = CreateTestWrapper();

        using var service = AzureKeyVaultSigningService.Create(
            TestVaultUri,
            mockKeyClient.Object,
            mockCredential.Object,
            wrapper);

        var context = new SigningContext("test"u8.ToArray(), "text/plain", additionalHeaderContributors: null);

        // Act
        var signer = service.GetCoseSigner(context);

        // Assert
        Assert.That(signer, Is.Not.Null);
    }

    #endregion

    #region Dispose Tests

    [Test]
    public void Dispose_CalledMultipleTimes_DoesNotThrow()
    {
        // Arrange
        var mockKeyClient = new Mock<KeyClient>();
        var mockCredential = new Mock<TokenCredential>();
        var wrapper = CreateTestWrapper();

        var service = AzureKeyVaultSigningService.Create(
            TestVaultUri,
            mockKeyClient.Object,
            mockCredential.Object,
            wrapper);

        // Act & Assert
        Assert.DoesNotThrow(() =>
        {
            service.Dispose();
            service.Dispose();
            service.Dispose();
        });
    }

    #endregion

    #region Helper Methods

    private KeyVaultCryptoClientWrapper CreateTestWrapper(KeyType? keyType = null)
    {
        var mockCryptoClient = CreateMockCryptographyClient();
        var key = keyType == KeyType.RsaHsm
            ? CreateMockRsaHsmKey()
            : CreateMockRsaKey(2048);
        return new KeyVaultCryptoClientWrapper(key, mockCryptoClient.Object);
    }

    private KeyVaultCryptoClientWrapper CreateEcKeyWrapper(KeyCurveName? curve = null)
    {
        var mockCryptoClient = CreateMockCryptographyClient();
        var key = CreateMockEcKey(curve ?? KeyCurveName.P256);
        return new KeyVaultCryptoClientWrapper(key, mockCryptoClient.Object);
    }

    private KeyVaultCryptoClientWrapper CreateEcHsmKeyWrapper()
    {
        var mockCryptoClient = CreateMockCryptographyClient();
        var key = CreateMockEcHsmKey();
        return new KeyVaultCryptoClientWrapper(key, mockCryptoClient.Object);
    }

    private Mock<CryptographyClient> CreateMockCryptographyClient()
    {
        var mock = new Mock<CryptographyClient>();

        mock.Setup(c => c.SignAsync(It.IsAny<SignatureAlgorithm>(), It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((SignatureAlgorithm alg, byte[] hash, CancellationToken ct) =>
                CryptographyModelFactory.SignResult(
                    keyId: TestKeyId.ToString(),
                    signature: new byte[] { 1, 2, 3, 4 },
                    algorithm: alg));

        return mock;
    }

    private Mock<CoseSign1.AzureKeyVault.Common.IKeyVaultClientFactory> CreateMockClientFactory(KeyVaultKey key)
    {
        var mockKeyClient = new Mock<KeyClient>(MockBehavior.Strict);
        mockKeyClient
            .Setup(k => k.GetKeyAsync(TestKeyName, It.Is<string?>(v => v == null), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(key, new Mock<Response>().Object));

        var mockCryptoClient = CreateMockCryptographyClient();

        var mockFactory = new Mock<CoseSign1.AzureKeyVault.Common.IKeyVaultClientFactory>(MockBehavior.Strict);
        mockFactory.SetupGet(f => f.VaultUri).Returns(TestVaultUri);
        mockFactory.SetupGet(f => f.KeyClient).Returns(mockKeyClient.Object);
        mockFactory.SetupGet(f => f.CertificateClient).Returns(new Mock<CertificateClient>().Object);
        mockFactory.SetupGet(f => f.SecretClient).Returns(new Mock<SecretClient>().Object);
        mockFactory.Setup(f => f.CreateCryptographyClient(It.IsAny<Uri>())).Returns(mockCryptoClient.Object);
        return mockFactory;
    }

    private KeyVaultKey CreateMockRsaKey(int keySize)
    {
        using var rsa = RSA.Create(keySize);
        var jsonWebKey = new JsonWebKey(rsa, includePrivateParameters: false);

        return KeyModelFactory.KeyVaultKey(
            properties: KeyModelFactory.KeyProperties(
                id: TestKeyId,
                vaultUri: TestVaultUri,
                name: TestKeyName,
                version: TestKeyVersion),
            key: jsonWebKey);
    }

    private KeyVaultKey CreateMockRsaHsmKey()
    {
        using var rsa = RSA.Create(2048);
        var jsonWebKey = new JsonWebKey(rsa, includePrivateParameters: false)
        {
            KeyType = KeyType.RsaHsm
        };

        return KeyModelFactory.KeyVaultKey(
            properties: KeyModelFactory.KeyProperties(
                id: TestKeyId,
                vaultUri: TestVaultUri,
                name: TestKeyName,
                version: TestKeyVersion),
            key: jsonWebKey);
    }

    private KeyVaultKey CreateMockEcKey(KeyCurveName curveName)
    {
        var curve = curveName.ToString() switch
        {
            "P-521" => ECCurve.NamedCurves.nistP521,
            "P-384" => ECCurve.NamedCurves.nistP384,
            _ => ECCurve.NamedCurves.nistP256
        };

        using var ecdsa = ECDsa.Create(curve);
        var jsonWebKey = new JsonWebKey(ecdsa, includePrivateParameters: false);

        return KeyModelFactory.KeyVaultKey(
            properties: KeyModelFactory.KeyProperties(
                id: TestKeyId,
                vaultUri: TestVaultUri,
                name: TestKeyName,
                version: TestKeyVersion),
            key: jsonWebKey);
    }

    private KeyVaultKey CreateMockEcHsmKey()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var jsonWebKey = new JsonWebKey(ecdsa, includePrivateParameters: false)
        {
            KeyType = KeyType.EcHsm
        };

        return KeyModelFactory.KeyVaultKey(
            properties: KeyModelFactory.KeyProperties(
                id: TestKeyId,
                vaultUri: TestVaultUri,
                name: TestKeyName,
                version: TestKeyVersion),
            key: jsonWebKey);
    }

    #endregion
}
