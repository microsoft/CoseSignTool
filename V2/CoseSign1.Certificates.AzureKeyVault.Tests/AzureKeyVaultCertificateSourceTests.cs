// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.AzureKeyVault.Common;

namespace CoseSign1.Certificates.AzureKeyVault.Tests;

/// <summary>
/// Tests for <see cref="AzureKeyVaultCertificateSource"/>.
/// </summary>
[TestFixture]
public class AzureKeyVaultCertificateSourceTests
{
    private const string TestCertificateName = "test-signing-cert";
    private const string TestCertificateVersion = "v1";
    private readonly Uri TestVaultUri = new("https://test-vault.vault.azure.net");
    private readonly Uri TestKeyId = new("https://test-vault.vault.azure.net/keys/test-signing-cert/v1");

    private Mock<TokenCredential> MockCredential = null!;
    private Mock<CertificateClient> MockCertificateClient = null!;
    private Mock<SecretClient> MockSecretClient = null!;
    private Mock<KeyClient> MockKeyClient = null!;
    private X509Certificate2 TestCertificate = null!;
    private X509Certificate2 TestEcdsaCertificate = null!;

    [SetUp]
    public void SetUp()
    {
        MockCredential = new Mock<TokenCredential>();
        MockCertificateClient = new Mock<CertificateClient>();
        MockSecretClient = new Mock<SecretClient>();
        MockKeyClient = new Mock<KeyClient>();

        // Create test certificates using helper from CoseSign1.Tests.Common
        TestCertificate = LocalCertificateFactory.CreateRsaCertificate("TestCert", 2048);
        TestEcdsaCertificate = LocalCertificateFactory.CreateEcdsaCertificate("TestEcdsaCert", 256);
    }

    [TearDown]
    public void TearDown()
    {
        TestCertificate?.Dispose();
        TestEcdsaCertificate?.Dispose();
    }

    #region CreateAsync Parameter Validation Tests

    [Test]
    public void CreateAsync_WithNullVaultUri_ThrowsArgumentNullException()
    {
        // Act & Assert
        var ex = Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await AzureKeyVaultCertificateSource.CreateAsync(
                null!,
                TestCertificateName,
                MockCredential.Object));

        Assert.That(ex.ParamName, Is.EqualTo("vaultUri"));
    }

    [Test]
    public void CreateAsync_WithNullCertificateName_ThrowsArgumentNullException()
    {
        // Act & Assert
        var ex = Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await AzureKeyVaultCertificateSource.CreateAsync(
                TestVaultUri,
                null!,
                MockCredential.Object));

        Assert.That(ex.ParamName, Is.EqualTo("certificateName"));
    }

    [Test]
    public void CreateAsync_WithNullCredential_ThrowsArgumentNullException()
    {
        // Act & Assert
        var ex = Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await AzureKeyVaultCertificateSource.CreateAsync(
                TestVaultUri,
                TestCertificateName,
                null!));

        Assert.That(ex.ParamName, Is.EqualTo("credential"));
    }

    [Test]
    public void CreateAsync_WithClients_NullCertificateClient_ThrowsArgumentNullException()
    {
        // Act & Assert
        var ex = Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await AzureKeyVaultCertificateSource.CreateAsync(
                TestVaultUri,
                TestCertificateName,
                MockCredential.Object,
                null!,
                MockSecretClient.Object,
                MockKeyClient.Object));

        Assert.That(ex.ParamName, Is.EqualTo("certificateClient"));
    }

    [Test]
    public void CreateAsync_WithClients_NullSecretClient_ThrowsArgumentNullException()
    {
        // Act & Assert
        var ex = Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await AzureKeyVaultCertificateSource.CreateAsync(
                TestVaultUri,
                TestCertificateName,
                MockCredential.Object,
                MockCertificateClient.Object,
                null!,
                MockKeyClient.Object));

        Assert.That(ex.ParamName, Is.EqualTo("secretClient"));
    }

    [Test]
    public void CreateAsync_WithClients_NullKeyClient_ThrowsArgumentNullException()
    {
        // Act & Assert
        var ex = Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await AzureKeyVaultCertificateSource.CreateAsync(
                TestVaultUri,
                TestCertificateName,
                MockCredential.Object,
                MockCertificateClient.Object,
                MockSecretClient.Object,
                null!));

        Assert.That(ex.ParamName, Is.EqualTo("keyClient"));
    }

    #endregion

    #region Create (DI Factory) Parameter Validation Tests

    [Test]
    public void Create_WithNullVaultUri_ThrowsArgumentNullException()
    {
        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() =>
            AzureKeyVaultCertificateSource.Create(
                null!,
                TestCertificateName,
                MockCredential.Object,
                MockCertificateClient.Object,
                MockSecretClient.Object,
                MockKeyClient.Object,
                TestCertificate,
                KeyVaultCertificateKeyMode.Local,
                null,
                TestCertificateVersion));

        Assert.That(ex.ParamName, Is.EqualTo("vaultUri"));
    }

    [Test]
    public void Create_WithNullCertificateName_ThrowsArgumentNullException()
    {
        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() =>
            AzureKeyVaultCertificateSource.Create(
                TestVaultUri,
                null!,
                MockCredential.Object,
                MockCertificateClient.Object,
                MockSecretClient.Object,
                MockKeyClient.Object,
                TestCertificate,
                KeyVaultCertificateKeyMode.Local,
                null,
                TestCertificateVersion));

        Assert.That(ex.ParamName, Is.EqualTo("certificateName"));
    }

    [Test]
    public void Create_WithNullCredential_ThrowsArgumentNullException()
    {
        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() =>
            AzureKeyVaultCertificateSource.Create(
                TestVaultUri,
                TestCertificateName,
                null!,
                MockCertificateClient.Object,
                MockSecretClient.Object,
                MockKeyClient.Object,
                TestCertificate,
                KeyVaultCertificateKeyMode.Local,
                null,
                TestCertificateVersion));

        Assert.That(ex.ParamName, Is.EqualTo("credential"));
    }

    [Test]
    public void Create_WithNullCertificateClient_ThrowsArgumentNullException()
    {
        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() =>
            AzureKeyVaultCertificateSource.Create(
                TestVaultUri,
                TestCertificateName,
                MockCredential.Object,
                null!,
                MockSecretClient.Object,
                MockKeyClient.Object,
                TestCertificate,
                KeyVaultCertificateKeyMode.Local,
                null,
                TestCertificateVersion));

        Assert.That(ex.ParamName, Is.EqualTo("certificateClient"));
    }

    [Test]
    public void Create_WithNullSecretClient_ThrowsArgumentNullException()
    {
        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() =>
            AzureKeyVaultCertificateSource.Create(
                TestVaultUri,
                TestCertificateName,
                MockCredential.Object,
                MockCertificateClient.Object,
                null!,
                MockKeyClient.Object,
                TestCertificate,
                KeyVaultCertificateKeyMode.Local,
                null,
                TestCertificateVersion));

        Assert.That(ex.ParamName, Is.EqualTo("secretClient"));
    }

    [Test]
    public void Create_WithNullKeyClient_ThrowsArgumentNullException()
    {
        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() =>
            AzureKeyVaultCertificateSource.Create(
                TestVaultUri,
                TestCertificateName,
                MockCredential.Object,
                MockCertificateClient.Object,
                MockSecretClient.Object,
                null!,
                TestCertificate,
                KeyVaultCertificateKeyMode.Local,
                null,
                TestCertificateVersion));

        Assert.That(ex.ParamName, Is.EqualTo("keyClient"));
    }

    [Test]
    public void Create_WithNullCertificate_ThrowsArgumentNullException()
    {
        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() =>
            AzureKeyVaultCertificateSource.Create(
                TestVaultUri,
                TestCertificateName,
                MockCredential.Object,
                MockCertificateClient.Object,
                MockSecretClient.Object,
                MockKeyClient.Object,
                null!,
                KeyVaultCertificateKeyMode.Local,
                null,
                TestCertificateVersion));

        Assert.That(ex.ParamName, Is.EqualTo("certificate"));
    }

    [Test]
    public void Create_WithNullCurrentVersion_ThrowsArgumentNullException()
    {
        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() =>
            AzureKeyVaultCertificateSource.Create(
                TestVaultUri,
                TestCertificateName,
                MockCredential.Object,
                MockCertificateClient.Object,
                MockSecretClient.Object,
                MockKeyClient.Object,
                TestCertificate,
                KeyVaultCertificateKeyMode.Local,
                null,
                null!));

        Assert.That(ex.ParamName, Is.EqualTo("currentVersion"));
    }

    [Test]
    public void Create_RemoteModeWithNullCryptoWrapper_ThrowsArgumentException()
    {
        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() =>
            AzureKeyVaultCertificateSource.Create(
                TestVaultUri,
                TestCertificateName,
                MockCredential.Object,
                MockCertificateClient.Object,
                MockSecretClient.Object,
                MockKeyClient.Object,
                TestCertificate,
                KeyVaultCertificateKeyMode.Remote,
                null,
                TestCertificateVersion));

        Assert.That(ex.ParamName, Is.EqualTo("cryptoWrapper"));
        Assert.That(ex.Message, Does.Contain("CryptoWrapper is required when keyMode is Remote"));
    }

    #endregion

    #region KeyVaultCertificateKeyMode Enum Tests

    [Test]
    public void KeyVaultCertificateKeyMode_Remote_HasCorrectValue()
    {
        Assert.That((int)KeyVaultCertificateKeyMode.Remote, Is.EqualTo(0));
    }

    [Test]
    public void KeyVaultCertificateKeyMode_Local_HasCorrectValue()
    {
        Assert.That((int)KeyVaultCertificateKeyMode.Local, Is.EqualTo(1));
    }

    #endregion

    #region Property Tests with Create Factory

    [Test]
    public void VaultUri_ReturnsConfiguredUri()
    {
        // Arrange
        using var source = CreateLocalModeSource();

        // Assert
        Assert.That(source.VaultUri, Is.EqualTo(TestVaultUri));
    }

    [Test]
    public void Name_ReturnsCertificateName()
    {
        // Arrange
        using var source = CreateLocalModeSource();

        // Assert
        Assert.That(source.Name, Is.EqualTo(TestCertificateName));
    }

    [Test]
    public void Version_ReturnsCurrentCertificateVersion()
    {
        // Arrange
        using var source = CreateLocalModeSource();

        // Assert
        Assert.That(source.Version, Is.EqualTo(TestCertificateVersion));
    }

    [Test]
    public void IsPinnedVersion_WhenVersionSpecified_ReturnsTrue()
    {
        // Arrange
        using var source = AzureKeyVaultCertificateSource.Create(
            TestVaultUri,
            TestCertificateName,
            MockCredential.Object,
            MockCertificateClient.Object,
            MockSecretClient.Object,
            MockKeyClient.Object,
            TestCertificate,
            KeyVaultCertificateKeyMode.Local,
            null,
            TestCertificateVersion,
            pinnedVersion: TestCertificateVersion);

        // Assert
        Assert.That(source.IsPinnedVersion, Is.True);
    }

    [Test]
    public void IsPinnedVersion_WhenVersionNotSpecified_ReturnsFalse()
    {
        // Arrange
        using var source = CreateLocalModeSource();

        // Assert
        Assert.That(source.IsPinnedVersion, Is.False);
    }

    [Test]
    public void AutoRefreshInterval_WhenPinned_ReturnsNull()
    {
        // Arrange
        using var source = AzureKeyVaultCertificateSource.Create(
            TestVaultUri,
            TestCertificateName,
            MockCredential.Object,
            MockCertificateClient.Object,
            MockSecretClient.Object,
            MockKeyClient.Object,
            TestCertificate,
            KeyVaultCertificateKeyMode.Local,
            null,
            TestCertificateVersion,
            pinnedVersion: TestCertificateVersion);

        // Assert
        Assert.That(source.AutoRefreshInterval, Is.Null);
    }

    [Test]
    public void AutoRefreshInterval_WhenConfigured_ReturnsConfiguredValue()
    {
        // Arrange
        var refreshInterval = TimeSpan.FromMinutes(30);
        using var source = AzureKeyVaultCertificateSource.Create(
            TestVaultUri,
            TestCertificateName,
            MockCredential.Object,
            MockCertificateClient.Object,
            MockSecretClient.Object,
            MockKeyClient.Object,
            TestCertificate,
            KeyVaultCertificateKeyMode.Local,
            null,
            TestCertificateVersion,
            refreshInterval: refreshInterval);

        // Assert
        Assert.That(source.AutoRefreshInterval, Is.EqualTo(refreshInterval));
    }

    [Test]
    public void KeyMode_WhenLocal_ReturnsLocal()
    {
        // Arrange
        using var source = CreateLocalModeSource();

        // Assert
        Assert.That(source.KeyMode, Is.EqualTo(KeyVaultCertificateKeyMode.Local));
    }

    [Test]
    public void KeyMode_WhenRemote_ReturnsRemote()
    {
        // Arrange
        using var source = CreateRemoteModeSource();

        // Assert
        Assert.That(source.KeyMode, Is.EqualTo(KeyVaultCertificateKeyMode.Remote));
    }

    [Test]
    public void RequiresRemoteSigning_WhenKeyModeRemote_ReturnsTrue()
    {
        // Arrange
        using var source = CreateRemoteModeSource();

        // Assert
        Assert.That(source.RequiresRemoteSigning, Is.True);
    }

    [Test]
    public void RequiresRemoteSigning_WhenKeyModeLocal_ReturnsFalse()
    {
        // Arrange
        using var source = CreateLocalModeSource();

        // Assert
        Assert.That(source.RequiresRemoteSigning, Is.False);
    }

    #endregion

    #region GetSigningCertificate Tests

    [Test]
    public void GetSigningCertificate_ReturnsCertificate()
    {
        // Arrange
        using var source = CreateLocalModeSource();

        // Act
        var cert = source.GetSigningCertificate();

        // Assert
        Assert.That(cert, Is.Not.Null);
        Assert.That(cert.Subject, Is.EqualTo(TestCertificate.Subject));
    }

    [Test]
    public void GetSigningCertificate_WhenLocalMode_CertificateHasPrivateKey()
    {
        // Arrange
        using var source = CreateLocalModeSource();

        // Act
        var cert = source.GetSigningCertificate();

        // Assert
        Assert.That(cert.HasPrivateKey, Is.True);
    }

    [Test]
    public void GetSigningCertificate_WhenRemoteMode_CertificatePublicKeyUsable()
    {
        // Arrange
        using var source = CreateRemoteModeSource();

        // Act
        var cert = source.GetSigningCertificate();

        // Assert - certificate should be accessible even in remote mode
        Assert.That(cert, Is.Not.Null);
        Assert.That(cert.Subject, Is.EqualTo(TestCertificate.Subject));
    }

    #endregion

    #region RSA Signing Tests - Local Mode

    [Test]
    public void SignDataWithRsa_WhenLocalMode_SignsData()
    {
        // Arrange
        using var source = CreateLocalModeSource();
        var data = new byte[] { 1, 2, 3, 4, 5 };

        // Act
        var signature = source.SignDataWithRsa(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Assert
        Assert.That(signature, Is.Not.Null);
        Assert.That(signature, Has.Length.GreaterThan(0));
    }

    [Test]
    public async Task SignDataWithRsaAsync_WhenLocalMode_SignsData()
    {
        // Arrange
        using var source = CreateLocalModeSource();
        var data = new byte[] { 1, 2, 3, 4, 5 };

        // Act
        var signature = await source.SignDataWithRsaAsync(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Assert
        Assert.That(signature, Is.Not.Null);
        Assert.That(signature, Has.Length.GreaterThan(0));
    }

    [Test]
    public void SignHashWithRsa_WhenLocalMode_SignsHash()
    {
        // Arrange
        using var source = CreateLocalModeSource();
        var data = new byte[] { 1, 2, 3, 4, 5 };
        var hash = SHA256.HashData(data);

        // Act
        var signature = source.SignHashWithRsa(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Assert
        Assert.That(signature, Is.Not.Null);
        Assert.That(signature, Has.Length.GreaterThan(0));
    }

    [Test]
    public async Task SignHashWithRsaAsync_WhenLocalMode_SignsHash()
    {
        // Arrange
        using var source = CreateLocalModeSource();
        var data = new byte[] { 1, 2, 3, 4, 5 };
        var hash = SHA256.HashData(data);

        // Act
        var signature = await source.SignHashWithRsaAsync(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Assert
        Assert.That(signature, Is.Not.Null);
        Assert.That(signature, Has.Length.GreaterThan(0));
    }

    [Test]
    public void SignDataWithRsa_WhenLocalMode_VerifiesSuccessfully()
    {
        // Arrange
        using var source = CreateLocalModeSource();
        var data = new byte[] { 1, 2, 3, 4, 5 };

        // Act
        var signature = source.SignDataWithRsa(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Assert - Verify the signature with the public key
        using var rsa = TestCertificate.GetRSAPublicKey();
        var isValid = rsa!.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        Assert.That(isValid, Is.True);
    }

    #endregion

    #region ECDSA Signing Tests - Local Mode

    [Test]
    public void SignDataWithEcdsa_WhenLocalMode_SignsData()
    {
        // Arrange
        using var source = CreateLocalModeEcdsaSource();
        var data = new byte[] { 1, 2, 3, 4, 5 };

        // Act
        var signature = source.SignDataWithEcdsa(data, HashAlgorithmName.SHA256);

        // Assert
        Assert.That(signature, Is.Not.Null);
        Assert.That(signature, Has.Length.GreaterThan(0));
    }

    [Test]
    public async Task SignDataWithEcdsaAsync_WhenLocalMode_SignsData()
    {
        // Arrange
        using var source = CreateLocalModeEcdsaSource();
        var data = new byte[] { 1, 2, 3, 4, 5 };

        // Act
        var signature = await source.SignDataWithEcdsaAsync(data, HashAlgorithmName.SHA256);

        // Assert
        Assert.That(signature, Is.Not.Null);
        Assert.That(signature, Has.Length.GreaterThan(0));
    }

    [Test]
    public void SignHashWithEcdsa_WhenLocalMode_SignsHash()
    {
        // Arrange
        using var source = CreateLocalModeEcdsaSource();
        var data = new byte[] { 1, 2, 3, 4, 5 };
        var hash = SHA256.HashData(data);

        // Act
        var signature = source.SignHashWithEcdsa(hash);

        // Assert
        Assert.That(signature, Is.Not.Null);
        Assert.That(signature, Has.Length.GreaterThan(0));
    }

    [Test]
    public async Task SignHashWithEcdsaAsync_WhenLocalMode_SignsHash()
    {
        // Arrange
        using var source = CreateLocalModeEcdsaSource();
        var data = new byte[] { 1, 2, 3, 4, 5 };
        var hash = SHA256.HashData(data);

        // Act
        var signature = await source.SignHashWithEcdsaAsync(hash);

        // Assert
        Assert.That(signature, Is.Not.Null);
        Assert.That(signature, Has.Length.GreaterThan(0));
    }

    [Test]
    public void SignDataWithEcdsa_WhenLocalMode_VerifiesSuccessfully()
    {
        // Arrange
        using var source = CreateLocalModeEcdsaSource();
        var data = new byte[] { 1, 2, 3, 4, 5 };

        // Act
        var signature = source.SignDataWithEcdsa(data, HashAlgorithmName.SHA256);

        // Assert - Verify the signature with the public key
        using var ecdsa = TestEcdsaCertificate.GetECDsaPublicKey();
        var isValid = ecdsa!.VerifyData(data, signature, HashAlgorithmName.SHA256);
        Assert.That(isValid, Is.True);
    }

    #endregion

    #region Remote Mode Signing Tests

    [Test]
    public async Task SignDataWithRsaAsync_WhenRemoteMode_UsesCryptoWrapper()
    {
        // Arrange
        var expectedSignature = new byte[] { 10, 20, 30, 40, 50 };
        var mockCryptoWrapper = CreateMockCryptoWrapper(expectedSignature);
        using var source = CreateRemoteModeSourceWithMockWrapper(mockCryptoWrapper);
        var data = new byte[] { 1, 2, 3, 4, 5 };

        // Act
        var signature = await source.SignDataWithRsaAsync(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Assert
        Assert.That(signature, Is.EqualTo(expectedSignature));
    }

    [Test]
    public async Task SignHashWithRsaAsync_WhenRemoteMode_UsesCryptoWrapper()
    {
        // Arrange
        var expectedSignature = new byte[] { 10, 20, 30, 40, 50 };
        var mockCryptoWrapper = CreateMockCryptoWrapper(expectedSignature);
        using var source = CreateRemoteModeSourceWithMockWrapper(mockCryptoWrapper);
        var hash = SHA256.HashData(new byte[] { 1, 2, 3, 4, 5 });

        // Act
        var signature = await source.SignHashWithRsaAsync(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Assert
        Assert.That(signature, Is.EqualTo(expectedSignature));
    }

    #endregion

    #region CreateAsync Integration Tests (Mocked Azure SDK Responses)

    [Test]
    public async Task CreateAsync_WhenCertificateIsExportableAndNotForced_UsesSecretPlaneAndReturnsLocalModeWithPrivateKey()
    {
        // Arrange
        using var certWithKey = LocalCertificateFactory.CreateRsaCertificate("AKVExportable", 2048);
        var pfxBytes = certWithKey.Export(X509ContentType.Pkcs12);
        var secretValue = Convert.ToBase64String(pfxBytes);

        var kvCert = CreateKeyVaultCertificateWithPolicy(
            exportable: true,
            version: TestCertificateVersion,
            cerBytes: certWithKey.Export(X509ContentType.Cert));

        MockCertificateClient
            .Setup(c => c.GetCertificateAsync(TestCertificateName, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(kvCert, new Mock<Response>().Object));

        MockSecretClient
            .Setup(s => s.GetSecretAsync(TestCertificateName, TestCertificateVersion, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(
                CreateKeyVaultSecret(
                    value: secretValue,
                    contentType: "application/x-pkcs12"),
                new Mock<Response>().Object));

        // Act
        using var source = await AzureKeyVaultCertificateSource.CreateAsync(
            TestVaultUri,
            TestCertificateName,
            MockCredential.Object,
            MockCertificateClient.Object,
            MockSecretClient.Object,
            MockKeyClient.Object,
            certificateVersion: null,
            refreshInterval: null,
            forceRemoteMode: false,
            cancellationToken: CancellationToken.None);

        // Assert
        Assert.That(source.KeyMode, Is.EqualTo(KeyVaultCertificateKeyMode.Local));
        Assert.That(source.RequiresRemoteSigning, Is.False);
        Assert.That(source.GetSigningCertificate().HasPrivateKey, Is.True);
        Assert.That(source.Version, Is.EqualTo(TestCertificateVersion));
    }

    [Test]
    public async Task CreateAsync_WhenExportableButForcedRemote_UsesRemoteModeAndCreatesCryptoWrapper()
    {
        // Arrange
        using var cert = LocalCertificateFactory.CreateRsaCertificate("AKVForcedRemote", 2048);

        var kvCert = CreateKeyVaultCertificateWithPolicy(
            exportable: true,
            version: TestCertificateVersion,
            cerBytes: cert.Export(X509ContentType.Cert));

        MockCertificateClient
            .Setup(c => c.GetCertificateAsync(TestCertificateName, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(kvCert, new Mock<Response>().Object));

        MockKeyClient
            .Setup(k => k.GetKeyAsync(TestCertificateName, TestCertificateVersion, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(CreateKeyVaultRsaKey(TestKeyId), new Mock<Response>().Object));

        // Act
        using var source = await AzureKeyVaultCertificateSource.CreateAsync(
            TestVaultUri,
            TestCertificateName,
            MockCredential.Object,
            MockCertificateClient.Object,
            MockSecretClient.Object,
            MockKeyClient.Object,
            certificateVersion: null,
            refreshInterval: null,
            forceRemoteMode: true,
            cancellationToken: CancellationToken.None);

        // Assert
        Assert.That(source.KeyMode, Is.EqualTo(KeyVaultCertificateKeyMode.Remote));
        Assert.That(source.RequiresRemoteSigning, Is.True);
        Assert.That(source.Version, Is.EqualTo(TestCertificateVersion));
    }

    [Test]
    public async Task CreateAsync_WhenCertificateIsNotExportable_UsesRemoteMode()
    {
        // Arrange
        using var cert = LocalCertificateFactory.CreateRsaCertificate("AKVNotExportable", 2048);

        var kvCert = CreateKeyVaultCertificateWithPolicy(
            exportable: false,
            version: TestCertificateVersion,
            cerBytes: cert.Export(X509ContentType.Cert));

        MockCertificateClient
            .Setup(c => c.GetCertificateAsync(TestCertificateName, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(kvCert, new Mock<Response>().Object));

        MockKeyClient
            .Setup(k => k.GetKeyAsync(TestCertificateName, TestCertificateVersion, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(CreateKeyVaultRsaKey(TestKeyId), new Mock<Response>().Object));

        // Act
        using var source = await AzureKeyVaultCertificateSource.CreateAsync(
            TestVaultUri,
            TestCertificateName,
            MockCredential.Object,
            MockCertificateClient.Object,
            MockSecretClient.Object,
            MockKeyClient.Object,
            certificateVersion: null,
            refreshInterval: null,
            forceRemoteMode: false,
            cancellationToken: CancellationToken.None);

        // Assert
        Assert.That(source.KeyMode, Is.EqualTo(KeyVaultCertificateKeyMode.Remote));
        Assert.That(source.RequiresRemoteSigning, Is.True);
        Assert.That(source.Version, Is.EqualTo(TestCertificateVersion));
    }

    [Test]
    public void CreateAsync_WhenRemoteModeAndCertBytesMissing_ThrowsInvalidOperationException()
    {
        // Arrange
        var kvCert = CreateKeyVaultCertificateWithPolicy(
            exportable: false,
            version: TestCertificateVersion,
            cerBytes: Array.Empty<byte>());

        MockCertificateClient
            .Setup(c => c.GetCertificateAsync(TestCertificateName, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(kvCert, new Mock<Response>().Object));

        // Act & Assert
        var ex = Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await AzureKeyVaultCertificateSource.CreateAsync(
                TestVaultUri,
                TestCertificateName,
                MockCredential.Object,
                MockCertificateClient.Object,
                MockSecretClient.Object,
                MockKeyClient.Object,
                certificateVersion: null,
                refreshInterval: null,
                forceRemoteMode: false,
                cancellationToken: CancellationToken.None));

        Assert.That(ex!.Message, Does.Contain("Certificate data"));
    }

    #endregion

    #region ML-DSA Signing Tests

    [Test]
    public void SignDataWithMLDsa_ThrowsNotSupportedException()
    {
        // Arrange
        using var source = CreateLocalModeSource();
        var data = new byte[] { 1, 2, 3, 4, 5 };

        // Act & Assert
        Assert.Throws<NotSupportedException>(() =>
            source.SignDataWithMLDsa(data));
    }

    [Test]
    public void SignDataWithMLDsaAsync_ThrowsNotSupportedException()
    {
        // Arrange
        using var source = CreateLocalModeSource();
        var data = new byte[] { 1, 2, 3, 4, 5 };

        // Act & Assert
        Assert.ThrowsAsync<NotSupportedException>(async () =>
            await source.SignDataWithMLDsaAsync(data));
    }

    #endregion

    #region RefreshCertificateAsync Tests

    [Test]
    public void RefreshCertificateAsync_WhenPinned_ThrowsInvalidOperationException()
    {
        // Arrange
        using var source = AzureKeyVaultCertificateSource.Create(
            TestVaultUri,
            TestCertificateName,
            MockCredential.Object,
            MockCertificateClient.Object,
            MockSecretClient.Object,
            MockKeyClient.Object,
            TestCertificate,
            KeyVaultCertificateKeyMode.Local,
            null,
            TestCertificateVersion,
            pinnedVersion: TestCertificateVersion);

        // Act & Assert
        Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await source.RefreshCertificateAsync());
    }

    [Test]
    public async Task RefreshCertificateAsync_WhenVersionUnchanged_ReturnsFalse()
    {
        // Arrange
        using var source = AzureKeyVaultCertificateSource.Create(
            TestVaultUri,
            TestCertificateName,
            MockCredential.Object,
            MockCertificateClient.Object,
            MockSecretClient.Object,
            MockKeyClient.Object,
            TestCertificate,
            KeyVaultCertificateKeyMode.Local,
            null,
            TestCertificateVersion,
            pinnedVersion: null);

        var kvCert = CreateKeyVaultCertificateWithPolicy(
            exportable: true,
            version: TestCertificateVersion,
            cerBytes: TestCertificate.Export(X509ContentType.Cert));

        MockCertificateClient
            .Setup(c => c.GetCertificateAsync(TestCertificateName, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(kvCert, new Mock<Response>().Object));

        // Act
        var refreshed = await source.RefreshCertificateAsync();

        // Assert
        Assert.That(refreshed, Is.False);
    }

    [Test]
    public async Task RefreshCertificateAsync_WhenVersionChanged_UpdatesCertificateAndReturnsTrue()
    {
        // Arrange
        const string newVersion = "v2";

        using var initialCert = LocalCertificateFactory.CreateRsaCertificate("AKVRefreshOld", 2048);
        using var newCert = LocalCertificateFactory.CreateRsaCertificate("AKVRefreshNew", 2048);

        using var source = AzureKeyVaultCertificateSource.Create(
            TestVaultUri,
            TestCertificateName,
            MockCredential.Object,
            MockCertificateClient.Object,
            MockSecretClient.Object,
            MockKeyClient.Object,
            initialCert,
            KeyVaultCertificateKeyMode.Local,
            null,
            TestCertificateVersion,
            pinnedVersion: null);

        // First call: check latest version (v2)
        var latestKvCert = CreateKeyVaultCertificateWithPolicy(
            exportable: true,
            version: newVersion,
            cerBytes: newCert.Export(X509ContentType.Cert));

        // Second call inside LoadCertificateAsync also hits GetCertificateAsync; return same latest
        MockCertificateClient
            .SetupSequence(c => c.GetCertificateAsync(TestCertificateName, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(latestKvCert, new Mock<Response>().Object))
            .ReturnsAsync(Response.FromValue(latestKvCert, new Mock<Response>().Object));

        // Secret download for v2
        var pfxBytes = newCert.Export(X509ContentType.Pkcs12);
        MockSecretClient
            .Setup(s => s.GetSecretAsync(TestCertificateName, newVersion, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(
                CreateKeyVaultSecret(
                    value: Convert.ToBase64String(pfxBytes),
                    contentType: "application/x-pkcs12"),
                new Mock<Response>().Object));

        // Act
        var refreshed = await source.RefreshCertificateAsync();

        // Assert
        Assert.That(refreshed, Is.True);
        Assert.That(source.Version, Is.EqualTo(newVersion));
        Assert.That(source.KeyMode, Is.EqualTo(KeyVaultCertificateKeyMode.Local));
        Assert.That(source.GetSigningCertificate().HasPrivateKey, Is.True);
    }

    #endregion

    #region Dispose Tests

    [Test]
    public void Dispose_DoesNotThrow()
    {
        // Arrange
        var source = CreateLocalModeSource();

        // Act & Assert
        Assert.DoesNotThrow(() => source.Dispose());
    }

    [Test]
    public void Dispose_CalledMultipleTimes_DoesNotThrow()
    {
        // Arrange
        var source = CreateLocalModeSource();

        // Act & Assert
        Assert.DoesNotThrow(() =>
        {
            source.Dispose();
            source.Dispose();
            source.Dispose();
        });
    }

    [Test]
    public void SignAfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        var source = CreateLocalModeSource();
        source.Dispose();
        var data = new byte[] { 1, 2, 3, 4, 5 };

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() =>
            source.SignDataWithRsa(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    [Test]
    public async Task SignAsyncAfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        var source = CreateLocalModeSource();
        source.Dispose();
        var data = new byte[] { 1, 2, 3, 4, 5 };

        // Act & Assert
        Assert.ThrowsAsync<ObjectDisposedException>(async () =>
            await source.SignDataWithRsaAsync(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    [Test]
    public void SignHashAfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        var source = CreateLocalModeSource();
        source.Dispose();
        var hash = SHA256.HashData(new byte[] { 1, 2, 3, 4, 5 });

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() =>
            source.SignHashWithRsa(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    [Test]
    public void SignEcdsaAfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        var source = CreateLocalModeEcdsaSource();
        source.Dispose();
        var data = new byte[] { 1, 2, 3, 4, 5 };

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() =>
            source.SignDataWithEcdsa(data, HashAlgorithmName.SHA256));
    }

    [Test]
    public void SignHashEcdsaAfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        var source = CreateLocalModeEcdsaSource();
        source.Dispose();
        var hash = SHA256.HashData(new byte[] { 1, 2, 3, 4, 5 });

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() =>
            source.SignHashWithEcdsa(hash));
    }

    #endregion

    #region Helper Methods

    private AzureKeyVaultCertificateSource CreateLocalModeSource()
    {
        return AzureKeyVaultCertificateSource.Create(
            TestVaultUri,
            TestCertificateName,
            MockCredential.Object,
            MockCertificateClient.Object,
            MockSecretClient.Object,
            MockKeyClient.Object,
            TestCertificate,
            KeyVaultCertificateKeyMode.Local,
            null,
            TestCertificateVersion);
    }

    private AzureKeyVaultCertificateSource CreateLocalModeEcdsaSource()
    {
        return AzureKeyVaultCertificateSource.Create(
            TestVaultUri,
            TestCertificateName,
            MockCredential.Object,
            MockCertificateClient.Object,
            MockSecretClient.Object,
            MockKeyClient.Object,
            TestEcdsaCertificate,
            KeyVaultCertificateKeyMode.Local,
            null,
            TestCertificateVersion);
    }

    private AzureKeyVaultCertificateSource CreateRemoteModeSource()
    {
        var cryptoWrapper = CreateTestCryptoWrapper();
        return AzureKeyVaultCertificateSource.Create(
            TestVaultUri,
            TestCertificateName,
            MockCredential.Object,
            MockCertificateClient.Object,
            MockSecretClient.Object,
            MockKeyClient.Object,
            TestCertificate,
            KeyVaultCertificateKeyMode.Remote,
            cryptoWrapper,
            TestCertificateVersion);
    }

    private AzureKeyVaultCertificateSource CreateRemoteModeSourceWithMockWrapper(KeyVaultCryptoClientWrapper wrapper)
    {
        return AzureKeyVaultCertificateSource.Create(
            TestVaultUri,
            TestCertificateName,
            MockCredential.Object,
            MockCertificateClient.Object,
            MockSecretClient.Object,
            MockKeyClient.Object,
            TestCertificate,
            KeyVaultCertificateKeyMode.Remote,
            wrapper,
            TestCertificateVersion);
    }

    private KeyVaultCryptoClientWrapper CreateTestCryptoWrapper()
    {
        var mockCryptoClient = new Mock<CryptographyClient>();

        mockCryptoClient.Setup(c => c.SignAsync(It.IsAny<SignatureAlgorithm>(), It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((SignatureAlgorithm alg, byte[] hash, CancellationToken ct) =>
                CryptographyModelFactory.SignResult(
                    keyId: TestKeyId.ToString(),
                    signature: new byte[] { 1, 2, 3, 4 },
                    algorithm: alg));

        using var rsa = RSA.Create(2048);
        var jsonWebKey = new JsonWebKey(rsa, includePrivateParameters: false);

        var keyVaultKey = KeyModelFactory.KeyVaultKey(
            properties: KeyModelFactory.KeyProperties(
                id: TestKeyId,
                vaultUri: TestVaultUri,
                name: TestCertificateName,
                version: TestCertificateVersion),
            key: jsonWebKey);

        return new KeyVaultCryptoClientWrapper(keyVaultKey, mockCryptoClient.Object);
    }

    private KeyVaultCryptoClientWrapper CreateMockCryptoWrapper(byte[] signatureToReturn)
    {
        var mockCryptoClient = new Mock<CryptographyClient>();

        mockCryptoClient.Setup(c => c.SignAsync(It.IsAny<SignatureAlgorithm>(), It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((SignatureAlgorithm alg, byte[] hash, CancellationToken ct) =>
                CryptographyModelFactory.SignResult(
                    keyId: TestKeyId.ToString(),
                    signature: signatureToReturn,
                    algorithm: alg));

        using var rsa = RSA.Create(2048);
        var jsonWebKey = new JsonWebKey(rsa, includePrivateParameters: false);

        var keyVaultKey = KeyModelFactory.KeyVaultKey(
            properties: KeyModelFactory.KeyProperties(
                id: TestKeyId,
                vaultUri: TestVaultUri,
                name: TestCertificateName,
                version: TestCertificateVersion),
            key: jsonWebKey);

        return new KeyVaultCryptoClientWrapper(keyVaultKey, mockCryptoClient.Object);
    }

    private KeyVaultCertificateWithPolicy CreateKeyVaultCertificateWithPolicy(bool exportable, string version, byte[] cerBytes)
    {
        var properties = CertificateModelFactory.CertificateProperties(
            name: TestCertificateName,
            id: new Uri($"{TestVaultUri}certificates/{TestCertificateName}/{version}"),
            vaultUri: TestVaultUri,
            version: version);

        var policy = CreateCertificatePolicy(exportable);

        return CertificateModelFactory.KeyVaultCertificateWithPolicy(
            properties,
            TestKeyId,
            new Uri($"{TestVaultUri}secrets/{TestCertificateName}/{version}"),
            cerBytes,
            policy);
    }

    private static KeyVaultSecret CreateKeyVaultSecret(string value, string? contentType)
    {
        var secret = new KeyVaultSecret(TestCertificateName, value);
        secret.Properties.ContentType = contentType;
        return secret;
    }

    private static CertificatePolicy CreateCertificatePolicy(bool exportable)
    {
        // CertificatePolicy constructors vary across Azure SDK versions.
        // We need Policy.Exportable to be true/false so the production logic can branch.
        var policyType = typeof(CertificatePolicy);

        var constructors = policyType.GetConstructors(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);

        // Prefer a ctor that accepts an exportable/isExportable bool parameter.
        var preferredCtor = constructors
            .Select(c => new { Ctor = c, Params = c.GetParameters() })
            .Where(x => x.Params.Any(p =>
                p.ParameterType == typeof(bool) &&
                p.Name != null &&
                p.Name.Contains("export", StringComparison.OrdinalIgnoreCase)))
            .OrderBy(x => x.Params.Length)
            .FirstOrDefault();

        var chosen = preferredCtor?.Ctor
            ?? constructors.OrderBy(c => c.GetParameters().Length).First();

        var args = chosen.GetParameters()
            .Select(p =>
            {
                if (p.ParameterType == typeof(bool) && p.Name != null && p.Name.Contains("export", StringComparison.OrdinalIgnoreCase))
                {
                    return (object)exportable;
                }

                if (p.ParameterType == typeof(string))
                {
                    return (object)"CN=Test";
                }

                if (p.ParameterType == typeof(Uri))
                {
                    return (object)new Uri("https://example.vault.azure.net/");
                }

                if (p.ParameterType.IsValueType)
                {
                    return Activator.CreateInstance(p.ParameterType)!;
                }

                return null!;
            })
            .ToArray();

        var policy = (CertificatePolicy)chosen.Invoke(args);

        // If the property has a setter, set it explicitly for safety.
        var exportableProp = policyType.GetProperty("Exportable");
        if (exportableProp?.CanWrite == true)
        {
            exportableProp.SetValue(policy, exportable);
        }

        return policy;
    }

    private static KeyVaultKey CreateKeyVaultRsaKey(Uri keyId)
    {
        using var rsa = RSA.Create(2048);
        var jsonWebKey = new JsonWebKey(rsa, includePrivateParameters: false);

        var keyProperties = KeyModelFactory.KeyProperties(
            id: keyId,
            vaultUri: new Uri(keyId.GetLeftPart(UriPartial.Authority)),
            name: "key",
            version: keyId.Segments.Length > 0 ? keyId.Segments[^1].TrimEnd('/') : "v1");

        return KeyModelFactory.KeyVaultKey(properties: keyProperties, key: jsonWebKey);
    }

    #endregion
}
