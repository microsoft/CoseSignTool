// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.AzureKeyVault.Tests;

using System.Reflection;
using CoseSign1.Certificates.AzureKeyVault;

[TestFixture]
[System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
public class AzureKeyVaultCertificateSourceDiTests
{
    private const string TestCertificateName = "test-signing-cert";
    private const string TestCertificateVersion = "v1";
    private static readonly Uri TestVaultUri = new("https://test-vault.vault.azure.net");
    private static readonly Uri TestKeyId = new("https://test-vault.vault.azure.net/keys/test-signing-cert/v1");

    private static (
        Mock<TokenCredential> Credential,
        Mock<IKeyVaultClientFactory> Factory,
        Mock<CertificateClient> CertificateClient,
        Mock<SecretClient> SecretClient,
        Mock<KeyClient> KeyClient) CreateMocks()
    {
        var mockCredential = new Mock<TokenCredential>();
        var mockFactory = new Mock<IKeyVaultClientFactory>(MockBehavior.Strict);
        var mockCertificateClient = new Mock<CertificateClient>(MockBehavior.Strict);
        var mockSecretClient = new Mock<SecretClient>(MockBehavior.Strict);
        var mockKeyClient = new Mock<KeyClient>(MockBehavior.Strict);

        mockFactory.SetupGet(f => f.VaultUri).Returns(TestVaultUri);
        mockFactory.SetupGet(f => f.CertificateClient).Returns(mockCertificateClient.Object);
        mockFactory.SetupGet(f => f.SecretClient).Returns(mockSecretClient.Object);
        mockFactory.SetupGet(f => f.KeyClient).Returns(mockKeyClient.Object);

        return (mockCredential, mockFactory, mockCertificateClient, mockSecretClient, mockKeyClient);
    }

    [Test]
    public void Constructor_WithNullFactory_ThrowsArgumentNullException()
    {
        var ex = Assert.Throws<ArgumentNullException>(() => new AzureKeyVaultCertificateSource(null!, TestCertificateName));
        Assert.That(ex!.ParamName, Is.EqualTo("clientFactory"));
    }

    [Test]
    public void Constructor_WithNullCertificateName_ThrowsArgumentNullException()
    {
        var mocks = CreateMocks();
        var ex = Assert.Throws<ArgumentNullException>(() => new AzureKeyVaultCertificateSource(mocks.Factory.Object, null!));
        Assert.That(ex!.ParamName, Is.EqualTo("certificateName"));
    }

    [Test]
    public void GetSigningCertificate_BeforeInitialize_ThrowsInvalidOperationException()
    {
        var mocks = CreateMocks();
        using var source = new AzureKeyVaultCertificateSource(mocks.Factory.Object, TestCertificateName);
        Assert.Throws<InvalidOperationException>(() => source.GetSigningCertificate());
    }

    [Test]
    public async Task InitializeAsync_WhenExportable_LoadsLocalCertificateAndSignsLocally()
    {
        var mocks = CreateMocks();
        using var inputCert = LocalCertificateFactory.CreateRsaCertificate("AkvLocal", 2048);
        var pfxBytes = inputCert.Export(X509ContentType.Pkcs12);
        var secretValue = Convert.ToBase64String(pfxBytes);

        var kvCert = CreateKeyVaultCertificateWithPolicy(
            exportable: true,
            version: TestCertificateVersion,
            cerBytes: inputCert.Export(X509ContentType.Cert));

        mocks.CertificateClient
            .Setup(c => c.GetCertificateAsync(TestCertificateName, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(kvCert, new Mock<Response>().Object));

        mocks.CertificateClient
            .Setup(c => c.GetCertificateVersionAsync(TestCertificateName, TestCertificateVersion, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(
                CreateKeyVaultCertificateVersion(TestCertificateVersion, inputCert.Export(X509ContentType.Cert)),
                new Mock<Response>().Object));

        mocks.CertificateClient
            .Setup(c => c.GetCertificateVersionAsync(TestCertificateName, TestCertificateVersion, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(CreateKeyVaultCertificateVersion(TestCertificateVersion, inputCert.Export(X509ContentType.Cert)), new Mock<Response>().Object));

        mocks.CertificateClient
            .Setup(c => c.GetCertificateVersionAsync(TestCertificateName, TestCertificateVersion, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(CreateKeyVaultCertificateVersion(TestCertificateVersion, kvCert.Cer), new Mock<Response>().Object));

        var secret = CreateKeyVaultSecret(secretValue, contentType: "application/x-pkcs12");
        mocks.SecretClient
            .Setup(s => s.GetSecretAsync(TestCertificateName, TestCertificateVersion, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(secret, new Mock<Response>().Object));

        using var source = new AzureKeyVaultCertificateSource(mocks.Factory.Object, TestCertificateName);
        await source.InitializeAsync();

        Assert.That(source.KeyMode, Is.EqualTo(KeyVaultCertificateKeyMode.Local));
        Assert.That(source.RequiresRemoteSigning, Is.False);

        var data = new byte[] { 1, 2, 3, 4, 5 };
        var signature = await source.SignDataWithRsaAsync(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        using var rsa = source.GetSigningCertificate().GetRSAPublicKey();
        Assert.That(rsa, Is.Not.Null);
        Assert.That(rsa!.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1), Is.True);

        mocks.KeyClient.VerifyNoOtherCalls();
    }

    [Test]
    public async Task InitializeAsync_WhenNotExportable_UsesRemoteModeAndCreatesWrapper()
    {
        var mocks = CreateMocks();
        using var inputCert = LocalCertificateFactory.CreateRsaCertificate("AkvRemote", 2048);

        var kvCert = CreateKeyVaultCertificateWithPolicy(
            exportable: false,
            version: TestCertificateVersion,
            cerBytes: inputCert.Export(X509ContentType.Cert));

        mocks.CertificateClient
            .Setup(c => c.GetCertificateAsync(TestCertificateName, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(kvCert, new Mock<Response>().Object));

        mocks.CertificateClient
            .Setup(c => c.GetCertificateVersionAsync(TestCertificateName, TestCertificateVersion, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(
                CreateKeyVaultCertificateVersion(TestCertificateVersion, inputCert.Export(X509ContentType.Cert)),
                new Mock<Response>().Object));

        mocks.CertificateClient
            .Setup(c => c.GetCertificateVersionAsync(TestCertificateName, TestCertificateVersion, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(CreateKeyVaultCertificateVersion(TestCertificateVersion, inputCert.Export(X509ContentType.Cert)), new Mock<Response>().Object));

        mocks.CertificateClient
            .Setup(c => c.GetCertificateVersionAsync(TestCertificateName, TestCertificateVersion, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(CreateKeyVaultCertificateVersion(TestCertificateVersion, kvCert.Cer), new Mock<Response>().Object));

        mocks.Factory
            .Setup(f => f.CreateCryptographyClient(It.IsAny<Uri>()))
            .Returns((Uri keyId) => new CryptographyClient(keyId, mocks.Credential.Object));

        var key = CreateKeyVaultRsaKey(TestKeyId);
        mocks.KeyClient
            .Setup(k => k.GetKeyAsync(TestCertificateName, TestCertificateVersion, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(key, new Mock<Response>().Object));

        using var source = new AzureKeyVaultCertificateSource(mocks.Factory.Object, TestCertificateName);
        await source.InitializeAsync();

        Assert.That(source.KeyMode, Is.EqualTo(KeyVaultCertificateKeyMode.Remote));
        Assert.That(source.RequiresRemoteSigning, Is.True);
        Assert.That(source.GetSigningCertificate(), Is.Not.Null);

        // Remote mode should not attempt to download secrets.
        mocks.SecretClient.VerifyNoOtherCalls();
    }

    [Test]
    public async Task InitializeAsync_WhenExportable_AndForceRemoteModeTrue_UsesRemoteMode()
    {
        var mocks = CreateMocks();
        using var inputCert = LocalCertificateFactory.CreateRsaCertificate("AkvForceRemote", 2048);

        var kvCert = CreateKeyVaultCertificateWithPolicy(
            exportable: true,
            version: TestCertificateVersion,
            cerBytes: inputCert.Export(X509ContentType.Cert));

        mocks.CertificateClient
            .Setup(c => c.GetCertificateAsync(TestCertificateName, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(kvCert, new Mock<Response>().Object));

        mocks.CertificateClient
            .Setup(c => c.GetCertificateVersionAsync(TestCertificateName, TestCertificateVersion, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(
                CreateKeyVaultCertificateVersion(TestCertificateVersion, kvCert.Cer),
                new Mock<Response>().Object));

        mocks.Factory
            .Setup(f => f.CreateCryptographyClient(It.IsAny<Uri>()))
            .Returns((Uri keyId) => new CryptographyClient(keyId, mocks.Credential.Object));

        var key = CreateKeyVaultRsaKey(TestKeyId);
        mocks.KeyClient
            .Setup(k => k.GetKeyAsync(TestCertificateName, TestCertificateVersion, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(key, new Mock<Response>().Object));

        using var source = new AzureKeyVaultCertificateSource(
            mocks.Factory.Object,
            TestCertificateName,
            certificateVersion: TestCertificateVersion,
            refreshInterval: null,
            forceRemoteMode: true);

        await source.InitializeAsync();

        Assert.That(source.KeyMode, Is.EqualTo(KeyVaultCertificateKeyMode.Remote));
        Assert.That(source.RequiresRemoteSigning, Is.True);

        // Force-remote must not attempt secret download.
        mocks.SecretClient.VerifyNoOtherCalls();
    }

    [Test]
    public async Task InitializeAsync_WhenExportable_AndSecretIsPem_LoadsLocalCertificate()
    {
        var mocks = CreateMocks();
        using var inputCert = LocalCertificateFactory.CreateRsaCertificate("AkvPem", 2048);
        var pem = PemEncoding.Write("CERTIFICATE", inputCert.Export(X509ContentType.Cert));
        var pemText = new string(pem);

        var kvCert = CreateKeyVaultCertificateWithPolicy(
            exportable: true,
            version: TestCertificateVersion,
            cerBytes: inputCert.Export(X509ContentType.Cert));

        mocks.CertificateClient
            .Setup(c => c.GetCertificateAsync(TestCertificateName, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(kvCert, new Mock<Response>().Object));

        var secret = CreateKeyVaultSecret(pemText, contentType: "application/x-pem-file");
        mocks.SecretClient
            .Setup(s => s.GetSecretAsync(TestCertificateName, TestCertificateVersion, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(secret, new Mock<Response>().Object));

        using var source = new AzureKeyVaultCertificateSource(
            mocks.Factory.Object,
            TestCertificateName,
            certificateVersion: TestCertificateVersion,
            refreshInterval: null);

        var ex = Assert.ThrowsAsync<InvalidOperationException>(async () => await source.InitializeAsync());
        Assert.That(ex!.Message, Does.Contain("private key"));
    }

    [Test]
    public async Task InitializeAsync_WhenExportable_AndSecretContentTypeUnknownButIsPem_UsesPemFallback()
    {
        var mocks = CreateMocks();
        using var inputCert = LocalCertificateFactory.CreateRsaCertificate("AkvPemFallback", 2048);

        var certPem = new string(PemEncoding.Write("CERTIFICATE", inputCert.Export(X509ContentType.Cert)));

        // The current implementation uses X509Certificate2.CreateFromPem(string),
        // which loads the certificate but does not attach the private key.
        // This still exercises the fallback path after the PKCS12 decode attempt fails.
        var pemText = certPem + Environment.NewLine;

        var kvCert = CreateKeyVaultCertificateWithPolicy(
            exportable: true,
            version: TestCertificateVersion,
            cerBytes: inputCert.Export(X509ContentType.Cert));

        mocks.CertificateClient
            .Setup(c => c.GetCertificateAsync(TestCertificateName, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(kvCert, new Mock<Response>().Object));

        var secret = CreateKeyVaultSecret(pemText, contentType: "application/unknown");
        mocks.SecretClient
            .Setup(s => s.GetSecretAsync(TestCertificateName, TestCertificateVersion, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(secret, new Mock<Response>().Object));

        using var source = new AzureKeyVaultCertificateSource(
            mocks.Factory.Object,
            TestCertificateName,
            certificateVersion: TestCertificateVersion,
            refreshInterval: null);

        var ex = Assert.ThrowsAsync<InvalidOperationException>(async () => await source.InitializeAsync());
        Assert.That(ex!.Message, Does.Contain("private key"));
    }

    [Test]
    public async Task SignEcdsa_WhenLocalCertificateIsRsa_ThrowsInvalidOperationException()
    {
        var mocks = CreateMocks();
        using var inputCert = LocalCertificateFactory.CreateRsaCertificate("AkvRsaForEcdsa", 2048);
        var pfxBytes = inputCert.Export(X509ContentType.Pkcs12);
        var secretValue = Convert.ToBase64String(pfxBytes);

        var kvCert = CreateKeyVaultCertificateWithPolicy(
            exportable: true,
            version: TestCertificateVersion,
            cerBytes: inputCert.Export(X509ContentType.Cert));

        mocks.CertificateClient
            .Setup(c => c.GetCertificateAsync(TestCertificateName, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(kvCert, new Mock<Response>().Object));

        var secret = CreateKeyVaultSecret(secretValue, contentType: "application/x-pkcs12");
        mocks.SecretClient
            .Setup(s => s.GetSecretAsync(TestCertificateName, TestCertificateVersion, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(secret, new Mock<Response>().Object));

        using var source = new AzureKeyVaultCertificateSource(
            mocks.Factory.Object,
            TestCertificateName,
            certificateVersion: TestCertificateVersion,
            refreshInterval: null);
        await source.InitializeAsync();

        var data = new byte[] { 1, 2, 3, 4 };
        var ex1 = Assert.Throws<InvalidOperationException>(() => source.SignDataWithEcdsa(data, HashAlgorithmName.SHA256));
        Assert.That(ex1!.Message, Does.Contain("ECDSA"));

        var ex2 = Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await source.SignDataWithEcdsaAsync(data, HashAlgorithmName.SHA256));
        Assert.That(ex2!.Message, Does.Contain("ECDSA"));

        var hash = SHA256.HashData(data);
        var ex3 = Assert.Throws<InvalidOperationException>(() => source.SignHashWithEcdsa(hash));
        Assert.That(ex3!.Message, Does.Contain("ECDSA"));
    }

    [Test]
    public async Task BackgroundRefresh_WhenPinned_DoesNotCallKeyVaultClients()
    {
        var mocks = CreateMocks();
        using var source = new AzureKeyVaultCertificateSource(
            mocks.Factory.Object,
            TestCertificateName,
            certificateVersion: TestCertificateVersion,
            refreshInterval: null);

        var method = typeof(AzureKeyVaultCertificateSource)
            .GetMethod("TryRefreshFromTimerAsync", BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.That(method, Is.Not.Null);

        Assert.DoesNotThrowAsync(async () => await (Task)method!.Invoke(source, null)!);

        mocks.CertificateClient.Verify(
            c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Never);
        mocks.SecretClient.Verify(
            s => s.GetSecretAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Never);
        mocks.KeyClient.Verify(
            k => k.GetKeyAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Test]
    public async Task BackgroundRefresh_WhenInitializationThrows_SwallowsException()
    {
        var mocks = CreateMocks();
        mocks.CertificateClient
            .Setup(c => c.GetCertificateAsync(TestCertificateName, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new RequestFailedException(500, "boom"));

        using var source = new AzureKeyVaultCertificateSource(
            mocks.Factory.Object,
            TestCertificateName,
            certificateVersion: null,
            refreshInterval: null);

        var method = typeof(AzureKeyVaultCertificateSource)
            .GetMethod("TryRefreshFromTimerAsync", BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.That(method, Is.Not.Null);

        Assert.DoesNotThrowAsync(async () => await (Task)method!.Invoke(source, null)!);
    }

    [Test]
    public async Task TryRefreshCertificateAsync_WhenLatestVersionIsMissing_ReturnsFalse()
    {
        var mocks = CreateMocks();
        using var inputCert = LocalCertificateFactory.CreateRsaCertificate("AkvRefresh", 2048);
        var pfxBytes = inputCert.Export(X509ContentType.Pkcs12);
        var secretValue = Convert.ToBase64String(pfxBytes);

        var initKvCert = CreateKeyVaultCertificateWithPolicy(
            exportable: true,
            version: TestCertificateVersion,
            cerBytes: inputCert.Export(X509ContentType.Cert));

        var propertiesMissingVersion = CertificateModelFactory.CertificateProperties(
            name: TestCertificateName,
            id: new Uri($"{TestVaultUri}certificates/{TestCertificateName}/"),
            vaultUri: TestVaultUri,
            version: null);

        var missingVersionKvCert = CertificateModelFactory.KeyVaultCertificateWithPolicy(
            propertiesMissingVersion,
            TestKeyId,
            new Uri($"{TestVaultUri}secrets/{TestCertificateName}/{TestCertificateVersion}"),
            initKvCert.Cer,
            CreateCertificatePolicy(exportable: true));

        mocks.CertificateClient
            .SetupSequence(c => c.GetCertificateAsync(TestCertificateName, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(initKvCert, new Mock<Response>().Object))
            .ReturnsAsync(Response.FromValue(missingVersionKvCert, new Mock<Response>().Object));

        var secret = CreateKeyVaultSecret(secretValue, contentType: "application/x-pkcs12");
        mocks.SecretClient
            .Setup(s => s.GetSecretAsync(TestCertificateName, TestCertificateVersion, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(secret, new Mock<Response>().Object));

        using var source = new AzureKeyVaultCertificateSource(
            mocks.Factory.Object,
            TestCertificateName,
            certificateVersion: TestCertificateVersion,
            refreshInterval: null);
        await source.InitializeAsync();

        var method = typeof(AzureKeyVaultCertificateSource)
            .GetMethod("TryRefreshCertificateAsync", BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.That(method, Is.Not.Null);

        var task = (Task<bool>)method!.Invoke(source, new object[] { CancellationToken.None })!;
        var refreshed = await task;

        Assert.That(refreshed, Is.False);
    }

    [Test]
    public void InitializeAsync_WhenRemoteModeAndCertificateBytesEmpty_ThrowsInvalidOperationException()
    {
        var mocks = CreateMocks();
        using var inputCert = LocalCertificateFactory.CreateRsaCertificate("AkvRemoteEmpty", 2048);

        var kvCert = CreateKeyVaultCertificateWithPolicy(
            exportable: true,
            version: TestCertificateVersion,
            cerBytes: inputCert.Export(X509ContentType.Cert));

        mocks.CertificateClient
            .Setup(c => c.GetCertificateAsync(TestCertificateName, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(kvCert, new Mock<Response>().Object));

        mocks.CertificateClient
            .Setup(c => c.GetCertificateVersionAsync(TestCertificateName, TestCertificateVersion, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(
                CreateKeyVaultCertificateVersion(TestCertificateVersion, Array.Empty<byte>()),
                new Mock<Response>().Object));

        using var source = new AzureKeyVaultCertificateSource(
            mocks.Factory.Object,
            TestCertificateName,
            certificateVersion: TestCertificateVersion,
            refreshInterval: null,
            forceRemoteMode: true);

        var ex = Assert.ThrowsAsync<InvalidOperationException>(async () => await source.InitializeAsync());
        Assert.That(ex!.Message, Does.Contain("Certificate data"));
    }

    [Test]
    public async Task RefreshCertificateAsync_WhenPinned_ThrowsInvalidOperationException()
    {
        var mocks = CreateMocks();
        using var inputCert = LocalCertificateFactory.CreateRsaCertificate("AkvPinned", 2048);
        var kvCert = CreateKeyVaultCertificateWithPolicy(
            exportable: false,
            version: TestCertificateVersion,
            cerBytes: inputCert.Export(X509ContentType.Cert));

        mocks.CertificateClient
            .Setup(c => c.GetCertificateAsync(TestCertificateName, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(kvCert, new Mock<Response>().Object));

        mocks.CertificateClient
            .Setup(c => c.GetCertificateVersionAsync(TestCertificateName, TestCertificateVersion, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(
                CreateKeyVaultCertificateVersion(TestCertificateVersion, inputCert.Export(X509ContentType.Cert)),
                new Mock<Response>().Object));

        mocks.Factory
            .Setup(f => f.CreateCryptographyClient(It.IsAny<Uri>()))
            .Returns((Uri keyId) => new CryptographyClient(keyId, mocks.Credential.Object));

        var key = CreateKeyVaultRsaKey(TestKeyId);
        mocks.KeyClient
            .Setup(k => k.GetKeyAsync(TestCertificateName, TestCertificateVersion, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(key, new Mock<Response>().Object));

        using var source = new AzureKeyVaultCertificateSource(
            mocks.Factory.Object,
            TestCertificateName,
            certificateVersion: TestCertificateVersion);

        await source.InitializeAsync();
        Assert.ThrowsAsync<InvalidOperationException>(async () => await source.RefreshCertificateAsync());
    }

    [Test]
    public async Task SignHashWithRsaAsync_WhenRemote_DelegatesToCryptoWrapper()
    {
        var mocks = CreateMocks();
        var expectedSignature = new byte[] { 9, 8, 7, 6 };

        using var inputCert = LocalCertificateFactory.CreateRsaCertificate("AkvRemoteSign", 2048);
        var kvCert = CreateKeyVaultCertificateWithPolicy(
            exportable: true,
            version: TestCertificateVersion,
            cerBytes: inputCert.Export(X509ContentType.Cert));

        mocks.CertificateClient
            .Setup(c => c.GetCertificateAsync(TestCertificateName, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(kvCert, new Mock<Response>().Object));

        mocks.CertificateClient
            .Setup(c => c.GetCertificateVersionAsync(TestCertificateName, TestCertificateVersion, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(
                CreateKeyVaultCertificateVersion(TestCertificateVersion, inputCert.Export(X509ContentType.Cert)),
                new Mock<Response>().Object));

        var key = CreateKeyVaultRsaKey(TestKeyId);
        mocks.KeyClient
            .Setup(k => k.GetKeyAsync(TestCertificateName, TestCertificateVersion, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(key, new Mock<Response>().Object));

        var mockCryptoClient = new Mock<CryptographyClient>(MockBehavior.Strict, TestKeyId, mocks.Credential.Object);
        mockCryptoClient
            .Setup(c => c.SignAsync(It.IsAny<SignatureAlgorithm>(), It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((SignatureAlgorithm alg, byte[] hash, CancellationToken ct) =>
                CryptographyModelFactory.SignResult(
                    keyId: TestKeyId.ToString(),
                    signature: expectedSignature,
                    algorithm: alg));

        mocks.Factory
            .Setup(f => f.CreateCryptographyClient(It.IsAny<Uri>()))
            .Returns(mockCryptoClient.Object);

        using var source = new AzureKeyVaultCertificateSource(
            mocks.Factory.Object,
            TestCertificateName,
            certificateVersion: TestCertificateVersion,
            refreshInterval: null,
            forceRemoteMode: true);

        await source.InitializeAsync();

        var hash = SHA256.HashData(new byte[] { 1, 2, 3 });
        var actual = await source.SignHashWithRsaAsync(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        Assert.That(actual, Is.EqualTo(expectedSignature));
    }

    [Test]
    public async Task InitializeAsync_WhenExportable_AndSecretContentTypeUnknownButIsPkcs12_LoadsLocalCertificateAndSignsLocally()
    {
        var mocks = CreateMocks();
        using var inputCert = LocalCertificateFactory.CreateRsaCertificate("AkvLocalUnknownContentType", 2048);
        var pfxBytes = inputCert.Export(X509ContentType.Pkcs12);
        var secretValue = Convert.ToBase64String(pfxBytes);

        var kvCert = CreateKeyVaultCertificateWithPolicy(
            exportable: true,
            version: TestCertificateVersion,
            cerBytes: inputCert.Export(X509ContentType.Cert));

        mocks.CertificateClient
            .Setup(c => c.GetCertificateAsync(TestCertificateName, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(kvCert, new Mock<Response>().Object));

        // Exercise the fallback path: content-type is not one of the known values, but the value is still a base64 PKCS#12.
        var secret = CreateKeyVaultSecret(secretValue, contentType: "application/octet-stream");
        mocks.SecretClient
            .Setup(s => s.GetSecretAsync(TestCertificateName, TestCertificateVersion, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(secret, new Mock<Response>().Object));

        using var source = new AzureKeyVaultCertificateSource(mocks.Factory.Object, TestCertificateName);
        await source.InitializeAsync();

        Assert.That(source.KeyMode, Is.EqualTo(KeyVaultCertificateKeyMode.Local));
        Assert.That(source.RequiresRemoteSigning, Is.False);

        var data = new byte[] { 10, 20, 30, 40 };
        var signature = source.SignDataWithRsa(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        using var rsaPub = source.GetSigningCertificate().GetRSAPublicKey();
        Assert.That(rsaPub, Is.Not.Null);
        Assert.That(rsaPub!.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1), Is.True);

        mocks.KeyClient.VerifyNoOtherCalls();
    }

    [Test]
    public void InitializeAsync_WhenExportable_AndSecretMissingPrivateKey_ThrowsInvalidOperationException()
    {
        var mocks = CreateMocks();
        using var inputCert = LocalCertificateFactory.CreateRsaCertificate("AkvMissingKey", 2048);
        var pemCertOnly = inputCert.ExportCertificatePem();

        var kvCert = CreateKeyVaultCertificateWithPolicy(
            exportable: true,
            version: TestCertificateVersion,
            cerBytes: inputCert.Export(X509ContentType.Cert));

        mocks.CertificateClient
            .Setup(c => c.GetCertificateAsync(TestCertificateName, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(kvCert, new Mock<Response>().Object));

        var secret = CreateKeyVaultSecret(pemCertOnly, contentType: "application/x-pem-file");
        mocks.SecretClient
            .Setup(s => s.GetSecretAsync(TestCertificateName, TestCertificateVersion, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(secret, new Mock<Response>().Object));

        using var source = new AzureKeyVaultCertificateSource(mocks.Factory.Object, TestCertificateName);

        var ex = Assert.ThrowsAsync<InvalidOperationException>(async () => await source.InitializeAsync());
        Assert.That(ex!.Message, Does.Contain("private key"));
    }

    [Test]
    public void InitializeAsync_WhenRemote_AndCertificateCerEmpty_ThrowsInvalidOperationException()
    {
        var mocks = CreateMocks();
        using var inputCert = LocalCertificateFactory.CreateRsaCertificate("AkvRemoteEmptyCer", 2048);

        var kvCert = CreateKeyVaultCertificateWithPolicy(
            exportable: false,
            version: TestCertificateVersion,
            cerBytes: Array.Empty<byte>());

        mocks.CertificateClient
            .Setup(c => c.GetCertificateAsync(TestCertificateName, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(kvCert, new Mock<Response>().Object));

        using var source = new AzureKeyVaultCertificateSource(mocks.Factory.Object, TestCertificateName);

        var ex = Assert.ThrowsAsync<InvalidOperationException>(async () => await source.InitializeAsync());
        Assert.That(ex!.Message, Does.Contain("Certificate data"));
    }

    [Test]
    public async Task RefreshCertificateAsync_WhenVersionUnchanged_ReturnsFalse()
    {
        var mocks = CreateMocks();
        using var inputCert = LocalCertificateFactory.CreateRsaCertificate("AkvRefreshSame", 2048);
        var kvCertV1 = CreateKeyVaultCertificateWithPolicy(
            exportable: false,
            version: TestCertificateVersion,
            cerBytes: inputCert.Export(X509ContentType.Cert));

        mocks.CertificateClient
            .SetupSequence(c => c.GetCertificateAsync(TestCertificateName, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(kvCertV1, new Mock<Response>().Object)) // init
            .ReturnsAsync(Response.FromValue(kvCertV1, new Mock<Response>().Object)); // refresh latest

        mocks.Factory
            .Setup(f => f.CreateCryptographyClient(It.IsAny<Uri>()))
            .Returns((Uri keyId) => new CryptographyClient(keyId, mocks.Credential.Object));

        var keyV1 = CreateKeyVaultRsaKey(TestKeyId);
        mocks.KeyClient
            .Setup(k => k.GetKeyAsync(TestCertificateName, TestCertificateVersion, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(keyV1, new Mock<Response>().Object));

        using var source = new AzureKeyVaultCertificateSource(mocks.Factory.Object, TestCertificateName);
        await source.InitializeAsync();

        var changed = await source.RefreshCertificateAsync();

        Assert.That(changed, Is.False);
        Assert.That(source.Version, Is.EqualTo(TestCertificateVersion));
    }

    [Test]
    public async Task RefreshCertificateAsync_WhenVersionChanges_ReturnsTrueAndUpdatesVersion()
    {
        var mocks = CreateMocks();
        const string v1 = "v1";
        const string v2 = "v2";

        using var certV1 = LocalCertificateFactory.CreateRsaCertificate("AkvRefreshV1", 2048);
        using var certV2 = LocalCertificateFactory.CreateRsaCertificate("AkvRefreshV2", 2048);

        var kvCert1 = CreateKeyVaultCertificateWithPolicy(
            exportable: false,
            version: v1,
            cerBytes: certV1.Export(X509ContentType.Cert));

        var kvCert2 = CreateKeyVaultCertificateWithPolicy(
            exportable: false,
            version: v2,
            cerBytes: certV2.Export(X509ContentType.Cert));

        mocks.CertificateClient
            .SetupSequence(c => c.GetCertificateAsync(TestCertificateName, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(kvCert1, new Mock<Response>().Object)) // init state
            .ReturnsAsync(Response.FromValue(kvCert2, new Mock<Response>().Object)) // refresh latest check
            .ReturnsAsync(Response.FromValue(kvCert2, new Mock<Response>().Object)); // refresh load state

        mocks.Factory
            .Setup(f => f.CreateCryptographyClient(It.IsAny<Uri>()))
            .Returns((Uri keyId) => new CryptographyClient(keyId, mocks.Credential.Object));

        var keyIdV1 = new Uri("https://test-vault.vault.azure.net/keys/test-signing-cert/v1");
        var keyIdV2 = new Uri("https://test-vault.vault.azure.net/keys/test-signing-cert/v2");

        var keyV1 = CreateKeyVaultRsaKey(keyIdV1);
        var keyV2 = CreateKeyVaultRsaKey(keyIdV2);

        mocks.KeyClient
            .Setup(k => k.GetKeyAsync(TestCertificateName, v1, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(keyV1, new Mock<Response>().Object));

        mocks.KeyClient
            .Setup(k => k.GetKeyAsync(TestCertificateName, v2, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(keyV2, new Mock<Response>().Object));

        using var source = new AzureKeyVaultCertificateSource(mocks.Factory.Object, TestCertificateName);
        await source.InitializeAsync();

        Assert.That(source.Version, Is.EqualTo(v1));

        var changed = await source.RefreshCertificateAsync();

        Assert.That(changed, Is.True);
        Assert.That(source.Version, Is.EqualTo(v2));
    }

    [Test]
    public async Task InitializeAsync_WhenExportable_AndEcdsaCertificate_LoadsLocalCertificateAndSignsLocally()
    {
        var mocks = CreateMocks();
        using var inputCert = LocalCertificateFactory.CreateEcdsaCertificate("AkvLocalEcdsa", 256);
        var pfxBytes = inputCert.Export(X509ContentType.Pkcs12);
        var secretValue = Convert.ToBase64String(pfxBytes);

        var kvCert = CreateKeyVaultCertificateWithPolicy(
            exportable: true,
            version: TestCertificateVersion,
            cerBytes: inputCert.Export(X509ContentType.Cert));

        mocks.CertificateClient
            .Setup(c => c.GetCertificateAsync(TestCertificateName, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(kvCert, new Mock<Response>().Object));

        var secret = CreateKeyVaultSecret(secretValue, contentType: "application/x-pkcs12");
        mocks.SecretClient
            .Setup(s => s.GetSecretAsync(TestCertificateName, TestCertificateVersion, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(secret, new Mock<Response>().Object));

        using var source = new AzureKeyVaultCertificateSource(mocks.Factory.Object, TestCertificateName);
        await source.InitializeAsync();

        Assert.That(source.KeyMode, Is.EqualTo(KeyVaultCertificateKeyMode.Local));
        Assert.That(source.RequiresRemoteSigning, Is.False);

        var data = new byte[] { 1, 4, 9, 16, 25 };
        var signature1 = source.SignDataWithEcdsa(data, HashAlgorithmName.SHA256);

        using var ecdsaPub = source.GetSigningCertificate().GetECDsaPublicKey();
        Assert.That(ecdsaPub, Is.Not.Null);
        Assert.That(ecdsaPub!.VerifyData(data, signature1, HashAlgorithmName.SHA256), Is.True);

        var hash = SHA256.HashData(new byte[] { 6, 7, 8, 9 });
        var signature2 = await source.SignHashWithEcdsaAsync(hash);
        Assert.That(ecdsaPub.VerifyHash(hash, signature2), Is.True);

        mocks.KeyClient.VerifyNoOtherCalls();
    }

    [Test]
    public void Constructor_ExposesVaultUriNameAndPinnedRefreshProperties()
    {
        var mocks = CreateMocks();
        using var pinned = new AzureKeyVaultCertificateSource(
            mocks.Factory.Object,
            TestCertificateName,
            certificateVersion: TestCertificateVersion,
            refreshInterval: TimeSpan.FromSeconds(1));

        Assert.That(pinned.VaultUri, Is.EqualTo(TestVaultUri));
        Assert.That(pinned.Name, Is.EqualTo(TestCertificateName));
        Assert.That(pinned.IsPinnedVersion, Is.True);
        Assert.That(pinned.AutoRefreshInterval, Is.Null);

        using var unpinned = new AzureKeyVaultCertificateSource(mocks.Factory.Object, TestCertificateName);
        Assert.That(unpinned.IsPinnedVersion, Is.False);
        Assert.That(unpinned.AutoRefreshInterval, Is.EqualTo(TimeSpan.FromMinutes(15)));
    }

    [Test]
    public async Task InitializeAsync_WhenCalledTwice_DoesNotReloadState()
    {
        var mocks = CreateMocks();
        using var inputCert = LocalCertificateFactory.CreateRsaCertificate("AkvInitTwice", 2048);
        var pfxBytes = inputCert.Export(X509ContentType.Pkcs12);
        var secretValue = Convert.ToBase64String(pfxBytes);

        var kvCert = CreateKeyVaultCertificateWithPolicy(
            exportable: true,
            version: TestCertificateVersion,
            cerBytes: inputCert.Export(X509ContentType.Cert));

        mocks.CertificateClient
            .Setup(c => c.GetCertificateAsync(TestCertificateName, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(kvCert, new Mock<Response>().Object));

        var secret = CreateKeyVaultSecret(secretValue, contentType: "application/x-pkcs12");
        mocks.SecretClient
            .Setup(s => s.GetSecretAsync(TestCertificateName, TestCertificateVersion, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(secret, new Mock<Response>().Object));

        using var source = new AzureKeyVaultCertificateSource(mocks.Factory.Object, TestCertificateName);
        await source.InitializeAsync();
        await source.InitializeAsync();

        mocks.CertificateClient.Verify(c => c.GetCertificateAsync(TestCertificateName, It.IsAny<CancellationToken>()), Times.Once);
        mocks.SecretClient.Verify(s => s.GetSecretAsync(TestCertificateName, TestCertificateVersion, It.IsAny<CancellationToken>()), Times.Once);
        mocks.KeyClient.VerifyNoOtherCalls();
    }

    [Test]
    public async Task SignMethods_WhenLocalEcdsa_CoversSyncAndAsyncVariants()
    {
        var mocks = CreateMocks();
        using var inputCert = LocalCertificateFactory.CreateEcdsaCertificate("AkvLocalEcdsaVariants", 256);
        var pfxBytes = inputCert.Export(X509ContentType.Pkcs12);
        var secretValue = Convert.ToBase64String(pfxBytes);

        var kvCert = CreateKeyVaultCertificateWithPolicy(
            exportable: true,
            version: TestCertificateVersion,
            cerBytes: inputCert.Export(X509ContentType.Cert));

        mocks.CertificateClient
            .Setup(c => c.GetCertificateAsync(TestCertificateName, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(kvCert, new Mock<Response>().Object));

        var secret = CreateKeyVaultSecret(secretValue, contentType: "application/x-pkcs12");
        mocks.SecretClient
            .Setup(s => s.GetSecretAsync(TestCertificateName, TestCertificateVersion, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(secret, new Mock<Response>().Object));

        using var source = new AzureKeyVaultCertificateSource(mocks.Factory.Object, TestCertificateName);
        await source.InitializeAsync();

        using var ecdsaPub = source.GetSigningCertificate().GetECDsaPublicKey();
        Assert.That(ecdsaPub, Is.Not.Null);

        var data = new byte[] { 1, 1, 2, 3, 5, 8, 13 };
        var sig1 = await source.SignDataWithEcdsaAsync(data, HashAlgorithmName.SHA256);
        Assert.That(ecdsaPub!.VerifyData(data, sig1, HashAlgorithmName.SHA256), Is.True);

        var hash = SHA256.HashData(data);
        var sig2 = source.SignHashWithEcdsa(hash);
        Assert.That(ecdsaPub.VerifyHash(hash, sig2), Is.True);

        var sig3 = source.SignHashWithEcdsaAsync(hash);
        Assert.That(ecdsaPub.VerifyHash(hash, await sig3), Is.True);

        mocks.KeyClient.VerifyNoOtherCalls();
    }

    [Test]
    public async Task TryRefreshFromTimerAsync_WhenInitializationThrows_DoesNotThrow()
    {
        var mocks = CreateMocks();
        mocks.CertificateClient
            .Setup(c => c.GetCertificateAsync(TestCertificateName, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new RequestFailedException("Simulated failure"));

        using var source = new AzureKeyVaultCertificateSource(mocks.Factory.Object, TestCertificateName);

        var method = typeof(AzureKeyVaultCertificateSource).GetMethod(
            "TryRefreshFromTimerAsync",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);

        Assert.That(method, Is.Not.Null);
        var task = (Task)method!.Invoke(source, null)!;
        await task;
    }

    [Test]
    public async Task InitializeAsync_WhenForceRemoteMode_AndEcdsa_SignHashDelegatesToCryptoWrapper()
    {
        var mocks = CreateMocks();
        var expectedSignature = new byte[] { 5, 4, 3, 2, 1 };

        using var inputCert = LocalCertificateFactory.CreateEcdsaCertificate("AkvRemoteEcdsa", 256);

        var kvCert = CreateKeyVaultCertificateWithPolicy(
            exportable: true,
            version: TestCertificateVersion,
            cerBytes: inputCert.Export(X509ContentType.Cert));

        mocks.CertificateClient
            .Setup(c => c.GetCertificateAsync(TestCertificateName, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(kvCert, new Mock<Response>().Object));

        // Pinned version triggers a GetCertificateVersionAsync call for the public cert bytes.
        mocks.CertificateClient
            .Setup(c => c.GetCertificateVersionAsync(TestCertificateName, TestCertificateVersion, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(
                CreateKeyVaultCertificateVersion(TestCertificateVersion, inputCert.Export(X509ContentType.Cert)),
                new Mock<Response>().Object));

        var key = CreateKeyVaultEcKey(TestKeyId);
        mocks.KeyClient
            .Setup(k => k.GetKeyAsync(TestCertificateName, TestCertificateVersion, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(key, new Mock<Response>().Object));

        var mockCryptoClient = new Mock<CryptographyClient>(MockBehavior.Strict, TestKeyId, mocks.Credential.Object);
        mockCryptoClient
            .Setup(c => c.SignAsync(It.IsAny<SignatureAlgorithm>(), It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((SignatureAlgorithm alg, byte[] hash, CancellationToken ct) =>
                CryptographyModelFactory.SignResult(
                    keyId: TestKeyId.ToString(),
                    signature: expectedSignature,
                    algorithm: alg));

        mocks.Factory
            .Setup(f => f.CreateCryptographyClient(It.IsAny<Uri>()))
            .Returns(mockCryptoClient.Object);

        using var source = new AzureKeyVaultCertificateSource(
            mocks.Factory.Object,
            TestCertificateName,
            certificateVersion: TestCertificateVersion,
            refreshInterval: null,
            forceRemoteMode: true);

        await source.InitializeAsync();

        Assert.That(source.KeyMode, Is.EqualTo(KeyVaultCertificateKeyMode.Remote));
        Assert.That(source.RequiresRemoteSigning, Is.True);

        var hash = SHA256.HashData(new byte[] { 1, 2, 3 });
        var actual = await source.SignHashWithEcdsaAsync(hash);
        Assert.That(actual, Is.EqualTo(expectedSignature));

        // Remote mode should not attempt to download secrets.
        mocks.SecretClient.VerifyNoOtherCalls();
    }

    [Test]
    public void SignDataWithMLDsa_Always_ThrowsNotSupportedException()
    {
        var mocks = CreateMocks();
        using var source = new AzureKeyVaultCertificateSource(mocks.Factory.Object, TestCertificateName);
        Assert.Throws<NotSupportedException>(() => source.SignDataWithMLDsa(new byte[] { 1, 2, 3 }));
    }

    [Test]
    public void SignDataWithMLDsaAsync_Always_ThrowsNotSupportedException()
    {
        var mocks = CreateMocks();
        using var source = new AzureKeyVaultCertificateSource(mocks.Factory.Object, TestCertificateName);
        Assert.ThrowsAsync<NotSupportedException>(async () => await source.SignDataWithMLDsaAsync(new byte[] { 1, 2, 3 }));
    }

    [Test]
    public async Task Dispose_AfterInitialize_MethodsThrowObjectDisposedException()
    {
        var mocks = CreateMocks();
        using var inputCert = LocalCertificateFactory.CreateRsaCertificate("AkvDispose", 2048);
        var pfxBytes = inputCert.Export(X509ContentType.Pkcs12);
        var secretValue = Convert.ToBase64String(pfxBytes);

        var kvCert = CreateKeyVaultCertificateWithPolicy(
            exportable: true,
            version: TestCertificateVersion,
            cerBytes: inputCert.Export(X509ContentType.Cert));

        mocks.CertificateClient
            .Setup(c => c.GetCertificateAsync(TestCertificateName, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(kvCert, new Mock<Response>().Object));

        var secret = CreateKeyVaultSecret(secretValue, contentType: "application/x-pkcs12");
        mocks.SecretClient
            .Setup(s => s.GetSecretAsync(TestCertificateName, TestCertificateVersion, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(secret, new Mock<Response>().Object));

        var source = new AzureKeyVaultCertificateSource(mocks.Factory.Object, TestCertificateName);
        await source.InitializeAsync();
        source.Dispose();

        Assert.Throws<ObjectDisposedException>(() => source.GetSigningCertificate());
        Assert.ThrowsAsync<ObjectDisposedException>(async () => await source.SignHashWithRsaAsync(new byte[] { 1, 2, 3 }, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    [Test]
    public async Task SignMethods_WhenLocalRsa_CoversSyncAndAsyncVariants()
    {
        var mocks = CreateMocks();
        using var inputCert = LocalCertificateFactory.CreateRsaCertificate("AkvLocalRsaVariants", 2048);
        var pfxBytes = inputCert.Export(X509ContentType.Pkcs12);
        var secretValue = Convert.ToBase64String(pfxBytes);

        var kvCert = CreateKeyVaultCertificateWithPolicy(
            exportable: true,
            version: TestCertificateVersion,
            cerBytes: inputCert.Export(X509ContentType.Cert));

        mocks.CertificateClient
            .Setup(c => c.GetCertificateAsync(TestCertificateName, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(kvCert, new Mock<Response>().Object));

        var secret = CreateKeyVaultSecret(secretValue, contentType: "application/x-pkcs12");
        mocks.SecretClient
            .Setup(s => s.GetSecretAsync(TestCertificateName, TestCertificateVersion, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(secret, new Mock<Response>().Object));

        using var source = new AzureKeyVaultCertificateSource(mocks.Factory.Object, TestCertificateName);
        await source.InitializeAsync();

        using var rsaPub = source.GetSigningCertificate().GetRSAPublicKey();
        Assert.That(rsaPub, Is.Not.Null);

        var data = new byte[] { 1, 2, 3, 4, 5, 6 };
        var sig1 = source.SignDataWithRsa(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        Assert.That(rsaPub!.VerifyData(data, sig1, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1), Is.True);

        var sig2 = await source.SignDataWithRsaAsync(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        Assert.That(rsaPub.VerifyData(data, sig2, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1), Is.True);

        var hash = SHA256.HashData(data);
        var sig3 = source.SignHashWithRsa(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        Assert.That(rsaPub.VerifyHash(hash, sig3, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1), Is.True);

        var sig4 = await source.SignHashWithRsaAsync(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        Assert.That(rsaPub.VerifyHash(hash, sig4, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1), Is.True);
    }

    [Test]
    public async Task SignMethods_WhenRemoteRsa_DelegatesToCryptoWrapper_ForSyncAndAsyncVariants()
    {
        var mocks = CreateMocks();
        var expectedSignature = new byte[] { 9, 9, 9, 9 };

        using var inputCert = LocalCertificateFactory.CreateRsaCertificate("AkvRemoteRsaVariants", 2048);
        var kvCert = CreateKeyVaultCertificateWithPolicy(
            exportable: false,
            version: TestCertificateVersion,
            cerBytes: inputCert.Export(X509ContentType.Cert));

        mocks.CertificateClient
            .Setup(c => c.GetCertificateAsync(TestCertificateName, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(kvCert, new Mock<Response>().Object));

        mocks.CertificateClient
            .Setup(c => c.GetCertificateVersionAsync(TestCertificateName, TestCertificateVersion, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(
                CreateKeyVaultCertificateVersion(TestCertificateVersion, inputCert.Export(X509ContentType.Cert)),
                new Mock<Response>().Object));

        var key = CreateKeyVaultRsaKey(TestKeyId);
        mocks.KeyClient
            .Setup(k => k.GetKeyAsync(TestCertificateName, TestCertificateVersion, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(key, new Mock<Response>().Object));

        var mockCryptoClient = new Mock<CryptographyClient>(MockBehavior.Strict, TestKeyId, mocks.Credential.Object);
        mockCryptoClient
            .Setup(c => c.SignAsync(It.IsAny<SignatureAlgorithm>(), It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((SignatureAlgorithm alg, byte[] hash, CancellationToken ct) =>
                CryptographyModelFactory.SignResult(
                    keyId: TestKeyId.ToString(),
                    signature: expectedSignature,
                    algorithm: alg));

        mocks.Factory
            .Setup(f => f.CreateCryptographyClient(It.IsAny<Uri>()))
            .Returns(mockCryptoClient.Object);

        using var source = new AzureKeyVaultCertificateSource(
            mocks.Factory.Object,
            TestCertificateName,
            certificateVersion: TestCertificateVersion,
            refreshInterval: null);

        await source.InitializeAsync();

        var data = new byte[] { 10, 20, 30 };
        var sig1 = source.SignDataWithRsa(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        Assert.That(sig1, Is.EqualTo(expectedSignature));

        var sig2 = await source.SignDataWithRsaAsync(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        Assert.That(sig2, Is.EqualTo(expectedSignature));

        var hash = SHA256.HashData(new byte[] { 1, 2, 3, 4 });
        var sig3 = source.SignHashWithRsa(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        Assert.That(sig3, Is.EqualTo(expectedSignature));

        var sig4 = await source.SignHashWithRsaAsync(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        Assert.That(sig4, Is.EqualTo(expectedSignature));

        // Remote mode should not attempt to download secrets.
        mocks.SecretClient.VerifyNoOtherCalls();
    }

    [Test]
    public async Task RefreshCertificateAsync_WhenCalledConcurrently_SecondCallReturnsFalse()
    {
        var mocks = CreateMocks();
        var v1Cert = LocalCertificateFactory.CreateRsaCertificate("AkvRefreshConcurrency", 2048);
        using (v1Cert)
        {
            var kvCertV1 = CreateKeyVaultCertificateWithPolicy(
                exportable: false,
                version: TestCertificateVersion,
                cerBytes: v1Cert.Export(X509ContentType.Cert));

            var enteredRefreshGet = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var refreshGetTcs = new TaskCompletionSource<Response<KeyVaultCertificateWithPolicy>>(TaskCreationOptions.RunContinuationsAsynchronously);

            mocks.CertificateClient
                .SetupSequence(c => c.GetCertificateAsync(TestCertificateName, It.IsAny<CancellationToken>()))
                .ReturnsAsync(Response.FromValue(kvCertV1, new Mock<Response>().Object))
                .Returns(() =>
                {
                    enteredRefreshGet.TrySetResult();
                    return refreshGetTcs.Task;
                });

            mocks.Factory
                .Setup(f => f.CreateCryptographyClient(It.IsAny<Uri>()))
                .Returns((Uri keyId) => new CryptographyClient(keyId, mocks.Credential.Object));

            var keyV1 = CreateKeyVaultRsaKey(TestKeyId);
            mocks.KeyClient
                .Setup(k => k.GetKeyAsync(TestCertificateName, TestCertificateVersion, It.IsAny<CancellationToken>()))
                .ReturnsAsync(Response.FromValue(keyV1, new Mock<Response>().Object));

            using var source = new AzureKeyVaultCertificateSource(mocks.Factory.Object, TestCertificateName, refreshInterval: null);
            await source.InitializeAsync();

            var refresh1 = source.RefreshCertificateAsync();
            await enteredRefreshGet.Task;

            var refresh2 = await source.RefreshCertificateAsync();
            Assert.That(refresh2, Is.False);

            // Unblock refresh1 with an invalid/empty latest version so it returns false.
            var latestNoVersion = CreateKeyVaultCertificateWithPolicy(
                exportable: false,
                version: string.Empty,
                cerBytes: v1Cert.Export(X509ContentType.Cert));

            refreshGetTcs.SetResult(Response.FromValue(latestNoVersion, new Mock<Response>().Object));
            var refresh1Result = await refresh1;
            Assert.That(refresh1Result, Is.False);
        }
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

    private static KeyVaultCertificateWithPolicy CreateKeyVaultCertificateWithPolicy(bool exportable, string version, byte[] cerBytes)
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

    private static KeyVaultCertificate CreateKeyVaultCertificateVersion(string version, byte[] cerBytes)
    {
        var properties = CertificateModelFactory.CertificateProperties(
            name: TestCertificateName,
            id: new Uri($"{TestVaultUri}certificates/{TestCertificateName}/{version}"),
            vaultUri: TestVaultUri,
            version: version);

        // This Azure SDK version returns KeyVaultCertificate (no Policy) for GetCertificateVersionAsync.
        return CertificateModelFactory.KeyVaultCertificate(
            properties,
            TestKeyId,
            new Uri($"{TestVaultUri}secrets/{TestCertificateName}/{version}"),
            cerBytes);
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

    private static KeyVaultKey CreateKeyVaultEcKey(Uri keyId)
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var jsonWebKey = new JsonWebKey(ecdsa, includePrivateParameters: false);

        var keyProperties = KeyModelFactory.KeyProperties(
            id: keyId,
            vaultUri: new Uri(keyId.GetLeftPart(UriPartial.Authority)),
            name: "key",
            version: keyId.Segments.Length > 0 ? keyId.Segments[^1].TrimEnd('/') : "v1");

        return KeyModelFactory.KeyVaultKey(properties: keyProperties, key: jsonWebKey);
    }

}
