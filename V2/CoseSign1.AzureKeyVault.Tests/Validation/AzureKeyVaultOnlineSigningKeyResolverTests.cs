// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.AzureKeyVault.Tests.Validation;

using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Text;
using Azure;
using Azure.Security.KeyVault.Keys;
using CoseSign1.AzureKeyVault.Common;
using CoseSign1.AzureKeyVault.Validation;
using Moq;
using NUnit.Framework;

[TestFixture]
[Category("AzureKeyVault")]
[Category("Validation")]
public class AzureKeyVaultOnlineSigningKeyResolverTests
{
    private static readonly Uri VaultUri = new("https://myvault.vault.azure.net/");

    [Test]
    public async Task ResolveAsync_WithNullMessage_ReturnsFailure()
    {
        var mockFactory = new Mock<IKeyVaultClientFactory>(MockBehavior.Strict);
        var resolver = new AzureKeyVaultOnlineSigningKeyResolver(mockFactory.Object);

        var result = await resolver.ResolveAsync(null!);

        Assert.That(result.IsSuccess, Is.False);
        Assert.That(result.ErrorCode, Is.EqualTo("NULL_INPUT"));
    }

    [Test]
    public async Task ResolveAsync_WithMissingKid_ReturnsFailure()
    {
        using var rsa = RSA.Create(2048);
        var signer = new CoseSigner(rsa, RSASignaturePadding.Pss, HashAlgorithmName.SHA256, protectedHeaders: null, unprotectedHeaders: null);
        var bytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var message = CoseSign1Message.DecodeSign1(bytes);

        var mockFactory = new Mock<IKeyVaultClientFactory>(MockBehavior.Strict);
        var resolver = new AzureKeyVaultOnlineSigningKeyResolver(mockFactory.Object);

        var result = await resolver.ResolveAsync(message);

        Assert.That(result.IsSuccess, Is.False);
        Assert.That(result.ErrorCode, Is.EqualTo("KID_INVALID"));
    }

    [Test]
    public async Task ResolveAsync_WithInvalidKidUri_ReturnsFailure()
    {
        using var rsa = RSA.Create(2048);

        CoseHeaderMap protectedHeaders = new();
        protectedHeaders.Add(new CoseHeaderLabel(4), Encoding.UTF8.GetBytes("not a uri"));

        var signer = new CoseSigner(rsa, RSASignaturePadding.Pss, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders: null);
        var bytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var message = CoseSign1Message.DecodeSign1(bytes);

        var mockFactory = new Mock<IKeyVaultClientFactory>(MockBehavior.Strict);
        var resolver = new AzureKeyVaultOnlineSigningKeyResolver(mockFactory.Object);

        var result = await resolver.ResolveAsync(message);

        Assert.That(result.IsSuccess, Is.False);
        Assert.That(result.ErrorCode, Is.EqualTo("KID_INVALID"));
    }

    [Test]
    public async Task ResolveAsync_WithValidKid_FetchesKeyAndVerifiesSignature()
    {
        using var rsa = RSA.Create(2048);
        var kid = "https://myvault.vault.azure.net/keys/mykey/abc";
        var kidBytes = Encoding.UTF8.GetBytes(kid);

        var jsonWebKey = new JsonWebKey(rsa, includePrivateParameters: false);
        var keyProps = KeyModelFactory.KeyProperties(id: new Uri(kid), vaultUri: VaultUri, name: "mykey", version: "abc");
        var keyVaultKey = KeyModelFactory.KeyVaultKey(properties: keyProps, key: jsonWebKey);

        var mockKeyClient = new Mock<KeyClient>(MockBehavior.Strict);
        mockKeyClient
            .Setup(c => c.GetKeyAsync("mykey", "abc", It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(keyVaultKey, new Mock<Response>().Object));

        var mockFactory = new Mock<IKeyVaultClientFactory>(MockBehavior.Strict);
        mockFactory.SetupGet(f => f.VaultUri).Returns(VaultUri);
        mockFactory.SetupGet(f => f.KeyClient).Returns(mockKeyClient.Object);

        // Sign a message and include kid header.
        CoseHeaderMap protectedHeaders = new();
        protectedHeaders.Add(new CoseHeaderLabel(4), kidBytes);
        var signer = new CoseSigner(rsa, RSASignaturePadding.Pss, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders: null);

        var bytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var message = CoseSign1Message.DecodeSign1(bytes);

        var resolver = new AzureKeyVaultOnlineSigningKeyResolver(mockFactory.Object);
        var result = await resolver.ResolveAsync(message);

        Assert.That(result.IsSuccess, Is.True);
        Assert.That(result.SigningKey, Is.Not.Null);

        using (result.SigningKey)
        {
            Assert.That(message.VerifyEmbedded(result.SigningKey!.GetCoseKey()), Is.True);
        }
     }

    [Test]
    public async Task ResolveAsync_WithVaultMismatch_ReturnsFailure()
    {
        using var rsa = RSA.Create(2048);
        var kid = "https://myvault.vault.azure.net/keys/mykey/abc";

        CoseHeaderMap protectedHeaders = new();
        protectedHeaders.Add(new CoseHeaderLabel(4), Encoding.UTF8.GetBytes(kid));

        var signer = new CoseSigner(rsa, RSASignaturePadding.Pss, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders: null);
        var bytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var message = CoseSign1Message.DecodeSign1(bytes);

        var otherVaultUri = new Uri("https://othervault.vault.azure.net/");
        var mockFactory = new Mock<IKeyVaultClientFactory>(MockBehavior.Strict);
        mockFactory.SetupGet(f => f.VaultUri).Returns(otherVaultUri);
        mockFactory.SetupGet(f => f.KeyClient).Returns(new Mock<KeyClient>().Object);

        var resolver = new AzureKeyVaultOnlineSigningKeyResolver(mockFactory.Object);
        var result = await resolver.ResolveAsync(message);

        Assert.That(result.IsSuccess, Is.False);
        Assert.That(result.ErrorCode, Is.EqualTo("VAULT_MISMATCH"));
    }

    [Test]
    public async Task ResolveAsync_WhenKeyFetchThrows_ReturnsFailure()
    {
        using var rsa = RSA.Create(2048);
        var kid = "https://myvault.vault.azure.net/keys/mykey/abc";

        CoseHeaderMap protectedHeaders = new();
        protectedHeaders.Add(new CoseHeaderLabel(4), Encoding.UTF8.GetBytes(kid));

        var signer = new CoseSigner(rsa, RSASignaturePadding.Pss, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders: null);
        var bytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var message = CoseSign1Message.DecodeSign1(bytes);

        var mockKeyClient = new Mock<KeyClient>(MockBehavior.Strict);
        mockKeyClient
            .Setup(c => c.GetKeyAsync("mykey", "abc", It.IsAny<CancellationToken>()))
            .ThrowsAsync(new RequestFailedException(500, "boom"));

        var mockFactory = new Mock<IKeyVaultClientFactory>(MockBehavior.Strict);
        mockFactory.SetupGet(f => f.VaultUri).Returns(VaultUri);
        mockFactory.SetupGet(f => f.KeyClient).Returns(mockKeyClient.Object);

        var resolver = new AzureKeyVaultOnlineSigningKeyResolver(mockFactory.Object);
        var result = await resolver.ResolveAsync(message);

        Assert.That(result.IsSuccess, Is.False);
        Assert.That(result.ErrorCode, Is.EqualTo("KEY_FETCH_FAILED"));
    }

    [Test]
    public async Task ResolveAsync_WithUnsupportedKeyType_ReturnsFailure()
    {
        using var rsa = RSA.Create(2048);
        var kid = "https://myvault.vault.azure.net/keys/mykey/abc";

        CoseHeaderMap protectedHeaders = new();
        protectedHeaders.Add(new CoseHeaderLabel(4), Encoding.UTF8.GetBytes(kid));

        var signer = new CoseSigner(rsa, RSASignaturePadding.Pss, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders: null);
        var bytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var message = CoseSign1Message.DecodeSign1(bytes);

        var jsonWebKey = new JsonWebKey(rsa, includePrivateParameters: false)
        {
            KeyType = KeyType.Oct
        };
        var keyProps = KeyModelFactory.KeyProperties(id: new Uri(kid), vaultUri: VaultUri, name: "mykey", version: "abc");
        var keyVaultKey = KeyModelFactory.KeyVaultKey(properties: keyProps, key: jsonWebKey);

        var mockKeyClient = new Mock<KeyClient>(MockBehavior.Strict);
        mockKeyClient
            .Setup(c => c.GetKeyAsync("mykey", "abc", It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(keyVaultKey, new Mock<Response>().Object));

        var mockFactory = new Mock<IKeyVaultClientFactory>(MockBehavior.Strict);
        mockFactory.SetupGet(f => f.VaultUri).Returns(VaultUri);
        mockFactory.SetupGet(f => f.KeyClient).Returns(mockKeyClient.Object);

        var resolver = new AzureKeyVaultOnlineSigningKeyResolver(mockFactory.Object);
        var result = await resolver.ResolveAsync(message);

        Assert.That(result.IsSuccess, Is.False);
        Assert.That(result.ErrorCode, Is.EqualTo("KEY_TYPE_UNSUPPORTED"));
    }

    [Test]
    public async Task ResolveAsync_WithEcKid_FetchesKeyAndVerifiesSignature()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var kid = "https://myvault.vault.azure.net/keys/myec/abc";

        var jsonWebKey = new JsonWebKey(ecdsa, includePrivateParameters: false);
        var keyProps = KeyModelFactory.KeyProperties(id: new Uri(kid), vaultUri: VaultUri, name: "myec", version: "abc");
        var keyVaultKey = KeyModelFactory.KeyVaultKey(properties: keyProps, key: jsonWebKey);

        var mockKeyClient = new Mock<KeyClient>(MockBehavior.Strict);
        mockKeyClient
            .Setup(c => c.GetKeyAsync("myec", "abc", It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(keyVaultKey, new Mock<Response>().Object));

        var mockFactory = new Mock<IKeyVaultClientFactory>(MockBehavior.Strict);
        mockFactory.SetupGet(f => f.VaultUri).Returns(VaultUri);
        mockFactory.SetupGet(f => f.KeyClient).Returns(mockKeyClient.Object);

        CoseHeaderMap protectedHeaders = new();
        protectedHeaders.Add(new CoseHeaderLabel(4), Encoding.UTF8.GetBytes(kid));

        var signer = new CoseSigner(ecdsa, HashAlgorithmName.SHA384, protectedHeaders, unprotectedHeaders: null);
        var bytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var message = CoseSign1Message.DecodeSign1(bytes);

        var resolver = new AzureKeyVaultOnlineSigningKeyResolver(mockFactory.Object);
        var result = await resolver.ResolveAsync(message);

        Assert.That(result.IsSuccess, Is.True);
        Assert.That(result.SigningKey, Is.Not.Null);

        using (result.SigningKey)
        {
            Assert.That(message.VerifyEmbedded(result.SigningKey!.GetCoseKey()), Is.True);
        }
    }

    [Test]
    public async Task ResolveAsync_WithValidKidAndRsa4096_UsesSha512AndVerifiesSignature()
    {
        using var rsa = RSA.Create(4096);
        var kid = "https://myvault.vault.azure.net/keys/bigkey/abc";

        var jsonWebKey = new JsonWebKey(rsa, includePrivateParameters: false);
        var keyProps = KeyModelFactory.KeyProperties(id: new Uri(kid), vaultUri: VaultUri, name: "bigkey", version: "abc");
        var keyVaultKey = KeyModelFactory.KeyVaultKey(properties: keyProps, key: jsonWebKey);

        var mockKeyClient = new Mock<KeyClient>(MockBehavior.Strict);
        mockKeyClient
            .Setup(c => c.GetKeyAsync("bigkey", "abc", It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(keyVaultKey, new Mock<Response>().Object));

        var mockFactory = new Mock<IKeyVaultClientFactory>(MockBehavior.Strict);
        mockFactory.SetupGet(f => f.VaultUri).Returns(VaultUri);
        mockFactory.SetupGet(f => f.KeyClient).Returns(mockKeyClient.Object);

        CoseHeaderMap protectedHeaders = new();
        protectedHeaders.Add(new CoseHeaderLabel(4), Encoding.UTF8.GetBytes(kid));

        var signer = new CoseSigner(rsa, RSASignaturePadding.Pss, HashAlgorithmName.SHA512, protectedHeaders, unprotectedHeaders: null);
        var bytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var message = CoseSign1Message.DecodeSign1(bytes);

        var resolver = new AzureKeyVaultOnlineSigningKeyResolver(mockFactory.Object);
        var result = await resolver.ResolveAsync(message);

        Assert.That(result.IsSuccess, Is.True);

        using (result.SigningKey)
        {
            Assert.That(message.VerifyEmbedded(result.SigningKey!.GetCoseKey()), Is.True);
        }
    }

    [Test]
    public async Task ResolveAsync_WithNonAkvHost_ReturnsFailure()
    {
        using var rsa = RSA.Create(2048);
        var kid = "https://example.com/keys/mykey/abc";

        CoseHeaderMap protectedHeaders = new();
        protectedHeaders.Add(new CoseHeaderLabel(4), Encoding.UTF8.GetBytes(kid));

        var signer = new CoseSigner(rsa, RSASignaturePadding.Pss, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders: null);
        var bytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var message = CoseSign1Message.DecodeSign1(bytes);

        var mockFactory = new Mock<IKeyVaultClientFactory>(MockBehavior.Strict);
        var resolver = new AzureKeyVaultOnlineSigningKeyResolver(mockFactory.Object);

        var result = await resolver.ResolveAsync(message);

        Assert.That(result.IsSuccess, Is.False);
        Assert.That(result.ErrorCode, Is.EqualTo("KID_INVALID"));
    }
}
