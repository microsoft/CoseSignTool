// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Azure.Core;
using CoseSign1.AzureKeyVault.Common;

namespace CoseSign1.AzureKeyVault.Tests;

public sealed class KeyVaultClientFactoryTests
{
    private sealed class FakeTokenCredential : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            return new AccessToken("fake-token", DateTimeOffset.UtcNow.AddHours(1));
        }

        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            return ValueTask.FromResult(new AccessToken("fake-token", DateTimeOffset.UtcNow.AddHours(1)));
        }
    }

    [Test]
    public void Ctor_WithNullVaultUri_Throws()
    {
        Assert.That(() => new KeyVaultClientFactory(null!, new FakeTokenCredential()),
            Throws.ArgumentNullException);
    }

    [Test]
    public void Ctor_WithNullCredential_Throws()
    {
        Assert.That(() => new KeyVaultClientFactory(new Uri("https://example.vault.azure.net"), null!),
            Throws.ArgumentNullException);
    }

    [Test]
    public void Ctor_WithValidArgs_SetsPropertiesAndCreatesPlaneClients()
    {
        var vaultUri = new Uri("https://example.vault.azure.net");
        var factory = new KeyVaultClientFactory(vaultUri, new FakeTokenCredential());

        Assert.That(factory.VaultUri, Is.EqualTo(vaultUri));
        Assert.That(factory.CertificateClient, Is.Not.Null);
        Assert.That(factory.SecretClient, Is.Not.Null);
        Assert.That(factory.KeyClient, Is.Not.Null);
    }

    [Test]
    public void CreateCryptographyClient_WithNullKeyId_Throws()
    {
        var factory = new KeyVaultClientFactory(new Uri("https://example.vault.azure.net"), new FakeTokenCredential());

        Assert.That(() => factory.CreateCryptographyClient(null!),
            Throws.ArgumentNullException);
    }

    [Test]
    public void CreateCryptographyClient_WithValidKeyId_ReturnsClient()
    {
        var factory = new KeyVaultClientFactory(new Uri("https://example.vault.azure.net"), new FakeTokenCredential());
        var keyId = new Uri("https://example.vault.azure.net/keys/key1/00000000000000000000000000000000");

        var cryptoClient = factory.CreateCryptographyClient(keyId);

        Assert.That(cryptoClient, Is.Not.Null);
    }
}
