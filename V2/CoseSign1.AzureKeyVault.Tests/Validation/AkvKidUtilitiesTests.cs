// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.AzureKeyVault.Tests.Validation;

using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Text;
using CoseSign1.AzureKeyVault.Validation;
using NUnit.Framework;

[TestFixture]
[Category("AzureKeyVault")]
[Category("Validation")]
public sealed class AkvKidUtilitiesTests
{
    private static readonly CoseHeaderLabel KidLabel = new(4);

    private static CoseSign1Message CreateMessage(CoseHeaderMap? protectedHeaders, CoseHeaderMap? unprotectedHeaders)
    {
        using var rsa = RSA.Create(2048);
        var signer = new CoseSigner(rsa, RSASignaturePadding.Pss, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders);
        byte[] bytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        return CoseSign1Message.DecodeSign1(bytes);
    }

    [Test]
    public void TryGetKid_WithNoKid_ReturnsFalse()
    {
        var message = CreateMessage(protectedHeaders: null, unprotectedHeaders: null);

        var success = AkvKidUtilities.TryGetKid(message, out var kid);

        Assert.That(success, Is.False);
        Assert.That(kid, Is.EqualTo(string.Empty));
    }

    [Test]
    public void TryGetKid_WithProtectedKid_ReturnsKid()
    {
        var expectedKid = "https://myvault.vault.azure.net/keys/mykey/abc";

        var protectedHeaders = new CoseHeaderMap();
        protectedHeaders.Add(KidLabel, Encoding.UTF8.GetBytes(expectedKid));

        var message = CreateMessage(protectedHeaders, unprotectedHeaders: null);

        var success = AkvKidUtilities.TryGetKid(message, out var kid);

        Assert.That(success, Is.True);
        Assert.That(kid, Is.EqualTo(expectedKid));
    }

    [Test]
    public void TryGetKid_WithUnprotectedKid_ReturnsKid()
    {
        var expectedKid = "https://myvault.vault.azure.net/keys/mykey/abc";

        var unprotectedHeaders = new CoseHeaderMap();
        unprotectedHeaders.Add(KidLabel, Encoding.UTF8.GetBytes(expectedKid));

        var message = CreateMessage(protectedHeaders: null, unprotectedHeaders);

        var success = AkvKidUtilities.TryGetKid(message, out var kid);

        Assert.That(success, Is.True);
        Assert.That(kid, Is.EqualTo(expectedKid));
    }

    [Test]
    public void TryGetKid_WithEmptyProtectedKid_ReturnsFalse()
    {
        var protectedHeaders = new CoseHeaderMap();
        protectedHeaders.Add(KidLabel, Array.Empty<byte>());

        var message = CreateMessage(protectedHeaders, unprotectedHeaders: null);

        var success = AkvKidUtilities.TryGetKid(message, out var kid);

        Assert.That(success, Is.False);
        Assert.That(kid, Is.EqualTo(string.Empty));
    }

    [TestCase(null, false)]
    [TestCase("", false)]
    [TestCase("   ", false)]
    [TestCase("not a uri", false)]
    [TestCase("https://example.com/keys/mykey/abc", false)]
    [TestCase("https://myvault.vault.azure.net/secrets/mykey/abc", false)]
    [TestCase("https://myvault.vault.azure.net/keys/mykey/abc", true)]
    [TestCase("https://MYVAULT.VAULT.AZURE.NET/keys/mykey/abc", true)]
    public void LooksLikeAzureKeyVaultKeyId_VariousInputs_ReturnsExpected(string? kid, bool expected)
    {
        Assert.That(AkvKidUtilities.LooksLikeAzureKeyVaultKeyId(kid), Is.EqualTo(expected));
    }
}
