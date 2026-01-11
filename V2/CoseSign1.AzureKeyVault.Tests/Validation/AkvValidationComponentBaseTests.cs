// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.AzureKeyVault.Tests.Validation;

using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Text;
using CoseSign1.AzureKeyVault.Validation;
using CoseSign1.Validation;
using NUnit.Framework;

/// <summary>
/// Tests for <see cref="AkvValidationComponentBase"/>.
/// </summary>
[TestFixture]
[Category("AzureKeyVault")]
[Category("Validation")]
public class AkvValidationComponentBaseTests
{
    // Test implementation that exposes the protected methods
    private sealed class TestableAkvComponent : AkvValidationComponentBase
    {
        public bool TestRequireAzureKeyVaultKid { get; set; }

        protected override bool RequireAzureKeyVaultKid => TestRequireAzureKeyVaultKid;

        public override string ComponentName => "TestableAkvComponent";

        public bool CallComputeApplicability(CoseSign1Message message, CoseSign1ValidationOptions? options = null)
            => ComputeApplicability(message, options);

        public static bool CallHasAzureKeyVaultKid(CoseSign1Message? message)
            => HasAzureKeyVaultKid(message);

        public static bool CallTryGetKid(CoseSign1Message message, out string kid)
            => TryGetKid(message, out kid);

        public static bool CallLooksLikeAzureKeyVaultKeyId(string? kid)
            => LooksLikeAzureKeyVaultKeyId(kid);
    }

    #region LooksLikeAzureKeyVaultKeyId Tests

    [Test]
    public void LooksLikeAzureKeyVaultKeyId_WithNull_ReturnsFalse()
    {
        Assert.That(TestableAkvComponent.CallLooksLikeAzureKeyVaultKeyId(null), Is.False);
    }

    [Test]
    public void LooksLikeAzureKeyVaultKeyId_WithEmptyString_ReturnsFalse()
    {
        Assert.That(TestableAkvComponent.CallLooksLikeAzureKeyVaultKeyId(string.Empty), Is.False);
    }

    [Test]
    public void LooksLikeAzureKeyVaultKeyId_WithWhitespace_ReturnsFalse()
    {
        Assert.That(TestableAkvComponent.CallLooksLikeAzureKeyVaultKeyId("   "), Is.False);
    }

    [Test]
    public void LooksLikeAzureKeyVaultKeyId_WithInvalidUri_ReturnsFalse()
    {
        Assert.That(TestableAkvComponent.CallLooksLikeAzureKeyVaultKeyId("not a uri"), Is.False);
    }

    [Test]
    public void LooksLikeAzureKeyVaultKeyId_WithNonAkvUri_ReturnsFalse()
    {
        Assert.That(TestableAkvComponent.CallLooksLikeAzureKeyVaultKeyId("https://example.com/keys/mykey"), Is.False);
    }

    [Test]
    public void LooksLikeAzureKeyVaultKeyId_WithAkvUriButNoKeysPath_ReturnsFalse()
    {
        Assert.That(TestableAkvComponent.CallLooksLikeAzureKeyVaultKeyId("https://myvault.vault.azure.net/secrets/mysecret"), Is.False);
    }

    [Test]
    public void LooksLikeAzureKeyVaultKeyId_WithValidAkvKeyUri_ReturnsTrue()
    {
        Assert.That(TestableAkvComponent.CallLooksLikeAzureKeyVaultKeyId("https://myvault.vault.azure.net/keys/mykey"), Is.True);
    }

    [Test]
    public void LooksLikeAzureKeyVaultKeyId_WithValidAkvKeyUriWithVersion_ReturnsTrue()
    {
        Assert.That(TestableAkvComponent.CallLooksLikeAzureKeyVaultKeyId("https://myvault.vault.azure.net/keys/mykey/abc123"), Is.True);
    }

    [Test]
    public void LooksLikeAzureKeyVaultKeyId_CaseInsensitive_ReturnsTrue()
    {
        Assert.That(TestableAkvComponent.CallLooksLikeAzureKeyVaultKeyId("HTTPS://MYVAULT.VAULT.AZURE.NET/KEYS/MYKEY"), Is.True);
    }

    #endregion

    #region HasAzureKeyVaultKid Tests

    [Test]
    public void HasAzureKeyVaultKid_WithNullMessage_ReturnsFalse()
    {
        Assert.That(TestableAkvComponent.CallHasAzureKeyVaultKid(null), Is.False);
    }

    [Test]
    public void HasAzureKeyVaultKid_WithMessageWithoutKid_ReturnsFalse()
    {
        var message = CreateMessageWithoutKid();
        Assert.That(TestableAkvComponent.CallHasAzureKeyVaultKid(message), Is.False);
    }

    [Test]
    public void HasAzureKeyVaultKid_WithMessageWithNonAkvKid_ReturnsFalse()
    {
        var message = CreateMessageWithKid("https://example.com/keys/mykey", inProtectedHeaders: true);
        Assert.That(TestableAkvComponent.CallHasAzureKeyVaultKid(message), Is.False);
    }

    [Test]
    public void HasAzureKeyVaultKid_WithMessageWithAkvKidInProtectedHeaders_ReturnsTrue()
    {
        var message = CreateMessageWithKid("https://myvault.vault.azure.net/keys/mykey", inProtectedHeaders: true);
        Assert.That(TestableAkvComponent.CallHasAzureKeyVaultKid(message), Is.True);
    }

    [Test]
    public void HasAzureKeyVaultKid_WithMessageWithAkvKidInUnprotectedHeaders_ReturnsTrue()
    {
        var message = CreateMessageWithKid("https://myvault.vault.azure.net/keys/mykey", inProtectedHeaders: false);
        Assert.That(TestableAkvComponent.CallHasAzureKeyVaultKid(message), Is.True);
    }

    #endregion

    #region TryGetKid Tests

    [Test]
    public void TryGetKid_WithMessageWithoutKid_ReturnsFalseAndEmptyString()
    {
        var message = CreateMessageWithoutKid();

        var result = TestableAkvComponent.CallTryGetKid(message, out var kid);

        Assert.That(result, Is.False);
        Assert.That(kid, Is.Empty);
    }

    [Test]
    public void TryGetKid_WithMessageWithKidInProtectedHeaders_ReturnsKid()
    {
        const string expectedKid = "https://myvault.vault.azure.net/keys/mykey";
        var message = CreateMessageWithKid(expectedKid, inProtectedHeaders: true);

        var result = TestableAkvComponent.CallTryGetKid(message, out var kid);

        Assert.That(result, Is.True);
        Assert.That(kid, Is.EqualTo(expectedKid));
    }

    [Test]
    public void TryGetKid_WithMessageWithKidInUnprotectedHeaders_ReturnsKid()
    {
        const string expectedKid = "https://myvault.vault.azure.net/keys/mykey";
        var message = CreateMessageWithKid(expectedKid, inProtectedHeaders: false);

        var result = TestableAkvComponent.CallTryGetKid(message, out var kid);

        Assert.That(result, Is.True);
        Assert.That(kid, Is.EqualTo(expectedKid));
    }

    [Test]
    public void TryGetKid_PrefersProtectedHeadersOverUnprotected()
    {
        // If there's a kid in both protected and unprotected, protected should be returned
        const string protectedKid = "https://protected.vault.azure.net/keys/key1";
        var message = CreateMessageWithKid(protectedKid, inProtectedHeaders: true);

        var result = TestableAkvComponent.CallTryGetKid(message, out var kid);

        Assert.That(result, Is.True);
        Assert.That(kid, Is.EqualTo(protectedKid));
    }

    #endregion

    #region ComputeApplicability Tests

    [Test]
    public void ComputeApplicability_WithMessageWithoutKid_ReturnsFalse()
    {
        var component = new TestableAkvComponent { TestRequireAzureKeyVaultKid = false };
        var message = CreateMessageWithoutKid();

        Assert.That(component.CallComputeApplicability(message), Is.False);
    }

    [Test]
    public void ComputeApplicability_WithNonAkvKidAndRequireAkvKeyFalse_ReturnsTrue()
    {
        var component = new TestableAkvComponent { TestRequireAzureKeyVaultKid = false };
        var message = CreateMessageWithKid("https://example.com/keys/mykey", inProtectedHeaders: true);

        Assert.That(component.CallComputeApplicability(message), Is.True);
    }

    [Test]
    public void ComputeApplicability_WithNonAkvKidAndRequireAkvKeyTrue_ReturnsFalse()
    {
        var component = new TestableAkvComponent { TestRequireAzureKeyVaultKid = true };
        var message = CreateMessageWithKid("https://example.com/keys/mykey", inProtectedHeaders: true);

        Assert.That(component.CallComputeApplicability(message), Is.False);
    }

    [Test]
    public void ComputeApplicability_WithAkvKidAndRequireAkvKeyTrue_ReturnsTrue()
    {
        var component = new TestableAkvComponent { TestRequireAzureKeyVaultKid = true };
        var message = CreateMessageWithKid("https://myvault.vault.azure.net/keys/mykey", inProtectedHeaders: true);

        Assert.That(component.CallComputeApplicability(message), Is.True);
    }

    [Test]
    public void ComputeApplicability_WithAkvKidAndRequireAkvKeyFalse_ReturnsTrue()
    {
        var component = new TestableAkvComponent { TestRequireAzureKeyVaultKid = false };
        var message = CreateMessageWithKid("https://myvault.vault.azure.net/keys/mykey", inProtectedHeaders: true);

        Assert.That(component.CallComputeApplicability(message), Is.True);
    }

    [Test]
    public void ComputeApplicability_WithEmptyKid_ReturnsFalse()
    {
        var component = new TestableAkvComponent { TestRequireAzureKeyVaultKid = false };
        var message = CreateMessageWithKid("", inProtectedHeaders: true);

        Assert.That(component.CallComputeApplicability(message), Is.False);
    }

    [Test]
    public void ComputeApplicability_WithWhitespaceKid_ReturnsFalse()
    {
        var component = new TestableAkvComponent { TestRequireAzureKeyVaultKid = false };
        var message = CreateMessageWithKid("   ", inProtectedHeaders: true);

        Assert.That(component.CallComputeApplicability(message), Is.False);
    }

    #endregion

    #region Helper Methods

    private static CoseSign1Message CreateMessageWithoutKid()
    {
        using var rsa = RSA.Create();
        var signer = new CoseSigner(rsa, RSASignaturePadding.Pss, HashAlgorithmName.SHA256);

        var bytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        return CoseSign1Message.DecodeSign1(bytes);
    }

    private static CoseSign1Message CreateMessageWithKid(string kid, bool inProtectedHeaders)
    {
        using var rsa = RSA.Create();
        var kidLabel = new CoseHeaderLabel(4);
        var kidBytes = Encoding.UTF8.GetBytes(kid);

        CoseHeaderMap protectedHeaders = new();
        CoseHeaderMap unprotectedHeaders = new();

        if (inProtectedHeaders)
        {
            protectedHeaders.Add(kidLabel, kidBytes);
        }
        else
        {
            unprotectedHeaders.Add(kidLabel, kidBytes);
        }

        var signer = new CoseSigner(rsa, RSASignaturePadding.Pss, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders);
        var bytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        return CoseSign1Message.DecodeSign1(bytes);
    }

    #endregion
}
