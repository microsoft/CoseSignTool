// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.AzureKeyVault.Tests.Validation;

using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Text;
using CoseSign1.Abstractions;
using CoseSign1.AzureKeyVault.Validation;
using Moq;
using NUnit.Framework;

/// <summary>
/// Tests for <see cref="AzureKeyVaultAssertionProvider"/>.
/// </summary>
[TestFixture]
[Category("AzureKeyVault")]
[Category("Validation")]
public class AzureKeyVaultAssertionProviderTests
{
    #region Helper Methods

    private static CoseSign1Message CreateMessageWithoutKid()
    {
        // Create a message without a kid header
        using var rsa = RSA.Create();
        var signer = new CoseSigner(rsa, RSASignaturePadding.Pss, HashAlgorithmName.SHA256);

        var bytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        return CoseSign1Message.DecodeSign1(bytes);
    }

    private static CoseSign1Message CreateMessageWithKid(string kid, bool inProtectedHeaders = true)
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

    #region Constructor Tests

    [Test]
    public void Constructor_WithNoPatterns_CreatesProvider()
    {
        var provider = new AzureKeyVaultAssertionProvider();

        Assert.That(provider.ComponentName, Is.EqualTo(nameof(AzureKeyVaultAssertionProvider)));
    }

    [Test]
    public void Constructor_WithAllowedPatterns_CreatesProvider()
    {
        var patterns = new[] { "https://myvault.vault.azure.net/keys/*" };
        var provider = new AzureKeyVaultAssertionProvider(patterns);

        Assert.That(provider.ComponentName, Is.EqualTo(nameof(AzureKeyVaultAssertionProvider)));
    }

    [Test]
    public void Constructor_WithRegexPattern_CreatesProvider()
    {
        var patterns = new[] { "regex:https://.*\\.vault\\.azure\\.net/keys/.*" };
        var provider = new AzureKeyVaultAssertionProvider(patterns);

        Assert.That(provider, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithRequireAzureKeyVaultKeyFalse_CreatesProvider()
    {
        var provider = new AzureKeyVaultAssertionProvider(null, requireAzureKeyVaultKey: false);

        Assert.That(provider, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithMixedPatterns_CreatesProvider()
    {
        var patterns = new[]
        {
            "https://myvault.vault.azure.net/keys/*",
            "https://othervault.vault.azure.net/keys/signing-?",
            "regex:https://.*\\.vault\\.azure\\.net/keys/special-.*"
        };
        var provider = new AzureKeyVaultAssertionProvider(patterns);

        Assert.That(provider.ComponentName, Is.EqualTo(nameof(AzureKeyVaultAssertionProvider)));
    }

    #endregion

    #region ExtractAssertions Tests

    [Test]
    public void ExtractAssertions_WithNullMessage_ReturnsEmptyList()
    {
        var provider = new AzureKeyVaultAssertionProvider();
        var mockKey = new Mock<ISigningKey>();

        var assertions = provider.ExtractAssertions(mockKey.Object, null!, null);

        Assert.That(assertions, Is.Empty);
    }

    [Test]
    public void ExtractAssertions_WithMessageWithoutKid_ReturnsEmptyList()
    {
        var provider = new AzureKeyVaultAssertionProvider();
        var mockKey = new Mock<ISigningKey>();
        var message = CreateMessageWithoutKid();

        var assertions = provider.ExtractAssertions(mockKey.Object, message, null);

        Assert.That(assertions, Is.Empty);
    }

    [Test]
    public void ExtractAssertions_WithAkvKid_ReturnsAssertions()
    {
        var provider = new AzureKeyVaultAssertionProvider();
        var mockKey = new Mock<ISigningKey>();
        var message = CreateMessageWithKid("https://myvault.vault.azure.net/keys/mykey");

        var assertions = provider.ExtractAssertions(mockKey.Object, message, null);

        Assert.That(assertions, Has.Count.EqualTo(2));
        Assert.That(assertions[0], Is.TypeOf<AkvKeyDetectedAssertion>());
        Assert.That(assertions[1], Is.TypeOf<AkvKidAllowedAssertion>());
    }

    [Test]
    public void ExtractAssertions_WithAkvKidAndMatchingPattern_ReturnsKidAllowedTrue()
    {
        var patterns = new[] { "https://myvault.vault.azure.net/keys/*" };
        var provider = new AzureKeyVaultAssertionProvider(patterns);
        var mockKey = new Mock<ISigningKey>();
        var message = CreateMessageWithKid("https://myvault.vault.azure.net/keys/mykey");

        var assertions = provider.ExtractAssertions(mockKey.Object, message, null);

        Assert.That(assertions, Has.Count.EqualTo(2));
        var kidAllowed = assertions[1] as AkvKidAllowedAssertion;
        Assert.That(kidAllowed?.IsAllowed, Is.True);
    }

    [Test]
    public void ExtractAssertions_WithAkvKidAndNonMatchingPattern_ReturnsKidAllowedFalse()
    {
        var patterns = new[] { "https://othervault.vault.azure.net/keys/*" };
        var provider = new AzureKeyVaultAssertionProvider(patterns);
        var mockKey = new Mock<ISigningKey>();
        var message = CreateMessageWithKid("https://myvault.vault.azure.net/keys/mykey");

        var assertions = provider.ExtractAssertions(mockKey.Object, message, null);

        Assert.That(assertions, Has.Count.EqualTo(2));
        var kidAllowed = assertions[1] as AkvKidAllowedAssertion;
        Assert.That(kidAllowed?.IsAllowed, Is.False);
    }

    [Test]
    public void ExtractAssertions_WithNonAkvKidAndRequireAkvKeyTrue_ReturnsEmptyList()
    {
        var provider = new AzureKeyVaultAssertionProvider(null, requireAzureKeyVaultKey: true);
        var mockKey = new Mock<ISigningKey>();
        var message = CreateMessageWithKid("https://example.com/keys/mykey");

        var assertions = provider.ExtractAssertions(mockKey.Object, message, null);

        Assert.That(assertions, Is.Empty);
    }

    [Test]
    public void ExtractAssertions_WithNonAkvKidAndRequireAkvKeyFalse_ReturnsAssertions()
    {
        var provider = new AzureKeyVaultAssertionProvider(null, requireAzureKeyVaultKey: false);
        var mockKey = new Mock<ISigningKey>();
        var message = CreateMessageWithKid("https://example.com/keys/mykey");

        var assertions = provider.ExtractAssertions(mockKey.Object, message, null);

        Assert.That(assertions, Has.Count.EqualTo(2));
        var keyDetected = assertions[0] as AkvKeyDetectedAssertion;
        Assert.That(keyDetected?.IsAkvKey, Is.False);
    }

    [Test]
    public void ExtractAssertions_WithRegexPattern_MatchesCorrectly()
    {
        var patterns = new[] { "regex:https://.*\\.vault\\.azure\\.net/keys/signing-.*" };
        var provider = new AzureKeyVaultAssertionProvider(patterns);
        var mockKey = new Mock<ISigningKey>();
        var message = CreateMessageWithKid("https://myvault.vault.azure.net/keys/signing-key1");

        var assertions = provider.ExtractAssertions(mockKey.Object, message, null);

        Assert.That(assertions, Has.Count.EqualTo(2));
        var kidAllowed = assertions[1] as AkvKidAllowedAssertion;
        Assert.That(kidAllowed?.IsAllowed, Is.True);
    }

    [Test]
    public void ExtractAssertions_WithQuestionMarkWildcard_MatchesSingleChar()
    {
        var patterns = new[] { "https://myvault.vault.azure.net/keys/key?" };
        var provider = new AzureKeyVaultAssertionProvider(patterns);
        var mockKey = new Mock<ISigningKey>();
        var message = CreateMessageWithKid("https://myvault.vault.azure.net/keys/key1");

        var assertions = provider.ExtractAssertions(mockKey.Object, message, null);

        var kidAllowed = assertions[1] as AkvKidAllowedAssertion;
        Assert.That(kidAllowed?.IsAllowed, Is.True);
    }

    [Test]
    public void ExtractAssertions_WithEmptyKid_ReturnsEmptyList()
    {
        var provider = new AzureKeyVaultAssertionProvider();
        var mockKey = new Mock<ISigningKey>();
        var message = CreateMessageWithKid("");

        var assertions = provider.ExtractAssertions(mockKey.Object, message, null);

        Assert.That(assertions, Is.Empty);
    }

    [Test]
    public void ExtractAssertions_WithWhitespaceKid_ReturnsEmptyList()
    {
        var provider = new AzureKeyVaultAssertionProvider();
        var mockKey = new Mock<ISigningKey>();
        var message = CreateMessageWithKid("   ");

        var assertions = provider.ExtractAssertions(mockKey.Object, message, null);

        Assert.That(assertions, Is.Empty);
    }

    [Test]
    public void ExtractAssertions_WithKidInUnprotectedHeaders_ReturnsAssertions()
    {
        var provider = new AzureKeyVaultAssertionProvider();
        var mockKey = new Mock<ISigningKey>();
        var message = CreateMessageWithKid("https://myvault.vault.azure.net/keys/mykey", inProtectedHeaders: false);

        var assertions = provider.ExtractAssertions(mockKey.Object, message, null);

        Assert.That(assertions, Has.Count.EqualTo(2));
    }

    [Test]
    public void ExtractAssertions_WithEmptyPatternList_ReturnsNoAllowedPatternsDetails()
    {
        var provider = new AzureKeyVaultAssertionProvider(Array.Empty<string>());
        var mockKey = new Mock<ISigningKey>();
        var message = CreateMessageWithKid("https://myvault.vault.azure.net/keys/mykey");

        var assertions = provider.ExtractAssertions(mockKey.Object, message, null);

        Assert.That(assertions, Has.Count.EqualTo(2));
        var kidAllowed = assertions[1] as AkvKidAllowedAssertion;
        Assert.That(kidAllowed?.IsAllowed, Is.False);
    }

    #endregion

    #region ExtractAssertionsAsync Tests

    [Test]
    public async Task ExtractAssertionsAsync_WithNullMessage_ReturnsEmptyList()
    {
        var provider = new AzureKeyVaultAssertionProvider();
        var mockKey = new Mock<ISigningKey>();

        var assertions = await provider.ExtractAssertionsAsync(mockKey.Object, null!, null);

        Assert.That(assertions, Is.Empty);
    }

    [Test]
    public async Task ExtractAssertionsAsync_WithCancellation_DoesNotThrow()
    {
        var provider = new AzureKeyVaultAssertionProvider();
        var mockKey = new Mock<ISigningKey>();
        using var cts = new CancellationTokenSource();

        var assertions = await provider.ExtractAssertionsAsync(mockKey.Object, null!, null, cts.Token);

        Assert.That(assertions, Is.Empty);
    }

    [Test]
    public async Task ExtractAssertionsAsync_WithMessageWithoutKid_ReturnsEmptyList()
    {
        var provider = new AzureKeyVaultAssertionProvider();
        var mockKey = new Mock<ISigningKey>();
        var message = CreateMessageWithoutKid();

        var assertions = await provider.ExtractAssertionsAsync(mockKey.Object, message, null);

        Assert.That(assertions, Is.Empty);
    }

    [Test]
    public async Task ExtractAssertionsAsync_WithAkvKid_ReturnsAssertions()
    {
        var provider = new AzureKeyVaultAssertionProvider();
        var mockKey = new Mock<ISigningKey>();
        var message = CreateMessageWithKid("https://myvault.vault.azure.net/keys/mykey");

        var assertions = await provider.ExtractAssertionsAsync(mockKey.Object, message, null);

        Assert.That(assertions, Has.Count.EqualTo(2));
    }

    #endregion
}
