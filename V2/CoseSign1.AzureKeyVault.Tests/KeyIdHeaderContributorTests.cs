// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.AzureKeyVault.Tests;

/// <summary>
/// Tests for <see cref="KeyIdHeaderContributor"/>.
/// </summary>
[TestFixture]
public class KeyIdHeaderContributorTests
{
    private const string TestKeyId = "https://test-vault.vault.azure.net/keys/test-key/abc123";

    #region Constructor Tests

    [Test]
    public void Constructor_WithValidKeyId_SetsProperties()
    {
        // Arrange & Act
        var contributor = new KeyIdHeaderContributor(TestKeyId);

        // Assert
        Assert.That(contributor.KeyId, Is.EqualTo(TestKeyId));
        Assert.That(contributor.IsHsmProtected, Is.False);
    }

    [Test]
    public void Constructor_WithHsmProtectedTrue_SetsIsHsmProtected()
    {
        // Arrange & Act
        var contributor = new KeyIdHeaderContributor(TestKeyId, isHsmProtected: true);

        // Assert
        Assert.That(contributor.KeyId, Is.EqualTo(TestKeyId));
        Assert.That(contributor.IsHsmProtected, Is.True);
    }

    [Test]
    public void Constructor_WithNullKeyId_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new KeyIdHeaderContributor(null!));
    }

    [Test]
    public void Constructor_WithEmptyKeyId_ThrowsArgumentException()
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => new KeyIdHeaderContributor(string.Empty));
    }

    [Test]
    public void Constructor_WithWhitespaceKeyId_ThrowsArgumentException()
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => new KeyIdHeaderContributor("   "));
    }

    #endregion

    #region MergeStrategy Tests

    [Test]
    public void MergeStrategy_ReturnsReplace()
    {
        // Arrange
        var contributor = new KeyIdHeaderContributor(TestKeyId);

        // Act & Assert
        Assert.That(contributor.MergeStrategy, Is.EqualTo(HeaderMergeStrategy.Replace));
    }

    #endregion

    #region ContributeProtectedHeaders Tests

    [Test]
    public void ContributeProtectedHeaders_AddsKidToHeaders()
    {
        // Arrange
        var contributor = new KeyIdHeaderContributor(TestKeyId);
        var headers = new CoseHeaderMap();
        var context = CreateHeaderContributorContext();

        // Act
        contributor.ContributeProtectedHeaders(headers, context);

        // Assert
        Assert.That(headers.ContainsKey(KeyIdHeaderContributor.KidHeaderLabel), Is.True);

        var reader = new CborReader(headers[KeyIdHeaderContributor.KidHeaderLabel].EncodedValue);
        var kidBytes = reader.ReadByteString();
        Assert.That(System.Text.Encoding.UTF8.GetString(kidBytes), Is.EqualTo(TestKeyId));
    }

    [Test]
    public void ContributeProtectedHeaders_ExistingKid_ReplacesValue()
    {
        // Arrange
        var contributor = new KeyIdHeaderContributor(TestKeyId);
        var headers = new CoseHeaderMap();
        // Use bytes for kid header as COSE spec requires bstr for kid (label 4)
        headers.Add(KeyIdHeaderContributor.KidHeaderLabel, CoseHeaderValue.FromBytes(System.Text.Encoding.UTF8.GetBytes("old-kid")));
        var context = CreateHeaderContributorContext();

        // Act
        contributor.ContributeProtectedHeaders(headers, context);

        // Assert
        Assert.That(headers.ContainsKey(KeyIdHeaderContributor.KidHeaderLabel), Is.True);

        var reader = new CborReader(headers[KeyIdHeaderContributor.KidHeaderLabel].EncodedValue);
        var kidBytes = reader.ReadByteString();
        Assert.That(System.Text.Encoding.UTF8.GetString(kidBytes), Is.EqualTo(TestKeyId));
    }

    [Test]
    public void ContributeProtectedHeaders_KidHeaderLabel_IsLabel4()
    {
        // Per RFC 9052, kid is header label 4
        Assert.That(KeyIdHeaderContributor.KidHeaderLabel, Is.EqualTo(new CoseHeaderLabel(4)));
    }

    #endregion

    #region ContributeUnprotectedHeaders Tests

    [Test]
    public void ContributeUnprotectedHeaders_DoesNotAddKid()
    {
        // Arrange
        var contributor = new KeyIdHeaderContributor(TestKeyId);
        var headers = new CoseHeaderMap();
        var context = CreateHeaderContributorContext();

        // Act
        contributor.ContributeUnprotectedHeaders(headers, context);

        // Assert
        Assert.That(headers.ContainsKey(KeyIdHeaderContributor.KidHeaderLabel), Is.False);
    }

    #endregion

    #region Helper Methods

    private static HeaderContributorContext CreateHeaderContributorContext()
    {
        var payload = new byte[] { 0x01, 0x02, 0x03 };
        var signingContext = new SigningContext(payload, "application/octet-stream");
        var mockSigningKey = new Mock<ISigningKey>();
        return new HeaderContributorContext(signingContext, mockSigningKey.Object);
    }

    #endregion
}
