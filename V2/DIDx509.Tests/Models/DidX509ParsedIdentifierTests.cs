// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace DIDx509.Tests.Models;

using DIDx509.Models;

[TestFixture]
public class DidX509ParsedIdentifierTests
{
    [Test]
    public void Constructor_WithAllParameters_SetsProperties()
    {
        // Arrange
        var did = "did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu7MLmxLQ::subject:CN:Test";
        var version = "0";
        var hashAlgorithm = "sha256";
        var caFingerprint = "WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu7MLmxLQ";
        var policies = new[]
        {
            new DidX509Policy("subject", "CN:Test")
        };

        // Act
        var identifier = new DidX509ParsedIdentifier(did, version, hashAlgorithm, caFingerprint, policies);

        // Assert
        Assert.That(identifier.Did, Is.EqualTo(did));
        Assert.That(identifier.Version, Is.EqualTo(version));
        Assert.That(identifier.HashAlgorithm, Is.EqualTo(hashAlgorithm));
        Assert.That(identifier.CaFingerprint, Is.EqualTo(caFingerprint));
        Assert.That(identifier.Policies, Is.EqualTo(policies));
        Assert.That(identifier.Policies.Count, Is.EqualTo(1));
    }

    [Test]
    public void Constructor_WithNullDid_ThrowsArgumentNullException()
    {
        // Arrange
        var policies = new[] { new DidX509Policy("subject", "CN:Test") };

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            new DidX509ParsedIdentifier(null!, "0", "sha256", "fingerprint", policies));
    }

    [Test]
    public void Constructor_WithNullVersion_ThrowsArgumentNullException()
    {
        // Arrange
        var policies = new[] { new DidX509Policy("subject", "CN:Test") };

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            new DidX509ParsedIdentifier("did", null!, "sha256", "fingerprint", policies));
    }

    [Test]
    public void Constructor_WithNullHashAlgorithm_ThrowsArgumentNullException()
    {
        // Arrange
        var policies = new[] { new DidX509Policy("subject", "CN:Test") };

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            new DidX509ParsedIdentifier("did", "0", null!, "fingerprint", policies));
    }

    [Test]
    public void Constructor_WithNullCaFingerprint_ThrowsArgumentNullException()
    {
        // Arrange
        var policies = new[] { new DidX509Policy("subject", "CN:Test") };

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            new DidX509ParsedIdentifier("did", "0", "sha256", null!, policies));
    }

    [Test]
    public void Constructor_WithNullPolicies_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            new DidX509ParsedIdentifier("did", "0", "sha256", "fingerprint", null!));
    }

    [Test]
    public void Constructor_WithEmptyPolicies_CreatesInstance()
    {
        // Arrange
        var policies = Array.Empty<DidX509Policy>();

        // Act
        var identifier = new DidX509ParsedIdentifier("did", "0", "sha256", "fingerprint", policies);

        // Assert
        Assert.That(identifier.Policies.Count, Is.EqualTo(0));
    }

    [Test]
    public void GetPolicy_WithExistingPolicy_ReturnsPolicy()
    {
        // Arrange
        var subjectPolicy = new DidX509Policy("subject", "CN:Test");
        var ekuPolicy = new DidX509Policy("eku", "1.3.6.1.5.5.7.3.1");
        var policies = new[] { subjectPolicy, ekuPolicy };
        var identifier = new DidX509ParsedIdentifier("did", "0", "sha256", "fingerprint", policies);

        // Act
        var result = identifier.GetPolicy("subject");

        // Assert
        Assert.That(result, Is.SameAs(subjectPolicy));
    }

    [Test]
    public void GetPolicy_WithNonExistingPolicy_ReturnsNull()
    {
        // Arrange
        var policies = new[] { new DidX509Policy("subject", "CN:Test") };
        var identifier = new DidX509ParsedIdentifier("did", "0", "sha256", "fingerprint", policies);

        // Act
        var result = identifier.GetPolicy("eku");

        // Assert
        Assert.That(result, Is.Null);
    }

    [Test]
    public void GetPolicy_IsCaseInsensitive()
    {
        // Arrange
        var subjectPolicy = new DidX509Policy("subject", "CN:Test");
        var policies = new[] { subjectPolicy };
        var identifier = new DidX509ParsedIdentifier("did", "0", "sha256", "fingerprint", policies);

        // Act & Assert
        Assert.That(identifier.GetPolicy("subject"), Is.SameAs(subjectPolicy));
        Assert.That(identifier.GetPolicy("SUBJECT"), Is.SameAs(subjectPolicy));
        Assert.That(identifier.GetPolicy("Subject"), Is.SameAs(subjectPolicy));
    }

    [Test]
    public void GetPolicy_WithEmptyPolicies_ReturnsNull()
    {
        // Arrange
        var policies = Array.Empty<DidX509Policy>();
        var identifier = new DidX509ParsedIdentifier("did", "0", "sha256", "fingerprint", policies);

        // Act
        var result = identifier.GetPolicy("subject");

        // Assert
        Assert.That(result, Is.Null);
    }

    [Test]
    public void HasPolicy_WithExistingPolicy_ReturnsTrue()
    {
        // Arrange
        var policies = new[]
        {
            new DidX509Policy("subject", "CN:Test"),
            new DidX509Policy("eku", "1.3.6.1.5.5.7.3.1")
        };
        var identifier = new DidX509ParsedIdentifier("did", "0", "sha256", "fingerprint", policies);

        // Act & Assert
        Assert.That(identifier.HasPolicy("subject"), Is.True);
        Assert.That(identifier.HasPolicy("eku"), Is.True);
    }

    [Test]
    public void HasPolicy_WithNonExistingPolicy_ReturnsFalse()
    {
        // Arrange
        var policies = new[] { new DidX509Policy("subject", "CN:Test") };
        var identifier = new DidX509ParsedIdentifier("did", "0", "sha256", "fingerprint", policies);

        // Act & Assert
        Assert.That(identifier.HasPolicy("san"), Is.False);
        Assert.That(identifier.HasPolicy("eku"), Is.False);
    }

    [Test]
    public void HasPolicy_IsCaseInsensitive()
    {
        // Arrange
        var policies = new[] { new DidX509Policy("subject", "CN:Test") };
        var identifier = new DidX509ParsedIdentifier("did", "0", "sha256", "fingerprint", policies);

        // Act & Assert
        Assert.That(identifier.HasPolicy("subject"), Is.True);
        Assert.That(identifier.HasPolicy("SUBJECT"), Is.True);
        Assert.That(identifier.HasPolicy("Subject"), Is.True);
    }

    [Test]
    public void HasPolicy_WithEmptyPolicies_ReturnsFalse()
    {
        // Arrange
        var policies = Array.Empty<DidX509Policy>();
        var identifier = new DidX509ParsedIdentifier("did", "0", "sha256", "fingerprint", policies);

        // Act
        var result = identifier.HasPolicy("subject");

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void Constructor_WithMultiplePolicies_StoresAll()
    {
        // Arrange
        var policies = new[]
        {
            new DidX509Policy("subject", "CN:Test"),
            new DidX509Policy("san", "dns:example.com"),
            new DidX509Policy("eku", "1.3.6.1.5.5.7.3.1"),
            new DidX509Policy("fulcio-issuer", "https://fulcio.sigstore.dev")
        };

        // Act
        var identifier = new DidX509ParsedIdentifier("did", "0", "sha256", "fingerprint", policies);

        // Assert
        Assert.That(identifier.Policies.Count, Is.EqualTo(4));
        Assert.That(identifier.HasPolicy("subject"), Is.True);
        Assert.That(identifier.HasPolicy("san"), Is.True);
        Assert.That(identifier.HasPolicy("eku"), Is.True);
        Assert.That(identifier.HasPolicy("fulcio-issuer"), Is.True);
    }

    [Test]
    public void Constructor_WithSHA384_StoresCorrectly()
    {
        // Arrange
        var policies = new[] { new DidX509Policy("subject", "CN:Test") };

        // Act
        var identifier = new DidX509ParsedIdentifier("did", "0", "sha384", "fingerprint", policies);

        // Assert
        Assert.That(identifier.HashAlgorithm, Is.EqualTo("sha384"));
    }

    [Test]
    public void Constructor_WithSHA512_StoresCorrectly()
    {
        // Arrange
        var policies = new[] { new DidX509Policy("subject", "CN:Test") };

        // Act
        var identifier = new DidX509ParsedIdentifier("did", "0", "sha512", "fingerprint", policies);

        // Assert
        Assert.That(identifier.HashAlgorithm, Is.EqualTo("sha512"));
    }

    [Test]
    public void GetPolicy_WithMultiplePolicies_ReturnsCorrectOne()
    {
        // Arrange
        var subjectPolicy = new DidX509Policy("subject", "CN:Test");
        var sanPolicy = new DidX509Policy("san", "dns:example.com");
        var ekuPolicy = new DidX509Policy("eku", "1.3.6.1.5.5.7.3.1");
        var policies = new[] { subjectPolicy, sanPolicy, ekuPolicy };
        var identifier = new DidX509ParsedIdentifier("did", "0", "sha256", "fingerprint", policies);

        // Act & Assert
        Assert.That(identifier.GetPolicy("subject"), Is.SameAs(subjectPolicy));
        Assert.That(identifier.GetPolicy("san"), Is.SameAs(sanPolicy));
        Assert.That(identifier.GetPolicy("eku"), Is.SameAs(ekuPolicy));
    }
}