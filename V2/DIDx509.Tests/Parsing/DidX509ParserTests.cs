// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using DIDx509;
using DIDx509.Models;
using DIDx509.Parsing;

namespace DIDx509.Tests.Parsing;

[TestFixture]
public class DidX509ParserTests
{
    [Test]
    public void Parse_WithValidDid_ParsesCorrectly()
    {
        // Arrange
        string did = "did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::subject:CN:example.com";

        // Act
        var result = DidX509Parser.Parse(did);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Did, Is.EqualTo(did));
        Assert.That(result.Version, Is.EqualTo("0"));
        Assert.That(result.HashAlgorithm, Is.EqualTo("sha256"));
        Assert.That(result.CaFingerprint, Is.EqualTo("WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk"));
        Assert.That(result.Policies, Has.Count.EqualTo(1));
    }

    [Test]
    public void Parse_WithNullOrEmpty_ThrowsArgumentException()
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => DidX509Parser.Parse(null!));
        Assert.Throws<ArgumentException>(() => DidX509Parser.Parse(""));
        Assert.Throws<ArgumentException>(() => DidX509Parser.Parse("  "));
    }

    [Test]
    public void Parse_WithoutDidPrefix_ThrowsFormatException()
    {
        // Arrange
        string invalidDid = "x509:0:sha256:abc::subject:CN:test";

        // Act & Assert
        var ex = Assert.Throws<FormatException>(() => DidX509Parser.Parse(invalidDid));
        Assert.That(ex!.Message, Does.Contain("Must start with 'did:x509:'"));
    }

    [Test]
    public void Parse_WithoutPolicies_ThrowsFormatException()
    {
        // Arrange
        string invalidDid = "did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk";

        // Act & Assert
        var ex = Assert.Throws<FormatException>(() => DidX509Parser.Parse(invalidDid));
        Assert.That(ex!.Message, Does.Contain("Must contain at least one policy"));
    }

    [Test]
    public void Parse_WithIncorrectNumberOfPrefixComponents_ThrowsFormatException()
    {
        // Arrange
        string invalidDid = "did:x509:0:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::subject:CN:test"; // Missing algorithm

        // Act & Assert
        var ex = Assert.Throws<FormatException>(() => DidX509Parser.Parse(invalidDid));
        Assert.That(ex!.Message, Does.Contain("Expected format 'did:x509:version:algorithm:fingerprint'"));
    }

    [Test]
    public void Parse_WithWrongMethod_ThrowsFormatException()
    {
        // Arrange
        string invalidDid = "did:web:0:sha256:abc::subject:CN:test";

        // Act & Assert
        var ex = Assert.Throws<FormatException>(() => DidX509Parser.Parse(invalidDid));
        Assert.That(ex!.Message, Does.Contain("Must start with 'did:x509:'"));
    }

    [Test]
    public void Parse_WithUnsupportedVersion_ThrowsFormatException()
    {
        // Arrange
        string invalidDid = "did:x509:1:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::subject:CN:test";

        // Act & Assert
        var ex = Assert.Throws<FormatException>(() => DidX509Parser.Parse(invalidDid));
        Assert.That(ex!.Message, Does.Contain("Unsupported version"));
    }

    [Test]
    public void Parse_WithUnsupportedHashAlgorithm_ThrowsFormatException()
    {
        // Arrange
        string invalidDid = "did:x509:0:md5:abc123::subject:CN:test";

        // Act & Assert
        var ex = Assert.Throws<FormatException>(() => DidX509Parser.Parse(invalidDid));
        Assert.That(ex!.Message, Does.Contain("Unsupported hash algorithm"));
    }

    [Test]
    public void Parse_WithEmptyCAFingerprint_ThrowsFormatException()
    {
        // Arrange
        string invalidDid = "did:x509:0:sha256:::subject:CN:test";

        // Act & Assert
        var ex = Assert.Throws<FormatException>(() => DidX509Parser.Parse(invalidDid));
        Assert.That(ex!.Message, Does.Contain("Expected format 'did:x509:version:algorithm:fingerprint'"));
    }

    [Test]
    public void Parse_WithWrongFingerprintLengthForSha256_ThrowsFormatException()
    {
        // Arrange
        string invalidDid = "did:x509:0:sha256:tooShort::subject:CN:test";

        // Act & Assert
        var ex = Assert.Throws<FormatException>(() => DidX509Parser.Parse(invalidDid));
        Assert.That(ex!.Message, Does.Contain("CA fingerprint length mismatch"));
        Assert.That(ex.Message, Does.Contain("expected 43"));
    }

    [Test]
    public void Parse_WithSha384_ValidatesCorrectLength()
    {
        // Arrange - SHA-384 produces 64 character base64url
        string did = "did:x509:0:sha384:1234567890123456789012345678901234567890123456789012345678901234::subject:CN:test";

        // Act
        var result = DidX509Parser.Parse(did);

        // Assert
        Assert.That(result.HashAlgorithm, Is.EqualTo("sha384"));
    }

    [Test]
    public void Parse_WithSha512_ValidatesCorrectLength()
    {
        // Arrange - SHA-512 produces 86 character base64url
        string did = "did:x509:0:sha512:12345678901234567890123456789012345678901234567890123456789012345678901234567890123456::subject:CN:test";

        // Act
        var result = DidX509Parser.Parse(did);

        // Assert
        Assert.That(result.HashAlgorithm, Is.EqualTo("sha512"));
    }

    [Test]
    public void Parse_WithInvalidBase64UrlCharacters_ThrowsFormatException()
    {
        // Arrange
        string invalidDid = "did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl3+/=::subject:CN:test"; // Contains +, /, =

        // Act & Assert
        var ex = Assert.Throws<FormatException>(() => DidX509Parser.Parse(invalidDid));
        Assert.That(ex!.Message, Does.Contain("invalid base64url characters"));
    }

    [Test]
    public void Parse_WithEmptyPolicy_ThrowsFormatException()
    {
        // Arrange
        string invalidDid = "did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::::subject:CN:test";

        // Act & Assert
        var ex = Assert.Throws<FormatException>(() => DidX509Parser.Parse(invalidDid));
        Assert.That(ex!.Message, Does.Contain("Empty policy"));
    }

    [Test]
    public void Parse_WithPolicyMissingColon_ThrowsFormatException()
    {
        // Arrange
        string invalidDid = "did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::invalidpolicy";

        // Act & Assert
        var ex = Assert.Throws<FormatException>(() => DidX509Parser.Parse(invalidDid));
        Assert.That(ex!.Message, Does.Contain("Policy must have format 'name:value'"));
    }

    [Test]
    public void Parse_WithEmptyPolicyName_ThrowsFormatException()
    {
        // Arrange
        string invalidDid = "did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk:::value";

        // Act & Assert
        var ex = Assert.Throws<FormatException>(() => DidX509Parser.Parse(invalidDid));
        Assert.That(ex!.Message, Does.Contain("Policy must have format 'name:value'"));
    }

    [Test]
    public void Parse_WithEmptyPolicyValue_ThrowsFormatException()
    {
        // Arrange
        string invalidDid = "did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::policy:";

        // Act & Assert
        var ex = Assert.Throws<FormatException>(() => DidX509Parser.Parse(invalidDid));
        Assert.That(ex!.Message, Does.Contain("Policy value cannot be empty"));
    }

    [Test]
    public void Parse_WithSubjectPolicy_ParsesCorrectly()
    {
        // Arrange
        string did = "did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::subject:CN:example.com:O:Acme%20Corp";

        // Act
        var result = DidX509Parser.Parse(did);

        // Assert
        Assert.That(result.Policies[0].Name, Is.EqualTo("subject"));
        var parsed = result.Policies[0].ParsedValue as Dictionary<string, string>;
        Assert.That(parsed, Is.Not.Null);
        Assert.That(parsed!["CN"], Is.EqualTo("example.com"));
        Assert.That(parsed["O"], Is.EqualTo("Acme Corp")); // Percent-decoded
    }

    [Test]
    public void Parse_WithSubjectPolicyOddComponents_ThrowsFormatException()
    {
        // Arrange
        string invalidDid = "did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::subject:CN:example.com:O"; // Missing value

        // Act & Assert
        var ex = Assert.Throws<FormatException>(() => DidX509Parser.Parse(invalidDid));
        Assert.That(ex!.Message, Does.Contain("even number of components"));
    }

    [Test]
    public void Parse_WithSubjectPolicyEmptyKey_ThrowsFormatException()
    {
        // Arrange
        string invalidDid = "did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::subject::value";

        // Act & Assert
        var ex = Assert.Throws<FormatException>(() => DidX509Parser.Parse(invalidDid));
        Assert.That(ex!.Message, Does.Contain("Policy must have format 'name:value'"));
    }

    [Test]
    public void Parse_WithSubjectPolicyDuplicateKey_ThrowsFormatException()
    {
        // Arrange
        string invalidDid = "did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::subject:CN:first:CN:second";

        // Act & Assert
        var ex = Assert.Throws<FormatException>(() => DidX509Parser.Parse(invalidDid));
        Assert.That(ex!.Message, Does.Contain("Duplicate key"));
    }

    [Test]
    public void Parse_WithSubjectPolicyNoKeyValuePairs_ThrowsFormatException()
    {
        // Arrange
        string invalidDid = "did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::subject:";

        // Act & Assert
        var ex = Assert.Throws<FormatException>(() => DidX509Parser.Parse(invalidDid));
        Assert.That(ex!.Message, Does.Contain("Policy value cannot be empty"));
    }

    [Test]
    public void Parse_WithSanPolicy_ParsesCorrectly()
    {
        // Arrange
        string did = "did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::san:email:user%40example.com";

        // Act
        var result = DidX509Parser.Parse(did);

        // Assert
        Assert.That(result.Policies[0].Name, Is.EqualTo("san"));
        var parsed = result.Policies[0].ParsedValue as (string Type, string Value)?;
        Assert.That(parsed, Is.Not.Null);
        Assert.That(parsed!.Value.Type, Is.EqualTo("email"));
        Assert.That(parsed.Value.Value, Is.EqualTo("user@example.com")); // Percent-decoded
    }

    [Test]
    public void Parse_WithSanPolicyDnsType_ParsesCorrectly()
    {
        // Arrange
        string did = "did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::san:dns:example.com";

        // Act
        var result = DidX509Parser.Parse(did);

        // Assert
        var parsed = result.Policies[0].ParsedValue as (string Type, string Value)?;
        Assert.That(parsed!.Value.Type, Is.EqualTo("dns"));
    }

    [Test]
    public void Parse_WithSanPolicyUriType_ParsesCorrectly()
    {
        // Arrange
        string did = "did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::san:uri:https%3A%2F%2Fexample.com";

        // Act
        var result = DidX509Parser.Parse(did);

        // Assert
        var parsed = result.Policies[0].ParsedValue as (string Type, string Value)?;
        Assert.That(parsed!.Value.Type, Is.EqualTo("uri"));
        Assert.That(parsed.Value.Value, Is.EqualTo("https://example.com"));
    }

    [Test]
    public void Parse_WithSanPolicyInvalidFormat_ThrowsFormatException()
    {
        // Arrange
        string invalidDid = "did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::san:email"; // No value

        // Act & Assert
        var ex = Assert.Throws<FormatException>(() => DidX509Parser.Parse(invalidDid));
        Assert.That(ex!.Message, Does.Contain("Must have format 'type:value'"));
    }

    [Test]
    public void Parse_WithSanPolicyInvalidType_ThrowsFormatException()
    {
        // Arrange
        string invalidDid = "did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::san:invalid:value";

        // Act & Assert
        var ex = Assert.Throws<FormatException>(() => DidX509Parser.Parse(invalidDid));
        Assert.That(ex!.Message, Does.Contain("SAN type must be 'email', 'dns', or 'uri'"));
    }

    [Test]
    public void Parse_WithEkuPolicy_ParsesCorrectly()
    {
        // Arrange
        string did = "did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::eku:1.3.6.1.5.5.7.3.3";

        // Act
        var result = DidX509Parser.Parse(did);

        // Assert
        Assert.That(result.Policies[0].Name, Is.EqualTo("eku"));
        Assert.That(result.Policies[0].ParsedValue, Is.EqualTo("1.3.6.1.5.5.7.3.3"));
    }

    [Test]
    public void Parse_WithEkuPolicyInvalidOid_ThrowsFormatException()
    {
        // Arrange
        string invalidDid = "did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::eku:not-an-oid";

        // Act & Assert
        var ex = Assert.Throws<FormatException>(() => DidX509Parser.Parse(invalidDid));
        Assert.That(ex!.Message, Does.Contain("Must be a valid OID"));
    }

    [Test]
    public void Parse_WithEkuPolicyTooShortOid_ThrowsFormatException()
    {
        // Arrange
        string invalidDid = "did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::eku:1";

        // Act & Assert
        var ex = Assert.Throws<FormatException>(() => DidX509Parser.Parse(invalidDid));
        Assert.That(ex!.Message, Does.Contain("Must be a valid OID"));
    }

    [Test]
    public void Parse_WithFulcioIssuerPolicy_ParsesCorrectly()
    {
        // Arrange
        string did = "did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::fulcio-issuer:accounts.google.com";

        // Act
        var result = DidX509Parser.Parse(did);

        // Assert
        Assert.That(result.Policies[0].Name, Is.EqualTo("fulcio-issuer"));
        Assert.That(result.Policies[0].ParsedValue, Is.EqualTo("accounts.google.com"));
    }

    [Test]
    public void Parse_WithFulcioIssuerPolicyEmpty_ThrowsFormatException()
    {
        // Arrange
        string invalidDid = "did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::fulcio-issuer:";

        // Act & Assert
        var ex = Assert.Throws<FormatException>(() => DidX509Parser.Parse(invalidDid));
        Assert.That(ex!.Message, Does.Contain("Policy value cannot be empty"));
    }

    [Test]
    public void Parse_WithUnknownPolicy_KeepsRawValue()
    {
        // Arrange
        string did = "did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::custom:value123";

        // Act
        var result = DidX509Parser.Parse(did);

        // Assert
        Assert.That(result.Policies[0].Name, Is.EqualTo("custom"));
        Assert.That(result.Policies[0].RawValue, Is.EqualTo("value123"));
        Assert.That(result.Policies[0].ParsedValue, Is.Null);
    }

    [Test]
    public void Parse_WithMultiplePolicies_ParsesAll()
    {
        // Arrange
        string did = "did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::subject:CN:example.com::san:email:user@example.com::eku:1.3.6.1.5.5.7.3.3";

        // Act
        var result = DidX509Parser.Parse(did);

        // Assert
        Assert.That(result.Policies, Has.Count.EqualTo(3));
        Assert.That(result.Policies[0].Name, Is.EqualTo("subject"));
        Assert.That(result.Policies[1].Name, Is.EqualTo("san"));
        Assert.That(result.Policies[2].Name, Is.EqualTo("eku"));
    }

    [Test]
    public void TryParse_WithValidDid_ReturnsTrue()
    {
        // Arrange
        string did = "did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::subject:CN:test";

        // Act
        bool result = DidX509Parser.TryParse(did, out var parsed);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(parsed, Is.Not.Null);
        Assert.That(parsed!.Version, Is.EqualTo("0"));
    }

    [Test]
    public void TryParse_WithInvalidDid_ReturnsFalse()
    {
        // Arrange
        string invalidDid = "invalid-did";

        // Act
        bool result = DidX509Parser.TryParse(invalidDid, out var parsed);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(parsed, Is.Null);
    }

    [Test]
    public void Parse_WithCaseInsensitiveHashAlgorithm_ParsesCorrectly()
    {
        // Arrange
        string did = "did:x509:0:SHA256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::subject:CN:test";

        // Act
        var result = DidX509Parser.Parse(did);

        // Assert
        Assert.That(result.HashAlgorithm, Is.EqualTo("sha256")); // Converted to lowercase
    }

    [Test]
    public void Parse_WithEkuPolicyEmptyComponent_ThrowsFormatException()
    {
        // Arrange
        string invalidDid = "did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::eku:1..3";

        // Act & Assert
        var ex = Assert.Throws<FormatException>(() => DidX509Parser.Parse(invalidDid));
        Assert.That(ex!.Message, Does.Contain("Must be a valid OID"));
    }
}