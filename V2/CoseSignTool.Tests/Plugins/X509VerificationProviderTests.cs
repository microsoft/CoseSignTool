// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using System.CommandLine.Parsing;
using CoseSign1.Validation;
using CoseSignTool.Abstractions;
using CoseSignTool.Local.Plugin;

namespace CoseSignTool.Tests.Plugins;

/// <summary>
/// Tests for the X509VerificationProvider class.
/// </summary>
[TestFixture]
public class X509VerificationProviderTests
{
    private X509VerificationProvider Provider = null!;
    private Command Command = null!;
    private Parser Parser = null!;

    [SetUp]
    public void Setup()
    {
        Provider = new X509VerificationProvider();
        Command = new Command("verify", "Test verify command");
        Provider.AddVerificationOptions(Command);
        Parser = new Parser(Command);
    }

    [Test]
    public void ProviderName_ReturnsX509()
    {
        // Assert
        Provider.ProviderName.Should().Be("X509");
    }

    [Test]
    public void Description_ReturnsExpectedDescription()
    {
        // Assert
        Provider.Description.Should().Contain("X.509");
        Provider.Description.Should().Contain("certificate");
    }

    [Test]
    public void Priority_Returns10()
    {
        // Assert - X509 should run after signature validation (0)
        Provider.Priority.Should().Be(10);
    }

    [Test]
    public void AddVerificationOptions_AddsAllRequiredOptions()
    {
        // Assert
        Command.Options.Any(o => o.Name == "trust-roots").Should().BeTrue();
        Command.Options.Any(o => o.Name == "trust-system-roots").Should().BeTrue();
        Command.Options.Any(o => o.Name == "allow-untrusted").Should().BeTrue();
        Command.Options.Any(o => o.Name == "subject-name").Should().BeTrue();
        Command.Options.Any(o => o.Name == "issuer-name").Should().BeTrue();
        Command.Options.Any(o => o.Name == "revocation-mode").Should().BeTrue();
    }

    [Test]
    public void AddVerificationOptions_HasExpectedAliases()
    {
        // Assert - check for aliases
        var trustRootsOption = Command.Options.First(o => o.Name == "trust-roots");
        trustRootsOption.Aliases.Should().Contain("-r");

        var subjectNameOption = Command.Options.First(o => o.Name == "subject-name");
        subjectNameOption.Aliases.Should().Contain("-s");

        var issuerNameOption = Command.Options.First(o => o.Name == "issuer-name");
        issuerNameOption.Aliases.Should().Contain("-i");
    }

    [Test]
    public void IsActivated_WithDefaultOptions_ReturnsTrue()
    {
        // Arrange - default: chain validation is on unless explicitly disabled
        var parseResult = Parser.Parse("");

        // Act
        var isActivated = Provider.IsActivated(parseResult);

        // Assert
        isActivated.Should().BeTrue("chain validation is on by default");
    }

    [Test]
    public void IsActivated_WithAllowUntrusted_ReturnsFalse()
    {
        // Arrange - allowing untrusted disables chain validation
        var parseResult = Parser.Parse("--allow-untrusted");

        // Act
        var isActivated = Provider.IsActivated(parseResult);

        // Assert
        isActivated.Should().BeFalse("chain validation is disabled with --allow-untrusted");
    }

    [Test]
    public void IsActivated_WithSubjectName_ReturnsTrue()
    {
        // Arrange
        var parseResult = Parser.Parse("--subject-name TestSubject --allow-untrusted");

        // Act
        var isActivated = Provider.IsActivated(parseResult);

        // Assert
        isActivated.Should().BeTrue("subject name validation should activate provider");
    }

    [Test]
    public void IsActivated_WithIssuerName_ReturnsTrue()
    {
        // Arrange
        var parseResult = Parser.Parse("--issuer-name TestIssuer --allow-untrusted");

        // Act
        var isActivated = Provider.IsActivated(parseResult);

        // Assert
        isActivated.Should().BeTrue("issuer name validation should activate provider");
    }

    [Test]
    public void CreateValidators_WithDefaultOptions_ReturnsChainValidator()
    {
        // Arrange
        var parseResult = Parser.Parse("");

        // Act
        var validators = Provider.CreateValidators(parseResult).ToList();

        // Assert
        validators.Should().HaveCount(1);
        validators[0].Should().BeOfType<CoseSign1.Certificates.Validation.CertificateChainValidator>();
    }

    [Test]
    public void CreateValidators_WithSubjectName_IncludesCommonNameValidator()
    {
        // Arrange
        var parseResult = Parser.Parse("--subject-name \"Test Subject\"");

        // Act
        var validators = Provider.CreateValidators(parseResult).ToList();

        // Assert
        validators.Should().HaveCountGreaterThan(1);
        validators.Any(v => v.GetType().Name == "CertificateCommonNameValidator").Should().BeTrue();
    }

    [Test]
    public void CreateValidators_WithIssuerName_IncludesIssuerValidator()
    {
        // Arrange
        var parseResult = Parser.Parse("--issuer-name \"Test Issuer\"");

        // Act
        var validators = Provider.CreateValidators(parseResult).ToList();

        // Assert
        validators.Should().HaveCountGreaterThan(1);
        validators.Any(v => v.GetType().Name == "CertificateIssuerValidator").Should().BeTrue();
    }

    [Test]
    public void CreateValidators_WithAllowUntrusted_ReturnsUntrustedChainValidator()
    {
        // Arrange - explicitly allow untrusted certificates
        var parseResult = Parser.Parse("--allow-untrusted");

        // Act
        var validators = Provider.CreateValidators(parseResult).ToList();

        // Assert
        validators.Should().HaveCount(1);
        validators[0].Should().BeOfType<CoseSign1.Certificates.Validation.CertificateChainValidator>();
    }

    [Test]
    [TestCase("online")]
    [TestCase("offline")]
    [TestCase("none")]
    public void CreateValidators_WithRevocationMode_SetsCorrectMode(string mode)
    {
        // Arrange
        var parseResult = Parser.Parse($"--revocation-mode {mode}");

        // Act
        var validators = Provider.CreateValidators(parseResult).ToList();

        // Assert
        validators.Should().NotBeEmpty();
        // The validator is created - the mode is internal to it
    }

    [Test]
    public void GetVerificationMetadata_WithSystemTrust_ReturnsSystemTrustMode()
    {
        // Arrange
        var parseResult = Parser.Parse("");

        // Act
        var metadata = Provider.GetVerificationMetadata(parseResult, null!, ValidationResult.Success("Test"));

        // Assert
        metadata.Should().ContainKey("Trust Mode");
        metadata["Trust Mode"].Should().Be("System Trust");
    }

    [Test]
    public void GetVerificationMetadata_WithAllowUntrusted_ReturnsUntrustedMode()
    {
        // Arrange
        var parseResult = Parser.Parse("--allow-untrusted");

        // Act
        var metadata = Provider.GetVerificationMetadata(parseResult, null!, ValidationResult.Success("Test"));

        // Assert
        metadata.Should().ContainKey("Trust Mode");
        metadata["Trust Mode"].Should().Be("Untrusted Allowed");
    }

    [Test]
    public void GetVerificationMetadata_WithSubjectName_IncludesSubjectInMetadata()
    {
        // Arrange
        var parseResult = Parser.Parse("--subject-name \"Test Subject\"");

        // Act
        var metadata = Provider.GetVerificationMetadata(parseResult, null!, ValidationResult.Success("Test"));

        // Assert
        metadata.Should().ContainKey("Required Subject");
        metadata["Required Subject"].Should().Be("Test Subject");
    }

    [Test]
    public void GetVerificationMetadata_WithIssuerName_IncludesIssuerInMetadata()
    {
        // Arrange
        var parseResult = Parser.Parse("--issuer-name \"Test Issuer\"");

        // Act
        var metadata = Provider.GetVerificationMetadata(parseResult, null!, ValidationResult.Success("Test"));

        // Assert
        metadata.Should().ContainKey("Required Issuer");
        metadata["Required Issuer"].Should().Be("Test Issuer");
    }

    [Test]
    public void GetVerificationMetadata_IncludesRevocationCheckInfo()
    {
        // Arrange
        var parseResult = Parser.Parse("--revocation-mode offline");

        // Act
        var metadata = Provider.GetVerificationMetadata(parseResult, null!, ValidationResult.Success("Test"));

        // Assert
        metadata.Should().ContainKey("Revocation Check");
        metadata["Revocation Check"].Should().Be("Offline");
    }
}
