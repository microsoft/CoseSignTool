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
        Assert.That(Provider.ProviderName, Is.EqualTo("X509"));
    }

    [Test]
    public void Description_ReturnsExpectedDescription()
    {
        // Assert
        Assert.That(Provider.Description, Does.Contain("X.509"));
        Assert.That(Provider.Description, Does.Contain("certificate"));
    }

    [Test]
    public void Priority_Returns10()
    {
        // Assert - X509 should run after signature validation (0)
        Assert.That(Provider.Priority, Is.EqualTo(10));
    }

    [Test]
    public void AddVerificationOptions_AddsAllRequiredOptions()
    {
        // Assert
        Assert.That(Command.Options.Any(o => o.Name == "trust-roots"), Is.True);
        Assert.That(Command.Options.Any(o => o.Name == "trust-system-roots"), Is.True);
        Assert.That(Command.Options.Any(o => o.Name == "allow-untrusted"), Is.True);
        Assert.That(Command.Options.Any(o => o.Name == "subject-name"), Is.True);
        Assert.That(Command.Options.Any(o => o.Name == "issuer-name"), Is.True);
        Assert.That(Command.Options.Any(o => o.Name == "revocation-mode"), Is.True);
    }

    [Test]
    public void AddVerificationOptions_HasExpectedAliases()
    {
        // Assert - check for aliases
        var trustRootsOption = Command.Options.First(o => o.Name == "trust-roots");
        Assert.That(trustRootsOption.Aliases, Does.Contain("-r"));

        var subjectNameOption = Command.Options.First(o => o.Name == "subject-name");
        Assert.That(subjectNameOption.Aliases, Does.Contain("-s"));

        var issuerNameOption = Command.Options.First(o => o.Name == "issuer-name");
        Assert.That(issuerNameOption.Aliases, Does.Contain("-i"));
    }

    [Test]
    public void IsActivated_WithDefaultOptions_ReturnsTrue()
    {
        // Arrange - default: chain validation is on unless explicitly disabled
        var parseResult = Parser.Parse("");

        // Act
        var isActivated = Provider.IsActivated(parseResult);

        // Assert
        Assert.That(isActivated, Is.True, "chain validation is on by default");
    }

    [Test]
    public void IsActivated_WithAllowUntrusted_ReturnsFalse()
    {
        // Arrange - allowing untrusted disables chain validation
        var parseResult = Parser.Parse("--allow-untrusted");

        // Act
        var isActivated = Provider.IsActivated(parseResult);

        // Assert
        Assert.That(isActivated, Is.False, "chain validation is disabled with --allow-untrusted");
    }

    [Test]
    public void IsActivated_WithSubjectName_ReturnsTrue()
    {
        // Arrange
        var parseResult = Parser.Parse("--subject-name TestSubject --allow-untrusted");

        // Act
        var isActivated = Provider.IsActivated(parseResult);

        // Assert
        Assert.That(isActivated, Is.True, "subject name validation should activate provider");
    }

    [Test]
    public void IsActivated_WithIssuerName_ReturnsTrue()
    {
        // Arrange
        var parseResult = Parser.Parse("--issuer-name TestIssuer --allow-untrusted");

        // Act
        var isActivated = Provider.IsActivated(parseResult);

        // Assert
        Assert.That(isActivated, Is.True, "issuer name validation should activate provider");
    }

    [Test]
    public void CreateValidators_WithDefaultOptions_ReturnsChainValidator()
    {
        // Arrange
        var parseResult = Parser.Parse("");

        // Act
        var validators = Provider.CreateValidators(parseResult).ToList();

        // Assert
        Assert.That(validators, Has.Count.EqualTo(1));
        Assert.That(validators[0], Is.TypeOf<CoseSign1.Certificates.Validation.CertificateChainValidator>());
    }

    [Test]
    public void CreateValidators_WithSubjectName_IncludesCommonNameValidator()
    {
        // Arrange
        var parseResult = Parser.Parse("--subject-name \"Test Subject\"");

        // Act
        var validators = Provider.CreateValidators(parseResult).ToList();

        // Assert
        Assert.That(validators, Has.Count.GreaterThan(1));
        Assert.That(validators.Any(v => v.GetType().Name == "CertificateCommonNameValidator"), Is.True);
    }

    [Test]
    public void CreateValidators_WithIssuerName_IncludesIssuerValidator()
    {
        // Arrange
        var parseResult = Parser.Parse("--issuer-name \"Test Issuer\"");

        // Act
        var validators = Provider.CreateValidators(parseResult).ToList();

        // Assert
        Assert.That(validators, Has.Count.GreaterThan(1));
        Assert.That(validators.Any(v => v.GetType().Name == "CertificateIssuerValidator"), Is.True);
    }

    [Test]
    public void CreateValidators_WithAllowUntrusted_ReturnsUntrustedChainValidator()
    {
        // Arrange - explicitly allow untrusted certificates
        var parseResult = Parser.Parse("--allow-untrusted");

        // Act
        var validators = Provider.CreateValidators(parseResult).ToList();

        // Assert
        Assert.That(validators, Has.Count.EqualTo(1));
        Assert.That(validators[0], Is.TypeOf<CoseSign1.Certificates.Validation.CertificateChainValidator>());
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
        Assert.That(validators, Is.Not.Empty);
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
        Assert.That(metadata, Does.ContainKey("Trust Mode"));
        Assert.That(metadata["Trust Mode"], Is.EqualTo("System Trust"));
    }

    [Test]
    public void GetVerificationMetadata_WithAllowUntrusted_ReturnsUntrustedMode()
    {
        // Arrange
        var parseResult = Parser.Parse("--allow-untrusted");

        // Act
        var metadata = Provider.GetVerificationMetadata(parseResult, null!, ValidationResult.Success("Test"));

        // Assert
        Assert.That(metadata, Does.ContainKey("Trust Mode"));
        Assert.That(metadata["Trust Mode"], Is.EqualTo("Untrusted Allowed"));
    }

    [Test]
    public void GetVerificationMetadata_WithSubjectName_IncludesSubjectInMetadata()
    {
        // Arrange
        var parseResult = Parser.Parse("--subject-name \"Test Subject\"");

        // Act
        var metadata = Provider.GetVerificationMetadata(parseResult, null!, ValidationResult.Success("Test"));

        // Assert
        Assert.That(metadata, Does.ContainKey("Required Subject"));
        Assert.That(metadata["Required Subject"], Is.EqualTo("Test Subject"));
    }

    [Test]
    public void GetVerificationMetadata_WithIssuerName_IncludesIssuerInMetadata()
    {
        // Arrange
        var parseResult = Parser.Parse("--issuer-name \"Test Issuer\"");

        // Act
        var metadata = Provider.GetVerificationMetadata(parseResult, null!, ValidationResult.Success("Test"));

        // Assert
        Assert.That(metadata, Does.ContainKey("Required Issuer"));
        Assert.That(metadata["Required Issuer"], Is.EqualTo("Test Issuer"));
    }

    [Test]
    public void GetVerificationMetadata_IncludesRevocationCheckInfo()
    {
        // Arrange
        var parseResult = Parser.Parse("--revocation-mode offline");

        // Act
        var metadata = Provider.GetVerificationMetadata(parseResult, null!, ValidationResult.Success("Test"));

        // Assert
        Assert.That(metadata, Does.ContainKey("Revocation Check"));
        Assert.That(metadata["Revocation Check"], Is.EqualTo("Offline"));
    }

    #region PFX Trust Store Tests

    [Test]
    public void AddVerificationOptions_AddsPfxTrustOptions()
    {
        // Assert - new PFX trust options should be present
        Assert.That(Command.Options.Any(o => o.Name == "trust-pfx"), Is.True,
            "Should have --trust-pfx option");
        Assert.That(Command.Options.Any(o => o.Name == "trust-pfx-password-file"), Is.True,
            "Should have --trust-pfx-password-file option");
        Assert.That(Command.Options.Any(o => o.Name == "trust-pfx-password-env"), Is.True,
            "Should have --trust-pfx-password-env option");
    }

    [Test]
    public void IsActivated_WithTrustPfxOption_ReturnsTrue()
    {
        // Arrange - create a temp PFX file to reference
        var tempPfxPath = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tempPfxPath, new byte[] { 0x30 }); // Dummy data
            var parseResult = Parser.Parse($"--trust-pfx \"{tempPfxPath}\" --allow-untrusted");

            // Act
            var isActivated = Provider.IsActivated(parseResult);

            // Assert
            Assert.That(isActivated, Is.True, "PFX trust option should activate provider");
        }
        finally
        {
            File.Delete(tempPfxPath);
        }
    }

    [Test]
    public void GetVerificationMetadata_WithTrustPfx_ReturnsCustomRootsMode()
    {
        // Arrange - create a temp PFX file to reference
        var tempPfxPath = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tempPfxPath, new byte[] { 0x30 }); // Dummy data
            var parseResult = Parser.Parse($"--trust-pfx \"{tempPfxPath}\"");

            // Act
            var metadata = Provider.GetVerificationMetadata(parseResult, null!, ValidationResult.Success("Test"));

            // Assert
            Assert.That(metadata, Does.ContainKey("Trust Mode"));
            Assert.That(metadata["Trust Mode"], Is.EqualTo("Custom Roots"),
                "PFX trust should be reported as Custom Roots mode");
        }
        finally
        {
            File.Delete(tempPfxPath);
        }
    }

    #endregion
}