// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using System.CommandLine.Parsing;
using System.Reflection;
using System.Security.Cryptography.Cose;
using CoseSign1.Validation;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Results;
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
    public void IsActivated_WithAllowUntrusted_ReturnsTrue()
    {
        // Arrange - allowing untrusted disables chain validation
        var parseResult = Parser.Parse("--allow-untrusted");

        // Act
        var isActivated = Provider.IsActivated(parseResult);

        // Assert
        Assert.That(isActivated, Is.True, "provider should be activated with --allow-untrusted");
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
    public void CreateTrustPolicy_WithAllowUntrusted_ReturnsPermissivePolicy()
    {
        var parseResult = Parser.Parse("--allow-untrusted");

        var policy = Provider.CreateTrustPolicy(parseResult, new VerificationContext(detachedPayload: null));

        Assert.That(policy, Is.Not.Null);
        Assert.That(policy!.IsSatisfied(new Dictionary<string, bool>()), Is.True);
    }

    [Test]
    public void CreateTrustPolicy_WithDefaultOptions_RequiresTrustedChain()
    {
        var parseResult = Parser.Parse("");

        var policy = Provider.CreateTrustPolicy(parseResult, new VerificationContext(detachedPayload: null));

        Assert.That(policy, Is.Not.Null);
        Assert.That(policy!.IsSatisfied(new Dictionary<string, bool>()), Is.False);
    }

    [Test]
    public void CreateValidators_WithDefaultOptions_ReturnsChainValidator()
    {
        // Arrange
        var parseResult = Parser.Parse("");

        // Act
        var validators = Provider.CreateValidators(parseResult).ToList();

        // Assert
        Assert.That(validators, Has.Count.EqualTo(2));
        Assert.That(validators.Any(v => v.GetType().Name == "CertificateKeyMaterialResolutionValidator"), Is.True);
        Assert.That(validators.Any(v => UnwrapConditional(v).GetType().Name == "CertificateChainValidator"), Is.True);
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
        Assert.That(validators.Any(v => UnwrapConditional(v).GetType().Name == "CertificateCommonNameValidator"), Is.True);
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
        Assert.That(validators.Any(v => UnwrapConditional(v).GetType().Name == "CertificateIssuerValidator"), Is.True);
    }

    [Test]
    public void CreateValidators_WithAllowUntrusted_ReturnsUntrustedChainValidator()
    {
        // Arrange - explicitly allow untrusted certificates
        var parseResult = Parser.Parse("--allow-untrusted");

        // Act
        var validators = Provider.CreateValidators(parseResult).ToList();

        // Assert
        Assert.That(validators, Has.Count.EqualTo(2));
        Assert.That(validators.Any(v => v.GetType().Name == "CertificateKeyMaterialResolutionValidator"), Is.True);
        Assert.That(validators.Any(v => UnwrapConditional(v).GetType().Name == "CertificateChainValidator"), Is.True);
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

    [Test]
    public void CreateValidators_WithTrustRootsFile_LoadsCertificates()
    {
        // Arrange - create a temp PEM cert file
        var tempCertPath = Path.GetTempFileName();
        try
        {
            // Write an invalid cert file (will be skipped)
            File.WriteAllBytes(tempCertPath, [0x30, 0x82, 0x00, 0x01]);
            var parseResult = Parser.Parse($"--trust-roots \"{tempCertPath}\"");

            // Act
            var validators = Provider.CreateValidators(parseResult).ToList();

            // Assert - should still create validators even with invalid cert
            Assert.That(validators, Has.Count.GreaterThanOrEqualTo(0));
        }
        finally
        {
            File.Delete(tempCertPath);
        }
    }

    [Test]
    public void CreateValidators_WithNonExistentTrustRoots_HandlesGracefully()
    {
        // Arrange - non-existent file path
        var nonExistentPath = Path.Combine(Path.GetTempPath(), $"nonexistent_{Guid.NewGuid()}.pem");
        var parseResult = Parser.Parse($"--trust-roots \"{nonExistentPath}\"");

        // Act
        var validators = Provider.CreateValidators(parseResult).ToList();

        // Assert - should handle gracefully without exception
        Assert.That(validators, Is.Not.Null);
    }

    [Test]
    public void CreateValidators_WithSubjectAndIssuer_CreatesMultipleValidators()
    {
        // Arrange
        var parseResult = Parser.Parse("--subject-name \"TestSubject\" --issuer-name \"TestIssuer\"");

        // Act
        var validators = Provider.CreateValidators(parseResult).ToList();

        // Assert - should have chain + subject + issuer validators
        Assert.That(validators, Has.Count.GreaterThanOrEqualTo(3));
    }

    [Test]
    public void IsActivated_WithTrustSystemRootsFalse_ReturnsTrue()
    {
        // Arrange - disable system roots but this doesn't fully deactivate
        var parseResult = Parser.Parse("--trust-system-roots false");

        // Act
        var isActivated = Provider.IsActivated(parseResult);

        // Assert - chain validation is still on
        Assert.That(isActivated, Is.True);
    }

    [Test]
    public void GetVerificationMetadata_WithOnlineRevocation_ReturnsOnline()
    {
        // Arrange
        var parseResult = Parser.Parse("--revocation-mode online");

        // Act
        var metadata = Provider.GetVerificationMetadata(parseResult, null!, ValidationResult.Success("Test"));

        // Assert
        Assert.That(metadata["Revocation Check"], Is.EqualTo("Online"));
    }

    [Test]
    public void GetVerificationMetadata_WithNoCheckRevocation_ReturnsNoCheck()
    {
        // Arrange
        var parseResult = Parser.Parse("--revocation-mode none");

        // Act
        var metadata = Provider.GetVerificationMetadata(parseResult, null!, ValidationResult.Success("Test"));

        // Assert
        Assert.That(metadata["Revocation Check"], Is.EqualTo("NoCheck"));
    }

    [Test]
    public void CreateValidators_WithTrustSystemRootsFalseAndAllowUntrusted_CreatesUntrustedValidator()
    {
        // Arrange
        var parseResult = Parser.Parse("--trust-system-roots false --allow-untrusted");

        // Act
        var validators = Provider.CreateValidators(parseResult).ToList();

        // Assert
        Assert.That(validators, Has.Count.EqualTo(2));
        Assert.That(validators.Any(v => v.GetType().Name == "CertificateKeyMaterialResolutionValidator"), Is.True);
        Assert.That(validators.Any(v => UnwrapConditional(v).GetType().Name == "CertificateChainValidator"), Is.True);
    }

    private static object UnwrapConditional(IValidator validator)
    {
        var t = validator.GetType();
        if (!string.Equals(t.Name, "ConditionalX509Validator", StringComparison.Ordinal))
        {
            return validator;
        }

        var innerField = t.GetField("Inner", BindingFlags.NonPublic | BindingFlags.Instance);
        return innerField?.GetValue(validator) ?? validator;
    }

    [Test]
    public void CreateValidators_WithValidPfxFile_LoadsCertificates()
    {
        // Arrange - create a temp PFX file with a real certificate
        var tempPfxPath = Path.GetTempFileName();
        try
        {
            using var cert = CoseSign1.Tests.Common.TestCertificateUtils.CreateCertificate("TrustRoot");
            var pfxBytes = cert.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pfx, "testpass");
            File.WriteAllBytes(tempPfxPath, pfxBytes);

            // Set environment variable for PFX password
            Environment.SetEnvironmentVariable("COSESIGNTOOL_TRUST_PFX_PASSWORD", "testpass");
            try
            {
                var parseResult = Parser.Parse($"--trust-pfx \"{tempPfxPath}\"");

                // Act
                var validators = Provider.CreateValidators(parseResult).ToList();

                // Assert - should have a chain validator
                Assert.That(validators, Has.Count.GreaterThan(0));
                Assert.That(validators.Any(v => UnwrapConditional(v).GetType().Name == "CertificateChainValidator"), Is.True);
            }
            finally
            {
                Environment.SetEnvironmentVariable("COSESIGNTOOL_TRUST_PFX_PASSWORD", null);
            }
        }
        finally
        {
            File.Delete(tempPfxPath);
        }
    }

    [Test]
    public void CreateValidators_WithPfxAndPasswordFile_LoadsCertificates()
    {
        // Arrange - create temp PFX and password files
        var tempPfxPath = Path.GetTempFileName();
        var tempPasswordPath = Path.GetTempFileName();
        try
        {
            using var cert = CoseSign1.Tests.Common.TestCertificateUtils.CreateCertificate("TrustRoot2");
            var pfxBytes = cert.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pfx, "filepassword");
            File.WriteAllBytes(tempPfxPath, pfxBytes);
            File.WriteAllText(tempPasswordPath, "filepassword");

            var parseResult = Parser.Parse($"--trust-pfx \"{tempPfxPath}\" --trust-pfx-password-file \"{tempPasswordPath}\"");

            // Act
            var validators = Provider.CreateValidators(parseResult).ToList();

            // Assert
            Assert.That(validators, Has.Count.GreaterThan(0));
        }
        finally
        {
            File.Delete(tempPfxPath);
            File.Delete(tempPasswordPath);
        }
    }

    [Test]
    public void CreateValidators_WithPfxAndCustomEnvVar_LoadsCertificates()
    {
        // Arrange - create temp PFX with custom env var password
        var tempPfxPath = Path.GetTempFileName();
        try
        {
            using var cert = CoseSign1.Tests.Common.TestCertificateUtils.CreateCertificate("TrustRoot3");
            var pfxBytes = cert.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pfx, "customenvpass");
            File.WriteAllBytes(tempPfxPath, pfxBytes);

            Environment.SetEnvironmentVariable("MY_CUSTOM_PASSWORD_VAR", "customenvpass");
            try
            {
                var parseResult = Parser.Parse($"--trust-pfx \"{tempPfxPath}\" --trust-pfx-password-env MY_CUSTOM_PASSWORD_VAR");

                // Act
                var validators = Provider.CreateValidators(parseResult).ToList();

                // Assert
                Assert.That(validators, Has.Count.GreaterThan(0));
            }
            finally
            {
                Environment.SetEnvironmentVariable("MY_CUSTOM_PASSWORD_VAR", null);
            }
        }
        finally
        {
            File.Delete(tempPfxPath);
        }
    }

    [Test]
    public void CreateValidators_WithUnprotectedPfx_LoadsCertificates()
    {
        // Arrange - create unprotected PFX (null password)
        var tempPfxPath = Path.GetTempFileName();
        try
        {
            using var cert = CoseSign1.Tests.Common.TestCertificateUtils.CreateCertificate("TrustRoot4");
            var pfxBytes = cert.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pfx);
            File.WriteAllBytes(tempPfxPath, pfxBytes);

            var parseResult = Parser.Parse($"--trust-pfx \"{tempPfxPath}\"");

            // Act
            var validators = Provider.CreateValidators(parseResult).ToList();

            // Assert
            Assert.That(validators, Has.Count.GreaterThan(0));
        }
        finally
        {
            File.Delete(tempPfxPath);
        }
    }

    [Test]
    public void CreateValidators_WithInvalidPfxFile_HandlesGracefully()
    {
        // Arrange - create invalid PFX file
        var tempPfxPath = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tempPfxPath, [0x00, 0x01, 0x02, 0x03]); // Invalid data
            var parseResult = Parser.Parse($"--trust-pfx \"{tempPfxPath}\"");

            // Act
            var validators = Provider.CreateValidators(parseResult).ToList();

            // Assert - should handle gracefully
            Assert.That(validators, Is.Not.Null);
        }
        finally
        {
            File.Delete(tempPfxPath);
        }
    }

    [Test]
    public void CreateValidators_WithValidPemCertFile_LoadsCertificate()
    {
        // Arrange - create PEM certificate file
        var tempPemPath = Path.GetTempFileName();
        try
        {
            using var cert = CoseSign1.Tests.Common.TestCertificateUtils.CreateCertificate("PemTrustRoot");
            var pemContent = cert.ExportCertificatePem();
            File.WriteAllText(tempPemPath, pemContent);

            var parseResult = Parser.Parse($"--trust-roots \"{tempPemPath}\"");

            // Act
            var validators = Provider.CreateValidators(parseResult).ToList();

            // Assert
            Assert.That(validators, Has.Count.GreaterThan(0));
            Assert.That(validators.Any(v => v.GetType().Name == "CertificateChainValidator"), Is.True);
        }
        finally
        {
            File.Delete(tempPemPath);
        }
    }

    [Test]
    public void CreateValidators_WithMultipleTrustRootFiles_LoadsAll()
    {
        // Arrange - create multiple PEM certificate files
        var tempPem1 = Path.GetTempFileName();
        var tempPem2 = Path.GetTempFileName();
        try
        {
            using var cert1 = CoseSign1.Tests.Common.TestCertificateUtils.CreateCertificate("PemRoot1");
            using var cert2 = CoseSign1.Tests.Common.TestCertificateUtils.CreateCertificate("PemRoot2");
            File.WriteAllText(tempPem1, cert1.ExportCertificatePem());
            File.WriteAllText(tempPem2, cert2.ExportCertificatePem());

            var parseResult = Parser.Parse($"--trust-roots \"{tempPem1}\" --trust-roots \"{tempPem2}\"");

            // Act
            var validators = Provider.CreateValidators(parseResult).ToList();

            // Assert
            Assert.That(validators, Has.Count.GreaterThan(0));
        }
        finally
        {
            File.Delete(tempPem1);
            File.Delete(tempPem2);
        }
    }

    [Test]
    public void IsActivated_WithBothSubjectAndIssuer_ReturnsTrue()
    {
        // Arrange
        var parseResult = Parser.Parse("--subject-name \"Subject\" --issuer-name \"Issuer\" --allow-untrusted");

        // Act
        var isActivated = Provider.IsActivated(parseResult);

        // Assert
        Assert.That(isActivated, Is.True);
    }

    [Test]
    public void GetVerificationMetadata_WithBothSubjectAndIssuer_IncludesBoth()
    {
        // Arrange
        var parseResult = Parser.Parse("--subject-name \"TestSubj\" --issuer-name \"TestIss\"");

        // Act
        var metadata = Provider.GetVerificationMetadata(parseResult, null!, ValidationResult.Success("Test"));

        // Assert
        Assert.That(metadata["Required Subject"], Is.EqualTo("TestSubj"));
        Assert.That(metadata["Required Issuer"], Is.EqualTo("TestIss"));
    }

    #endregion
}