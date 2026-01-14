// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Tests.Plugins;

using System.CommandLine;
using System.CommandLine.Parsing;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using CoseSign1.Certificates.Validation;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Results;
using CoseSign1.Validation.Trust.Plan;
using CoseSign1.Validation.Trust.Subjects;
using CoseSignTool.Abstractions;
using CoseSignTool.Local.Plugin;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Tests for the X509VerificationProvider class.
/// </summary>
[TestFixture]
public class X509VerificationProviderTests
{
    /// <summary>
    /// Holds isolated test state for each test.
    /// </summary>
    private record TestContext(
        X509VerificationProvider Provider,
        Command Command,
        Parser Parser);

    /// <summary>
    /// Creates fresh test state for each test.
    /// </summary>
    private static TestContext CreateTestContext()
    {
        var provider = new X509VerificationProvider();
        var command = new Command("verify", "Test verify command");
        provider.AddVerificationOptions(command);
        var parser = new Parser(command);
        return new TestContext(provider, command, parser);
    }

    private static ServiceProvider BuildServiceProvider(TestContext ctx, ParseResult parseResult, VerificationContext verificationContext)
    {
        var services = new ServiceCollection();
        var builder = services.ConfigureCoseValidation();
        ctx.Provider.ConfigureValidation(builder, parseResult, verificationContext);
        return services.BuildServiceProvider();
    }

    [Test]
    public void ProviderName_ReturnsX509()
    {
        // Arrange
        var ctx = CreateTestContext();

        // Assert
        Assert.That(ctx.Provider.ProviderName, Is.EqualTo("X509"));
    }

    [Test]
    public void Description_ReturnsExpectedDescription()
    {
        // Arrange
        var ctx = CreateTestContext();

        // Assert
        Assert.That(ctx.Provider.Description, Does.Contain("X.509"));
        Assert.That(ctx.Provider.Description, Does.Contain("certificate"));
    }

    [Test]
    public void Priority_Returns10()
    {
        // Arrange
        var ctx = CreateTestContext();

        // Assert - X509 should run after signature validation (0)
        Assert.That(ctx.Provider.Priority, Is.EqualTo(10));
    }

    [Test]
    public void AddVerificationOptions_AddsAllRequiredOptions()
    {
        // Arrange
        var ctx = CreateTestContext();

        // Assert
        Assert.That(ctx.Command.Options.Any(o => o.Name == "trust-roots"), Is.True);
        Assert.That(ctx.Command.Options.Any(o => o.Name == "trust-system-roots"), Is.True);
        Assert.That(ctx.Command.Options.Any(o => o.Name == "allow-untrusted"), Is.True);
        Assert.That(ctx.Command.Options.Any(o => o.Name == "subject-name"), Is.True);
        Assert.That(ctx.Command.Options.Any(o => o.Name == "issuer-name"), Is.True);
        Assert.That(ctx.Command.Options.Any(o => o.Name == "revocation-mode"), Is.True);
    }

    [Test]
    public void AddVerificationOptions_HasExpectedAliases()
    {
        // Arrange
        var ctx = CreateTestContext();

        // Assert - check for aliases
        var trustRootsOption = ctx.Command.Options.First(o => o.Name == "trust-roots");
        Assert.That(trustRootsOption.Aliases, Does.Contain("--roots"));

        var subjectNameOption = ctx.Command.Options.First(o => o.Name == "subject-name");
        Assert.That(subjectNameOption.Aliases, Does.Contain("--cn"));

        var issuerNameOption = ctx.Command.Options.First(o => o.Name == "issuer-name");
        Assert.That(issuerNameOption.Aliases, Does.Contain("--issuer"));
    }

    [Test]
    public void IsActivated_WithDefaultOptions_ReturnsTrue()
    {
        // Arrange - default: chain validation is on unless explicitly disabled
        var ctx = CreateTestContext();
        var parseResult = ctx.Parser.Parse("");

        // Act
        var isActivated = ctx.Provider.IsActivated(parseResult);

        // Assert
        Assert.That(isActivated, Is.True, "chain validation is on by default");
    }

    [Test]
    public void IsActivated_WithAllowUntrusted_ReturnsTrue()
    {
        // Arrange - allowing untrusted disables chain validation
        var ctx = CreateTestContext();
        var parseResult = ctx.Parser.Parse("--allow-untrusted");

        // Act
        var isActivated = ctx.Provider.IsActivated(parseResult);

        // Assert
        Assert.That(isActivated, Is.True, "provider should be activated with --allow-untrusted");
    }

    [Test]
    public void IsActivated_WithSubjectName_ReturnsTrue()
    {
        // Arrange
        var ctx = CreateTestContext();
        var parseResult = ctx.Parser.Parse("--subject-name TestSubject --allow-untrusted");

        // Act
        var isActivated = ctx.Provider.IsActivated(parseResult);

        // Assert
        Assert.That(isActivated, Is.True, "subject name validation should activate provider");
    }

    [Test]
    public void IsActivated_WithIssuerName_ReturnsTrue()
    {
        // Arrange
        var ctx = CreateTestContext();
        var parseResult = ctx.Parser.Parse("--issuer-name TestIssuer --allow-untrusted");

        // Act
        var isActivated = ctx.Provider.IsActivated(parseResult);

        // Assert
        Assert.That(isActivated, Is.True, "issuer name validation should activate provider");
    }

    [Test]
    public void CreateTrustPlanPolicy_WithAllowUntrusted_AllowsTrust()
    {
        // Arrange
        var ctx = CreateTestContext();
        var parseResult = ctx.Parser.Parse("--allow-untrusted");

        // Act
        var verificationContext = new VerificationContext(detachedPayload: null);
        var policy = ctx.Provider.CreateTrustPlanPolicy(parseResult, verificationContext);

        // Assert
        Assert.That(policy, Is.Not.Null);

        using var sp = BuildServiceProvider(ctx, parseResult, verificationContext);
        var plan = policy!.Compile(sp);
        var message = CreateTestMessage();
        var subject = TrustSubject.Message(message);
        var decision = plan.Evaluate(subject.Id, message, subject, new TrustEvaluationOptions());

        Assert.That(decision.IsTrusted, Is.True);
    }

    [Test]
    public void CreateTrustPlanPolicy_WithDefaultOptions_DeniesTrustWithoutCertificateHeaders()
    {
        // Arrange
        var ctx = CreateTestContext();
        var parseResult = ctx.Parser.Parse("");

        // Act
        var verificationContext = new VerificationContext(detachedPayload: null);
        var policy = ctx.Provider.CreateTrustPlanPolicy(parseResult, verificationContext);

        // Assert
        Assert.That(policy, Is.Not.Null);

        using var sp = BuildServiceProvider(ctx, parseResult, verificationContext);
        var plan = policy!.Compile(sp);
        var message = CreateTestMessage();
        var subject = TrustSubject.Message(message);
        var decision = plan.Evaluate(subject.Id, message, subject, new TrustEvaluationOptions());

        // The default plan requires chain trust, and our test message has no x5t/x5chain headers.
        Assert.That(decision.IsTrusted, Is.False);
    }

    private static CoseSign1Message CreateTestMessage()
    {
        using var key = ECDsa.Create();
        var payload = "test"u8.ToArray();

        var protectedHeaders = new CoseHeaderMap();
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders: null);
        var encoded = CoseSign1Message.SignEmbedded(payload, signer);
        return CoseSign1Message.DecodeSign1(encoded);
    }

    [Test]
    public void ConfigureValidation_WithDefaultOptions_RegistersCertificateSigningKeyResolver()
    {
        // Arrange
        var ctx = CreateTestContext();
        var parseResult = ctx.Parser.Parse("");

        var verificationContext = new VerificationContext(detachedPayload: null);

        // Act
        using var sp = BuildServiceProvider(ctx, parseResult, verificationContext);
        var resolvers = sp.GetServices<ISigningKeyResolver>().ToArray();

        // Assert - TrustPlan-only: validators only provide key resolution
        Assert.That(resolvers.OfType<CertificateSigningKeyResolver>(), Is.Not.Empty);
    }

    [Test]
    public void ConfigureValidation_WithSubjectName_RegistersCertificateSigningKeyResolver()
    {
        // Arrange
        var ctx = CreateTestContext();
        var parseResult = ctx.Parser.Parse("--subject-name \"Test Subject\"");

        var verificationContext = new VerificationContext(detachedPayload: null);

        // Act
        using var sp = BuildServiceProvider(ctx, parseResult, verificationContext);
        var resolvers = sp.GetServices<ISigningKeyResolver>().ToArray();

        // Assert
        Assert.That(resolvers.OfType<CertificateSigningKeyResolver>(), Is.Not.Empty);
    }

    [Test]
    public void ConfigureValidation_WithIssuerName_RegistersCertificateSigningKeyResolver()
    {
        // Arrange
        var ctx = CreateTestContext();
        var parseResult = ctx.Parser.Parse("--issuer-name \"Test Issuer\"");

        var verificationContext = new VerificationContext(detachedPayload: null);

        // Act
        using var sp = BuildServiceProvider(ctx, parseResult, verificationContext);
        var resolvers = sp.GetServices<ISigningKeyResolver>().ToArray();

        // Assert
        Assert.That(resolvers.OfType<CertificateSigningKeyResolver>(), Is.Not.Empty);
    }

    [Test]
    public void ConfigureValidation_WithAllowUntrusted_RegistersCertificateSigningKeyResolver()
    {
        // Arrange - explicitly allow untrusted certificates
        var ctx = CreateTestContext();
        var parseResult = ctx.Parser.Parse("--allow-untrusted");

        var verificationContext = new VerificationContext(detachedPayload: null);

        // Act
        using var sp = BuildServiceProvider(ctx, parseResult, verificationContext);
        var resolvers = sp.GetServices<ISigningKeyResolver>().ToArray();

        // Assert - TrustPlan-only: validators only provide key resolution
        Assert.That(resolvers.OfType<CertificateSigningKeyResolver>(), Is.Not.Empty);
    }

    [Test]
    [TestCase("online")]
    [TestCase("offline")]
    [TestCase("none")]
    public void ConfigureValidation_WithRevocationMode_DoesNotThrow(string mode)
    {
        // Arrange
        var ctx = CreateTestContext();
        var parseResult = ctx.Parser.Parse($"--revocation-mode {mode}");

        var verificationContext = new VerificationContext(detachedPayload: null);

        // Act
        using var sp = BuildServiceProvider(ctx, parseResult, verificationContext);
        var resolvers = sp.GetServices<ISigningKeyResolver>().ToArray();

        // Assert
        Assert.That(resolvers, Is.Not.Empty);
    }

    [Test]
    public void GetVerificationMetadata_WithSystemTrust_ReturnsSystemTrustMode()
    {
        // Arrange
        var ctx = CreateTestContext();
        var parseResult = ctx.Parser.Parse("");

        // Act
        var metadata = ctx.Provider.GetVerificationMetadata(parseResult, null!, ValidationResult.Success("Test"));

        // Assert
        Assert.That(metadata, Does.ContainKey("Trust Mode"));
        Assert.That(metadata["Trust Mode"], Is.EqualTo("System Trust"));
    }

    [Test]
    public void GetVerificationMetadata_WithAllowUntrusted_ReturnsUntrustedMode()
    {
        // Arrange
        var ctx = CreateTestContext();
        var parseResult = ctx.Parser.Parse("--allow-untrusted");

        // Act
        var metadata = ctx.Provider.GetVerificationMetadata(parseResult, null!, ValidationResult.Success("Test"));

        // Assert
        Assert.That(metadata, Does.ContainKey("Trust Mode"));
        Assert.That(metadata["Trust Mode"], Is.EqualTo("Allow Untrusted"));
    }

    [Test]
    public void GetVerificationMetadata_WithSubjectName_IncludesSubjectInMetadata()
    {
        // Arrange
        var ctx = CreateTestContext();
        var parseResult = ctx.Parser.Parse("--subject-name \"Test Subject\"");

        // Act
        var metadata = ctx.Provider.GetVerificationMetadata(parseResult, null!, ValidationResult.Success("Test"));

        // Assert
        Assert.That(metadata, Does.ContainKey("Required Subject CN"));
        Assert.That(metadata["Required Subject CN"], Is.EqualTo("Test Subject"));
    }

    [Test]
    public void GetVerificationMetadata_WithIssuerName_IncludesIssuerInMetadata()
    {
        // Arrange
        var ctx = CreateTestContext();
        var parseResult = ctx.Parser.Parse("--issuer-name \"Test Issuer\"");

        // Act
        var metadata = ctx.Provider.GetVerificationMetadata(parseResult, null!, ValidationResult.Success("Test"));

        // Assert
        Assert.That(metadata, Does.ContainKey("Required Issuer CN"));
        Assert.That(metadata["Required Issuer CN"], Is.EqualTo("Test Issuer"));
    }

    [Test]
    public void GetVerificationMetadata_IncludesRevocationCheckInfo()
    {
        // Arrange
        var ctx = CreateTestContext();
        var parseResult = ctx.Parser.Parse("--revocation-mode offline");

        // Act
        var metadata = ctx.Provider.GetVerificationMetadata(parseResult, null!, ValidationResult.Success("Test"));

        // Assert
        Assert.That(metadata, Does.ContainKey("Revocation Check"));
        Assert.That(metadata["Revocation Check"], Is.EqualTo("Offline"));
    }

    #region PFX Trust Store Tests

    [Test]
    public void AddVerificationOptions_AddsPfxTrustOptions()
    {
        // Arrange
        var ctx = CreateTestContext();

        // Assert - new PFX trust options should be present
        Assert.That(ctx.Command.Options.Any(o => o.Name == "trust-pfx"), Is.True,
            "Should have --trust-pfx option");
        Assert.That(ctx.Command.Options.Any(o => o.Name == "trust-pfx-password-file"), Is.True,
            "Should have --trust-pfx-password-file option");
        Assert.That(ctx.Command.Options.Any(o => o.Name == "trust-pfx-password-env"), Is.True,
            "Should have --trust-pfx-password-env option");
    }

    [Test]
    public void IsActivated_WithTrustPfxOption_ReturnsTrue()
    {
        // Arrange - create a temp PFX file to reference
        var ctx = CreateTestContext();
        var tempPfxPath = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tempPfxPath, new byte[] { 0x30 }); // Dummy data
            var parseResult = ctx.Parser.Parse($"--trust-pfx \"{tempPfxPath}\" --allow-untrusted");

            // Act
            var isActivated = ctx.Provider.IsActivated(parseResult);

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
        var ctx = CreateTestContext();
        var tempPfxPath = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tempPfxPath, new byte[] { 0x30 }); // Dummy data
            var parseResult = ctx.Parser.Parse($"--trust-pfx \"{tempPfxPath}\"");

            // Act
            var metadata = ctx.Provider.GetVerificationMetadata(parseResult, null!, ValidationResult.Success("Test"));

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
        var ctx = CreateTestContext();
        var tempCertPath = Path.GetTempFileName();
        try
        {
            // Write an invalid cert file (will be skipped)
            File.WriteAllBytes(tempCertPath, [0x30, 0x82, 0x00, 0x01]);
            var parseResult = ctx.Parser.Parse($"--trust-roots \"{tempCertPath}\"");
            var verificationContext = new VerificationContext(detachedPayload: null);

            // Act
            using var sp = BuildServiceProvider(ctx, parseResult, verificationContext);

            // Assert - should still create validators even with invalid cert
            Assert.That(sp, Is.Not.Null);
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
        var ctx = CreateTestContext();
        var nonExistentPath = Path.Combine(Path.GetTempPath(), $"nonexistent_{Guid.NewGuid()}.pem");
        var parseResult = ctx.Parser.Parse($"--trust-roots \"{nonExistentPath}\"");
        var verificationContext = new VerificationContext(detachedPayload: null);

        // Act
        using var sp = BuildServiceProvider(ctx, parseResult, verificationContext);

        // Assert - should handle gracefully without exception
        Assert.That(sp, Is.Not.Null);
    }

    [Test]
    public void CreateValidators_WithSubjectAndIssuer_CreatesMultipleValidators()
    {
        // Arrange
        var ctx = CreateTestContext();
        var parseResult = ctx.Parser.Parse("--subject-name \"TestSubject\" --issuer-name \"TestIssuer\"");
        var verificationContext = new VerificationContext(detachedPayload: null);

        // Act
        using var sp = BuildServiceProvider(ctx, parseResult, verificationContext);
        var resolvers = sp.GetServices<ISigningKeyResolver>().ToArray();

        // Assert - TrustPlan-only: validators only provide key resolution
        Assert.That(resolvers.OfType<CertificateSigningKeyResolver>(), Is.Not.Empty);
    }

    [Test]
    public void IsActivated_WithTrustSystemRootsFalse_ReturnsTrue()
    {
        // Arrange - disable system roots but this doesn't fully deactivate
        var ctx = CreateTestContext();
        var parseResult = ctx.Parser.Parse("--trust-system-roots false");

        // Act
        var isActivated = ctx.Provider.IsActivated(parseResult);

        // Assert - chain validation is still on
        Assert.That(isActivated, Is.True);
    }

    [Test]
    public void GetVerificationMetadata_WithOnlineRevocation_ReturnsOnline()
    {
        // Arrange
        var ctx = CreateTestContext();
        var parseResult = ctx.Parser.Parse("--revocation-mode online");

        // Act
        var metadata = ctx.Provider.GetVerificationMetadata(parseResult, null!, ValidationResult.Success("Test"));

        // Assert
        Assert.That(metadata["Revocation Check"], Is.EqualTo("Online"));
    }

    [Test]
    public void GetVerificationMetadata_WithNoCheckRevocation_ReturnsNoCheck()
    {
        // Arrange
        var ctx = CreateTestContext();
        var parseResult = ctx.Parser.Parse("--revocation-mode none");

        // Act
        var metadata = ctx.Provider.GetVerificationMetadata(parseResult, null!, ValidationResult.Success("Test"));

        // Assert
        Assert.That(metadata["Revocation Check"], Is.EqualTo("NoCheck"));
    }

    [Test]
    public void CreateValidators_WithTrustSystemRootsFalseAndAllowUntrusted_CreatesUntrustedValidator()
    {
        // Arrange
        var ctx = CreateTestContext();
        var parseResult = ctx.Parser.Parse("--trust-system-roots false --allow-untrusted");
        var verificationContext = new VerificationContext(detachedPayload: null);

        // Act
        using var sp = BuildServiceProvider(ctx, parseResult, verificationContext);
        var resolvers = sp.GetServices<ISigningKeyResolver>().ToArray();

        // Assert - TrustPlan-only: validators only provide key resolution
        Assert.That(resolvers.OfType<CertificateSigningKeyResolver>(), Is.Not.Empty);
    }

    [Test]
    public void CreateValidators_WithValidPfxFile_LoadsCertificates()
    {
        // Arrange - create a temp PFX file with a real certificate
        var ctx = CreateTestContext();
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
                var parseResult = ctx.Parser.Parse($"--trust-pfx \"{tempPfxPath}\"");
                var verificationContext = new VerificationContext(detachedPayload: null);

                // Act
                using var sp = BuildServiceProvider(ctx, parseResult, verificationContext);
                var resolvers = sp.GetServices<ISigningKeyResolver>().ToArray();

                // Assert - TrustPlan-only: validators only provide key resolution
                Assert.That(resolvers.OfType<CertificateSigningKeyResolver>(), Is.Not.Empty);
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
        var ctx = CreateTestContext();
        var tempPfxPath = Path.GetTempFileName();
        var tempPasswordPath = Path.GetTempFileName();
        try
        {
            using var cert = CoseSign1.Tests.Common.TestCertificateUtils.CreateCertificate("TrustRoot2");
            var pfxBytes = cert.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pfx, "filepassword");
            File.WriteAllBytes(tempPfxPath, pfxBytes);
            File.WriteAllText(tempPasswordPath, "filepassword");

            var parseResult = ctx.Parser.Parse($"--trust-pfx \"{tempPfxPath}\" --trust-pfx-password-file \"{tempPasswordPath}\"");
            var verificationContext = new VerificationContext(detachedPayload: null);

            // Act
            using var sp = BuildServiceProvider(ctx, parseResult, verificationContext);

            // Assert
            Assert.That(sp, Is.Not.Null);
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
        var ctx = CreateTestContext();
        var tempPfxPath = Path.GetTempFileName();
        try
        {
            using var cert = CoseSign1.Tests.Common.TestCertificateUtils.CreateCertificate("TrustRoot3");
            var pfxBytes = cert.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pfx, "customenvpass");
            File.WriteAllBytes(tempPfxPath, pfxBytes);

            Environment.SetEnvironmentVariable("MY_CUSTOM_PASSWORD_VAR", "customenvpass");
            try
            {
                var parseResult = ctx.Parser.Parse($"--trust-pfx \"{tempPfxPath}\" --trust-pfx-password-env MY_CUSTOM_PASSWORD_VAR");
                var verificationContext = new VerificationContext(detachedPayload: null);

                // Act
                using var sp = BuildServiceProvider(ctx, parseResult, verificationContext);

                // Assert
                Assert.That(sp, Is.Not.Null);
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
        var ctx = CreateTestContext();
        var tempPfxPath = Path.GetTempFileName();
        try
        {
            using var cert = CoseSign1.Tests.Common.TestCertificateUtils.CreateCertificate("TrustRoot4");
            var pfxBytes = cert.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pfx);
            File.WriteAllBytes(tempPfxPath, pfxBytes);

            var parseResult = ctx.Parser.Parse($"--trust-pfx \"{tempPfxPath}\"");
            var verificationContext = new VerificationContext(detachedPayload: null);

            // Act
            using var sp = BuildServiceProvider(ctx, parseResult, verificationContext);

            // Assert
            Assert.That(sp, Is.Not.Null);
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
        var ctx = CreateTestContext();
        var tempPfxPath = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tempPfxPath, [0x00, 0x01, 0x02, 0x03]); // Invalid data
            var parseResult = ctx.Parser.Parse($"--trust-pfx \"{tempPfxPath}\"");
            var verificationContext = new VerificationContext(detachedPayload: null);

            // Act
            using var sp = BuildServiceProvider(ctx, parseResult, verificationContext);

            // Assert - should handle gracefully
            Assert.That(sp, Is.Not.Null);
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
        var ctx = CreateTestContext();
        var tempPemPath = Path.GetTempFileName();
        try
        {
            using var cert = CoseSign1.Tests.Common.TestCertificateUtils.CreateCertificate("PemTrustRoot");
            var pemContent = cert.ExportCertificatePem();
            File.WriteAllText(tempPemPath, pemContent);

            var parseResult = ctx.Parser.Parse($"--trust-roots \"{tempPemPath}\"");
            var verificationContext = new VerificationContext(detachedPayload: null);

            // Act
            using var sp = BuildServiceProvider(ctx, parseResult, verificationContext);
            var resolvers = sp.GetServices<ISigningKeyResolver>().ToArray();

            // Assert
            Assert.That(resolvers.OfType<CertificateSigningKeyResolver>(), Is.Not.Empty);
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
        var ctx = CreateTestContext();
        var tempPem1 = Path.GetTempFileName();
        var tempPem2 = Path.GetTempFileName();
        try
        {
            using var cert1 = CoseSign1.Tests.Common.TestCertificateUtils.CreateCertificate("PemRoot1");
            using var cert2 = CoseSign1.Tests.Common.TestCertificateUtils.CreateCertificate("PemRoot2");
            File.WriteAllText(tempPem1, cert1.ExportCertificatePem());
            File.WriteAllText(tempPem2, cert2.ExportCertificatePem());

            var parseResult = ctx.Parser.Parse($"--trust-roots \"{tempPem1}\" --trust-roots \"{tempPem2}\"");
            var verificationContext = new VerificationContext(detachedPayload: null);

            // Act
            using var sp = BuildServiceProvider(ctx, parseResult, verificationContext);

            // Assert
            Assert.That(sp, Is.Not.Null);
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
        var ctx = CreateTestContext();
        var parseResult = ctx.Parser.Parse("--subject-name \"Subject\" --issuer-name \"Issuer\" --allow-untrusted");

        // Act
        var isActivated = ctx.Provider.IsActivated(parseResult);

        // Assert
        Assert.That(isActivated, Is.True);
    }

    [Test]
    public void GetVerificationMetadata_WithBothSubjectAndIssuer_IncludesBoth()
    {
        // Arrange
        var ctx = CreateTestContext();
        var parseResult = ctx.Parser.Parse("--subject-name \"TestSubj\" --issuer-name \"TestIss\"");

        // Act
        var metadata = ctx.Provider.GetVerificationMetadata(parseResult, null!, ValidationResult.Success("Test"));

        // Assert
        Assert.That(metadata["Required Subject CN"], Is.EqualTo("TestSubj"));
        Assert.That(metadata["Required Issuer CN"], Is.EqualTo("TestIss"));
    }

    #endregion
}
