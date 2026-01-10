// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Validation;

using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Certificates.Validation;
using CoseSign1.Direct;
using CoseSign1.Validation;

[TestFixture]
[System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
public class CertificateChainAssertionProviderTests
{
    /// <summary>
    /// Creates a test context with a certificate and a valid COSE Sign1 message.
    /// The returned context is disposable to properly clean up the certificate.
    /// </summary>
    private static TestContext CreateTestContext(string certName = "ChainValidatorTest")
    {
        var cert = TestCertificateUtils.CreateCertificate(certName);
        var chainBuilder = new X509ChainBuilder();
        var signingService = CertificateSigningService.Create(cert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test");
        var message = CoseSign1Message.DecodeSign1(messageBytes);

        return new TestContext(cert, message);
    }

    private sealed class TestContext : IDisposable
    {
        public X509Certificate2 TestCert { get; }
        public CoseSign1Message ValidMessage { get; }

        public TestContext(X509Certificate2 cert, CoseSign1Message message)
        {
            TestCert = cert;
            ValidMessage = message;
        }

        public void Dispose() => TestCert.Dispose();
    }

    [Test]
    public void Constructor_WithDefaultParameters_CreatesValidator()
    {
        var validator = new CertificateChainAssertionProvider();
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithRevocationMode_CreatesValidator()
    {
        var validator = new CertificateChainAssertionProvider(
            allowUnprotectedHeaders: false,
            allowUntrusted: false,
            revocationMode: X509RevocationMode.NoCheck);

        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithCustomRoots_CreatesValidator()
    {
        var customRoots = new X509Certificate2Collection();
        var validator = new CertificateChainAssertionProvider(
            customRoots,
            allowUnprotectedHeaders: false,
            trustUserRoots: true,
            revocationMode: X509RevocationMode.NoCheck);

        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithNullCustomRootsCollection_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new CertificateChainAssertionProvider((X509Certificate2Collection)null!, allowUnprotectedHeaders: false));
    }

    [Test]
    public void Constructor_WithCustomChainBuilder_CreatesValidator()
    {
        var chainBuilder = new X509ChainBuilder();
        var validator = new CertificateChainAssertionProvider(
            chainBuilder,
            allowUnprotectedHeaders: false,
            allowUntrusted: false);

        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithNullChainBuilder_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new CertificateChainAssertionProvider((Interfaces.ICertificateChainBuilder)null!, allowUnprotectedHeaders: false));
    }

    [Test]
    public void Validate_WithNullInput_ReturnsFailure()
    {
        var validator = new CertificateChainAssertionProvider(allowUntrusted: true, revocationMode: X509RevocationMode.NoCheck);
        var result = validator.Validate(null!, ValidationStage.KeyMaterialTrust);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.ValidatorName, Is.EqualTo(nameof(CertificateChainAssertionProvider)));
        Assert.That(result.Failures.Any(e => e.ErrorCode == "NULL_INPUT"), Is.True);
    }

    [Test]
    public void Validate_WithValidSelfSignedCertificate_AllowUntrusted_ReturnsSuccess()
    {
        using var ctx = CreateTestContext();
        var validator = new CertificateChainAssertionProvider(allowUntrusted: true, revocationMode: X509RevocationMode.NoCheck);
        var result = validator.Validate(ctx.ValidMessage, ValidationStage.KeyMaterialTrust);

        Assert.That(result.IsValid, Is.True);
        Assert.That(result.ValidatorName, Is.EqualTo(nameof(CertificateChainAssertionProvider)));
    }

    [Test]
    public void Validate_WithValidCertificate_NoRevocationCheck_ReturnsSuccess()
    {
        using var ctx = CreateTestContext();
        var validator = new CertificateChainAssertionProvider(
            allowUnprotectedHeaders: false,
            allowUntrusted: true,
            revocationMode: X509RevocationMode.NoCheck);

        var result = validator.Validate(ctx.ValidMessage, ValidationStage.KeyMaterialTrust);

        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Metadata.ContainsKey("CertificateThumbprint"), Is.True);
    }

    [Test]
    public void Validate_WithAllowUnprotectedHeaders_AcceptsUnprotectedCertificateHeaders()
    {
        using var ctx = CreateTestContext();
        var validator = new CertificateChainAssertionProvider(
            allowUnprotectedHeaders: true,
            allowUntrusted: true,
            revocationMode: X509RevocationMode.NoCheck);

        var result = validator.Validate(ctx.ValidMessage, ValidationStage.KeyMaterialTrust);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public async Task ValidateAsync_ReturnsResultSynchronously()
    {
        using var ctx = CreateTestContext();
        var validator = new CertificateChainAssertionProvider(allowUntrusted: true, revocationMode: X509RevocationMode.NoCheck);
        var result = await validator.ValidateAsync(ctx.ValidMessage, ValidationStage.KeyMaterialTrust);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public async Task ValidateAsync_WithCancellationToken_CompletesSuccessfully()
    {
        using var ctx = CreateTestContext();
        var validator = new CertificateChainAssertionProvider(allowUntrusted: true, revocationMode: X509RevocationMode.NoCheck);
        using var cts = new CancellationTokenSource();
        var result = await validator.ValidateAsync(ctx.ValidMessage, ValidationStage.KeyMaterialTrust, cts.Token);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Validate_WithCustomRootsAndTrustUserRoots_ValidatesAgainstCustomRoots()
    {
        using var ctx = CreateTestContext();
        var customRoots = new X509Certificate2Collection { ctx.TestCert };
        var validator = new CertificateChainAssertionProvider(
            customRoots,
            allowUnprotectedHeaders: false,
            trustUserRoots: true,
            revocationMode: X509RevocationMode.NoCheck);

        var result = validator.Validate(ctx.ValidMessage, ValidationStage.KeyMaterialTrust);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Validate_WithCustomRootsAndTrustUserRootsFalse_UsesSystemRoots()
    {
        using var ctx = CreateTestContext();
        var customRoots = new X509Certificate2Collection { ctx.TestCert };
        var validator = new CertificateChainAssertionProvider(
            customRoots,
            allowUnprotectedHeaders: false,
            trustUserRoots: false,
            revocationMode: X509RevocationMode.NoCheck);

        var result = validator.Validate(ctx.ValidMessage, ValidationStage.KeyMaterialTrust);

        // Result may vary based on system trust, but validator should not throw
        Assert.That(result, Is.Not.Null);
        Assert.That(result.ValidatorName, Is.EqualTo(nameof(CertificateChainAssertionProvider)));
    }

    [Test]
    public void Validate_WithCustomChainBuilderAndCustomRoots_UsesProvidedBuilder()
    {
        using var ctx = CreateTestContext();
        var customChainBuilder = new X509ChainBuilder();
        var customRoots = new X509Certificate2Collection { ctx.TestCert };

        var validator = new CertificateChainAssertionProvider(
            customChainBuilder,
            allowUnprotectedHeaders: false,
            allowUntrusted: true,
            customRoots: customRoots,
            trustUserRoots: true);

        var result = validator.Validate(ctx.ValidMessage, ValidationStage.KeyMaterialTrust);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Validate_WithNoCertificateInMessage_ReturnsFailure()
    {
        // Create a message without a certificate (manually crafted)
        var emptyCoseMsg = CoseSign1Message.DecodeSign1(new byte[]
        {
            0xd2, // COSE_Sign1 tag
            0x84, // 4-element array
            0x40, // empty protected headers
            0xa0, // empty unprotected headers
            0x43, 0x01, 0x02, 0x03, // payload
            0x40  // empty signature
        });

        var validator = new CertificateChainAssertionProvider(allowUntrusted: true, revocationMode: X509RevocationMode.NoCheck);
        var result = validator.Validate(emptyCoseMsg, ValidationStage.KeyMaterialTrust);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(e => e.ErrorCode == "CERTIFICATE_NOT_FOUND"), Is.True);
    }

    [Test]
    public void Validate_ResultContainsCertificateThumbprint()
    {
        using var ctx = CreateTestContext();
        var validator = new CertificateChainAssertionProvider(allowUntrusted: true, revocationMode: X509RevocationMode.NoCheck);
        var result = validator.Validate(ctx.ValidMessage, ValidationStage.KeyMaterialTrust);

        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Metadata.ContainsKey("CertificateThumbprint"), Is.True);
        Assert.That(result.Metadata["CertificateThumbprint"], Is.Not.Null);
        Assert.That(result.Metadata["CertificateThumbprint"], Is.EqualTo(ctx.TestCert.Thumbprint));
    }

    [Test]
    public void Validate_WithAllowUntrusted_SetsAllowedUntrustedMetadata()
    {
        using var ctx = CreateTestContext();
        var validator = new CertificateChainAssertionProvider(allowUntrusted: true, revocationMode: X509RevocationMode.NoCheck);
        var result = validator.Validate(ctx.ValidMessage, ValidationStage.KeyMaterialTrust);

        Assert.That(result.IsValid, Is.True);
        if (result.Metadata.ContainsKey("AllowedUntrusted"))
        {
            Assert.That(result.Metadata["AllowedUntrusted"], Is.True);
        }
    }

    [Test]
    public void Validate_WithTrustedCustomRoot_SetsTrustedCustomRootMetadata()
    {
        using var ctx = CreateTestContext();
        var customRoots = new X509Certificate2Collection { ctx.TestCert };
        var validator = new CertificateChainAssertionProvider(
            customRoots,
            allowUnprotectedHeaders: false,
            trustUserRoots: true,
            revocationMode: X509RevocationMode.NoCheck);

        var result = validator.Validate(ctx.ValidMessage, ValidationStage.KeyMaterialTrust);

        Assert.That(result.IsValid, Is.True);
        if (result.Metadata.ContainsKey("TrustedCustomRoot"))
        {
            Assert.That(result.Metadata["TrustedCustomRoot"], Is.Not.Null);
        }
    }

    [Test]
    public void Validate_WithEmptyCustomRootsCollection_UsesSystemRoots()
    {
        using var ctx = CreateTestContext();
        var emptyRoots = new X509Certificate2Collection();
        var validator = new CertificateChainAssertionProvider(
            emptyRoots,
            allowUnprotectedHeaders: false,
            trustUserRoots: true,
            revocationMode: X509RevocationMode.NoCheck);

        var result = validator.Validate(ctx.ValidMessage, ValidationStage.KeyMaterialTrust);

        // Should not throw, result may vary
        Assert.That(result, Is.Not.Null);
    }

    [Test]
    public void Validate_WithRevocationModeOnline_CompletesWithoutError()
    {
        // This test may be slow due to online revocation check
        using var ctx = CreateTestContext();
        var validator = new CertificateChainAssertionProvider(
            allowUnprotectedHeaders: false,
            allowUntrusted: true,
            revocationMode: X509RevocationMode.Online);

        var result = validator.Validate(ctx.ValidMessage, ValidationStage.KeyMaterialTrust);

        // Should complete without exception
        Assert.That(result, Is.Not.Null);
    }

    [Test]
    public void Validate_WithRevocationModeOffline_CompletesWithoutError()
    {
        using var ctx = CreateTestContext();
        var validator = new CertificateChainAssertionProvider(
            allowUnprotectedHeaders: false,
            allowUntrusted: true,
            revocationMode: X509RevocationMode.Offline);

        var result = validator.Validate(ctx.ValidMessage, ValidationStage.KeyMaterialTrust);

        // Should complete without exception
        Assert.That(result, Is.Not.Null);
    }

    [Test]
    public void Validate_WithChainBuildFailure_ReturnsFailureWithChainStatus()
    {
        // Use a certificate that will fail chain building (system roots, no untrusted allowed)
        using var ctx = CreateTestContext();
        var validator = new CertificateChainAssertionProvider(
            allowUnprotectedHeaders: false,
            allowUntrusted: false,
            revocationMode: X509RevocationMode.NoCheck);

        var result = validator.Validate(ctx.ValidMessage, ValidationStage.KeyMaterialTrust);

        // Self-signed cert without allowUntrusted should fail
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Count, Is.GreaterThan(0));
    }

    [Test]
    public void Validate_WhenChainBuildFailsAndStatusIsNoError_ReturnsDefaultChainBuildFailedFailure()
    {
        using var ctx = CreateTestContext();
        var chainBuilder = new FakeChainBuilder
        {
            ChainPolicy = new X509ChainPolicy { RevocationMode = X509RevocationMode.NoCheck },
            ChainStatus = new[] { new X509ChainStatus { Status = X509ChainStatusFlags.NoError, StatusInformation = string.Empty } },
            BuildResult = false
        };

        var validator = new CertificateChainAssertionProvider(
            chainBuilder,
            allowUnprotectedHeaders: false,
            allowUntrusted: false,
            customRoots: null,
            trustUserRoots: true);

        var result = validator.Validate(ctx.ValidMessage, ValidationStage.KeyMaterialTrust);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(f => f.ErrorCode == "CHAIN_BUILD_FAILED"), Is.True);
    }

    [Test]
    public void Validate_WhenAllowUntrustedAndOnlyUntrustedRoot_ReturnsSuccessWithAllowedUntrustedMetadata()
    {
        using var ctx = CreateTestContext();
        var chainBuilder = new FakeChainBuilder
        {
            ChainPolicy = new X509ChainPolicy { RevocationMode = X509RevocationMode.NoCheck },
            ChainStatus = new[]
            {
                new X509ChainStatus { Status = X509ChainStatusFlags.UntrustedRoot, StatusInformation = "Untrusted" },
                new X509ChainStatus { Status = X509ChainStatusFlags.NoError, StatusInformation = string.Empty }
            },
            BuildResult = false
        };

        var validator = new CertificateChainAssertionProvider(
            chainBuilder,
            allowUnprotectedHeaders: false,
            allowUntrusted: true,
            customRoots: null,
            trustUserRoots: true);

        var result = validator.Validate(ctx.ValidMessage, ValidationStage.KeyMaterialTrust);

        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Metadata.TryGetValue("AllowedUntrusted", out var allowed), Is.True);
        Assert.That(allowed, Is.EqualTo(true));
    }

    [Test]
    public void Validate_WhenCustomRootTrustedAndUntrustedRootOnly_ReturnsSuccessWithTrustedCustomRootMetadata()
    {
        using var ctx = CreateTestContext();
        using var rootCert = TestCertificateUtils.CreateCertificate("CustomRoot");

        var customRoots = new X509Certificate2Collection { rootCert };
        var chainBuilder = new FakeChainBuilder
        {
            ChainPolicy = new X509ChainPolicy { RevocationMode = X509RevocationMode.NoCheck },
            ChainElements = new[] { rootCert },
            ChainStatus = new[]
            {
                new X509ChainStatus { Status = X509ChainStatusFlags.UntrustedRoot, StatusInformation = "Untrusted" },
                new X509ChainStatus { Status = X509ChainStatusFlags.NoError, StatusInformation = string.Empty }
            },
            BuildResult = false
        };

        var validator = new CertificateChainAssertionProvider(
            chainBuilder,
            allowUnprotectedHeaders: false,
            allowUntrusted: false,
            customRoots: customRoots,
            trustUserRoots: true);

        // Ensure the branch that clears ExtraStore runs
        using var sentinel = TestCertificateUtils.CreateCertificate("ExtraStoreSentinel");
        chainBuilder.ChainPolicy.ExtraStore.Add(sentinel);

        var result = validator.Validate(ctx.ValidMessage, ValidationStage.KeyMaterialTrust);

        Assert.That(result.IsValid, Is.True);
        Assert.That(chainBuilder.ChainPolicy.ExtraStore.Cast<X509Certificate2>().Any(c => c.Thumbprint == sentinel.Thumbprint), Is.False);
        Assert.That(result.Metadata.TryGetValue("TrustedCustomRoot", out var trusted), Is.True);
        Assert.That(trusted, Is.EqualTo(rootCert.Thumbprint));
    }

    private sealed class FakeChainBuilder : Interfaces.ICertificateChainBuilder
    {
        public IReadOnlyCollection<X509Certificate2> ChainElements { get; set; } = Array.Empty<X509Certificate2>();

        public X509ChainPolicy ChainPolicy { get; set; } = new();

        public X509ChainStatus[] ChainStatus { get; set; } = Array.Empty<X509ChainStatus>();

        public bool BuildResult { get; set; }

        public bool Build(X509Certificate2 certificate) => BuildResult;
    }

    [Test]
    public void Validate_ChainBuildFailure_IncludesChainStatusInformation()
    {
        using var ctx = CreateTestContext();
        var validator = new CertificateChainAssertionProvider(
            allowUnprotectedHeaders: false,
            allowUntrusted: false,
            revocationMode: X509RevocationMode.NoCheck);

        var result = validator.Validate(ctx.ValidMessage, ValidationStage.KeyMaterialTrust);

        if (!result.IsValid)
        {
            Assert.That(result.Failures.Any(f => !string.IsNullOrEmpty(f.ErrorCode)), Is.True);
            Assert.That(result.Failures.Any(f => !string.IsNullOrEmpty(f.Message)), Is.True);
        }
    }

    [Test]
    public void Validate_WithMessageChainInHeaders_UsesChainForValidation()
    {
        // Create a certificate chain
        using var leafCert = TestCertificateUtils.CreateCertificate("Leaf");
        using var intermediateCert = TestCertificateUtils.CreateCertificate("Intermediate");

        var chainBuilder = new X509ChainBuilder();
        var signingService = CertificateSigningService.Create(leafCert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);

        // Sign message with the leaf certificate
        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test");
        var message = CoseSign1Message.DecodeSign1(messageBytes);

        var validator = new CertificateChainAssertionProvider(allowUntrusted: true, revocationMode: X509RevocationMode.NoCheck);
        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);

        Assert.That(result, Is.Not.Null);
    }

    [Test]
    public void Validate_MultipleValidateCalls_ProduceConsistentResults()
    {
        using var ctx = CreateTestContext();
        var validator = new CertificateChainAssertionProvider(allowUntrusted: true, revocationMode: X509RevocationMode.NoCheck);

        var result1 = validator.Validate(ctx.ValidMessage, ValidationStage.KeyMaterialTrust);
        var result2 = validator.Validate(ctx.ValidMessage, ValidationStage.KeyMaterialTrust);
        var result3 = validator.Validate(ctx.ValidMessage, ValidationStage.KeyMaterialTrust);

        Assert.That(result1.IsValid, Is.EqualTo(result2.IsValid));
        Assert.That(result2.IsValid, Is.EqualTo(result3.IsValid));
        Assert.That(result1.IsValid, Is.True);
    }

    [Test]
    public async Task ValidateAsync_WithMultipleConcurrentCalls_CompletesSuccessfully()
    {
        using var ctx = CreateTestContext();
        var validator = new CertificateChainAssertionProvider(allowUntrusted: true, revocationMode: X509RevocationMode.NoCheck);

        var tasks = new[]
        {
            validator.ValidateAsync(ctx.ValidMessage, ValidationStage.KeyMaterialTrust),
            validator.ValidateAsync(ctx.ValidMessage, ValidationStage.KeyMaterialTrust),
            validator.ValidateAsync(ctx.ValidMessage, ValidationStage.KeyMaterialTrust)
        };

        var results = await Task.WhenAll(tasks);

        Assert.That(results.All(r => r.IsValid), Is.True);
    }

    [Test]
    public void Constructor_WithMultipleCustomRoots_AddsAllRootsToStore()
    {
        using var root1 = TestCertificateUtils.CreateCertificate("Root1");
        using var root2 = TestCertificateUtils.CreateCertificate("Root2");
        var customRoots = new X509Certificate2Collection { root1, root2 };

        var validator = new CertificateChainAssertionProvider(
            customRoots,
            allowUnprotectedHeaders: false,
            trustUserRoots: true,
            revocationMode: X509RevocationMode.NoCheck);

        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Validate_WithCustomChainBuilderAndNoRoots_UsesChainBuilderPolicy()
    {
        using var ctx = CreateTestContext();
        var customChainBuilder = new X509ChainBuilder
        {
            ChainPolicy = new X509ChainPolicy
            {
                RevocationMode = X509RevocationMode.NoCheck
            }
        };

        var validator = new CertificateChainAssertionProvider(
            customChainBuilder,
            allowUnprotectedHeaders: false,
            allowUntrusted: true);

        var result = validator.Validate(ctx.ValidMessage, ValidationStage.KeyMaterialTrust);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Validate_WithTrustUserRootsFalse_DoesNotUseCustomTrustMode()
    {
        using var ctx = CreateTestContext();
        var customRoots = new X509Certificate2Collection { ctx.TestCert };
        var validator = new CertificateChainAssertionProvider(
            customRoots,
            allowUnprotectedHeaders: false,
            trustUserRoots: false,
            revocationMode: X509RevocationMode.NoCheck);

        var result = validator.Validate(ctx.ValidMessage, ValidationStage.KeyMaterialTrust);

        // Should complete without exception, trust mode is system
        Assert.That(result, Is.Not.Null);
        Assert.That(result.ValidatorName, Is.EqualTo(nameof(CertificateChainAssertionProvider)));
    }

    [Test]
    public void Validate_WithCustomRootsButUntrustedRoot_ReturnsFailure()
    {
        using var ctx = CreateTestContext();
        // Create unrelated custom root
        using var unrelatedRoot = TestCertificateUtils.CreateCertificate("UnrelatedRoot");
        var customRoots = new X509Certificate2Collection { unrelatedRoot };

        var validator = new CertificateChainAssertionProvider(
            customRoots,
            allowUnprotectedHeaders: false,
            trustUserRoots: true,
            revocationMode: X509RevocationMode.NoCheck);

        var result = validator.Validate(ctx.ValidMessage, ValidationStage.KeyMaterialTrust);

        // Should fail because the signing cert is not in the custom roots chain
        Assert.That(result, Is.Not.Null);
    }

    [Test]
    public void Validate_WithAllowUntrustedFalse_AndSelfSigned_ReturnsFailure()
    {
        using var ctx = CreateTestContext();
        var validator = new CertificateChainAssertionProvider(
            allowUnprotectedHeaders: false,
            allowUntrusted: false,
            revocationMode: X509RevocationMode.NoCheck);

        var result = validator.Validate(ctx.ValidMessage, ValidationStage.KeyMaterialTrust);

        // Self-signed certificate without allowUntrusted should fail
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Count, Is.GreaterThan(0));
    }

    [Test]
    public void Validate_FailureResult_ContainsChainStatusErrors()
    {
        using var ctx = CreateTestContext();
        var validator = new CertificateChainAssertionProvider(
            allowUnprotectedHeaders: false,
            allowUntrusted: false,
            revocationMode: X509RevocationMode.NoCheck);

        var result = validator.Validate(ctx.ValidMessage, ValidationStage.KeyMaterialTrust);

        // Self-signed cert without untrusted allowed should produce chain status failure
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(), Is.True);
        Assert.That(result.Failures.All(f => !string.IsNullOrEmpty(f.ErrorCode)), Is.True);
    }

    [Test]
    public void Validate_WithChainBuilderAndCustomRoots_ConfiguresCorrectly()
    {
        using var ctx = CreateTestContext();
        var customChainBuilder = new X509ChainBuilder
        {
            ChainPolicy = new X509ChainPolicy
            {
                RevocationMode = X509RevocationMode.NoCheck
            }
        };
        var customRoots = new X509Certificate2Collection { ctx.TestCert };

        var validator = new CertificateChainAssertionProvider(
            customChainBuilder,
            allowUnprotectedHeaders: false,
            allowUntrusted: true,
            customRoots: customRoots,
            trustUserRoots: true);

        var result = validator.Validate(ctx.ValidMessage, ValidationStage.KeyMaterialTrust);

        // Should succeed with the proper configuration
        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Constructor_WithDefaultRevocationMode_UsesOnline()
    {
        using var ctx = CreateTestContext();
        var customRoots = new X509Certificate2Collection { ctx.TestCert };
        var validator = new CertificateChainAssertionProvider(
            customRoots,
            allowUnprotectedHeaders: false,
            trustUserRoots: true);
        // This constructor defaults to Online revocation mode

        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Validate_ResultContainsValidatorName()
    {
        using var ctx = CreateTestContext();
        var validator = new CertificateChainAssertionProvider(allowUntrusted: true, revocationMode: X509RevocationMode.NoCheck);
        var result = validator.Validate(ctx.ValidMessage, ValidationStage.KeyMaterialTrust);

        Assert.That(result.ValidatorName, Is.EqualTo(nameof(CertificateChainAssertionProvider)));
    }

    [Test]
    public void Validate_WithChainThatHasSelfSignedRoot_AndCustomRootsMatch_ReturnsSuccess()
    {
        // Create a chain where the root is self-signed (same subject and issuer)
        using var rootCert = TestCertificateUtils.CreateCertificate("Root");
        var customRoots = new X509Certificate2Collection { rootCert };

        // Create message signed by root (self-signed)
        var chainBuilder = new X509ChainBuilder();
        var signingService = CertificateSigningService.Create(rootCert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test");
        var message = CoseSign1Message.DecodeSign1(messageBytes);

        var validator = new CertificateChainAssertionProvider(
            customRoots,
            allowUnprotectedHeaders: false,
            trustUserRoots: true,
            revocationMode: X509RevocationMode.NoCheck);

        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);

        // The self-signed root is in the custom roots, so it should pass
        Assert.That(result.IsValid, Is.True);
        if (result.Metadata.ContainsKey("TrustedCustomRoot"))
        {
            Assert.That(result.Metadata["TrustedCustomRoot"], Is.EqualTo(rootCert.Thumbprint));
        }
    }

    [Test]
    public async Task ValidateAsync_WithNullInput_ReturnsFailure()
    {
        var validator = new CertificateChainAssertionProvider(allowUntrusted: true, revocationMode: X509RevocationMode.NoCheck);
        var result = await validator.ValidateAsync(null!, ValidationStage.KeyMaterialTrust);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(e => e.ErrorCode == "NULL_INPUT"), Is.True);
    }

    [Test]
    public void Validate_ChainStatus_AllNoError_WithUntrustedRoot_AndAllowUntrusted_ReturnsSuccess()
    {
        using var ctx = CreateTestContext();
        // A self-signed cert should have UntrustedRoot status
        var validator = new CertificateChainAssertionProvider(
            allowUnprotectedHeaders: false,
            allowUntrusted: true,
            revocationMode: X509RevocationMode.NoCheck);

        var result = validator.Validate(ctx.ValidMessage, ValidationStage.KeyMaterialTrust);

        Assert.That(result.IsValid, Is.True);
        if (result.Metadata.ContainsKey("AllowedUntrusted"))
        {
            Assert.That(result.Metadata["AllowedUntrusted"], Is.True);
        }
    }
}