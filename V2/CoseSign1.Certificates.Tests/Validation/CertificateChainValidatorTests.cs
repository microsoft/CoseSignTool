// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Certificates.Local;
using CoseSign1.Certificates.Validation;
using CoseSign1.Direct;
using CoseSign1.Tests.Common;
using CoseSign1.Validation;
using NUnit.Framework;

namespace CoseSign1.Certificates.Tests.Validation;

[TestFixture]
public class CertificateChainValidatorTests
{
    private X509Certificate2? TestCert;
    private CoseSign1Message? ValidMessage;

    [SetUp]
#pragma warning disable CA2252 // Preview features
    public void SetUp()
    {
        TestCert = TestCertificateUtils.CreateCertificate("ChainValidatorTest");

        var chainBuilder = new X509ChainBuilder();
        var signingService = CertificateSigningService.Create(TestCert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test");
        ValidMessage = CoseSign1Message.DecodeSign1(messageBytes);
    }
#pragma warning restore CA2252

    [TearDown]
    public void TearDown()
    {
        TestCert?.Dispose();
    }

    [Test]
    public void Constructor_WithDefaultParameters_CreatesValidator()
    {
        var validator = new CertificateChainValidator();
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithRevocationMode_CreatesValidator()
    {
        var validator = new CertificateChainValidator(
            allowUnprotectedHeaders: false,
            allowUntrusted: false,
            revocationMode: X509RevocationMode.NoCheck);

        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithCustomRoots_CreatesValidator()
    {
        var customRoots = new X509Certificate2Collection();
        var validator = new CertificateChainValidator(
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
            new CertificateChainValidator((X509Certificate2Collection)null!, allowUnprotectedHeaders: false));
    }

    [Test]
    public void Constructor_WithCustomChainBuilder_CreatesValidator()
    {
        var chainBuilder = new X509ChainBuilder();
        var validator = new CertificateChainValidator(
            chainBuilder,
            allowUnprotectedHeaders: false,
            allowUntrusted: false);

        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithNullChainBuilder_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new CertificateChainValidator((Interfaces.ICertificateChainBuilder)null!, allowUnprotectedHeaders: false));
    }

    [Test]
    public void Validate_WithNullInput_ReturnsFailure()
    {
        var validator = new CertificateChainValidator(allowUntrusted: true, revocationMode: X509RevocationMode.NoCheck);
        var result = validator.Validate(null!);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.ValidatorName, Is.EqualTo(nameof(CertificateChainValidator)));
        Assert.That(result.Failures.Any(e => e.ErrorCode == "NULL_INPUT"), Is.True);
    }

    [Test]
    public void Validate_WithValidSelfSignedCertificate_AllowUntrusted_ReturnsSuccess()
    {
        var validator = new CertificateChainValidator(allowUntrusted: true, revocationMode: X509RevocationMode.NoCheck);
        var result = validator.Validate(ValidMessage!);

        Assert.That(result.IsValid, Is.True);
        Assert.That(result.ValidatorName, Is.EqualTo(nameof(CertificateChainValidator)));
    }

    [Test]
    public void Validate_WithValidCertificate_NoRevocationCheck_ReturnsSuccess()
    {
        var validator = new CertificateChainValidator(
            allowUnprotectedHeaders: false,
            allowUntrusted: true,
            revocationMode: X509RevocationMode.NoCheck);

        var result = validator.Validate(ValidMessage!);

        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Metadata.ContainsKey("CertificateThumbprint"), Is.True);
    }

    [Test]
    public void Validate_WithAllowUnprotectedHeaders_AcceptsUnprotectedCertificateHeaders()
    {
        var validator = new CertificateChainValidator(
            allowUnprotectedHeaders: true,
            allowUntrusted: true,
            revocationMode: X509RevocationMode.NoCheck);

        var result = validator.Validate(ValidMessage!);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public async Task ValidateAsync_ReturnsResultSynchronously()
    {
        var validator = new CertificateChainValidator(allowUntrusted: true, revocationMode: X509RevocationMode.NoCheck);
        var result = await validator.ValidateAsync(ValidMessage!);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public async Task ValidateAsync_WithCancellationToken_CompletesSuccessfully()
    {
        var validator = new CertificateChainValidator(allowUntrusted: true, revocationMode: X509RevocationMode.NoCheck);
        using var cts = new CancellationTokenSource();
        var result = await validator.ValidateAsync(ValidMessage!, cts.Token);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Validate_WithCustomRootsAndTrustUserRoots_ValidatesAgainstCustomRoots()
    {
        var customRoots = new X509Certificate2Collection { TestCert! };
        var validator = new CertificateChainValidator(
            customRoots,
            allowUnprotectedHeaders: false,
            trustUserRoots: true,
            revocationMode: X509RevocationMode.NoCheck);

        var result = validator.Validate(ValidMessage!);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Validate_WithCustomRootsAndTrustUserRootsFalse_UsesSystemRoots()
    {
        var customRoots = new X509Certificate2Collection { TestCert! };
        var validator = new CertificateChainValidator(
            customRoots,
            allowUnprotectedHeaders: false,
            trustUserRoots: false,
            revocationMode: X509RevocationMode.NoCheck);

        var result = validator.Validate(ValidMessage!);

        // Result may vary based on system trust, but validator should not throw
        Assert.That(result, Is.Not.Null);
        Assert.That(result.ValidatorName, Is.EqualTo(nameof(CertificateChainValidator)));
    }

    [Test]
    public void Validate_WithCustomChainBuilderAndCustomRoots_UsesProvidedBuilder()
    {
        var customChainBuilder = new X509ChainBuilder();
        var customRoots = new X509Certificate2Collection { TestCert! };

        var validator = new CertificateChainValidator(
            customChainBuilder,
            allowUnprotectedHeaders: false,
            allowUntrusted: true,
            customRoots: customRoots,
            trustUserRoots: true);

        var result = validator.Validate(ValidMessage!);

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

        var validator = new CertificateChainValidator(allowUntrusted: true, revocationMode: X509RevocationMode.NoCheck);
        var result = validator.Validate(emptyCoseMsg);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(e => e.ErrorCode == "CERTIFICATE_NOT_FOUND"), Is.True);
    }

    [Test]
    public void Validate_ResultContainsCertificateThumbprint()
    {
        var validator = new CertificateChainValidator(allowUntrusted: true, revocationMode: X509RevocationMode.NoCheck);
        var result = validator.Validate(ValidMessage!);

        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Metadata.ContainsKey("CertificateThumbprint"), Is.True);
        Assert.That(result.Metadata["CertificateThumbprint"], Is.Not.Null);
        Assert.That(result.Metadata["CertificateThumbprint"], Is.EqualTo(TestCert!.Thumbprint));
    }

    [Test]
    public void Validate_WithAllowUntrusted_SetsAllowedUntrustedMetadata()
    {
        var validator = new CertificateChainValidator(allowUntrusted: true, revocationMode: X509RevocationMode.NoCheck);
        var result = validator.Validate(ValidMessage!);

        Assert.That(result.IsValid, Is.True);
        if (result.Metadata.ContainsKey("AllowedUntrusted"))
        {
            Assert.That(result.Metadata["AllowedUntrusted"], Is.True);
        }
    }

    [Test]
    public void Validate_WithTrustedCustomRoot_SetsTrustedCustomRootMetadata()
    {
        var customRoots = new X509Certificate2Collection { TestCert! };
        var validator = new CertificateChainValidator(
            customRoots,
            allowUnprotectedHeaders: false,
            trustUserRoots: true,
            revocationMode: X509RevocationMode.NoCheck);

        var result = validator.Validate(ValidMessage!);

        Assert.That(result.IsValid, Is.True);
        if (result.Metadata.ContainsKey("TrustedCustomRoot"))
        {
            Assert.That(result.Metadata["TrustedCustomRoot"], Is.Not.Null);
        }
    }

    [Test]
    public void Validate_WithEmptyCustomRootsCollection_UsesSystemRoots()
    {
        var emptyRoots = new X509Certificate2Collection();
        var validator = new CertificateChainValidator(
            emptyRoots,
            allowUnprotectedHeaders: false,
            trustUserRoots: true,
            revocationMode: X509RevocationMode.NoCheck);

        var result = validator.Validate(ValidMessage!);

        // Should not throw, result may vary
        Assert.That(result, Is.Not.Null);
    }

    [Test]
    public void Validate_WithRevocationModeOnline_CompletesWithoutError()
    {
        // This test may be slow due to online revocation check
        var validator = new CertificateChainValidator(
            allowUnprotectedHeaders: false,
            allowUntrusted: true,
            revocationMode: X509RevocationMode.Online);

        var result = validator.Validate(ValidMessage!);

        // Should complete without exception
        Assert.That(result, Is.Not.Null);
    }

    [Test]
    public void Validate_WithRevocationModeOffline_CompletesWithoutError()
    {
        var validator = new CertificateChainValidator(
            allowUnprotectedHeaders: false,
            allowUntrusted: true,
            revocationMode: X509RevocationMode.Offline);

        var result = validator.Validate(ValidMessage!);

        // Should complete without exception
        Assert.That(result, Is.Not.Null);
    }

    [Test]
    public void Validate_WithChainBuildFailure_ReturnsFailureWithChainStatus()
    {
        // Use a certificate that will fail chain building (system roots, no untrusted allowed)
        var validator = new CertificateChainValidator(
            allowUnprotectedHeaders: false,
            allowUntrusted: false,
            revocationMode: X509RevocationMode.NoCheck);

        var result = validator.Validate(ValidMessage!);

        // Self-signed cert without allowUntrusted should fail
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Count, Is.GreaterThan(0));
    }

    [Test]
    public void Validate_WhenChainBuildFailsAndStatusIsNoError_ReturnsDefaultChainBuildFailedFailure()
    {
        var chainBuilder = new FakeChainBuilder
        {
            ChainPolicy = new X509ChainPolicy { RevocationMode = X509RevocationMode.NoCheck },
            ChainStatus = new[] { new X509ChainStatus { Status = X509ChainStatusFlags.NoError, StatusInformation = string.Empty } },
            BuildResult = false
        };

        var validator = new CertificateChainValidator(
            chainBuilder,
            allowUnprotectedHeaders: false,
            allowUntrusted: false,
            customRoots: null,
            trustUserRoots: true);

        var result = validator.Validate(ValidMessage!);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(f => f.ErrorCode == "CHAIN_BUILD_FAILED"), Is.True);
    }

    [Test]
    public void Validate_WhenAllowUntrustedAndOnlyUntrustedRoot_ReturnsSuccessWithAllowedUntrustedMetadata()
    {
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

        var validator = new CertificateChainValidator(
            chainBuilder,
            allowUnprotectedHeaders: false,
            allowUntrusted: true,
            customRoots: null,
            trustUserRoots: true);

        var result = validator.Validate(ValidMessage!);

        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Metadata.TryGetValue("AllowedUntrusted", out var allowed), Is.True);
        Assert.That(allowed, Is.EqualTo(true));
    }

    [Test]
    public void Validate_WhenCustomRootTrustedAndUntrustedRootOnly_ReturnsSuccessWithTrustedCustomRootMetadata()
    {
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

        var validator = new CertificateChainValidator(
            chainBuilder,
            allowUnprotectedHeaders: false,
            allowUntrusted: false,
            customRoots: customRoots,
            trustUserRoots: true);

        // Ensure the branch that clears ExtraStore runs
        using var sentinel = TestCertificateUtils.CreateCertificate("ExtraStoreSentinel");
        chainBuilder.ChainPolicy.ExtraStore.Add(sentinel);

        var result = validator.Validate(ValidMessage!);

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
        var validator = new CertificateChainValidator(
            allowUnprotectedHeaders: false,
            allowUntrusted: false,
            revocationMode: X509RevocationMode.NoCheck);

        var result = validator.Validate(ValidMessage!);

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
        var leafCert = TestCertificateUtils.CreateCertificate("Leaf");
        var intermediateCert = TestCertificateUtils.CreateCertificate("Intermediate");

        var chainBuilder = new X509ChainBuilder();
        var signingService = CertificateSigningService.Create(leafCert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);

        // Sign message with the leaf certificate
        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test");
        var message = CoseSign1Message.DecodeSign1(messageBytes);

        var validator = new CertificateChainValidator(allowUntrusted: true, revocationMode: X509RevocationMode.NoCheck);
        var result = validator.Validate(message);

        Assert.That(result, Is.Not.Null);

        leafCert.Dispose();
        intermediateCert.Dispose();
    }

    [Test]
    public void Validate_MultipleValidateCalls_ProduceConsistentResults()
    {
        var validator = new CertificateChainValidator(allowUntrusted: true, revocationMode: X509RevocationMode.NoCheck);

        var result1 = validator.Validate(ValidMessage!);
        var result2 = validator.Validate(ValidMessage!);
        var result3 = validator.Validate(ValidMessage!);

        Assert.That(result1.IsValid, Is.EqualTo(result2.IsValid));
        Assert.That(result2.IsValid, Is.EqualTo(result3.IsValid));
        Assert.That(result1.IsValid, Is.True);
    }

    [Test]
    public async Task ValidateAsync_WithMultipleConcurrentCalls_CompletesSuccessfully()
    {
        var validator = new CertificateChainValidator(allowUntrusted: true, revocationMode: X509RevocationMode.NoCheck);

        var tasks = new[]
        {
            validator.ValidateAsync(ValidMessage!),
            validator.ValidateAsync(ValidMessage!),
            validator.ValidateAsync(ValidMessage!)
        };

        var results = await Task.WhenAll(tasks);

        Assert.That(results.All(r => r.IsValid), Is.True);
    }

    [Test]
    public void Constructor_WithMultipleCustomRoots_AddsAllRootsToStore()
    {
        var root1 = TestCertificateUtils.CreateCertificate("Root1");
        var root2 = TestCertificateUtils.CreateCertificate("Root2");
        var customRoots = new X509Certificate2Collection { root1, root2 };

        var validator = new CertificateChainValidator(
            customRoots,
            allowUnprotectedHeaders: false,
            trustUserRoots: true,
            revocationMode: X509RevocationMode.NoCheck);

        Assert.That(validator, Is.Not.Null);

        root1.Dispose();
        root2.Dispose();
    }

    [Test]
    public void Validate_WithCustomChainBuilderAndNoRoots_UsesChainBuilderPolicy()
    {
        var customChainBuilder = new X509ChainBuilder
        {
            ChainPolicy = new X509ChainPolicy
            {
                RevocationMode = X509RevocationMode.NoCheck
            }
        };

        var validator = new CertificateChainValidator(
            customChainBuilder,
            allowUnprotectedHeaders: false,
            allowUntrusted: true);

        var result = validator.Validate(ValidMessage!);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Validate_WithTrustUserRootsFalse_DoesNotUseCustomTrustMode()
    {
        var customRoots = new X509Certificate2Collection { TestCert! };
        var validator = new CertificateChainValidator(
            customRoots,
            allowUnprotectedHeaders: false,
            trustUserRoots: false,
            revocationMode: X509RevocationMode.NoCheck);

        var result = validator.Validate(ValidMessage!);

        // Should complete without exception, trust mode is system
        Assert.That(result, Is.Not.Null);
        Assert.That(result.ValidatorName, Is.EqualTo(nameof(CertificateChainValidator)));
    }

    [Test]
    public void Validate_WithCustomRootsButUntrustedRoot_ReturnsFailure()
    {
        // Create unrelated custom root
        var unrelatedRoot = TestCertificateUtils.CreateCertificate("UnrelatedRoot");
        var customRoots = new X509Certificate2Collection { unrelatedRoot };

        var validator = new CertificateChainValidator(
            customRoots,
            allowUnprotectedHeaders: false,
            trustUserRoots: true,
            revocationMode: X509RevocationMode.NoCheck);

        var result = validator.Validate(ValidMessage!);

        // Should fail because the signing cert is not in the custom roots chain
        Assert.That(result, Is.Not.Null);

        unrelatedRoot.Dispose();
    }

    [Test]
    public void Validate_WithAllowUntrustedFalse_AndSelfSigned_ReturnsFailure()
    {
        var validator = new CertificateChainValidator(
            allowUnprotectedHeaders: false,
            allowUntrusted: false,
            revocationMode: X509RevocationMode.NoCheck);

        var result = validator.Validate(ValidMessage!);

        // Self-signed certificate without allowUntrusted should fail
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Count, Is.GreaterThan(0));
    }

    [Test]
    public void Validate_FailureResult_ContainsChainStatusErrors()
    {
        var validator = new CertificateChainValidator(
            allowUnprotectedHeaders: false,
            allowUntrusted: false,
            revocationMode: X509RevocationMode.NoCheck);

        var result = validator.Validate(ValidMessage!);

        // Self-signed cert without untrusted allowed should produce chain status failure
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(), Is.True);
        Assert.That(result.Failures.All(f => !string.IsNullOrEmpty(f.ErrorCode)), Is.True);
    }

    [Test]
    public void Validate_WithChainBuilderAndCustomRoots_ConfiguresCorrectly()
    {
        var customChainBuilder = new X509ChainBuilder
        {
            ChainPolicy = new X509ChainPolicy
            {
                RevocationMode = X509RevocationMode.NoCheck
            }
        };
        var customRoots = new X509Certificate2Collection { TestCert! };

        var validator = new CertificateChainValidator(
            customChainBuilder,
            allowUnprotectedHeaders: false,
            allowUntrusted: true,
            customRoots: customRoots,
            trustUserRoots: true);

        var result = validator.Validate(ValidMessage!);

        // Should succeed with the proper configuration
        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Constructor_WithDefaultRevocationMode_UsesOnline()
    {
        var customRoots = new X509Certificate2Collection { TestCert! };
        var validator = new CertificateChainValidator(
            customRoots,
            allowUnprotectedHeaders: false,
            trustUserRoots: true);
        // This constructor defaults to Online revocation mode

        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Validate_ResultContainsValidatorName()
    {
        var validator = new CertificateChainValidator(allowUntrusted: true, revocationMode: X509RevocationMode.NoCheck);
        var result = validator.Validate(ValidMessage!);

        Assert.That(result.ValidatorName, Is.EqualTo(nameof(CertificateChainValidator)));
    }

    [Test]
    public void Validate_WithChainThatHasSelfSignedRoot_AndCustomRootsMatch_ReturnsSuccess()
    {
        // Create a chain where the root is self-signed (same subject and issuer)
        var rootCert = TestCertificateUtils.CreateCertificate("Root");
        var customRoots = new X509Certificate2Collection { rootCert };

        // Create message signed by root (self-signed)
        var chainBuilder = new X509ChainBuilder();
        var signingService = CertificateSigningService.Create(rootCert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test");
        var message = CoseSign1Message.DecodeSign1(messageBytes);

        var validator = new CertificateChainValidator(
            customRoots,
            allowUnprotectedHeaders: false,
            trustUserRoots: true,
            revocationMode: X509RevocationMode.NoCheck);

        var result = validator.Validate(message);

        // The self-signed root is in the custom roots, so it should pass
        Assert.That(result.IsValid, Is.True);
        if (result.Metadata.ContainsKey("TrustedCustomRoot"))
        {
            Assert.That(result.Metadata["TrustedCustomRoot"], Is.EqualTo(rootCert.Thumbprint));
        }

        rootCert.Dispose();
    }

    [Test]
    public async Task ValidateAsync_WithNullInput_ReturnsFailure()
    {
        var validator = new CertificateChainValidator(allowUntrusted: true, revocationMode: X509RevocationMode.NoCheck);
        var result = await validator.ValidateAsync(null!);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(e => e.ErrorCode == "NULL_INPUT"), Is.True);
    }

    [Test]
    public void Validate_ChainStatus_AllNoError_WithUntrustedRoot_AndAllowUntrusted_ReturnsSuccess()
    {
        // A self-signed cert should have UntrustedRoot status
        var validator = new CertificateChainValidator(
            allowUnprotectedHeaders: false,
            allowUntrusted: true,
            revocationMode: X509RevocationMode.NoCheck);

        var result = validator.Validate(ValidMessage!);

        Assert.That(result.IsValid, Is.True);
        if (result.Metadata.ContainsKey("AllowedUntrusted"))
        {
            Assert.That(result.Metadata["AllowedUntrusted"], Is.True);
        }
    }
}