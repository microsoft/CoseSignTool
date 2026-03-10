# Testing Guide

This guide explains how to test COSE signatures and integrate CoseSignTool V2 into your testing workflows.

## Overview

Proper testing ensures your signing and verification code works correctly. CoseSignTool V2 provides test utilities and patterns for unit, integration, and end-to-end testing.

## Test Utilities

### Ephemeral Certificates

Use ephemeral (temporary self-signed) certificates for testing:

```csharp
using CoseSign1.Tests.Common;
using CoseSign1.Certificates;
using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Factories;
using CoseSign1.Factories.Direct;
using CoseSign1.Validation.DependencyInjection;
using CoseSign1.Validation.Trust.Plan;
using Microsoft.Extensions.DependencyInjection;
using System.Security.Cryptography.Cose;
using System.Text;
using NUnit.Framework;

[TestFixture]
public class SigningTests
{
    [Test]
    public void SignAndVerify_WithEphemeralCert_Succeeds()
    {
        // Create ephemeral certificate
        using var cert = LocalCertificateFactory.CreateEcdsaCertificate(keySize: 256);

        // Use for signing
        using var chainBuilder = new X509ChainBuilder();
        using var service = CertificateSigningService.Create(cert, chainBuilder);
        using var factory = new CoseSign1MessageFactory(service);
        
        var payload = Encoding.UTF8.GetBytes("test payload");
        var signature = factory.CreateCoseSign1MessageBytes<DirectSignatureOptions>(payload, "text/plain");

        // Verify
        var message = CoseMessage.DecodeSign1(signature);
        var services = new ServiceCollection();
        var validation = services.ConfigureCoseValidation();

        // Registers the certificate signing-key resolver used to verify X.509-backed signatures.
        validation.EnableCertificateSupport(certTrust => certTrust.UseEmbeddedChainOnly());

        using var sp = services.BuildServiceProvider();
        using var scope = sp.CreateScope();

        var validator = scope.ServiceProvider
            .GetRequiredService<ICoseSign1ValidatorFactory>()
            .Create(trustEvaluationOptions: new TrustEvaluationOptions { BypassTrust = true });
        var result = message.Validate(validator);
        Assert.That(result.Overall.IsValid, Is.True);
    }
}
```

### Test Certificate Factory

```csharp
// Create various test certificates
using var rsaCert = LocalCertificateFactory.CreateRsaCertificate(keySize: 2048);
using var ecdsaP256 = LocalCertificateFactory.CreateEcdsaCertificate(keySize: 256);
using var ecdsaP384 = LocalCertificateFactory.CreateEcdsaCertificate(keySize: 384);

// Create certificate chain (leaf-first order)
var chain = LocalCertificateFactory.CreateEcdsaChain(leafFirst: true);
using var leaf = chain[0];
using var intermediate = chain[1];
using var root = chain[2];
```

## Unit Testing

### Testing Validators

```csharp
using CoseSign1.Validation;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Results;
using CoseSign1.Validation.Trust;
using NUnit.Framework;

[TestFixture]
public class CustomValidatorTests
{
    private IPostSignatureValidator _validator = null!;

    [SetUp]
    public void SetUp()
    {
        _validator = new CustomValidator();
    }

    [Test]
    public async Task ValidateAsync_WithValidContext_ReturnsSuccess()
    {
        // Arrange
        var context = CreateValidPostSignatureContext();

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public async Task ValidateAsync_WithInvalidContext_ReturnsFailure()
    {
        // Arrange
        var context = CreateInvalidPostSignatureContext();

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.First().ErrorCode, Is.EqualTo("CUSTOM_ERROR"));
    }

    private static IPostSignatureValidationContext CreateValidPostSignatureContext()
    {
        var message = /* CreateValidTestMessage() */ throw new NotImplementedException();
        return new PostSignatureValidationContext(
            message,
            trustAssertions: Array.Empty<ISigningKeyAssertion>(),
            trustDecision: TrustDecision.Trusted(),
            signatureMetadata: new Dictionary<string, object>(),
            options: new CoseSign1ValidationOptions());
    }

    private static IPostSignatureValidationContext CreateInvalidPostSignatureContext()
    {
        var message = /* CreateInvalidTestMessage() */ throw new NotImplementedException();
        return new PostSignatureValidationContext(
            message,
            trustAssertions: Array.Empty<ISigningKeyAssertion>(),
            trustDecision: TrustDecision.Trusted(),
            signatureMetadata: new Dictionary<string, object>(),
            options: new CoseSign1ValidationOptions());
    }
}
```

### Testing Header Contributors

```csharp
using NUnit.Framework;
using CoseSign1.Validation.DependencyInjection;
using CoseSign1.Validation.Trust.Plan;
using Microsoft.Extensions.DependencyInjection;

[TestFixture]
public class CustomHeaderContributorTests
{
    [Test]
    public void ContributeProtectedHeaders_AddsExpectedHeaders()
    {
        // Arrange
        var contributor = new CustomHeaderContributor("test-value");
        var headers = new CoseHeaderMap();
        var context = /* create a HeaderContributorContext */;

        // Act
        contributor.ContributeProtectedHeaders(headers, context);

        // Assert
        Assert.That(headers.ContainsKey(new CoseHeaderLabel("custom-header")), Is.True);
    }
}
```

### Testing Signing Services

```csharp
using NUnit.Framework;

[TestFixture]
public class SigningServiceTests
{
    [Test]
    public void SignAndVerify_WithValidData_ReturnsValidSignature()
    {
        // Arrange
        using var cert = LocalCertificateFactory.CreateEcdsaCertificate(keySize: 256);
        using var chainBuilder = new X509ChainBuilder();
        using var service = CertificateSigningService.Create(cert, chainBuilder);
        using var factory = new CoseSign1MessageFactory(service);

        byte[] payload = new byte[] { 1, 2, 3, 4, 5 };
        byte[] signatureBytes = factory.CreateCoseSign1MessageBytes<DirectSignatureOptions>(payload, "application/octet-stream");

        var message = CoseMessage.DecodeSign1(signatureBytes);
        var services = new ServiceCollection();
        var validation = services.ConfigureCoseValidation();
        validation.EnableCertificateSupport(certTrust => certTrust.UseEmbeddedChainOnly());

        using var sp = services.BuildServiceProvider();
        using var scope = sp.CreateScope();

        var validator = scope.ServiceProvider
            .GetRequiredService<ICoseSign1ValidatorFactory>()
            .Create(trustEvaluationOptions: new TrustEvaluationOptions { BypassTrust = true });

        Assert.That(message.Validate(validator).Overall.IsValid, Is.True);
    }
}
```

## Integration Testing

### Full Sign-Verify Cycle

```csharp
[TestFixture]
public class SignVerifyIntegrationTests
{
    [Test]
    public Task FullCycle_DirectSignature_Succeeds()
    {
        // Arrange
        using var cert = LocalCertificateFactory.CreateEcdsaCertificate(keySize: 256);
        using var chainBuilder = new X509ChainBuilder();
        using var signingService = CertificateSigningService.Create(cert, chainBuilder);
        using var factory = new CoseSign1MessageFactory(signingService);
        
        var payload = Encoding.UTF8.GetBytes("""
            {
                "name": "test",
                "version": "1.0.0"
            }
            """);
        
        // Act - Sign
        var signature = factory.CreateCoseSign1MessageBytes<DirectSignatureOptions>(
            payload, 
            "application/json");
        
        // Act - Verify
        var message = CoseMessage.DecodeSign1(signature);
        var services = new ServiceCollection();
        var validation = services.ConfigureCoseValidation();
        validation.EnableCertificateSupport(certTrust => certTrust.UseEmbeddedChainOnly());

        using var sp = services.BuildServiceProvider();
        using var scope = sp.CreateScope();

        var validator = scope.ServiceProvider
            .GetRequiredService<ICoseSign1ValidatorFactory>()
            .Create(trustEvaluationOptions: new TrustEvaluationOptions { BypassTrust = true });

        var result = message.Validate(validator);
        
        // Assert
        Assert.That(result.Overall.IsValid, Is.True);

        return Task.CompletedTask;
    }
    
    [Test]
    public Task FullCycle_IndirectSignature_Succeeds()
    {
        // Arrange
        using var cert = LocalCertificateFactory.CreateEcdsaCertificate(keySize: 256);
        using var chainBuilder = new X509ChainBuilder();
        using var signingService = CertificateSigningService.Create(cert, chainBuilder);
        using var factory = new IndirectSignatureFactory(signingService);
        
        var payload = new byte[10000]; // Large payload
        Random.Shared.NextBytes(payload);
        
        // Act - Sign
        var signature = factory.CreateIndirectSignatureBytes(
            payload,
            HashAlgorithmName.SHA256,
            "application/octet-stream");

        // Act - Verify signature over the hash envelope (payload is not required for signature verification)
        var message = CoseMessage.DecodeSign1(signature);
        var services = new ServiceCollection();
        var validation = services.ConfigureCoseValidation();
        validation.EnableCertificateSupport(certTrust => certTrust.UseEmbeddedChainOnly());

        using var sp = services.BuildServiceProvider();
        using var scope = sp.CreateScope();

        var validator = scope.ServiceProvider
            .GetRequiredService<ICoseSign1ValidatorFactory>()
            .Create(trustEvaluationOptions: new TrustEvaluationOptions { BypassTrust = true });

        var result = message.Validate(validator);
        
        // Assert
        Assert.That(result.Overall.IsValid, Is.True);

        return Task.CompletedTask;
    }
}
```

### Certificate Chain Testing

```csharp
[Test]
public void Verify_WithFullChain_Succeeds()
{
    // Create test chain
    var chain = LocalCertificateFactory.CreateEcdsaChain(leafFirst: true);
    using var leaf = chain[0];
    using var intermediate = chain[1];
    using var root = chain[2];
    
    // Sign with leaf
    using var service = CertificateSigningService.Create(
        leaf,
        new[] { leaf, intermediate, root });
    using var factory = new CoseSign1MessageFactory(service);
    
    var signature = factory.CreateCoseSign1MessageBytes<DirectSignatureOptions>(payload, "application/octet-stream");
    
    // Verify with custom trust root
    var message = CoseMessage.DecodeSign1(signature);
    var trustedRoots = new X509Certificate2Collection { root };

    var services = new ServiceCollection();
    var validation = services.ConfigureCoseValidation();
    validation.EnableCertificateSupport(certTrust => certTrust
        .UseCustomRootTrust(trustedRoots)
        );

    using var sp = services.BuildServiceProvider();
    using var scope = sp.CreateScope();

    var validator = scope.ServiceProvider
        .GetRequiredService<ICoseSign1ValidatorFactory>()
        .Create();

    var result = message.Validate(validator);
    Assert.That(result.Signature.IsValid, Is.True);
    Assert.That(result.Trust.IsValid, Is.True);
}
```

## CLI Testing

### Testing CLI Commands

```csharp
[TestFixture]
public class CliIntegrationTests
{
    [Test]
    public async Task SignPfx_CreatesValidSignature()
    {
        // Arrange
        var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tempDir);
        
        try
        {
            var inputFile = Path.Combine(tempDir, "input.json");
            var outputFile = Path.Combine(tempDir, "output.cose");
            var pfxFile = Path.Combine(tempDir, "test.pfx");
            
            await File.WriteAllTextAsync(inputFile, "{}");
            var chain = new CoseSign1.Certificates.Local.CertificateChainFactory()
                .CreateChain(o => o.ForPfxExport());
            File.WriteAllBytes(pfxFile, chain.Export(X509ContentType.Pfx, "test-password")!);
            foreach (var c in chain) { c.Dispose(); }
            
            // Set password in environment
            Environment.SetEnvironmentVariable("COSESIGNTOOL_PFX_PASSWORD", "test-password");
            
            // Act
            var exitCode = CoseSignTool.Program.Main(new[]
            {
                "sign",
                "x509",
                "pfx",
                inputFile,
                "--pfx", pfxFile,
                "--output", outputFile
            });
            
            // Assert
            Assert.That(exitCode, Is.EqualTo(0));
            Assert.That(File.Exists(outputFile), Is.True);
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }
}
```

## Mock Objects

When testing validation composition, you can register lightweight post-signature validators in DI.
The simplest option is an always-pass post-signature validator:

```csharp
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Results;

public sealed class AlwaysPassPostSignatureValidator : IPostSignatureValidator
{
    public ValidationResult Validate(IPostSignatureValidationContext context) => ValidationResult.Success("AlwaysPass");
    public Task<ValidationResult> ValidateAsync(IPostSignatureValidationContext context, CancellationToken cancellationToken = default)
        => Task.FromResult(Validate(context));
}

using CoseSign1.Validation.DependencyInjection;
using CoseSign1.Validation.Trust.Plan;
using Microsoft.Extensions.DependencyInjection;

var services = new ServiceCollection();
var validation = services.ConfigureCoseValidation();
validation.EnableCertificateSupport(certTrust => certTrust.UseEmbeddedChainOnly());
services.AddSingleton<IPostSignatureValidator, AlwaysPassPostSignatureValidator>();

using var sp = services.BuildServiceProvider();
using var scope = sp.CreateScope();

var validator = scope.ServiceProvider
    .GetRequiredService<ICoseSign1ValidatorFactory>()
    .Create(trustEvaluationOptions: new TrustEvaluationOptions { BypassTrust = true });
```

## Test Data

### Sample Payloads

```csharp
public static class TestPayloads
{
    public static byte[] Json => Encoding.UTF8.GetBytes("""
        {
            "type": "test",
            "version": "1.0.0",
            "timestamp": "2024-01-01T00:00:00Z"
        }
        """);
    
    public static byte[] Binary => new byte[] { 0x00, 0x01, 0x02, 0x03 };
    
    public static byte[] Large(int size)
    {
        var data = new byte[size];
        Random.Shared.NextBytes(data);
        return data;
    }
}
```

### Pre-signed Test Files

Store known-good signatures for regression testing:

```
TestData/
├── valid-es256.cose
├── valid-es384.cose
├── valid-ps256.cose
├── invalid-signature.cose
├── expired-cert.cose
└── revoked-cert.cose
```

## Test Categories

Organize tests with categories:

```csharp
[TestFixture, Category("Unit")]
public class UnitTests { }

[TestFixture, Category("Integration")]
public class IntegrationTests { }

[TestFixture, Category("PQC")]
public class PostQuantumTests { }

[TestFixture, Category("Slow")]
public class SlowTests { }
```

Run specific categories:

```bash
dotnet test --filter "Category=Unit"
dotnet test --filter "Category!=Slow"
```

## Code Coverage

### Running with Coverage

```bash
dotnet test --collect:"XPlat Code Coverage"
```

For the same coverage process enforced by CI (including the 95% line-coverage gate), use:

```powershell
cd V2
powershell -ExecutionPolicy Bypass -File .\collect-coverage.ps1
```

### Coverage Reports

```bash
reportgenerator -reports:coverage.cobertura.xml -targetdir:coverage-report
```

### Coverage Targets

V2 uses an enforced coverage gate:
- **95%+** line coverage overall (see [Test Coverage](../development/coverage.md))

## See Also

- [Development Setup](../development/setup.md)
- [Test Coverage](../development/coverage.md)
- [Validation Framework](../architecture/validation-framework.md)
