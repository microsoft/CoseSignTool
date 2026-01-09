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
using CoseSign1.Certificates.Validation;
using CoseSign1.Direct;
using CoseSign1.Validation;
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
        using var factory = new DirectSignatureFactory(service);
        
        var payload = Encoding.UTF8.GetBytes("test payload");
        var signature = factory.CreateCoseSign1MessageBytes(payload, "text/plain");

        // Verify
        var message = CoseSign1Message.DecodeSign1(signature);
        var validator = Cose.Sign1Message()
            .ValidateCertificate(cert => cert.NotExpired())
            .AllowAllTrust("test")
            .Build();
        var result = validator.Validate(message);
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
using NUnit.Framework;

[TestFixture]
public class CustomValidatorTests
{
    private IValidator _validator = null!;

    [SetUp]
    public void SetUp()
    {
        _validator = new CustomValidator();
    }

    [Test]
    public async Task ValidateAsync_WithValidMessage_ReturnsSuccess()
    {
        // Arrange
        var message = CreateValidTestMessage();

        // Act
        var result = await _validator.ValidateAsync(message, ValidationStage.PostSignature);

        // Assert
        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public async Task ValidateAsync_WithInvalidMessage_ReturnsFailure()
    {
        // Arrange
        var message = CreateInvalidTestMessage();

        // Act
        var result = await _validator.ValidateAsync(message, ValidationStage.PostSignature);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.First().ErrorCode, Is.EqualTo("CUSTOM_ERROR"));
    }
}
```

### Testing Header Contributors

```csharp
using NUnit.Framework;

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
        using var factory = new DirectSignatureFactory(service);

        byte[] payload = new byte[] { 1, 2, 3, 4, 5 };
        byte[] signatureBytes = factory.CreateCoseSign1MessageBytes(payload, "application/octet-stream");

        var message = CoseSign1Message.DecodeSign1(signatureBytes);
        var validator = Cose.Sign1Message()
            .ValidateCertificate(cert => cert.NotExpired())
            .AllowAllTrust("test")
            .Build();

        Assert.That(validator.Validate(message).Overall.IsValid, Is.True);
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
        using var factory = new DirectSignatureFactory(signingService);
        
        var payload = Encoding.UTF8.GetBytes("""
            {
                "name": "test",
                "version": "1.0.0"
            }
            """);
        
        // Act - Sign
        var signature = factory.CreateCoseSign1MessageBytes(
            payload, 
            "application/json");
        
        // Act - Verify
        var message = CoseSign1Message.DecodeSign1(signature);
        var validator = Cose.Sign1Message()
            .ValidateCertificate(cert => cert.NotExpired())
            .AllowAllTrust("test")
            .Build();

        var result = validator.Validate(message);
        
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
        var message = CoseSign1Message.DecodeSign1(signature);
        var validator = Cose.Sign1Message()
            .ValidateCertificate(cert => cert.NotExpired())
            .AllowAllTrust("test")
            .Build();

        var result = validator.Validate(message);
        
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
    using var factory = new DirectSignatureFactory(service);
    
    var signature = factory.CreateCoseSign1MessageBytes(payload, "application/octet-stream");
    
    // Verify with custom trust root
    var message = CoseSign1Message.DecodeSign1(signature);
    var trustedRoots = new X509Certificate2Collection { root };

    var validator = Cose.Sign1Message()
        .ValidateCertificate(cert => cert
            .ValidateChain(trustedRoots))
        .Build();

    var result = validator.Validate(message);
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
            var exitCode = await CoseSignToolCli.Main(new[]
            {
                "sign-pfx",
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

When testing validation composition, you can register lightweight validators directly on the builder:

```csharp
var validator = Cose.Sign1Message()
    .AddValidator(_ => ValidationResult.Success("AlwaysPass"))
    .Build();
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

### Coverage Reports

```bash
reportgenerator -reports:coverage.cobertura.xml -targetdir:coverage-report
```

### Coverage Targets

Aim for:
- **80%+** overall coverage
- **90%+** for security-critical code (validators, signing)
- **100%** for public API surface

## See Also

- [Development Setup](../development/setup.md)
- [Test Coverage](../development/coverage.md)
- [Validation Framework](../architecture/validation-framework.md)
