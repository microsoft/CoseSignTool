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

[TestClass]
public class SigningTests
{
    [TestMethod]
    public void SignAndVerify_WithEphemeralCert_Succeeds()
    {
        // Create ephemeral certificate
        using var cert = TestCertificates.CreateEphemeral();

        // Use for signing
        using var chainBuilder = new X509ChainBuilder();
        using var service = CertificateSigningService.Create(cert, chainBuilder);
        using var factory = new DirectSignatureFactory(service);
        
        var payload = Encoding.UTF8.GetBytes("test payload");
        var signature = factory.CreateCoseSign1MessageBytes(payload);

        // Verify
        var message = CoseMessage.DecodeSign1(signature);
        var validator = Cose.Sign1Message()
            .ValidateCertificateSignature()
            .Build();
        var result = validator.Validate(message, ValidationStage.Signature);
        Assert.IsTrue(result.IsValid);
    }
}
```

### Test Certificate Factory

```csharp
// Create various test certificates
var rsaCert = TestCertificates.CreateRsa(keySize: 2048);
var ecdsaP256 = TestCertificates.CreateEcdsa(ECCurve.NamedCurves.nistP256);
var ecdsaP384 = TestCertificates.CreateEcdsa(ECCurve.NamedCurves.nistP384);

// Create certificate chain
var (root, intermediate, leaf) = TestCertificates.CreateChain();
```

## Unit Testing

### Testing Validators

```csharp
[TestClass]
public class CustomValidatorTests
{
    private CustomValidator _validator;
    
    [TestInitialize]
    public void Setup()
    {
        _validator = new CustomValidator();
    }
    
    [TestMethod]
    public async Task ValidateAsync_WithValidMessage_ReturnsSuccess()
    {
        // Arrange
        var message = CreateValidTestMessage();
        
        // Act
        var result = await _validator.ValidateAsync(message, ValidationStage.PostSignature);
        
        // Assert
        Assert.IsTrue(result.IsValid);
    }
    
    [TestMethod]
    public async Task ValidateAsync_WithInvalidMessage_ReturnsFailure()
    {
        // Arrange
        var message = CreateInvalidTestMessage();
        
        // Act
        var result = await _validator.ValidateAsync(message, ValidationStage.PostSignature);
        
        // Assert
        Assert.IsFalse(result.IsValid);
        Assert.AreEqual("CUSTOM_ERROR", result.Failures.First().ErrorCode);
    }
}
```

### Testing Header Contributors

```csharp
[TestClass]
public class CustomHeaderContributorTests
{
    [TestMethod]
    public void ContributeProtectedHeaders_AddsExpectedHeaders()
    {
        // Arrange
        var contributor = new CustomHeaderContributor("test-value");
        var headers = new CoseHeaderMap();
        var context = /* create a HeaderContributorContext */;
        
        // Act
        contributor.ContributeProtectedHeaders(headers, context);
        
        // Assert
        Assert.IsTrue(headers.ContainsKey(new CoseHeaderLabel("custom-header")));
    }
}
```

### Testing Signing Services

```csharp
[TestClass]
public class SigningServiceTests
{
    [TestMethod]
    public void SignAndVerify_WithValidData_ReturnsValidSignature()
    {
        // Arrange
        using var cert = TestCertificates.CreateEcdsa();
        using var chainBuilder = new X509ChainBuilder();
        using var service = CertificateSigningService.Create(cert, chainBuilder);
        using var factory = new DirectSignatureFactory(service);

        byte[] payload = new byte[] { 1, 2, 3, 4, 5 };
        byte[] signatureBytes = factory.CreateCoseSign1MessageBytes(payload);

        var message = CoseMessage.DecodeSign1(signatureBytes);
        var validator = Cose.Sign1Message()
            .ValidateCertificateSignature()
            .Build();

        Assert.IsTrue(validator.Validate(message, ValidationStage.Signature).IsValid);
    }
}
```

## Integration Testing

### Full Sign-Verify Cycle

```csharp
[TestClass]
public class SignVerifyIntegrationTests
{
    [TestMethod]
    public async Task FullCycle_DirectSignature_Succeeds()
    {
        // Arrange
        using var cert = TestCertificates.CreateEcdsa();
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
        var message = CoseMessage.DecodeSign1(signature);
        var validator = Cose.Sign1Message()
            .ValidateCertificateSignature()
            .Build();

        var result = await validator.ValidateAsync(message, ValidationStage.Signature);
        
        // Assert
        Assert.IsTrue(result.IsValid);
    }
    
    [TestMethod]
    public async Task FullCycle_IndirectSignature_Succeeds()
    {
        // Arrange
        using var cert = TestCertificates.CreateEcdsa();
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
        var validator = Cose.Sign1Message()
            .ValidateCertificateSignature()
            .Build();

        var result = await validator.ValidateAsync(message, ValidationStage.Signature);
        
        // Assert
        Assert.IsTrue(result.IsValid);
    }
}
```

### Certificate Chain Testing

```csharp
[TestMethod]
public async Task Verify_WithFullChain_Succeeds()
{
    // Create test chain
    var (root, intermediate, leaf) = TestCertificates.CreateChain();
    
    // Sign with leaf
    using var service = CertificateSigningService.Create(
        leaf,
        new[] { leaf, intermediate, root });
    using var factory = new DirectSignatureFactory(service);
    
    var signature = factory.CreateCoseSign1MessageBytes(payload);
    
    // Verify with custom trust root
    var message = CoseMessage.DecodeSign1(signature);
    var trustedRoots = new X509Certificate2Collection { root };

    var validator = Cose.Sign1Message()
        .ValidateCertificate(cert => cert
            .ValidateChain(trustedRoots))
        .Build();

    var signatureResult = await validator.ValidateAsync(message, ValidationStage.Signature);
    var trustResult = await validator.ValidateAsync(message, ValidationStage.KeyMaterialTrust);
    Assert.IsTrue(signatureResult.IsValid);
    Assert.IsTrue(trustResult.IsValid);
}
```

## CLI Testing

### Testing CLI Commands

```csharp
[TestClass]
public class CliIntegrationTests
{
    [TestMethod]
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
            TestCertificates.CreatePfxFile(pfxFile, "test-password");
            
            // Set password in environment
            Environment.SetEnvironmentVariable("COSESIGNTOOL_PFX_PASSWORD", "test-password");
            
            // Act
            var exitCode = await CoseSignToolCli.Main(new[]
            {
                "sign-pfx",
                inputFile,
                "--pfx-file", pfxFile,
                "--output", outputFile
            });
            
            // Assert
            Assert.AreEqual(0, exitCode);
            Assert.IsTrue(File.Exists(outputFile));
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
[TestClass]
[TestCategory("Unit")]
public class UnitTests { }

[TestClass]
[TestCategory("Integration")]
public class IntegrationTests { }

[TestClass]
[TestCategory("PQC")]
public class PostQuantumTests { }

[TestClass]
[TestCategory("Slow")]
public class SlowTests { }
```

Run specific categories:

```bash
dotnet test --filter "TestCategory=Unit"
dotnet test --filter "TestCategory!=Slow"
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
