# CoseSign1.Tests.Common

Shared test utilities and helpers for testing CoseSignTool V2 components.

## Overview

CoseSign1.Tests.Common provides test utilities, mock objects, and certificate generation helpers for writing unit and integration tests against CoseSignTool V2 APIs.

## Installation

```bash
dotnet add package CoseSign1.Tests.Common --version 2.0.0-preview
```

## Test Certificate Generation

### Ephemeral Certificates

Create temporary certificates for testing:

```csharp
using CoseSign1.Tests.Common;

// Create ephemeral ECDSA certificate
using var cert = TestCertificates.CreateEphemeral();

// Create with specific algorithm
using var ecdsaCert = TestCertificates.CreateEcdsa(ECCurve.NamedCurves.nistP384);
using var rsaCert = TestCertificates.CreateRsa(keySize: 3072);
```

### Certificate Chains

Create complete certificate chains for chain validation testing:

```csharp
// Create root, intermediate, and leaf certificates
var (root, intermediate, leaf) = TestCertificates.CreateChain();

// Use in tests
var chainValidator = new CertificateChainValidator(
    trustedRoots: new X509Certificate2Collection { root });
```

### PFX File Generation

Create PFX files for CLI testing:

```csharp
// Create PFX file with password
TestCertificates.CreatePfxFile("test.pfx", "test-password");

// Create PFX with specific algorithm
TestCertificates.CreatePfxFile("ecdsa.pfx", "password", ECCurve.NamedCurves.nistP256);
```

## Test Payloads

### Common Test Data

```csharp
using CoseSign1.Tests.Common;

// JSON payload
byte[] json = TestPayloads.Json;

// Binary payload
byte[] binary = TestPayloads.Binary;

// Large payload for streaming tests
byte[] large = TestPayloads.Large(size: 1024 * 1024);

// Custom payload
byte[] custom = TestPayloads.Create("my test content");
```

## Mock Objects

### Mock Signing Service

```csharp
using CoseSign1.Tests.Common.Mocks;

var mockService = new MockSigningService();
mockService.SignatureToReturn = new byte[64]; // Custom signature

// Use in factory
var factory = new DirectSignatureFactory(mockService);

// Verify calls
Assert.AreEqual(1, mockService.SignCallCount);
```

### Mock Validator

```csharp
var mockValidator = new MockValidator();
mockValidator.ResultToReturn = ValidationResult.Failure("Test failure");

// Use in validation
var result = await mockValidator.ValidateAsync(message, context);
Assert.IsFalse(result.IsValid);
```

### Mock Transparency Provider

```csharp
var mockProvider = new MockTransparencyProvider();
mockProvider.ReceiptToReturn = new MockReceipt(timestamp: DateTimeOffset.UtcNow);

var receipt = await mockProvider.GetReceiptAsync(signature);
```

## Test Helpers

### Temp Directory

```csharp
using CoseSign1.Tests.Common;

// Create temp directory that auto-cleans on dispose
using var temp = new TempDirectory();

// Create files in temp directory
var inputFile = temp.CreateFile("input.json", "{}");
var outputFile = temp.GetPath("output.cose");
var pfxFile = temp.CreatePfxFile("test.pfx", "password");
```

### Signature Builders

```csharp
// Build test signatures
var signature = TestSignatureBuilder.Create()
    .WithPayload("test payload")
    .WithContentType("text/plain")
    .WithAlgorithm(CoseAlgorithm.ES256)
    .Build();
```

## Assertion Helpers

### Validation Assertions

```csharp
using CoseSign1.Tests.Common.Assertions;

// Assert validation succeeds
ValidationAssert.IsValid(result);

// Assert specific error code
ValidationAssert.HasError(result, ValidationFailureCode.CertificateExpired);

// Assert error message contains text
ValidationAssert.ErrorContains(result, "expired");
```

### Signature Assertions

```csharp
// Assert signature structure
SignatureAssert.HasProtectedHeader(signature, CoseHeaderLabel.ContentType);
SignatureAssert.HasAlgorithm(signature, CoseAlgorithm.ES256);
SignatureAssert.PayloadMatches(signature, expectedPayload);
```

## Integration Test Base Class

```csharp
using CoseSign1.Tests.Common;

[TestClass]
public class MyIntegrationTests : IntegrationTestBase
{
    [TestMethod]
    public async Task MyTest()
    {
        // TempDirectory is automatically created and cleaned up
        var inputFile = CreateTempFile("test.json", "{}");
        
        // EphemeralCertificate is available
        var signature = SignWithEphemeral(inputFile);
        
        // Standard assertions
        AssertSignatureValid(signature);
    }
}
```

## Test Categories

Use standard test categories for organization:

```csharp
[TestClass]
[TestCategory("Unit")]
public class UnitTests { }

[TestClass]
[TestCategory("Integration")]
public class IntegrationTests { }

[TestClass]
[TestCategory("PQC")]
[TestCategory("Windows")]
public class PqcTests { }
```

## Platform-Specific Testing

### Skip on Unsupported Platforms

```csharp
[TestMethod]
public void MlDsaTest()
{
    // Skip if not on Windows
    PlatformAssert.RequiresWindows();
    
    // Skip if PQC not available
    PlatformAssert.RequiresPqc();
    
    // Test ML-DSA functionality
}
```

## Example Test Class

```csharp
using CoseSign1.Tests.Common;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public class SigningTests
{
    [TestMethod]
    public async Task SignAndVerify_WithEphemeralCert_Succeeds()
    {
        // Arrange
        using var cert = TestCertificates.CreateEphemeral();
        var service = new LocalSigningService(cert);
        var factory = new DirectSignatureFactory(service);
        var payload = TestPayloads.Json;
        
        // Act
        var signature = factory.CreateCoseSign1MessageBytes(
            payload, 
            "application/json");
        
        // Assert
        var validator = ValidationBuilder.Create()
            .AddSignatureValidator()
            .Build();
        
        var result = await validator.ValidateAsync(signature);
        ValidationAssert.IsValid(result);
    }
    
    [TestMethod]
    public void Verify_WithExpiredCert_Fails()
    {
        // Arrange
        using var expiredCert = TestCertificates.CreateExpired();
        var signature = CreateSignatureWith(expiredCert);
        
        // Act
        var result = validator.Validate(signature);
        
        // Assert
        ValidationAssert.HasError(result, ValidationFailureCode.CertificateExpired);
    }
}
```

## See Also

- [Testing Guide](../guides/testing.md)
- [Development Testing](../development/testing.md)
- [Code Coverage](../development/coverage.md)
