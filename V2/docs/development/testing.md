# Testing Guide for Development

This guide covers testing practices and procedures for CoseSignTool V2 development.

## Test Organization

### Test Projects

| Project | Description |
|---------|-------------|
| `CoseSign1.Abstractions.Tests` | Core interface tests |
| `CoseSign1.Tests` | Direct signature tests |
| `CoseIndirectSignature.Tests` | Indirect signature tests |
| `CoseSign1.Certificates.Tests` | Certificate handling tests |
| `CoseSign1.Headers.Tests` | Header contributor tests |
| `CoseSign1.Transparent.Tests` | Transparency tests |
| `CoseSign1.Transparent.MST.Tests` | MST integration tests |
| `CoseSignTool.Tests` | CLI tests |
| `CoseSignTool.Abstractions.Tests` | Plugin interface tests |

### Test Categories

```csharp
[TestCategory("Unit")]       // Fast, isolated tests
[TestCategory("Integration")]// Tests with dependencies
[TestCategory("PQC")]        // Post-quantum specific
[TestCategory("Slow")]       // Long-running tests
[TestCategory("Windows")]    // Windows-only tests
```

## Running Tests

### All Tests

```bash
dotnet test CoseSignTool.sln
```

### Specific Project

```bash
dotnet test V2/CoseSign1.Tests/CoseSign1.Tests.csproj
```

### By Category

```bash
# Only unit tests
dotnet test --filter "TestCategory=Unit"

# Exclude slow tests
dotnet test --filter "TestCategory!=Slow"

# Multiple categories
dotnet test --filter "TestCategory=Unit|TestCategory=Integration"
```

### By Name Pattern

```bash
# Tests containing "Sign"
dotnet test --filter "FullyQualifiedName~Sign"

# Specific test class
dotnet test --filter "FullyQualifiedName~DirectSignatureFactoryTests"

# Specific test method
dotnet test --filter "Name=CreateCoseSign1MessageBytes_WithValidPayload_ReturnsSignature"
```

### With Verbosity

```bash
dotnet test --verbosity normal
dotnet test --verbosity detailed
```

## Writing Tests

### Test Structure

```csharp
[TestClass]
public class MyClassTests
{
    private MyClass _sut; // System Under Test
    
    [TestInitialize]
    public void Setup()
    {
        _sut = new MyClass();
    }
    
    [TestCleanup]
    public void Cleanup()
    {
        // Dispose resources
    }
    
    [TestMethod]
    public void MethodName_Scenario_ExpectedResult()
    {
        // Arrange
        var input = "test";
        
        // Act
        var result = _sut.Method(input);
        
        // Assert
        Assert.AreEqual(expected, result);
    }
}
```

### Async Tests

```csharp
[TestMethod]
public async Task AsyncMethod_Scenario_ExpectedResult()
{
    // Arrange
    var input = "test";
    
    // Act
    var result = await _sut.MethodAsync(input);
    
    // Assert
    Assert.AreEqual(expected, result);
}
```

### Data-Driven Tests

```csharp
[TestMethod]
[DataRow("ES256", -7)]
[DataRow("ES384", -35)]
[DataRow("ES512", -36)]
public void ParseAlgorithm_ValidInput_ReturnsCorrectValue(string name, int expected)
{
    var result = CoseAlgorithm.Parse(name);
    Assert.AreEqual(expected, result);
}
```

### Exception Testing

```csharp
[TestMethod]
public void Method_WithNullInput_ThrowsArgumentNullException()
{
    Assert.ThrowsException<ArgumentNullException>(() => _sut.Method(null));
}

[TestMethod]
public async Task AsyncMethod_WithInvalidInput_ThrowsArgumentException()
{
    await Assert.ThrowsExceptionAsync<ArgumentException>(
        () => _sut.MethodAsync("invalid"));
}
```

### Platform-Specific Tests

```csharp
[TestMethod]
[TestCategory("Windows")]
public void MlDsa_OnWindows_Available()
{
    if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
    {
        Assert.Inconclusive("Test requires Windows");
    }
    
    // Test ML-DSA functionality
}
```

## Test Utilities

### Test Certificates

```csharp
// Create ephemeral certificate
using var cert = TestCertificates.CreateEphemeral();

// Create specific algorithm
using var ecdsaCert = TestCertificates.CreateEcdsa(ECCurve.NamedCurves.nistP384);
using var rsaCert = TestCertificates.CreateRsa(keySize: 3072);

// Create chain
var (root, intermediate, leaf) = TestCertificates.CreateChain();
```

### Test Payloads

```csharp
// JSON payload
var json = TestPayloads.Json;

// Binary payload
var binary = TestPayloads.Binary;

// Large payload for streaming tests
var large = TestPayloads.Large(size: 1024 * 1024);
```

### Mock Objects

```csharp
// Mock signing service
var mockService = new Mock<ISigningService>();
mockService.Setup(s => s.SignAsync(It.IsAny<ReadOnlyMemory<byte>>(), It.IsAny<CoseAlgorithm>(), It.IsAny<CancellationToken>()))
    .ReturnsAsync(new byte[64]);

// Mock validator
var mockValidator = new Mock<IValidator>();
mockValidator.Setup(v => v.ValidateAsync(It.IsAny<CoseSign1Message>(), It.IsAny<ValidationContext>(), It.IsAny<CancellationToken>()))
    .ReturnsAsync(ValidationResult.Success());
```

## Test Data

### Test Files

Store test data in `TestData/` folders:

```
ProjectName.Tests/
├── TestData/
│   ├── valid-signature.cose
│   ├── invalid-signature.cose
│   ├── test-payload.json
│   └── test-cert.pfx
└── Tests/
```

### Embedded Resources

```csharp
// Mark file as embedded resource in .csproj
// <EmbeddedResource Include="TestData\sample.cose" />

var assembly = Assembly.GetExecutingAssembly();
using var stream = assembly.GetManifestResourceStream("Tests.TestData.sample.cose");
```

## Integration Testing

### Full Sign-Verify Cycle

```csharp
[TestClass]
[TestCategory("Integration")]
public class SignVerifyIntegrationTests
{
    [TestMethod]
    public async Task SignAndVerify_RoundTrip_Succeeds()
    {
        // Create certificate
        using var cert = TestCertificates.CreateEcdsa();
        
        // Sign
        var service = new LocalSigningService(cert);
        var factory = new DirectSignatureFactory(service);
        var payload = Encoding.UTF8.GetBytes("test payload");
        var signature = factory.CreateCoseSign1MessageBytes(payload, "text/plain");
        
        // Verify
        var validator = ValidationBuilder.Create()
            .AddSignatureValidator()
            .Build();
        var result = await validator.ValidateAsync(signature);
        
        Assert.IsTrue(result.IsValid);
    }
}
```

### CLI Testing

```csharp
[TestClass]
[TestCategory("Integration")]
public class CliIntegrationTests
{
    [TestMethod]
    public async Task SignCommand_WithValidInput_ExitsSuccessfully()
    {
        using var temp = new TempDirectory();
        var inputFile = temp.CreateFile("input.json", "{}");
        var outputFile = temp.GetPath("output.cose");
        var pfxFile = temp.CreatePfxFile("test.pfx", "password");
        
        Environment.SetEnvironmentVariable("COSESIGNTOOL_PFX_PASSWORD", "password");
        
        var exitCode = await CoseSignToolCli.Main(new[]
        {
            "sign-pfx", inputFile,
            "--pfx-file", pfxFile,
            "--output", outputFile
        });
        
        Assert.AreEqual(0, exitCode);
        Assert.IsTrue(File.Exists(outputFile));
    }
}
```

## Debugging Tests

### Visual Studio

1. Right-click test → Debug Test
2. Set breakpoints
3. Use Test Explorer for navigation

### VS Code

1. Click "Debug Test" above test method
2. Use Debug Console

### Command Line

```bash
# Wait for debugger
dotnet test --logger "console;verbosity=detailed"
```

## Continuous Integration

Tests run automatically in CI:

```yaml
- task: DotNetCoreCLI@2
  displayName: 'Run Tests'
  inputs:
    command: 'test'
    projects: '**/*.Tests.csproj'
    arguments: '--collect:"XPlat Code Coverage"'
```

## See Also

- [Development Setup](setup.md)
- [Coverage Guide](coverage.md)
- [Testing Guide (User)](../guides/testing.md)
