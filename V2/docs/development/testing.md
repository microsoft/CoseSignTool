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
[Category("Unit")]        // Fast, isolated tests
[Category("Integration")] // Tests with dependencies
[Category("PQC")]         // Post-quantum specific
[Category("Slow")]        // Long-running tests
[Category("Windows")]     // Windows-only tests
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
dotnet test --filter "Category=Unit"

# Exclude slow tests
dotnet test --filter "Category!=Slow"

# Multiple categories
dotnet test --filter "Category=Unit|Category=Integration"
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

### Test Isolation Requirements

**IMPORTANT:** All tests MUST be fully isolated to support parallel test execution. Do NOT use `[SetUp]` or `[TearDown]` attributes with class-level state. Each test must create its own state within the test method.

#### Why No SetUp/TearDown?

- **Parallel Execution**: NUnit runs tests in parallel by default. Class-level fields modified in `[SetUp]` can be overwritten by concurrent tests.
- **Deterministic Behavior**: Each test should be self-contained and produce the same result regardless of execution order.
- **Clear Dependencies**: Test dependencies are explicit when created inline.

### Test Structure

```csharp
[TestFixture]
public sealed class MyClassTests
{
    // ✓ Constants are OK - immutable
    private const string TestValue = "test";
    
    // ✓ Readonly value types are OK - immutable
    private readonly Uri TestUri = new("https://example.com");
    
    // ✗ AVOID: Mutable class-level fields that change per test
    // private MyClass _sut;
    
    // ✗ AVOID: [SetUp] with mutable state
    // [SetUp]
    // public void Setup() { _sut = new MyClass(); }

    [Test]
    public void MethodName_Scenario_ExpectedResult()
    {
        // Arrange - create all state within the test
        var sut = new MyClass();
        var input = TestValue;

        // Act
        var result = sut.Method(input);

        // Assert
        Assert.That(result, Is.EqualTo(expected));
    }
    
    [Test]
    public void MethodName_WithDisposable_DisposesCorrectly()
    {
        // Arrange - use 'using' for IDisposable resources
        using var cert = LocalCertificateFactory.CreateRsaCertificate();
        using var sut = new MyDisposableClass(cert);

        // Act
        var result = sut.DoSomething();

        // Assert
        Assert.That(result, Is.Not.Null);
    }
}
```

### Helper Methods for Test State

When multiple tests need similar setup, use private static factory methods:

```csharp
[TestFixture]
public sealed class ValidatorTests
{
    [Test]
    public void Validate_WithValidMessage_ReturnsSuccess()
    {
        // Arrange
        using var testContext = CreateTestContext();
        var validator = new CertificateChainValidator(allowUntrusted: true);

        // Act
        var result = validator.Validate(testContext.Message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Validate_WithNullMessage_ReturnsFailure()
    {
        // Arrange
        var validator = new CertificateChainValidator(allowUntrusted: true);

        // Act
        var result = validator.Validate(null!, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsValid, Is.False);
    }

    // Private helper that returns a disposable context
    private static TestContext CreateTestContext()
    {
        var cert = TestCertificateUtils.CreateCertificate("TestCert");
        var chainBuilder = new X509ChainBuilder();
        var signingService = CertificateSigningService.Create(cert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);
        var messageBytes = factory.CreateCoseSign1MessageBytes(
            new byte[] { 1, 2, 3 }, "application/test");
        var message = CoseSign1Message.DecodeSign1(messageBytes);
        
        return new TestContext(cert, message);
    }

    private sealed class TestContext : IDisposable
    {
        public X509Certificate2 Certificate { get; }
        public CoseSign1Message Message { get; }

        public TestContext(X509Certificate2 cert, CoseSign1Message message)
        {
            Certificate = cert;
            Message = message;
        }

        public void Dispose() => Certificate.Dispose();
    }
}
```

### Async Tests

```csharp
[Test]
public async Task AsyncMethod_Scenario_ExpectedResult()
{
    // Arrange - create state within the test
    using var sut = new MyAsyncClass();
    var input = "test";

    // Act
    var result = await sut.MethodAsync(input);

    // Assert
    Assert.That(result, Is.EqualTo(expected));
}
```

### Data-Driven Tests

```csharp
[TestCase("ES256", -7)]
[TestCase("ES384", -35)]
[TestCase("ES512", -36)]
public void ParseAlgorithm_ValidInput_ReturnsCorrectValue(string name, int expected)
{
    var result = CoseAlgorithm.Parse(name);
    Assert.That(result, Is.EqualTo(expected));
}
```

### Exception Testing

```csharp
[Test]
public void Method_WithNullInput_ThrowsArgumentNullException()
{
    Assert.Throws<ArgumentNullException>(() => _sut.Method(null));
}

[Test]
public async Task AsyncMethod_WithInvalidInput_ThrowsArgumentException()
{
    Assert.ThrowsAsync<ArgumentException>(() => _sut.MethodAsync("invalid"));
}
```

### Platform-Specific Tests

```csharp
[Test]
[Category("Windows")]
public void MlDsa_OnWindows_Available()
{
    if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
    {
        Assert.Ignore("Test requires Windows");
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
// Mock validator
var mockValidator = new Mock<IValidator>();
mockValidator
    .Setup(v => v.ValidateAsync(It.IsAny<CoseSign1Message>(), It.IsAny<ValidationStage>(), It.IsAny<CancellationToken>()))
    .ReturnsAsync(ValidationResult.Success("MockValidator", ValidationStage.PostSignature));
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
        var service = CertificateSigningService.Create(cert, new X509ChainBuilder());
        var factory = new DirectSignatureFactory(service);
        var payload = Encoding.UTF8.GetBytes("test payload");
        var signature = factory.CreateCoseSign1MessageBytes(payload, "text/plain");
        
        // Verify
        var message = CoseMessage.DecodeSign1(signature);
        var validator = Cose.Sign1Message()
            .ValidateCertificate(cert => { })
            .AllowAllTrust("test")
            .Build();
        var result = await validator.ValidateAsync(message);
        
        Assert.IsTrue(result.Overall.IsValid);
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
