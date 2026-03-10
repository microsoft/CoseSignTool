# Testing Guide for Development

This guide covers testing practices and procedures for CoseSignTool V2 development.

## Test Organization

### Test Projects

| Project | Description |
|---------|-------------|
| `CoseSign1.Abstractions.Tests` | Shared contract tests |
| `CoseSign1.Tests` | Core signing tests (direct + indirect) |
| `CoseSign1.Certificates.Tests` | Certificate sources, chain building, X.509 validation |
| `CoseSign1.Headers.Tests` | Header contributors and header parsing |
| `CoseSign1.Transparent.MST.Tests` | MST integration and receipt validation (offline/unit scenarios) |
| `CoseSign1.Validation.Tests` | Staged validation framework and builder APIs |
| `CoseSign1.Integration.Tests` | End-to-end integration tests across packages |
| `CoseSignTool.Tests` | CLI behavior tests |
| `CoseSignTool.Abstractions.Tests` | Plugin API surface tests |
| `DIDx509.Tests` | DID:x509 parsing/resolution/validation tests |

### Test Categories

The V2 test suite primarily uses naming + project boundaries rather than heavy category tagging.

If a test needs an explicit category (e.g., for CI filtering), it uses NUnit's `[Category("...")]`.
Currently, category usage is intentionally sparse.

## Running Tests

### All Tests

```bash
dotnet test CoseSignToolV2.sln
```

### Specific Project

```bash
dotnet test CoseSign1.Tests/CoseSign1.Tests.csproj
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

Tests should be deterministic and safe to run in parallel.

- Prefer creating state inside each test method.
- `[SetUp]` is allowed for per-test initialization as long as it does not rely on shared mutable/static state and does not introduce ordering dependencies.
- Avoid using shared mutable fields across tests; if you must keep data on the fixture, keep it immutable.

### Test Structure

```csharp
[TestFixture]
public sealed class MyClassTests
{
    // ✓ Constants are OK - immutable
    private const string TestValue = "test";
    
    // ✓ Readonly value types are OK - immutable
    private readonly Uri TestUri = new("https://example.com");
    
    // Avoid shared mutable fields; if you use [SetUp], keep it per-test and deterministic.

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
using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Factories;
using CoseSign1.Tests.Common;
using CoseSign1.Validation;
using CoseSign1.Validation.DependencyInjection;
using CoseSign1.Validation.Trust.Plan;
using Microsoft.Extensions.DependencyInjection;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using NUnit.Framework;

[TestFixture]
public sealed class ValidatorTests
{
    [Test]
    public void Validate_WithValidMessage_ReturnsSuccess()
    {
        // Arrange
        using var testContext = CreateTestContext();
        var services = new ServiceCollection();
        var validation = services.ConfigureCoseValidation();

        // Enable X.509 signing key resolution (x5chain/x5t).
        validation.EnableCertificateSupport(certTrust => certTrust
            .UseSystemTrust()
            );

        using var sp = services.BuildServiceProvider();
        using var scope = sp.CreateScope();

        // In unit tests it's common to bypass trust and focus on signature correctness.
        var validator = scope.ServiceProvider
            .GetRequiredService<ICoseSign1ValidatorFactory>()
            .Create(
                options: new CoseSign1ValidationOptions { CertificateHeaderLocation = CoseHeaderLocation.Any },
                trustEvaluationOptions: new TrustEvaluationOptions { BypassTrust = true });

        // Act
        var result = testContext.Message.Validate(validator);

        // Assert
        Assert.That(result.Overall.IsValid, Is.True);
    }

    // Private helper that returns a disposable context
    private static TestContext CreateTestContext()
    {
        var cert = TestCertificateUtils.CreateCertificate("TestCert");
        var chainBuilder = new X509ChainBuilder();
        var signingService = CertificateSigningService.Create(cert, chainBuilder);
        using var factory = new CoseSign1MessageFactory(signingService);
        var messageBytes = factory.CreateCoseSign1MessageBytes<CoseSign1.Factories.Direct.DirectSignatureOptions>(
            new byte[] { 1, 2, 3 }, "application/test");
        var message = CoseMessage.DecodeSign1(messageBytes);
        
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
using CoseSign1.AzureKeyVault;
using NUnit.Framework;
using System.Security.Cryptography;

[TestCase(-37)] // PS256
[TestCase(-38)] // PS384
[TestCase(-39)] // PS512
public void CoseKeyHeaderContributor_StoresAlgorithmId(int coseAlgorithmId)
{
    using var rsa = RSA.Create(2048);
    var publicParams = rsa.ExportParameters(includePrivateParameters: false);

    var contributor = new CoseKeyHeaderContributor(publicParams, coseAlgorithmId);
    Assert.That(contributor.CoseAlgorithm, Is.EqualTo(coseAlgorithmId));
}
```

### Exception Testing

```csharp
[Test]
public void Method_WithNullInput_ThrowsArgumentNullException()
{
    var sut = new MyClass();
    Assert.Throws<ArgumentNullException>(() => sut.Method(null));
}

[Test]
public async Task AsyncMethod_WithInvalidInput_ThrowsArgumentException()
{
    Assert.ThrowsAsync<ArgumentException>(() => _sut.MethodAsync("invalid"));
}
```

### Platform-Specific Tests

```csharp
using CoseSign1.Tests.Common;
using NUnit.Framework;

[Test]
public void MlDsa_OnSupportedPlatforms_Available()
{
    PlatformHelper.SkipIfMLDsaNotSupported();

    // Test ML-DSA functionality
}
```

## Test Utilities

### Test Certificates

```csharp
using CoseSign1.Tests.Common;
using System.Security.Cryptography.X509Certificates;

using var ecdsaCert = LocalCertificateFactory.CreateEcdsaCertificate();
using var rsaCert = LocalCertificateFactory.CreateRsaCertificate();

X509Certificate2Collection chain = LocalCertificateFactory.CreateEcdsaChain(leafFirst: true);
X509Certificate2 leaf = chain[0];
```

### Test Payloads

```csharp
using System.Text;

byte[] json = Encoding.UTF8.GetBytes("{\"hello\":\"world\"}");
byte[] binary = new byte[] { 0x01, 0x02, 0x03 };
byte[] large = new byte[1024 * 1024];
```

### Mock Objects

```csharp
// Mock a post-signature validator component
var mockValidator = new Mock<IPostSignatureValidator>();
mockValidator
    .Setup(v => v.ValidateAsync(It.IsAny<IPostSignatureValidationContext>(), It.IsAny<CancellationToken>()))
    .ReturnsAsync(ValidationResult.Success("MockValidator"));
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
using CoseSign1.Certificates;
using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Factories;
using CoseSign1.Tests.Common;
using CoseSign1.Validation;
using NUnit.Framework;
using CoseSign1.Factories.Direct;
using System.Security.Cryptography.Cose;
using System.Text;

[TestFixture]
public class SignVerifyIntegrationTests
{
    [Test]
    public void SignAndVerify_RoundTrip_Succeeds()
    {
        // Create certificate
        using var cert = LocalCertificateFactory.CreateEcdsaCertificate();
        
        // Sign
        using var service = CertificateSigningService.Create(cert, new X509ChainBuilder());
        using var factory = new CoseSign1MessageFactory(service);
        var payload = Encoding.UTF8.GetBytes("test payload");
        var signature = factory.CreateCoseSign1MessageBytes<DirectSignatureOptions>(payload, "text/plain");
        
        // Verify
        var message = CoseMessage.DecodeSign1(signature);
        var services = new ServiceCollection();
        var validation = services.ConfigureCoseValidation();
        validation.EnableCertificateSupport(certTrust => certTrust
            .UseSystemTrust()
            );

        using var sp = services.BuildServiceProvider();
        using var scope = sp.CreateScope();

        var validator = scope.ServiceProvider
            .GetRequiredService<ICoseSign1ValidatorFactory>()
            .Create(
                options: new CoseSign1ValidationOptions { CertificateHeaderLocation = CoseHeaderLocation.Any },
                trustEvaluationOptions: new TrustEvaluationOptions { BypassTrust = true });
        var result = message.Validate(validator);
        
        Assert.That(result.Overall.IsValid, Is.True);
    }
}
```

### CLI Testing

```csharp
using NUnit.Framework;
using System.IO;

[TestFixture]
public class CliIntegrationTests
{
    [Test]
    public void VerifyCommand_WithMissingArgs_ReturnsNonZero()
    {
        int exitCode = CoseSignTool.Program.Main(["verify"]);
        Assert.That(exitCode, Is.Not.EqualTo(0));
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
