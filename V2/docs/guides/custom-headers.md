# Custom Headers Guide

This guide explains how to add custom headers to COSE signatures using the V2 Header Contributor system.

## Overview

CoseSignTool V2 uses a contributor-based architecture for headers, allowing you to add custom headers without modifying core signing logic.

## IHeaderContributor Interface

Header contributors implement the `IHeaderContributor` interface:

```csharp
public interface IHeaderContributor
{
    /// <summary>
    /// Gets the merge strategy for handling conflicts when headers already exist.
    /// </summary>
    HeaderMergeStrategy MergeStrategy { get; }

    /// <summary>
    /// Adds headers to the protected header bucket.
    /// </summary>
    void ContributeProtectedHeaders(CoseHeaderMap headers, HeaderContributorContext context);

    /// <summary>
    /// Adds headers to the unprotected header bucket.
    /// </summary>
    void ContributeUnprotectedHeaders(CoseHeaderMap headers, HeaderContributorContext context);
}
```

## Creating a Custom Header Contributor

### Basic Structure

```csharp
using CoseSign1.Headers;

public class MyCustomHeaderContributor : IHeaderContributor
{
    public HeaderMergeStrategy MergeStrategy => HeaderMergeStrategy.Fail;

    public void ContributeProtectedHeaders(CoseHeaderMap headers, HeaderContributorContext context)
    {
        // Add headers that must be integrity-protected
        headers.Add(new CoseHeaderLabel("my-protected-header"), "value");
    }

    public void ContributeUnprotectedHeaders(CoseHeaderMap headers, HeaderContributorContext context)
    {
        // Add headers that don't need integrity protection
        headers.Add(new CoseHeaderLabel("my-unprotected-header"), "value");
    }
}
```

### Example: Build Information Header

```csharp
public class BuildInfoHeaderContributor : IHeaderContributor
{
    private readonly string _buildId;
    private readonly string _buildPipeline;
    
    public BuildInfoHeaderContributor(string buildId, string buildPipeline)
    {
        _buildId = buildId;
        _buildPipeline = buildPipeline;
    }

    public HeaderMergeStrategy MergeStrategy => HeaderMergeStrategy.Fail;

    public void ContributeProtectedHeaders(CoseHeaderMap headers, HeaderContributorContext context)
    {
        // Build info in protected headers for integrity
        headers.Add(new CoseHeaderLabel("build-id"), _buildId);
        headers.Add(new CoseHeaderLabel("build-pipeline"), _buildPipeline);
        headers.Add(new CoseHeaderLabel("build-timestamp"), DateTimeOffset.UtcNow.ToUnixTimeSeconds());
    }

    public void ContributeUnprotectedHeaders(CoseHeaderMap headers, HeaderContributorContext context)
    {
        // No unprotected headers needed
    }
}
```

### Example: Environment Tag Header

```csharp
public class EnvironmentTagHeaderContributor : IHeaderContributor
{
    private readonly string _environment;
    
    public EnvironmentTagHeaderContributor(string environment)
    {
        _environment = environment;
    }

    public HeaderMergeStrategy MergeStrategy => HeaderMergeStrategy.Fail;

    public void ContributeProtectedHeaders(CoseHeaderMap headers, HeaderContributorContext context)
    {
        headers.Add(new CoseHeaderLabel("environment"), _environment);
    }

    public void ContributeUnprotectedHeaders(CoseHeaderMap headers, HeaderContributorContext context)
    {
        // Environment is protected, nothing unprotected
    }
}
```

## Using Custom Contributors

### With Signature Factory

```csharp
var options = new DirectSignatureOptions
{
    AdditionalHeaderContributors =
    [
        new BuildInfoHeaderContributor("12345", "main-ci"),
        new EnvironmentTagHeaderContributor("production")
    ]
};

var factory = new CoseSign1MessageFactory(signingService);
var signatureBytes = factory.CreateCoseSign1MessageBytes<DirectSignatureOptions>(
    payload,
    contentType: "application/octet-stream",
    options: options);
```

### With Dependency Injection

```csharp
services.AddSingleton<IHeaderContributor>(sp => 
    new BuildInfoHeaderContributor(
        Environment.GetEnvironmentVariable("BUILD_ID") ?? "unknown",
        Environment.GetEnvironmentVariable("BUILD_PIPELINE") ?? "unknown"));

services.AddSingleton<IHeaderContributor>(sp => 
    new EnvironmentTagHeaderContributor(
        Environment.GetEnvironmentVariable("ENVIRONMENT") ?? "development"));

// Later, when signing:
var contributors = serviceProvider.GetServices<IHeaderContributor>().ToArray();
var options = new DirectSignatureOptions { AdditionalHeaderContributors = contributors };
```

## Header Context

The `HeaderContributorContext` provides information about the signing operation:

```csharp
public class HeaderContributorContext
{
    public SigningContext SigningContext { get; }
    public ISigningKey SigningKey { get; }
}
```

Payload and content type are available on `context.SigningContext`.

## COSE Header Labels

### Standard Headers

Use predefined labels for standard headers:

```csharp
headers.Add(CoseHeaderLabel.Algorithm, algorithmValue);
headers.Add(CoseHeaderLabel.ContentType, "application/json");
headers.Add(CoseHeaderLabel.KeyId, keyId);
```

### Custom String Labels

For custom application headers:

```csharp
headers.Add(new CoseHeaderLabel("my-app-header"), "value");
```

### Custom Integer Labels

For IANA-registered or private-use integer labels:

```csharp
headers.Add(new CoseHeaderLabel(12345), value); // Integer label
```

## Protected vs Unprotected Headers

| Header Type | Use For | Security |
|-------------|---------|----------|
| **Protected** | Headers that affect signature validity | Integrity-protected, included in signature |
| **Unprotected** | Metadata, routing info, receipts | Not signed, can be modified |

### Guidelines

- Put security-critical headers in **protected** (algorithm, key ID, certificates)
- Put mutable metadata in **unprotected** (timestamps, receipts, routing)
- Content type should typically be **protected**

## CWT Claims Header

For CWT (CBOR Web Token) claims, use the CWT claims header contributor:

```csharp
var cwtContributor = new CwtClaimsHeaderContributor()
    .SetIssuer("my-service")
    .SetSubject("document-id-12345")
    .SetAudience("my-audience")
    .SetIssuedAt(DateTimeOffset.UtcNow)
    .SetExpirationTime(DateTimeOffset.UtcNow.AddHours(1));
```

## Ordering

Contributor ordering is controlled by the signing service / factory.

- Factory-required contributors run first (for example, the content-type contributor).
- `SigningOptions.AdditionalHeaderContributors` are appended after required contributors.
- Within `AdditionalHeaderContributors`, contributors are invoked in the order provided.

## Reading Custom Headers

When validating or inspecting signatures:

```csharp
// Get protected header value
if (message.ProtectedHeaders.TryGetValue(
    new CoseHeaderLabel("my-custom-header"), 
    out var value))
{
    var headerValue = value.ToString();
}

// Get unprotected header value
if (message.UnprotectedHeaders.TryGetValue(
    new CoseHeaderLabel("my-unprotected-header"), 
    out var value))
{
    var headerValue = value.ToString();
}
```

## Testing Header Contributors

```csharp
using NUnit.Framework;

[TestFixture]
public class BuildInfoHeaderContributorTests
{
    [Test]
    public void ContributeProtectedHeaders_AddsBuildInfo()
    {
        // Arrange
        var contributor = new BuildInfoHeaderContributor("build-123", "main-pipeline");
        var headers = new CoseHeaderMap();

        // Header contributors need a HeaderContributorContext.
        // In unit tests, it's typical to use a mock/fake ISigningKey.
        var signingKey = new Mock<ISigningKey>();
        signingKey.SetupGet(k => k.Metadata).Returns(new SigningKeyMetadata(
            coseAlgorithmId: -7,
            keyType: CryptographicKeyType.ECDsa,
            isRemote: false));
        signingKey.SetupGet(k => k.SigningService).Returns(Mock.Of<ISigningService<SigningOptions>>());

        var signingContext = new SigningContext(
            payloadBytes: ReadOnlyMemory<byte>.Empty,
            contentType: "application/octet-stream");

        var context = new HeaderContributorContext(signingContext, signingKey.Object);
        
        // Act
        contributor.ContributeProtectedHeaders(headers, context);
        
        // Assert
        Assert.That(headers.ContainsKey(new CoseHeaderLabel("build-id")), Is.True);
        Assert.That(headers.ContainsKey(new CoseHeaderLabel("build-pipeline")), Is.True);
    }
}
```

## See Also

- [Header Contributors Architecture](../architecture/header-contributors.md)
- [CWT Claims](../api/README.md)
- [COSE Specification](https://datatracker.ietf.org/doc/html/rfc9052)
