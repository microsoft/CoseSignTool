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
    /// Adds headers to the protected header bucket.
    /// </summary>
    void ContributeProtectedHeaders(CoseHeaderMap headers, HeaderContext context);
    
    /// <summary>
    /// Adds headers to the unprotected header bucket.
    /// </summary>
    void ContributeUnprotectedHeaders(CoseHeaderMap headers, HeaderContext context);
    
    /// <summary>
    /// Order in which this contributor runs.
    /// </summary>
    int Order { get; }
}
```

## Creating a Custom Header Contributor

### Basic Structure

```csharp
using CoseSign1.Headers;

public class MyCustomHeaderContributor : IHeaderContributor
{
    public int Order => 100;

    public void ContributeProtectedHeaders(CoseHeaderMap headers, HeaderContext context)
    {
        // Add headers that must be integrity-protected
        headers.Add(new CoseHeaderLabel("my-protected-header"), "value");
    }

    public void ContributeUnprotectedHeaders(CoseHeaderMap headers, HeaderContext context)
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
    
    public int Order => 50;

    public void ContributeProtectedHeaders(CoseHeaderMap headers, HeaderContext context)
    {
        // Build info in protected headers for integrity
        headers.Add(new CoseHeaderLabel("build-id"), _buildId);
        headers.Add(new CoseHeaderLabel("build-pipeline"), _buildPipeline);
        headers.Add(new CoseHeaderLabel("build-timestamp"), DateTimeOffset.UtcNow.ToUnixTimeSeconds());
    }

    public void ContributeUnprotectedHeaders(CoseHeaderMap headers, HeaderContext context)
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
    
    public int Order => 60;

    public void ContributeProtectedHeaders(CoseHeaderMap headers, HeaderContext context)
    {
        headers.Add(new CoseHeaderLabel("environment"), _environment);
    }

    public void ContributeUnprotectedHeaders(CoseHeaderMap headers, HeaderContext context)
    {
        // Environment is protected, nothing unprotected
    }
}
```

## Using Custom Contributors

### With Signature Factory

```csharp
var contributors = new List<IHeaderContributor>
{
    new BuildInfoHeaderContributor("12345", "main-ci"),
    new EnvironmentTagHeaderContributor("production")
};

var factory = new DirectSignatureFactory(
    signingService,
    headerContributors: contributors);

var signature = factory.CreateCoseSign1MessageBytes(payload);
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
```

## Header Context

The `HeaderContext` provides information about the signing operation:

```csharp
public class HeaderContext
{
    /// <summary>
    /// The payload being signed.
    /// </summary>
    public ReadOnlyMemory<byte> Payload { get; }
    
    /// <summary>
    /// The content type of the payload.
    /// </summary>
    public string? ContentType { get; }
    
    /// <summary>
    /// The signing certificate.
    /// </summary>
    public X509Certificate2? SigningCertificate { get; }
    
    /// <summary>
    /// Whether this is a detached signature.
    /// </summary>
    public bool IsDetached { get; }
}
```

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
var cwtContributor = new CwtClaimsHeaderContributor(claims =>
{
    claims.Issuer = "my-service";
    claims.Subject = "document-id-12345";
    claims.Audience = "my-audience";
    claims.IssuedAt = DateTimeOffset.UtcNow;
    claims.Expiration = DateTimeOffset.UtcNow.AddHours(1);
});
```

## Contributor Ordering

Contributors run in order of their `Order` property:

| Order Range | Typical Usage |
|-------------|---------------|
| 0-20 | Core headers (algorithm, content type) |
| 20-40 | Certificate headers |
| 40-60 | Application headers |
| 60-80 | CWT claims |
| 80-100 | Custom/extension headers |

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
[TestClass]
public class BuildInfoHeaderContributorTests
{
    [TestMethod]
    public void ContributeProtectedHeaders_AddsBuildInfo()
    {
        // Arrange
        var contributor = new BuildInfoHeaderContributor("build-123", "main-pipeline");
        var headers = new CoseHeaderMap();
        var context = new HeaderContext();
        
        // Act
        contributor.ContributeProtectedHeaders(headers, context);
        
        // Assert
        Assert.IsTrue(headers.ContainsKey(new CoseHeaderLabel("build-id")));
        Assert.IsTrue(headers.ContainsKey(new CoseHeaderLabel("build-pipeline")));
    }
}
```

## See Also

- [Header Contributors Architecture](../architecture/header-contributors.md)
- [CWT Claims](../api/README.md)
- [COSE Specification](https://datatracker.ietf.org/doc/html/rfc9052)
