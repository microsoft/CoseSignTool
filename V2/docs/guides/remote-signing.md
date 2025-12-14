# Remote Signing Guide

This guide explains how to use remote signing services with CoseSignTool V2.

## Overview

Remote signing allows you to sign artifacts without having direct access to private keys. The private keys remain secure in a remote service (HSM, cloud KMS, or signing service), and only the signature operation is performed remotely.

## Benefits of Remote Signing

- **Enhanced Security** - Private keys never leave secure hardware
- **Centralized Key Management** - Single source of truth for keys
- **Audit Logging** - All signing operations are logged
- **Compliance** - Meet regulatory requirements for key protection
- **Scalability** - Support high-volume signing operations

## Supported Remote Signing Services

### Azure Trusted Signing

Microsoft's cloud-based code signing service:

```csharp
using CoseSign1.Certificates.AzureTrustedSigning;

var options = new AzureTrustedSigningOptions
{
    Endpoint = new Uri("https://myaccount.codesigning.azure.net"),
    AccountName = "myaccount",
    CertificateProfileName = "myprofile",
    Credential = new DefaultAzureCredential()
};

var service = new AzureTrustedSigningService(options);
```

**CLI:**
```bash
CoseSignTool sign-azure document.json ^
    --ats-endpoint https://myaccount.codesigning.azure.net ^
    --ats-account-name myaccount ^
    --ats-cert-profile-name myprofile
```

### Azure Key Vault

Use certificates stored in Azure Key Vault:

```csharp
using Azure.Security.KeyVault.Keys.Cryptography;

var credential = new DefaultAzureCredential();
var cryptoClient = new CryptographyClient(
    new Uri("https://myvault.vault.azure.net/keys/my-key"),
    credential);

var service = new KeyVaultSigningService(cryptoClient);
```

## ISigningService Interface

Remote signing services implement `ISigningService`:

```csharp
public interface ISigningService
{
    /// <summary>
    /// Signs data using the remote key.
    /// </summary>
    Task<byte[]> SignAsync(
        ReadOnlyMemory<byte> data, 
        CoseAlgorithm algorithm,
        CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Gets the signing certificate.
    /// </summary>
    Task<X509Certificate2> GetSigningCertificateAsync(
        CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Gets the supported algorithms.
    /// </summary>
    IReadOnlyList<CoseAlgorithm> SupportedAlgorithms { get; }
}
```

## Creating a Custom Remote Signing Service

### Basic Implementation

```csharp
public class MyRemoteSigningService : ISigningService
{
    private readonly HttpClient _httpClient;
    private readonly string _keyId;
    
    public MyRemoteSigningService(HttpClient httpClient, string keyId)
    {
        _httpClient = httpClient;
        _keyId = keyId;
    }
    
    public IReadOnlyList<CoseAlgorithm> SupportedAlgorithms => 
        new[] { CoseAlgorithm.ES256, CoseAlgorithm.ES384 };

    public async Task<byte[]> SignAsync(
        ReadOnlyMemory<byte> data,
        CoseAlgorithm algorithm,
        CancellationToken cancellationToken = default)
    {
        var request = new SignRequest
        {
            KeyId = _keyId,
            Algorithm = algorithm.ToString(),
            Data = Convert.ToBase64String(data.ToArray())
        };
        
        var response = await _httpClient.PostAsJsonAsync(
            "https://signing-service.example.com/sign",
            request,
            cancellationToken);
        
        response.EnsureSuccessStatusCode();
        
        var result = await response.Content.ReadFromJsonAsync<SignResponse>(cancellationToken);
        return Convert.FromBase64String(result.Signature);
    }
    
    public async Task<X509Certificate2> GetSigningCertificateAsync(
        CancellationToken cancellationToken = default)
    {
        var response = await _httpClient.GetAsync(
            $"https://signing-service.example.com/keys/{_keyId}/certificate",
            cancellationToken);
        
        var certBytes = await response.Content.ReadAsByteArrayAsync(cancellationToken);
        return new X509Certificate2(certBytes);
    }
}
```

## Using Remote Signing with Signature Factory

```csharp
// Create remote signing service
var signingService = new AzureTrustedSigningService(options);

// Create signature factory with remote service
var factory = new DirectSignatureFactory(signingService);

// Sign payload
byte[] signature = await factory.CreateCoseSign1MessageBytesAsync(
    payload, 
    "application/json",
    cancellationToken);
```

## Authentication

### Azure Default Credential

Recommended for Azure services:

```csharp
var credential = new DefaultAzureCredential();
```

Supports:
- Environment variables
- Managed Identity
- Visual Studio/VS Code credentials
- Azure CLI
- Interactive browser

### Managed Identity

For Azure-hosted workloads:

```csharp
var credential = new ManagedIdentityCredential();
// Or with specific client ID:
var credential = new ManagedIdentityCredential("client-id");
```

### Service Principal

For service-to-service scenarios:

```csharp
var credential = new ClientSecretCredential(
    tenantId: "tenant-id",
    clientId: "client-id",
    clientSecret: "client-secret");
```

## Retry and Resilience

Implement retry policies for remote services:

```csharp
var retryPolicy = Policy
    .Handle<HttpRequestException>()
    .WaitAndRetryAsync(3, retryAttempt => 
        TimeSpan.FromSeconds(Math.Pow(2, retryAttempt)));

var httpClient = new HttpClient(new PolicyHttpMessageHandler(retryPolicy));
var service = new MyRemoteSigningService(httpClient, keyId);
```

## Performance Considerations

### Batching

For high-volume signing, consider batching:

```csharp
var tasks = payloads.Select(async payload =>
{
    return await factory.CreateCoseSign1MessageBytesAsync(payload, contentType);
});

var signatures = await Task.WhenAll(tasks);
```

### Caching

Cache certificates to reduce round trips:

```csharp
public class CachedSigningService : ISigningService
{
    private readonly ISigningService _inner;
    private X509Certificate2? _cachedCert;
    
    public async Task<X509Certificate2> GetSigningCertificateAsync(
        CancellationToken cancellationToken = default)
    {
        return _cachedCert ??= await _inner.GetSigningCertificateAsync(cancellationToken);
    }
}
```

## Security Best Practices

1. **Use Managed Identity** when running in Azure
2. **Rotate credentials** regularly for service principals
3. **Enable audit logging** on the signing service
4. **Use HTTPS** for all remote calls
5. **Implement rate limiting** to prevent abuse
6. **Monitor for anomalies** in signing patterns

## Troubleshooting

### Authentication Failures

```
Azure.Identity.CredentialUnavailableException
```

- Verify credentials are configured
- Check environment variables
- Ensure Managed Identity is enabled

### Timeout Errors

```
System.Threading.Tasks.TaskCanceledException
```

- Increase timeout settings
- Check network connectivity
- Verify service availability

### Permission Errors

```
Azure.RequestFailedException: Status: 403 (Forbidden)
```

- Verify RBAC assignments
- Check key access policies
- Ensure certificate profile permissions

## See Also

- [Azure Trusted Signing](../components/azure-trusted-signing.md)
- [Signing Services Architecture](../architecture/signing-services.md)
- [Certificate Sources](certificate-sources.md)
