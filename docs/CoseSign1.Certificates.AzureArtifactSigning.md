# [CoseSign1.Certificates.AzureArtifactSigning](https://github.com/microsoft/CoseSignTool/tree/main/CoseSign1.Certificates.AzureArtifactSigning)  

**CoseSign1.Certificates.AzureArtifactSigning** is a .NET 8.0 library that provides an implementation of the `CertificateCoseSigningKeyProvider` class for Azure Artifact Signing. This library integrates with the Azure Artifact Signing service to provide signing certificates, certificate chains, and cryptographic keys.

## Requirements
- **.NET 8.0 Runtime**: This library requires .NET 8.0 or later.
- **Azure Artifact Signing Account**: An active Azure Artifact Signing account with configured certificate profiles.
- **Azure Authentication**: Valid Azure credentials (Azure CLI, Managed Identity, environment variables, etc.).  

## Dependencies  
**CoseSign1.Certificates.AzureArtifactSigning** has the following package dependencies:  
* **CoseSign1.Certificates** - Base certificate provider abstractions
* **Azure.Developer.ArtifactSigning.CryptoProvider** - Azure Artifact Signing SDK for cryptographic operations
* **Azure.Identity** (transitive) - Azure authentication mechanisms
* **Azure.Core** (transitive) - Azure SDK core functionality  

## Creation  
The following class is provided for creating a proper `CoseSign1Message` object signed by an Azure Artifact Signing certificate.  

### [AzureArtifactSigningCoseSigningKeyProvider](https://github.com/microsoft/CoseSignTool/blob/main/CoseSign1.Certificates.AzureArtifactSigning/AzureArtifactSigningCoseSigningKeyProvider.cs)  
This class is a concrete implementation of `CertificateCoseSigningKeyProvider` that integrates with the Azure Artifact Signing service. It provides the following functionality:  
* Retrieves the signing certificate from the Azure Artifact Signing service.  
* Retrieves the certificate chain from the Azure Artifact Signing service.  
* Provides an RSA key for signing or verification operations.  

#### Key Features:  
- **GetSigningCertificate**: Retrieves the signing certificate from the Azure Artifact Signing service.  
- **GetCertificateChain**: Retrieves the certificate chain in the desired sort order (root-first or leaf-first).  
- **ProvideRSAKey**: Provides an RSA key for signing or verification operations.  
- **ProvideECDsaKey**: Not supported for Azure Artifact Signing and will throw a `NotSupportedException`.
- **Issuer Property (SCITT)**: Overrides the base class to provide Azure-specific DID:X509:0 format with EKU support for non-standard certificates.  

#### Constructor:  
- `AzureArtifactSigningCoseSigningKeyProvider(AzSignContext signContext)`: Initializes a new instance of the class using the provided `AzSignContext`.  
#### Exceptions:  
- `ArgumentNullException`: Thrown if the `signContext` parameter is null.  
- `InvalidOperationException`: Thrown if the signing certificate or certificate chain is not available or is empty.  
- `NotSupportedException`: Thrown when attempting to use ECDsa keys, as they are not supported.  

## SCITT Compliance and DID:X509:0 Support

Azure Artifact Signing certificates automatically support **SCITT (Supply Chain Integrity, Transparency, and Trust)** compliance through an enhanced DID:X509:0 format that includes Extended Key Usage (EKU) information per the [DID:X509 specification](https://github.com/microsoft/did-x509/blob/main/specification.md#eku-policy).

### DID:X509:0 Format with EKU

Azure Artifact Signing certificates include **Microsoft-specific EKUs** (Enhanced Key Usages starting with `1.3.6.1.4.1.311`) that identify the certificate's intended purpose. When these Microsoft EKUs are present, the `Issuer` property automatically generates an EKU-based DID identifier:

```
did:x509:0:sha256:{base64url-hash}::eku:{oid}
```

Where:
- `{base64url-hash}` is the base64url-encoded root certificate fingerprint (43 characters for SHA256 per RFC 4648 Section 5)
- `{oid}` is the EKU OID in dotted decimal notation (e.g., `1.3.6.1.4.1.311.10.3.13`)
- The OID is NOT percent-encoded (just the raw OID string)

#### Microsoft EKU Detection
The generator detects any EKU starting with the **Microsoft reserved prefix `1.3.6.1.4.1.311`**. When Microsoft EKUs are present, an EKU-based DID is generated. When no Microsoft EKUs are found, the generator falls back to the standard subject-based DID format.

#### Deepest Greatest EKU Selection
When multiple Microsoft EKUs are present in an Azure Artifact Signing certificate, the "deepest greatest" EKU is selected using:
1. **Depth Priority**: EKU with the most OID segments (e.g., `1.3.6.1.4.1.311.20.30` has 9 segments)
2. **Last Segment Tiebreaker**: If multiple EKUs have the same depth, the one with the largest last segment value is selected

**Examples:**
- `1.3.6.1.4.1.311.20.99` beats `1.3.6.1.4.1.311.20.50` (same depth, 99 > 50)
- `1.3.6.1.4.1.311.20.30.40` beats `1.3.6.1.4.1.311.999` (10 segments > 8 segments)

### Implementation Details

The Azure Artifact Signing provider uses [`AzureArtifactSigningDidX509Generator`](https://github.com/microsoft/CoseSignTool/blob/main/CoseSign1.Certificates.AzureArtifactSigning/AzureArtifactSigningDidX509Generator.cs), which:
- Extends the base `DidX509Generator` class and reuses its hash computation and formatting
- Calls the base class once to generate the properly formatted DID with subject policy
- Detects Microsoft EKUs (starting with `1.3.6.1.4.1.311`) in the leaf certificate
- Replaces the `::subject:...` portion with `::eku:{oid}` when Microsoft EKUs are present
- Returns the base implementation unchanged when no Microsoft EKUs are found
- Ensures base64url encoding (43 characters for SHA256) per RFC 4648 Section 5
- Provides virtual methods for customization if needed

### Example DID Formats

**Without Microsoft EKUs (subject-based format):**
```
did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::subject:CN:MyCompany:O:Example
```

**With Microsoft EKU (Azure Artifact Signing specific format):**
```
did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::eku:1.3.6.1.4.1.311.10.3.13
```

Note the base64url-encoded hash is exactly 43 characters for SHA256 (not 64-character hex encoding).

This enhanced format provides additional identity context for Azure Artifact Signing certificates, enabling better audit trails and certificate policy identification in SCITT-compliant systems.

## Plugin Integration
For command-line usage, this library is integrated into CoseSignTool through the **CoseSignTool.AzureArtifactSigning.Plugin**. The plugin automatically handles:
- Azure authentication via `DefaultAzureCredential`
- Certificate retrieval and chain building
- Signing operations with cloud-based keys
- Automatic DID:X509:0 generation with EKU support for SCITT compliance

See the [CoseSignTool documentation](https://github.com/microsoft/CoseSignTool) for command-line usage examples.

## Example Usage
### Creating a Signing Key Provider
```csharp
using System;
using Azure.Developer.ArtifactSigning.CryptoProvider;
using CoseSign1.Certificates.AzureArtifactSigning;

public class Example
{
    public void CreateSigningKeyProvider()
    {
        // Note: In .NET 8.0, you must properly configure the AzSignContext
        // with endpoint URL, account name, and certificate profile name
        // This example shows the structure; actual initialization requires valid Azure credentials
        
        AzSignContext signContext = new AzSignContext();

        // Create the signing key provider
        AzureArtifactSigningCoseSigningKeyProvider keyProvider = new AzureArtifactSigningCoseSigningKeyProvider(signContext);

        Console.WriteLine("Azure Artifact Signing key provider created successfully.");
    }
}
```
### Retrieving the Signing Certificate
```csharp
using System;
using Azure.Developer.ArtifactSigning.CryptoProvider;
using CoseSign1.Certificates.AzureArtifactSigning;

public class Example
{
    public void GetSigningCertificate()
    {
        // Initialize the Azure Artifact Signing context
        AzSignContext signContext = new AzSignContext();

        // Create the signing key provider
        AzureArtifactSigningCoseSigningKeyProvider keyProvider = new AzureArtifactSigningCoseSigningKeyProvider(signContext);
        // Retrieve the signing certificate
        var signingCertificate = keyProvider.GetSigningCertificate();

        Console.WriteLine($"Signing certificate retrieved: {signingCertificate.Subject}");
    }
}
```
### Retrieving the Certificate Chain
```csharp
using System;
using System.Linq;
using Azure.Developer.ArtifactSigning.CryptoProvider;
using CoseSign1.Certificates.AzureArtifactSigning;
using System.Security.Cryptography.X509Certificates;

public class Example
{
    public void GetCertificateChain()
    {
        // Initialize the Azure Artifact Signing context
        AzSignContext signContext = new AzSignContext();

        // Create the signing key provider
        AzureArtifactSigningCoseSigningKeyProvider keyProvider = new AzureArtifactSigningCoseSigningKeyProvider(signContext);

        // Retrieve the certificate chain in leaf-first order
        var certificateChain = keyProvider.GetCertificateChain(X509ChainSortOrder.LeafFirst).ToList();

        Console.WriteLine("Certificate chain retrieved:");
        foreach (var cert in certificateChain)
        {
            Console.WriteLine($"- {cert.Subject}");
        }
    }
}
```
### Using RSA for Signing
```csharp
using System;
using Azure.Developer.ArtifactSigning.CryptoProvider;
using CoseSign1.Certificates.AzureArtifactSigning;
using System.Security.Cryptography;

public class Example
{
    public void UseRSAKey()
    {
        // Initialize the Azure Artifact Signing context
        AzSignContext signContext = new AzSignContext();

        // Create the signing key provider
        AzureArtifactSigningCoseSigningKeyProvider keyProvider = new AzureArtifactSigningCoseSigningKeyProvider(signContext);

        // Retrieve the RSA key
        RSA rsaKey = keyProvider.ProvideRSAKey();

        Console.WriteLine("RSA key retrieved successfully.");
    }
}
```
## Advanced: Custom DID Generation

While the default EKU-based DID generation is suitable for most scenarios, you can customize the behavior by inheriting from `AzureArtifactSigningDidX509Generator`:

```csharp
using CoseSign1.Certificates.AzureArtifactSigning;

public class CustomAzureDidGenerator : AzureArtifactSigningDidX509Generator
{
    // Override to customize EKU extraction logic
    protected override List<string> ExtractEkus(X509Certificate2 certificate)
    {
        // Custom EKU extraction logic
        return base.ExtractEkus(certificate);
    }
    
    // Override to customize EKU selection algorithm
    protected override string SelectDeepestGreatestEku(List<string> ekus)
    {
        // Custom selection logic
        return base.SelectDeepestGreatestEku(ekus);
    }
}
```

## Limitations
- **ECDsa Not Supported**: The `ProvideECDsaKey` method is not supported for Azure Artifact Signing and will throw a `NotSupportedException`.
- **.NET 8.0 Only**: This library requires .NET 8.0 runtime and is not compatible with .NET Standard 2.0 or earlier .NET versions.
- **RSA Only**: Only RSA-based signing algorithms are supported by Azure Artifact Signing.
- **Cloud Connectivity Required**: Active internet connection to Azure Artifact Signing service is required for all signing operations.
- **DID Format**: The EKU-based DID format is specific to Azure Artifact Signing and may not be recognized by systems expecting standard subject-based DIDs.
## Conclusion
The [AzureArtifactSigningCoseSigningKeyProvider](https://github.com/microsoft/CoseSignTool/blob/main/CoseSign1.Certificates.AzureArtifactSigning/AzureArtifactSigningCoseSigningKeyProvider.cs) class provides a robust integration with the Azure Artifact Signing service, enabling seamless retrieval of signing certificates, certificate chains, and RSA keys. It is a powerful tool for creating and managing CoseSign1Message objects in environments that leverage Azure Artifact Signing.
<br/>
<br/>
For more information, refer to the [CoseSign1.Certificates](https://github.com/microsoft/CoseSignTool/blob/main/docs/CoseSign1.Certificates.md).