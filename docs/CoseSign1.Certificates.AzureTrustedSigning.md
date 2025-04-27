# [CoseSign1.Certificates.AzureTrustedSigning](https://github.com/microsoft/CoseSignTool/tree/main/CoseSign1.Certificates.AzureTrustedSigning)  

**CoseSign1.Certificates.AzureTrustedSigning** is a .NET Standard 2.0 library that provides an implementation of the `CertificateCoseSigningKeyProvider` class for Azure Trusted Signing. This library integrates with the Azure Trusted Signing service to provide signing certificates, certificate chains, and cryptographic keys.  

## Dependencies  
**CoseSign1.Certificates.AzureTrustedSigning** has the following package dependencies:  
* CoseSign1.Certificates
* Azure.Developer.TrustedSigning.CryptoProvider  

## Creation  
The following class is provided for creating a proper `CoseSign1Message` object signed by an Azure Trusted Signing certificate.  

### [AzureTrustedSigningCoseSigningKeyProvider](https://github.com/microsoft/CoseSignTool/blob/main/CoseSign1.Certificates.AzureTrustedSigning/AzureTrustedSigningCoseSigningKeyProvider.cs)  
This class is a concrete implementation of `CertificateCoseSigningKeyProvider` that integrates with the Azure Trusted Signing service. It provides the following functionality:  
* Retrieves the signing certificate from the Azure Trusted Signing service.  
* Retrieves the certificate chain from the Azure Trusted Signing service.  
* Provides an RSA key for signing or verification operations.  

#### Key Features:  
- **GetSigningCertificate**: Retrieves the signing certificate from the Azure Trusted Signing service.  
- **GetCertificateChain**: Retrieves the certificate chain in the desired sort order (root-first or leaf-first).  
- **ProvideRSAKey**: Provides an RSA key for signing or verification operations.  
- **ProvideECDsaKey**: Not supported for Azure Trusted Signing and will throw a `NotSupportedException`.  

#### Constructor:  
- `AzureTrustedSigningCoseSigningKeyProvider(AzSignContext signContext)`: Initializes a new instance of the class using the provided `AzSignContext`.  
#### Exceptions:  
- `ArgumentNullException`: Thrown if the `signContext` parameter is null.  
- `InvalidOperationException`: Thrown if the signing certificate or certificate chain is not available or is empty.  
- `NotSupportedException`: Thrown when attempting to use ECDsa keys, as they are not supported.  

## Example Usage
### Creating a Signing Key Provider
```csharp
using System;
using Azure.Developer.TrustedSigning.CryptoProvider;
using CoseSign1.Certificates.AzureTrustedSigning;

public class Example
{
    public void CreateSigningKeyProvider()
    {
        // Initialize the Azure Trusted Signing context
        AzSignContext signContext = new AzSignContext();

        // Create the signing key provider
        AzureTrustedSigningCoseSigningKeyProvider keyProvider = new AzureTrustedSigningCoseSigningKeyProvider(signContext);

        Console.WriteLine("Azure Trusted Signing key provider created successfully.");
    }
}
```
### Retrieving the Signing Certificate
```csharp
using System;
using Azure.Developer.TrustedSigning.CryptoProvider;
using CoseSign1.Certificates.AzureTrustedSigning;

public class Example
{
    public void GetSigningCertificate()
    {
        // Initialize the Azure Trusted Signing context
        AzSignContext signContext = new AzSignContext();

        // Create the signing key provider
        AzureTrustedSigningCoseSigningKeyProvider keyProvider = new AzureTrustedSigningCoseSigningKeyProvider(signContext);

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
using Azure.Developer.TrustedSigning.CryptoProvider;
using CoseSign1.Certificates.AzureTrustedSigning;
using System.Security.Cryptography.X509Certificates;

public class Example
{
    public void GetCertificateChain()
    {
        // Initialize the Azure Trusted Signing context
        AzSignContext signContext = new AzSignContext();

        // Create the signing key provider
        AzureTrustedSigningCoseSigningKeyProvider keyProvider = new AzureTrustedSigningCoseSigningKeyProvider(signContext);

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
using Azure.Developer.TrustedSigning.CryptoProvider;
using CoseSign1.Certificates.AzureTrustedSigning;
using System.Security.Cryptography;

public class Example
{
    public void UseRSAKey()
    {
        // Initialize the Azure Trusted Signing context
        AzSignContext signContext = new AzSignContext();

        // Create the signing key provider
        AzureTrustedSigningCoseSigningKeyProvider keyProvider = new AzureTrustedSigningCoseSigningKeyProvider(signContext);

        // Retrieve the RSA key
        RSA rsaKey = keyProvider.ProvideRSAKey();

        Console.WriteLine("RSA key retrieved successfully.");
    }
}
```
## Limitations
- <b>ECDsa Not Supported</b>: The ProvideECDsaKey method is not supported for Azure Trusted Signing and will throw a NotSupportedException.
## Conclusion
The [AzureTrustedSigningCoseSigningKeyProvider](https://github.com/microsoft/CoseSignTool/blob/main/CoseSign1.Certificates.AzureTrustedSigning/AzureTrustedSigningCoseSigningKeyProvider.cs) class provides a robust integration with the Azure Trusted Signing service, enabling seamless retrieval of signing certificates, certificate chains, and RSA keys. It is a powerful tool for creating and managing CoseSign1Message objects in environments that leverage Azure Trusted Signing.
<br/>
<br/>
For more information, refer to the [CoseSign1.Certificates](https://github.com/microsoft/CoseSignTool/blob/main/docs/CoseSign1.Certificates.md).