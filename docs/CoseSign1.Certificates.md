# [CoseSign1.Certificates](https://github.com/microsoft/CoseSignTool/tree/main/CoseSign1.Certificates)
**CoseSign1.Certificates** is a .NET Standard 2.0 library containing implementations and validators related to X509Certificate2 objects as signing key providers.
Most of the common logic for CoseSign1Message object creation and handling with certificates is handled in [CertificateCoseSigningKeyProvider](https://github.com/microsoft/CoseSignTool/blob/main/CoseSign1.Certificates/CertificateCoseSigningKeyProvider.cs) abstract base class. A default concrete implementation can be found in [Local/X509Certificate2CoseSigningKeyProvider ](https://github.com/microsoft/CoseSignTool/blob/main/CoseSign1.Certificates/Local/X509Certificate2CoseSigningKeyProvider.cs) which provides the interface on top of an already existing X509Certificate2 object.
## Dependencies
**CoseSign1.Certificates** has the following package dependencies
* CoseSign1
* System.Runtime.Caching >= 7.0.0
## Creation
The following classes are provide for creating a proper CoseSign1Message object which is signed by an X509Certificate2 object.
### [CertificateCoseSigningKeyProvider](https://github.com/microsoft/CoseSignTool/blob/main/CoseSign1.Certificates/CertificateCoseSigningKeyProvider.cs)
This class contains all the common logic of any certificate which is used as a signing key provider for CoseSign1Message signing. It will ensure that the x5t, x5chain protected headers are populated prior to signing as well as provide the interface to either the ECDsa or the ECC key set.
Any derived class must implement all methods as described in each protected method.
### [Local/X509Certificate2CoseSigningKeyProvider](https://github.com/microsoft/CoseSignTool/blob/main/CoseSign1.Certificates/Local/X509Certificate2CoseSigningKeyProvider.cs)
This class is a concrete implementation of **CertificateCoseSigningKeyProvider** which operates on an existing X509Certificate2 object.  It leverages a instance of a [ICertificateChainBuilder](https://github.com/microsoft/CoseSignTool/blob/main/CoseSign1.Certificates/Interfaces/ICertificateChainBuilder.cs) (specifically [X509ChainBuilder](https://github.com/microsoft/CoseSignTool/blob/main/CoseSign1.Certificates/Local/X509ChainBuilder.cs) by default) to build the certificate chain for the certificate.
## Extraction
The following classes are provide for extracting certificate information from a CoseSign1Message object which has been thought to be signed by an certificate.
### [CoseSign1MessageExtensions](https://github.com/microsoft/CoseSignTool/blob/main/CoseSign1.Certificates/Extensions/CoseSign1MessageExtensions.cs)
This C# extension class extends CoseSign1Message objects to provide the following functionality:
* `CoseSign1Message.TryGetSigningCertificate` - TryGet pattern for the presence of a signing certificate in the x5t header value.
* `CoseSign1Message.TryGetCertificateChain` - TryGet pattern for the certificate chain embedded in the x5chain header value.
