# [CoseIndirectSignature](https://github.com/microsoft/CoseSignTool/tree/main/CoseIndirectSignature)
**CoseIndirectSignature** is a .NET Standard 2.0 library containing a concrete implementation which embeds the hash of an object into the .Content of a CoseSign1Message object and updates the ContentType field to include a new content type extension of `+cose_hash_v` to indicate the content is a cose_hash_v structure of the original content type. This functionality is exposed via a factory pattern in [**IndirectSignatureFactory**](https://github.com/microsoft/CoseSignTool/tree/main/CoseIndirectSignature/IndirectSignatureFactory.cs) for use with Supply Chain Integrity Transparency and Trust [SCITT](https://scitt.io/).
## Dependencies
**CoseIndirecSignature** has the following package dependencies
* CoseSign1
## Creation
This library includes the following classes:
### [**IndirectSignatureFactory**](https://github.com/microsoft/CoseSignTool/tree/main/CoseIndirectSignature/IndirectSignatureFactory.cs)
This class implements the creation of a CoseSign1Message object leveraging CoseSign1 which conforms to an embedded IndirectSignature format for content which is needed to be submitted to SCITT for receipt generation.
There are various `Create*` methods which support both synchronous and asynchronous operations.

#### Example
```
using CoseIndirectSignature;
using CoseSign1;
using CoseSign1.Certificates.Local;

...

using IndirectSignatureFactory factory = new();
byte[] randomBytes = new byte[50];
new Random().NextBytes(randomBytes);
using MemoryStream memStream = new(randomBytes);

X509Certificate2CoseSigningKeyProvider coseSigningKeyProvider = new(...);
CoseSign1Message indirectSignature = factory.CreateIndirectSignature(payload: randomBytes, signingKeyProvider: coseSigningKeyProvider, contentType: "application/test.payload");
```

## Validation
To help with validation of IndirectSignatures which are embedded within a CoseSign1Message object, [CoseSign1MessageIndirectSignatureExtensions](https://github.com/microsoft/CoseSignTool/tree/main/CoseIndirectSignature/Extensions/CoseSign1MessageIndirectSignatureExtensions.cs) C# extension class is provided to add a `SignatureMatches(...)` overload that accepts **Stream** or **Byte[]** content.

#### Example:
```
using CoseIndirectSignature.Extensions;
using CoseSign1;
using CoseSign1.Certificates.Local;
using System.IO;

...

Stream coseFileStream = File.OpenRead(...);
Stream originalContentStream = File.OpenRead(...);
CoseSign1Message message = CoseMessage.DecodeSign1(coseFileStream);
if(message.IsIndirectSignature())
{
   return message.SignatureMatches(originalContentStream);
}
return false;
```