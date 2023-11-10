# [CoseDetachedSignature](https://github.com/microsoft/CoseSignTool/tree/main/CoseDetachedSignature)
**CoseDetachedSignature** is a .NET Standard 2.0 library containing a concrete implementation which embeds the hash of an object into the .Content of a CoseSign1Message object and updates the ContentType field to include a new content type extension of `+hash-{algorithm}` to indicate the content is a hash of the original content type. This functionality is exposed via a factory pattern in [**DetachedSignatureFactory**](https://github.com/microsoft/CoseSignTool/tree/main/CoseDetachedSignature/CoseSignatureFactory.cs) for use with Supply Chain Integrity Transparency and Trust [SCITT](https://scitt.io/).
## Dependencies
**CoseDetachedSignature** has the following package dependencies
* CoseSign1
## Creation
This library includes the following classes:
### [**DetachedSignatureFactory**](https://github.com/microsoft/CoseSignTool/tree/main/CoseDetachedSignature/DetachedSignatureFactory.cs)
This class implements the creation of a CoseSign1Message object leveraging CoseSign1 which conforms to an embedded DetachedSignature format for content which is needed to be submitted to SCITT for receipt generation.
There are various `Create*` methods which support both synchronous and asynchronous operations.

#### Example
```
using CoseDetachedSignature;
using CoseSign1;
using CoseSign1.Certificates.Local;

...

using DetachedSignatureFactory factory = new();
byte[] randomBytes = new byte[50];
new Random().NextBytes(randomBytes);
using MemoryStream memStream = new(randomBytes);

X509Certificate2CoseSigningKeyProvider coseSigningKeyProvider = new(...);
CoseSign1Message detachedSignature = factory.CreateDetachedSignature(payload: randomBytes, signingKeyProvider: coseSigningKeyProvider, contentType: "application/test.payload");
```

## Validation
To help with validation of DetachedSignatures which are embedded within a CoseSign1Message object, [CoseSign1MessageDetachedSignatureExtensions](https://github.com/microsoft/CoseSignTool/tree/main/CoseDetachedSignature/Extensions/CoseSign1MessageDetachedSignatureExtensions.cs) C# extension class is provided to add a `SignatureMatches(...)` overload that accepts **Stream** or **Byte[]** content.

#### Example:
```
using CoseDetachedSignature.Extensions;
using CoseSign1;
using CoseSign1.Certificates.Local;
using System.IO;

...

Stream coseFileStream = File.OpenRead(...);
Stream originalContentStream = File.OpenRead(...);
CoseSign1Message message = CoseMessage.DecodeSign1(coseFileStream);
if(message.IsDetachedSignature())
{
   return message.SignatureMatches(originalContentStream);
}
return false;
```