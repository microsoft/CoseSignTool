# [CoseIndirectSignature](https://github.com/microsoft/CoseSignTool/tree/main/CoseIndirectSignature)
**CoseIndirectSignature** is a .NET Standard 2.0 library containing a concrete implementation which embeds the hash of an object into the .Content of a CoseSign1Message object and updates the ContentType field to include a new content type extension of `+cose-hash-v` to indicate the content is a cose_hash_v structure of the original content type. This functionality is exposed via a factory pattern in [**IndirectSignatureFactory**](https://github.com/microsoft/CoseSignTool/tree/main/CoseIndirectSignature/IndirectSignatureFactory.cs) for use with Supply Chain Integrity Transparency and Trust [SCITT](https://scitt.io/).
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

> [!IMPORTANT]
> `SignatureMatches(...)` performs a **content-hash consistency check only** &mdash; it recomputes the hash of the supplied artifact and compares it to the hash embedded in the message `.Content`. It does **not** verify the COSE_Sign1 signature. The embedded hash is only trustworthy once the signature has been verified, so you **must** cryptographically verify the signature and establish trust in the signer **before** calling `SignatureMatches(...)`. A `true` result from an unverified message is meaningless, because the embedded hash would itself be attacker-controllable.
>
> For end-to-end validation (signature + trust + indirect content), prefer `CoseHandler.Validate(...)`, which verifies the signature first and only then compares the indirect content hash. Call `SignatureMatches(...)` directly only when you have already verified the signature and established trust through some other path (for example `VerifyEmbedded`/`VerifyDetached` together with a trust decision).
>
> A clearer alias, `ContentDigestMatches(...)`, is provided with the same `Stream`/`Byte[]` shapes and identical behavior &mdash; the name avoids overloading "Signature" (which otherwise conflicts with the cryptographic COSE_Sign1 signature). Prefer `ContentDigestMatches(...)` in new code.

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

// REQUIRED: cryptographically verify the COSE_Sign1 signature and establish trust in the
// signer BEFORE inspecting or comparing any value carried in the envelope. Replace the guard
// below with your chosen verification path (for example CoseHandler.Validate(...), or
// VerifyEmbedded/VerifyDetached with an appropriate trust decision). SignatureMatches(...) only
// checks that the artifact hash equals the embedded hash; it does not verify the signature.
if(!CallerVerifiedSignatureAndTrust(message))
{
   return false;
}

if(message.IsIndirectSignature())
{
   // Safe to compare now that the signature has been verified and the signer is trusted.
   return message.SignatureMatches(originalContentStream);
}
return false;
```