# [CoseSign1](https://github.com/microsoft/CoseSignTool/tree/main/CoseSign1) API
The CoseSign1 library is a .NET Standard 2.0 library (for maximum compatibility) for [CoseSign1Message](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.cose.cosesign1message) object creation leveraging the abstractions provided by [CoseSign1.Abstractions](https://github.com/microsoft/CoseSignTool/tree/main/CoseSign1.Abstractions) package. The library consists of two distinct usage models offered by two distinct classes. [**CoseSign1MessageFactory**](https://github.com/microsoft/CoseSignTool/blob/main/CoseSign1/CoseSign1MessageFactory.cs) is provided for dependency injection or direct usage patterns while [**CoseSign1MessageBuilder**](https://github.com/microsoft/CoseSignTool/blob/main/CoseSign1/CoseSign1MessageBuilder.cs) is provided to match a more builder style consumption model.

This library performs the basic creation (signing) of a [CoseSign1Message](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.cose.cosesign1message) object with no validation or constraints imposed. It should be used in conjunction with a concrete signing key provider implementation such as [**CoseSign1.Certificates**](./CoseSign1.Certificates.md) to be of most use. At its core it provides the following functionality above the .Net native object types:
* Allows for consistent extension of the Protected and Unprotected headers at time of signing operation
* Allows both RSA and ECdsa signing key abstractions to be provided
* Enforces content type is present with a valid, non-empty payload before creating the object.

## Dependencies
**CoseSign1** has the following package dependencies
* CoseSign1.Abstractions

#### [CoseSign1MessageFactory](https://github.com/microsoft/CoseSignTool/blob/main/CoseSign1/CoseSign1MessageFactory.cs)
An implementation of [**CoseSign1.Interfaces.ICoseSign1MessageFactory**](https://github.com/microsoft/CoseSignTool/blob/main/CoseSign1/Interfaces/ICoseSign1MessageFactory.cs) over either **Stream** or **Byte[]** payloads.  It provides a proper CoseSign1Message object in either full object, or byte[] form through the various methods in accordance with the interface contract.

#### [**CoseSign1MessageBuilder**](https://github.com/microsoft/CoseSignTool/blob/main/CoseSign1/CoseSign1MessageBuilder.cs)
A builder pattern implementation operating over [**ICoseSign1MessageFactory**](https://github.com/microsoft/CoseSignTool/blob/main/CoseSign1/Interfaces/ICoseSign1MessageFactory.cs) and [**ICoseSigningKeyProvider**](https://github.com/microsoft/CoseSignTool/blob/main/CoseSign1.Abstractions/Interfaces/ICoseSigningKeyProvider.cs) abstractions.  It defaults to [**CoseSign1MessageFactory**](https://github.com/microsoft/CoseSignTool/blob/main/CoseSign1/CoseSign1MessageFactory.cs) if none is specified and requires a provided [**ICoseSign1MessageFactory**](https://github.com/microsoft/CoseSignTool/blob/main/CoseSign1/Interfaces/ICoseSign1MessageFactory.cs) and [**ICoseSigningKeyProvider**](https://github.com/microsoft/CoseSignTool/blob/main/CoseSign1.Abstractions/Interfaces/ICoseSigningKeyProvider.cs) to provide the signing keys used for signing operations.

## [CoseSign1MessageFactory](https://github.com/microsoft/CoseSignTool/blob/main/CoseSign1/CoseSign1MessageFactory.cs) Usage
An example of creating a [CoseSign1Message](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.cose.cosesign1message) via the Factory pattern is provided below.
**Note** The example uses the [CoseSign1.Certificates.Local](https://github.com/microsoft/CoseSignTool/tree/main/CoseSign1.Certificates/Local) [SigningKeyProvider](https://github.com/microsoft/CoseSignTool/blob/main/CoseSign1.Certificates/Local/X509Certificate2CoseSigningKeyProvider.cs) for illustrative purposes only.
```
using CoseSign1;
using CoseSign1.Certificates.Local;

...

byte[] testPayload = Encoding.ASCII.GetBytes("testPayload!");
X509Certificate2CoseSigningKeyProvider coseSigningKeyProvider = new(...);
CoseSign1Message response = coseSign1MessageFactory.CreateCoseSign1Message(
            payload: testPayload,
            signingKeyProvider: coseSigningKeyProvider,
            embedPayload: true,
            contentType: ContentTypeConstants.Cose);
```

## [CoseSign1MessageBuilder](https://github.com/microsoft/CoseSignTool/blob/main/CoseSign1/CoseSign1MessageBuilder.cs) Usage
An example of creating a [CoseSign1Message](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.cose.cosesign1message) via the builder pattern is provided below.
**Note** The example uses the [CoseSign1.Certificates.Local](https://github.com/microsoft/CoseSignTool/tree/main/CoseSign1.Certificates/Local) [SigningKeyProvider](https://github.com/microsoft/CoseSignTool/blob/main/CoseSign1.Certificates/Local/X509Certificate2CoseSigningKeyProvider.cs) for illustrative purposes only.
```
using CoseSign1;
using CoseSign1.Certificates.Local;

...

byte[] testPayload = Encoding.ASCII.GetBytes("testPayload!");
X509Certificate2CoseSigningKeyProvider coseSigningKeyProvider = new(...);
CoseSign1MessageBuilder CoseSign1Builder = new(coseSigingKeyProvider);
CoseSign1Message response = CoseSign1Builder.SetPayloadBytes(testPayload)
                                            .SetContentType(ContentTypeConstants.Cose)
                                            .ExtendCoseHeader(mockedHeaderExtender.Object)
                                            .Build();
```
