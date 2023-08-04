# CoseParser library
The CoseParser library provides a static CoseParser object with a broad selection of methods to sign and validate, and to retrieve content from COSE-signed files. It also provides some supporting objects and extension methods for working with COSE signatures.
NOTE: This document refers to a previous version of the CoseParser API, which has been replaced with CoseHandler.
## CoseParser class
Provides static methods to sign, validate, and retrieve content from COSE-signed files.
### Sign
The **Sign** method creates a COSE signature for a file or string. This may be a *detached* signature, where the signature file is separate from the original file to be signed, or an *embedded* signature, where an encoded copy of the signed content is included in the signature file. Note that embed-signed files are not readable by default in most text editors, so the content will have to be extracted and decoded, such as by the GetPayload command, before it can be read.

The *detached* signature includes a hash of the original payload for validation against the source file, and are saved by default with a .cose file extension. Embed signed files are validated internally and use the .csm extension by default.
#### *Arguments*
The **Sign** command has a variety of overloads to support different combinations of the following arguments.

- *payloadFile*: (string) Required. The path to the file to sign.
  -OR-
  *payloadBytes:* (ReadOnlyMemory<byte>) The content of the file to sign.
- *certificate:* (X509Certificate2) Required. The leaf node certificate to sign with.
  -OR-
  *thumbprint:* (string) The thumbprint of a file in the Windows certificate store to sign with. Only valid on Windows machines.
  -AND-
  - *storeName:* (string) Optional. Sets the name of the certificate store to look in when checking for a cert that matches *thumbprint*. Default value is “My”. This field takes a string instead of a StoreName enum value to allow for user-defined stores. If it is set to a store name that does not already exist on the machine, one will be created. 
  - *storeLocation:* (StoreLocation) Optional. Sets the location of the certificate store to look in when checking for a cert that matches *thumbprint*. Default value is StoreName.CurrentUser. 
- *signatureFile:* (string) Optional. The path to write the signature file to. Default value is *[payloadFile]*.cose for detached or *[payloadFile]*.csm for embedded.
- *embedPayload:* (bool) Optional. Set this flag to embed-sign the file. Default behavior is detached signing.
- *additionalCerts:* (IEnumerable<X509Certificate2>) Optional. Additional certificates to include in the signature block.
### TrySign
The **TrySign** method simply wraps the **Sign** method in a try/catch block and outputs any exceptions it catches.
#### *Arguments*
- [All of the Sign command arguments]
- *ex:* (Exception) A variable to hold the exception caught by TrySign, if any.
#### *Return value*
*True* on success, *false* on failure.
### Validate
The **Validate** method validates a COSE signature on a file or string. This may be a *detached* signature, where the signature file is separate from the original file to be signed, or an *embedded* signature, where an encoded copy of the signed content is included in the signature file. Alternatively, you can use the **GetPayload** method on embed-signed files to return the payload content of the original file after validation.

The **Validate** method validates that

1. The signature file meets COSE format requirements
1. The certificate the file was signed with forms a valid certificate chain with at least some of the certificates provided to validate against
1. The body of the signature file contains either
   1. The hash of the supplied payload file (if the file was detach-signed)
   1. Valid encoded JSON content (if the file was embed-signed.)
1. (Optional) The signing certificate has not been revoked
1. (Optional) The signing certificate matches a user-specified Certificate Common Name

This is a void method, and failure is represented by thrown exceptions.
#### *Arguments*
The **Validate** command has a variety of overloads to support different combinations of the following arguments.

- *signatureFile:* (string) Required. The path to the COSE signature file or COSE-embed-signed file.
- *payloadFile*: (string) The path to the source file that contains the original payload. Required for detached signatures. Do not use for embed-signed files.
- *roots:* (List<X509Certificate2>) Required. A collection of certificates for the signing certificate to try to chain to one or more of. Only the public key certificate (.cer) is required for roots, though private key certificates (.pfx) can also be used. In the case of a self-signed certificate, that certificate must be passed in as a root.
  -OR-
  *thumbprints:* (List<string>) The thumbprints of files in the Windows certificate store to try to use as *roots*. Only valid on Windows machines.
  -AND if using thumbprints-
  - *storeName:* (string) Optional. Sets the name of the certificate store to look in when checking for a cert that matches *thumbprint*. Default value is “My”. This field takes a string instead of a StoreName enum value to allow for user-defined stores. If it is set to a store name that does not already exist on the machine, one will be created. 
  - *storeLocation:* (StoreLocation) Optional. Sets the location of the certificate store to look in when checking for a cert that matches *thumbprint*. Default value is StoreName.CurrentUser. 
- *revocationMode:* (revocationMode) Optional. Whether to check for certificate revocation online, offline, or not at all. Default is online.
- *requiredCommonName:* (string) Optional. Specifies a Certificate Common Name that the signing certificate must match. This match is case-sensitive.
### TryValidate
The **TryValidate** method simply wraps the **Validate** method in a try/catch block and outputs any exceptions it catches.
#### *Arguments*
- [All of the Validate command arguments]
- *ex:* (Exception) A variable to hold the exception caught by TryValidate, if any.
#### *Return value*
*True* on success, *false* on failure.

GetPayload

The **GetPayload** method performs the same validation steps as **Validate** and then returns a copy of the original file content on success.
#### *Arguments*
The **GetPayload** command has a variety of overloads to support different combinations of the following arguments.

- *signatureFile:* (string) Required. The path to the COSE signature file or COSE-embed-signed file.
- *payloadFile*: (string) The path to the source file that contains the original payload. Required for detached signatures. Do not use for embed-signed files.
- *roots:* (List<X509Certificate2>) Required. A collection of certificates for the signing certificate to try to chain to one or more of. Only the public key certificate (.cer) is required for roots, though private key certificates (.pfx) can also be used. In the case of a self-signed certificate, that certificate must be passed in as a root.
  -OR-
  *thumbprints:* (List<string>) The thumbprints of files in the Windows certificate store to try to use as *roots*. Only valid on Windows machines.
  -AND if using thumbprints-
  - *storeName:* (string) Optional. Sets the name of the certificate store to look in when checking for a cert that matches *thumbprint*. Default value is “My”. This field takes a string instead of a StoreName enum value to allow for user-defined stores. If it is set to a store name that does not already exist on the machine, one will be created. 
  - *storeLocation:* (StoreLocation) Optional. Sets the location of the certificate store to look in when checking for a cert that matches *thumbprint*. Default value is StoreName.CurrentUser. 
- *revocationMode:* (revocationMode) Optional. Whether to check for certificate revocation online, offline, or not at all. Default is online.
- *requiredCommonName:* (string) Optional. Specifies a Certificate Common Name that the signing certificate must match. This match is case-sensitive.
#### *Return value*
The unencoded content of the original source file as a byte array.
### TryValidate
The **TryGetPayload** method wraps the **GetPayload** method in a try/catch block and outputs either the original file content or any exception it catches.
#### *Arguments*
- [All of the GetPayload command arguments]
- *payload:* The original file content as a byte array, if validation successful.
- *ex:* (Exception) A variable to hold the exception caught by TryGetPayload, if any.
#### *Return value*
*True* on success, *false* on failure.
## CertificateStoreHelper class
Provides static methods for retrieving certificates from the Windows Certificate Store. Windows only.
### LookupCertificate
Checks the local Windows certificate store for a certificate matching the specified thumbprint.
#### *Arguments*
- *thumbprint*: (string) The SHA1 thumbprint of the certificate to find.
- *storeName:* (string) Optional. Sets the name of the certificate store to look in when checking for a cert that matches *thumbprint*. Default value is “My”. This field takes a string instead of a StoreName enum value to allow for user-defined stores. If it is set to a store name that does not already exist on the machine, one will be created. 
- *storeLocation:* (StoreLocation) Optional. Sets the location of the certificate store to look in when checking for a cert that matches *thumbprint*. Default value is StoreName.CurrentUser. 
#### *Return value*
The matching certificate if found.
### LookupCertificates
Checks the local Windows certificate store for certificates matching the specified thumbprints.
#### *Arguments*
- *thumbprints*: (List<string>) The SHA1 thumbprints of the certificates to find.
- *storeName:* (string) Optional. Sets the name of the certificate store to look in when checking for a cert that matches *thumbprint*. Default value is “My”. This field takes a string instead of a StoreName enum value to allow for user-defined stores. If it is set to a store name that does not already exist on the machine, one will be created. 
- *storeLocation:* (StoreLocation) Optional. Sets the location of the certificate store to look in when checking for a cert that matches *thumbprint*. Default value is StoreName.CurrentUser. 
#### *Return value*
The matching certificates if found.
## CoseX509Thumprint class
Represents a COSE X509 thumbprint, which corresponds to the x5t header in a COSE signature structure. This is different from an X509 certificate thumbprint, which is the SHA1 hash of the certificate. This class is for working with the internal details of the COSE signature structure and not suitable for lay users.
### Constructor
Creates a CoseX509Thumbprint object.
#### *Arguments*
- *cert:* (X509Certificate2) The certificate the COSE signature file was signed with.
- *hashAlgorithm:* (HashAlgorithmName) Optional. The hash algorithm to use. Default is SHA256.
### Thumbprint property
(ReadOnlyMemory<byte>) The thumbprint value from the x5t header.
### HashId property
(int) The hash ID used in the CBOR representation of the x5t header.
### Match method
Checks if a certificate matches this thumbprint.
#### *Arguments*
- *certificate*: (X509Certificate2) The certificate to match.
#### *Return value*
*True* if the certificate matches the thumbprint; *false* otherwise.
### Serialize method
Encodes and serializes the current thumbprint and loads it into a CborWriter.
#### *Arguments*
- *writer*: (CborWriter) A CborWriter object to load the thumbprint data into.
#### *Return value*
The encoded data as a byte array.
### Deserialize method
Deserializes an encoded x5t header into a new CoseX509Thumbprint object.
#### *Arguments*
- *reader*: (CborReader) A CborReader object containing a COSE x5t header.
#### *Return value*
A new CoseX509Thumbprint object containing the x5t header data if successful; null otherwise.
## Exceptions
The CoseParser library adds three new exception types. All three inherit directly from System.Exception and are purely semantic, changing only the default error message when thrown with no arguments.

- CoseSigningException: Thrown for failures in COSE sign operations.
- CoseValidationException: Thrown for validation failures.
- CoseX509FormatException: Thrown when the COSE header cannot be read or constructed.
## Extension Methods
CoseParser adds the following extension methods to existing classes.
### CoseSign1Message.VerifyWithX509
Validates the structure, content, and certificate chain of the current CoseSign1Message object.
#### *Arguments*
- *content*: (ReadOnlySpan<byte>) The content of an external payload file if any.
- *policy:* () An optional X509 chain policy to use when getting the signing certificate.
- *requiredCommonName*: (string) Sets a specific certificate Common Name that the signing certificate must match.
#### *Return value*
*True* if all verification checks succeed; *false* otherwise.
### CoseSign1Message.TryGetSigningCertificate
Tries to get the leaf node certificate of the current CoseSign1Message object, along with any extra certificates it may also be carrying.
#### *Arguments*
- *signingCert*: (out X509Certificate2) The leaf node signing certificate if found.
- *extraCerts:* (out X509Certificate2Collection) Any additional certificates that are part of the certificate chain if found.
- *policy:* (X509ChainPolicy) An optional X509 chain policy to enforce.
#### *Return value*
*True* if there is a signing certificate and it is part of a valid certificate chain, even if it is a chain of 1; *false* otherwise.
### X509Certificate2.GetChain
Builds the certificate chain for the current certificate as a leaf node, based on its known trust relationships.
#### *Return value*
An X509Chain object containing the complete certificate chain.
### X509Certificate2.ValidateCommonName
Validates that the Common Name provided matches the common name of the certificate. The match is case-sensitive.
#### *Arguments*
- *commonName*: (string) Optional. The Certificate Common Name to try to match. If not set, validation passes automatically.
### CborReader.TryReadCertificateSet
Tries to load a collection of certificates into the current CborReader.
#### *Arguments*
- *certificates:* (ref X509Certificate2Collection) The certificates to read.
- *ex:* (out CoseX509FormatException) the exception thrown if the read operation fails.
#### *Return value*
*True* on success; *false* otherwise.
### CborReader.ReadCertificateSet
Loads a collection of certificates into the current CborReader, or throws a CoseX509FormatException on failure.
#### *Arguments*
- *certificates:* (ref X509Certificate2Collection) The certificates to read.
