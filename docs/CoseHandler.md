# CoseHandler API
The CoseHandler library is a .NET 7 library (soon to be ported to .NET Standard 2.0 for compatibility) for COSE signing and validation. It consists mainly of a static **CoseHandler** class, a **ValidationResult** object to hold result data, and a **CoseValidationError** object to hold individual errors. 
The Sign, Validate, and GetPayload functions are all invoked as static methods from the CoseHandler object, and have a variety of overloads to support different combinations of input.

## CoseHandler.Sign 
The **Sign** method creates a COSE signature and returns it as a read-only byte array.

You must provide:
* Content to sign. This may be a byte array, a stream, or a *FileInfo* object.
* A certificate to sign with. This can be an *X509Certificate2* object or the SHA1 thumbprint of an installed certificate.
  * An *X509Certificate* object must include a private key to be used for signing.

You may also want to specify:
* Detached or embedded: By default, CoseHandler creates a detached signature, which contains a hash of the original payoad. Setting ***embedSign=true*** creates an embedded signature, meaning that the signature file includes a copy of the payload as a byte array. Note that embedded signatures are only supported for payload of less than 2gb.
* A *FileInfo* object to write the signature to. Or you can leave this value as *null* and run File.WriteAllBytes on the return value to accomplish the same thing.
* What certificate store to use. If you passed in a thumbprint instead of an *X509Certificate2* object, you can either specify a *StoreName* and *StoreLocation* or use the default values of *My/CurrentUser*.
>Pro tip: Certificate store operations run faster if you use a custom store that has only the certificates you will sign with. You can create a custom store by creating a new *X509Store* object with a custom *StoreName* and then adding a certificate to it.
* A *SigningKeyProvider* object. This is a wrapper class that you can use instead of passing in an *X509Certificate2* object directly. It allows you to specify a custom certificate chain builder and/or pass in a set of optional root certificates to be stores in the *UprotectedHeaders* area of the COSE signature structure. See [the Advanced Scenarios guide](Advanced.md) for details on why you might want to do this.


## CoseHandler.Validate
The **Validate** method validates that a COSE signature is properly constructed, matches the signed payload, and roots to a valid certificate chain. It returns a **ValidationResult** object that indicates success or failure and includes information about specific criteria that validation passed or failed on.

You will need to specify:
* The **signature** to validate. You can pass in your COSE signature structure as either a byte array, a stream, or a *FileInfo* object. 
* The **payload** that was signed (for detached signatures only.) Again, you can pass it in as a byte array, a stream, or a *FileInfo*. 
Which types you should use for signature and payload depends on your scenario.
  * Arrays and most stream types are limited to 2gb or less, so if you anticipate large payloads, either use *FileInfo*, *FileStream*, or a custom stream type that doesn't have a backing array.
  * Payloads may be more than 2gb but signatures will not, because embedded signatures use byte arrays to store the payload.
  * If you choose *FileInfo* for one you have to use it for both. Or, read the file into a stream with *File.ReadAllBytes*.
  * Leave the **payload** field blank for embedded signatures.

You may also want to specify:
* Some **root** certificates. By default, CoseHandler will try to chain the signing certificate to whatever certificates are installed on the machine. You can pass in additional certificates to try to chain to via the **roots** parameter.
  * User-specified roots will be treated as "trusted" for validation purposes.
  * Root certificates for validation do not have to include a private key.
  * Certificate chain validation always checks installed certificates first, so even if you pass in a copy of the same certificate, it will still use the installed version.

And in some cases:
* A **revocationMode** -- By default, CoseHandler checks the signing certificate against an online database to see if it has been revoked. You can skip this check by using **RevocationMode.None**, which is often a good choice for testing. RevocationMode.Offline is not yet implemented.
* A **requiredCommonName** -- Forces validation to require that the signing certificate match a specific certificate *Common Name* value.
* A **validator** -- You can optionally pass in a *CoseSign1MessageValidator* object instead of **roots**, **revocationMode** and **requiredCommonName.** CoseHandler uses an *X509ChainTrustValidator* internally, but if you create a custom CoseSign1MessageValidator type you can specify different sets of criteria to validate on. See [the Advanced Scenarios guide](Advanced.md) for details.

## CoseHandler.Getpayload
The **GetPayload** method retrieves the payload from an embedded COSE signature structure, and if possible, returns it as a string. It also validates the signature structure and provides the validation result as an *out* parameter. 

You will need to specify:
* The embedded **signature** to read from. You can pass in your COSE signature structure as either a byte array or a stream. 

You may also want to specify:
* Additional **roots**, **revocationMode**, and **requiredCommonName** values, or a **validator**, as with the Validate method.

## CoseHandler.LookupCertificate
This is a convenience method that checks the local certificate store for a certificate matching the specified thumbprint.

Required arguments:
* **thumbprint**: The SHA1 thumbprint of the certificate to find.

Optional arguments:
* **storeName** and **storeLocation**: The store name and store location to check in. Default store is My/CurrentUser.

## Validation Results
When you validate a COSE signature with *CoseHandler.Validate* it returns a **ValidationResult** object. Likewise, *CoseHandler.GetPayload* gives you a **ValidationResult** as an *out* parameter.

A **ValidationResult** contains:
* **Success** -- a boolean value indicating success or failure.
* **Errors** -- a list of **CoseValidationError** objects describing any errors you may have hit. These are top level errors that cover all of the basic validation criteria. A **CoseValidationError** object has these properties:
  * **ErrorCode** -- a **ValidationFailureCode** enum value.
  * **Message** -- a description of the error.
* **InnerResults** -- a list of **CoseSignValidationResult** objects passed back from the internal validator. These will mostly pertain to chain trust validation unless you use a custom validator. A **CoseSign1ValidationResult** has these properties:
  * **Validator** -- the *type* of validator that returned the result.
  * **PassedValidation** -- a boolean indicating whether the signature passed against this particular validator.
  * **ResultMessage** -- the error or warning message if any.
  * **Includes** -- an optional list of objects such as exceptions and *ChainStatus* objects passed back from the validator.

A **ValidationResult** has these methods:
* **ToString** -- returns a nicely formatted summary of the result.
* **AddError** -- adds a **CoseValidationError** to the **Errors** list. You would mostly use this in a custom validator.

