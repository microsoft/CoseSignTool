# Troubleshooting and Tips
The best way to 'shoot' trouble is to avoid it in the first place. The error messages from CoseSignTool and CoseHandler should give you all the guidance you need for most issues, in combination with the practices recommended on this page.

## Certificate handling
* Make sure the certificate you sign with has a private key, and that said key uses either the RSA or the ECDSA algorithm.
* Make sure your certificates have not expired.
* When signing with installed certificates you will get quicker lookups if you load the certificate from a custom store instead of from My/CurrentUser.
* When signing with a loose certificate file, you should delete the file as soon as you are done signing with it to protect your private keys.
* **PFX Certificate Chain Files**: When using a PFX file that contains multiple certificates (such as a complete certificate chain with root, intermediate, and leaf certificates), CoseSignTool will automatically extract and use all certificates for proper chain building. This ensures that the complete certificate chain is embedded in the COSE signature for proper validation.
  * If you need to sign with a specific certificate from a multi-certificate PFX file, use the **/Thumbprint** option to specify which certificate to use for signing.
  * The remaining certificates in the PFX will be used as additional roots for chain validation, ensuring proper trust chain establishment.

## Detached vs embedded signatures
* Detached signatures are more efficient to produce than embeddeded signatures, have smaller file sizes, and are the only way to sign payloads larger than 2gb. In general, we recommend detached signing for most scenarios.
* The advantage of embedded signatures is that you can share them without sending the original payload, so long as the recipient has CoseSignTool or other means available to extract the content.

## Payload and signature handling
* Use a standard naming convention for signature files, such as payload_filename*.cose* for detached and payload_filename*.csm* for embedded signatures. This will help ensure that you always validate your signatures against the correct payload.
* Do not supply payload when validating an embed-signed file. This is why a naming convention that differentiates between the two signature types is your friend.
* When signing it is generally more secure to keep everything in memory and not write anything to disk until the signing operation is complete. This prevents the payload from getting tampered with before it is signed. Therefore, you should use streams or byte arrays where possible. However, when working with large payloads you may run into difficulties:
    * Arrays and most stream types cannot hold more than 2gb of data. This may include the stream used used to pipe data to applications in your operating system or command shell.
    * Your system might not have enough memory to handle very large payloads efficiently.
>If you work with payloads of more than 2gb we recommend you first experiment to make sure that the signature produced when loading from an in-memory stream matches the signature produced when loading from a file. If not, you are probably better off loading from a file, at least for now.

## Log an issue if...
* You get an error involving invalid COSE headers. If you created the signature with CoseHandler or CoseSignTool and get the error, that means you found a bug. If the signature was created by a third party tool, that means you found a compatibility issue. If you were mucking about with the CoseSign1 APIs and created an invalid header, that might be a bug or it might be user error.
* You see an uninformative Exception. Any exceptions coming out of CoseHandler should make sense in context of what you did. If they don't, that probably means you got an Exception that we didn't plan for (unless it's a FileNotFound -- those are informative enough by default.) Likewise, errors from CoseSignTool should have informative error messages, so if you see a stack trace that's not prefaced by a clear error message, let us know.

## When logging issues
Please include:
* The exact repro steps for how you hit the error.
* The CoseSignTool version number.
* The exact syntax you used in your commands
* The full error text you got back, including stack trace if any.
* The payload and signature files, or if you have a large or proprietary payload, see if you can reproduce the issue with a small, generic payload and include that instead.

Do not include non-test certificates unless they are necessary to reproduce the error. If they are:
* If the certificates are publicly available, include the Common Names and Thumbprints, and a link to where you got them from if not from Microsoft.
* If the certificates are proprietary, try to reproduce the issue with a similar set of test certificates and include those.
* If you cannot reproduce the error with non-proprietary certificates, tell us and we will either try to diagnose the problem without the certificates or arrange a secure transfer.
* **For PFX certificate chain issues**: Include information about how many certificates are in your PFX file, whether you're using a thumbprint to select a specific certificate, and the Common Names of the certificates in the chain (root, intermediate, leaf).
