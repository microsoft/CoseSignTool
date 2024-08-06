## Advanced usage and the CoseSign1 libraries

#### Indirect Signatures
COSE signing normally uses either a "detached" signature, where the signature is in a separate file from the payload, or an "embedded" signature, where an encrypted copy of the payload is inserted into the signature file. This can be cumbersome for large payloads, especially when they must be sent to a remote server for signing or validation.
Indirect signing is a new feature that allows you to create and validate a signature against a hash of the payload instead of the payload itself. This feature is not yet integrated into the CoseHandler API or CoseSignTool.exe, but is available through the [CoseIndirectSignature](.\CoseIndirectSignature.md) library.

#### Timestamping
The [COSE specification](https://www.iana.org/assignments/cose/cose.xhtml) is still evolving. Originally, there were plans to support an [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161) timestamp solution, but the [requisite headers were never defined](https://www.ietf.org/archive/id/draft-ietf-cose-tsa-tst-header-parameter-00.html) by the standards body.
The current default behavior of COSE validation is to fail if any of the certificates in the certificate chain have expired. However, there are user scenarios where a signature needs to be considered valid even after one or more certificates have expired. Staring in version 1.2.4-pre2, you have the option to allow signatures to pass with expired certificates in the chain by passing "AllowOutdated = true" to the ChainTrustValidator constructor.
This will allow signatures to pass validation with expired certificates, so long as none of the expired certificates have a lifetime EKU.
In the near future, we plan to implement timestamping via [SCITT](https://scitt.io/), and will then deprecate the use of AllowOutdated.