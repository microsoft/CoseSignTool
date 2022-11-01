# CoseSignTool
CoseSignTool is a platform-independent command line application to COSE sign file, validate COSE signatures, and optionally retrieve the unencoded content from a COSE embed-signed file. 

COSE signatures may be *detached* or *embedded*. A detached signature is separate from the source file that was signed, but it contains the hash of the source file so they can be matched in validation. 

An embedded signature file is the same as a detached signature file, except that instead of the hash, it contains an encoded copy of the file’s content. An embed-signed file can therefore be validated without the original file present, but it requires a COSE-aware application, such as CoseSignTool, to read.
## Usage
`    `CoseSignTool.exe [sign | validate] [options]
### Sign options
`    `**Payload / p**: Path to the file whose content will be signed.

`    `**SignedFile / sf**: Optional. File to write the Cose signature to. Default value is

`             `Detached: [payload file].cose, or

`             `Embedded: [payload file].csm

`    `**EmbedPayload / ep**: Optional. If true, encrypts and embeds the payload in the in Cose signature file.

`        `Default behavior is 'detached signing', where the signature is in a separate file from the payload.

`        `Note that embed-signed files are not readable by standard text editors.

`    `**PfxCertificate / pfx**: A path to a private key certificate file (.pfx) to sign with.

`    `--OR--

`    `**Thumbprint / th**: The SHA1 thumbprint of a certificate in the Windows local certificate store to sign the file with.

`    `**StoreName / sn**: Optional. The name of the Windows local certificate store to look for certificates in.

`        `Default value is 'My'.

`    `**StoreLocation / sl**: Optional. The location of the Windows local certificate store to look for certificates in.

`        `Default value is 'CurrentUser'.
### Validate options
`    `**SignedFile / sf**: Required. The file containing the COSE signature.

`        `If embedded, this file also includes the encoded payload.

`    `**PayloadFile / p**: Path to the external file, if any, containing the original payload to validate against.

`        `Required for detached signatures. Do not use for embedded.

`    `**X509RootFiles / xr**: A comma-separated list of public key certificate files (.cer or .p7b) to attempt to chain

`        `the COSE signature to.

`    `--OR--

`    `**Thumbprints / th**: A comma-separated list of SHA1 thumbprints of one or more certificates in the Windows local

`        `certificate store to attempt to chain the certificate on the COSE signature to, and

`    `**StoreName / sn**: Optional. The name of the Windows local certificate store to look for certificates in.

`        `Default value is 'My'.

`    `**StoreLocation / sl**: Optional. The location of the Windows local certificate store to look for certificates in.

`        `Default value is 'CurrentUser'.

`    `**RevocationMode / rm**: The method to check for certificate revocation.

`        `Valid values: Online, Offline, NoCheck

`        `Default value: Online

`    `**CommonName / cn**: Specifies a certificate Common Name that the signing certificate must match to pass validation.

`    `**SavePayload / sp**: Writes the payload of an embed-signed file to the specified file path.

`        `For embedded signatures only.
