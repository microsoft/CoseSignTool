# CoseSignTool
CoseSignTool is a platform-independent command line application to COSE sign files, validate COSE signatures, and optionally retrieve the content from COSE embed-signed files. 
It supports three built-in commands: **Sign**, **Validate**, and **Get**, and can be extended with custom commands through the **Plugin System**.

## Plugin System
CoseSignTool includes a powerful plugin architecture that allows developers to extend the tool with custom commands and integrations. Plugins are automatically discovered and loaded from the `plugins` subdirectory.

**Key Features:**
- **Custom Commands**: Add new functionality beyond the built-in commands
- **Third-party Integrations**: Connect with external services and APIs (e.g., Azure Code Transparency Service)
- **Secure Loading**: Plugins are only loaded from the authorized `plugins` directory
- **Easy Development**: Simple interfaces and base classes for rapid development
- **🚀 Automatic CI/CD Packaging**: Plugins following naming conventions are automatically included in releases

**🎯 Plugin Naming Convention for Auto-Packaging:**
- **Project files** must end with `.Plugin.csproj` for automatic CI/CD inclusion
- **Assembly names** must end with `.Plugin.dll` for runtime discovery
- **Example**: `YourCompany.CustomSigning.Plugin.csproj` → Automatically packaged!

**Using Plugins:**
```bash
# List all available commands (including plugins)
CoseSignTool --help

# Use a plugin command (example: Azure CTS)
export AZURE_CTS_TOKEN="your-access-token"
CoseSignTool cts_register --endpoint https://your-cts.azure.com --payload file.txt --signature file.txt.cose
```

**For Developers:**
- See [PluginNamingConventions.md](PluginNamingConventions.md) for **naming requirements and auto-packaging**
- See [Plugins.md](Plugins.md) for comprehensive plugin development documentation
- See [PluginQuickStart.md](PluginQuickStart.md) for a quick start guide
- See [PluginExamples.md](PluginExamples.md) for example plugin implementations
- See [AzureCTS.md](AzureCTS.md) for Azure Code Transparency Service plugin documentation

## Concepts to know before you start
* **Payload**: We use the term "Payload" to describe the content that is or will be signed. This might be a file or an object in memory.
* **Detached vs. Embedded**: By default, CoseSignTool produces a detached signature, which is separate from the file or stream containing the payload. Both the signature and the original payload must be present for validation. An embedded signature is where a copy of the payload is inserted into the signature structure as a byte array. An embedded signature may be validated without the orginal payload present, but is not readable in a text editor. The CoseSignTool "get" command retrieves the payload and writes it to file or console.

## Sign
The **Sign** command signs a file or stream.

You will need to specify:
* The payload content to sign. This may be a file specified with the **/Payload** option or you can pipe it in on the Standard Input channel when you call CoseSignTool. Piping in the content is generally considered more secure and performant option but large streams of > 2gb in length are not yet supported.
* A certificate to sign with. You can either use the **/Thumbprint** option to pass the SHA1 thumbprint of an installed certificate or use the **/PfxCertificate** option to point to a .pfx certificate file and a **/Password** to open the certificate file with if it is locked. The certificate must include a private key.
  * **PFX Certificate Chain Handling**: When using a PFX file that contains multiple certificates (such as a complete certificate chain), CoseSignTool will automatically use all certificates in the PFX for proper chain building. If you specify a **/Thumbprint** along with the PFX file, CoseSignTool will use the certificate matching that thumbprint for signing and treat the remaining certificates as additional roots for chain validation. If no thumbprint is specified, the first certificate with a private key will be used for signing.

You may also want to specify:
* Detached or embedded: By default, CoseSignTool creates a detached signature, which contains a hash of the original payoad. If you want it embedded, meaning that the signature file includes a copy of the payload, use the **/EmbedPayload option.** Note that embedded signatures are only supported for payload of less than 2gb.
* Where to write the signature to. You have three ways to go here:
    1. Write to the Standard Output channel (STDOUT) / console by using the **/PipeOutput** option.
    1. Specify an output file with **/SignatureFile**
    1. Let CoseSignTool decide. It will write to *payload-file*.cose for detached or *payload-file*.csm for embedded signatures. But if you don't specify a payload file at all, it will exit with an error.
* What certificate store to use. If you passed in a thumbprint instead of a .pfx certificate, CoseSignTool will assume that certificate is in the default store (My/CurrentUser on Windows) unless you tell it otherwise. Use the **/StoreName** and **/StoreLocation** options to specify a store.
>Pro tip: Certificate store operations run faster if you use a custom store containing only the certificates you will sign with. You can create a custom store by adding a certificate to a store with a unique Store Name and pre-defined Store Location. For example, in Powershell: 
~~~
Import-Certificate -FilePath 'c:\my\cert.pfx' -CertStoreLocation 'Cert:CurrentUser\MyNewStore'
~~~

### SCITT Compliance Options

**CoseSignTool automatically enables SCITT (Supply Chain Integrity, Transparency, and Trust) compliance** when signing with certificates. This includes adding CWT (CBOR Web Token) Claims to your signatures with DID:x509 identifiers.

#### SCITT Arguments:
* **/EnableScitt**, **/scitt** - Enable or disable SCITT compliance (default: **true**).
  ```bash
  CoseSignTool sign /p payload.txt /pfx cert.pfx /scitt false  # Disable SCITT
  ```

* **/CwtIssuer**, **/cwt-iss** - Set the issuer claim. If not specified, a **DID:x509 identifier is automatically generated** from your certificate chain.
  ```bash
  CoseSignTool sign /p payload.txt /pfx cert.pfx /cwt-iss "did:example:custom-issuer"
  ```

* **/CwtSubject**, **/cwt-sub** - Set the subject claim (default: **"unknown.intent"**). This should describe the purpose or intent of the signature.
  ```bash
  CoseSignTool sign /p payload.txt /pfx cert.pfx /cwt-sub "software.release.v1.2.3"
  ```

* **/CwtAudience**, **/cwt-aud** - Set the audience claim. Specifies the intended recipient or system.
  ```bash
  CoseSignTool sign /p payload.txt /pfx cert.pfx /cwt-aud "production.systems"
  ```

* **/CwtClaims**, **/cwt** - Add custom CWT claims using `label:value` format. Can be specified multiple times.
  ```bash
  # Standard timestamp claims (accepts ISO 8601 date/time strings or Unix timestamps)
  CoseSignTool sign /p payload.txt /pfx cert.pfx /cwt "exp:2025-12-31T23:59:59Z"
  CoseSignTool sign /p payload.txt /pfx cert.pfx /cwt "nbf:2024-01-01T00:00:00Z"
  CoseSignTool sign /p payload.txt /pfx cert.pfx /cwt "iat:2024-11-19T10:30:00-05:00"
  
  # Using Unix timestamps
  CoseSignTool sign /p payload.txt /pfx cert.pfx /cwt "exp:1735689600"
  
  # Custom claims (use integer labels 100+)
  CoseSignTool sign /p payload.txt /pfx cert.pfx /cwt "100:custom-value" /cwt "101:another-value"
  
  # Combining multiple claims
  CoseSignTool sign /p payload.txt /pfx cert.pfx \
    /cwt-sub "release.v2.0" \
    /cwt "exp:2025-12-31T23:59:59Z" \
    /cwt "200:build-metadata"
  ```

#### Standard CWT Claim Labels:
- **iss** (1): Issuer - automatically set to DID:x509 from certificate chain
- **sub** (2): Subject - defaults to "unknown.intent"
- **aud** (3): Audience
- **exp** (4): Expiration Time - Unix timestamp or ISO 8601 date/time
- **nbf** (5): Not Before - Unix timestamp or ISO 8601 date/time
- **iat** (6): Issued At - Unix timestamp or ISO 8601 date/time
- **cti** (7): CWT ID - unique identifier

For comprehensive SCITT documentation, examples, and programmatic API usage, see **[SCITTCompliance.md](./SCITTCompliance.md)**.

#### SCITT Examples:

**Basic SCITT-compliant signature (automatic DID:x509 issuer + default subject):**
```bash
CoseSignTool sign /p payload.txt /pfx mycert.pfx /sf signature.cose
```

**Custom subject and expiration:**
```bash
CoseSignTool sign /p payload.txt /pfx mycert.pfx /sf signature.cose \
  /cwt-sub "software.release.v1.0" \
  /cwt "exp:2025-12-31T23:59:59Z"
```

**Full SCITT signature with all standard claims:**
```bash
CoseSignTool sign /p payload.txt /pfx mycert.pfx /sf signature.cose \
  /cwt-sub "container.image.production" \
  /cwt-aud "production.kubernetes.cluster" \
  /cwt "exp:2025-06-30T23:59:59Z" \
  /cwt "nbf:2024-01-01T00:00:00Z" \
  /cwt "iat:2024-11-19T15:30:00Z"
```

**Custom issuer (override DID:x509 auto-generation):**
```bash
CoseSignTool sign /p payload.txt /pfx mycert.pfx /sf signature.cose \
  /cwt-iss "did:example:custom-issuer" \
  /cwt-sub "document.approval"
```

**Disable SCITT compliance:**
```bash
CoseSignTool sign /p payload.txt /pfx mycert.pfx /sf signature.cose /scitt false
```

### Headers:
*   There are two ways to supply headers: (1) command-line, and, (2) a JSON file. Both options support providing protected and un-protected headers with int32 and string values. The header label is always a string value.
>Note: When both file and command-line header options are specified, the command-line input is ignored.
>Note: SCITT CWT Claims are automatically added to protected headers when enabled. Custom headers are applied in addition to CWT Claims.

    * Command-line:
        * /IntProtectedHeaders, /iph - A collection of name-value pairs (separated by comma ',') with the value being an int32. Example: /IntProtectedHeaders created-at=12345678,customer-count=10
        * /StringProtectedHeaders, /sph - A collection of name-value pairs (separated by comma ',') with the value being a string. Example: /StringProtectedHeaders message-type="cose",customer-name="contoso"
        * /IntUnProtectedHeaders, /iuh - A collection of name-value pairs (separated by comma ',') with the value being an int32. Example: /IntUnProtectedHeaders created-at=12345678,customer-count=10
        * /StringUnProtectedHeaders, /suh - A collection of name-value pairs (separated by comma ',') with the value being a string. Example: /StringUnProtectedHeaders message-type="cose",customer-name="contoso"
    * File:
        * /IntHeaders, /ih - A JSON file containing the headers with the value being an int32.
        * /StringHeaders, /sh - A JSON file containing the headers with the value being a string.

The JSON schema is the same for both types of header files. Sample int32 and string headers file are shown below.

>Note: protected is optional. When ignored, it defaults to False.

~~~
[
    {
        "label":"created-at",
        "value": 12345678,
        "protected": true
    },
    {
        "label": "customer-count",
        "value": 10,
        "protected": false
    }
]
~~~

~~~
[
    {
        "label":"message-type",
        "value": "cose",
        "protected": false
    },
    {
        "label": "customer-name",
        "value": "contoso",
        "protected": true
    }
]
~~~

Run *CoseSignTool sign /?* for the complete command line usage.

### PFX Certificate Chain Examples

**Sign with a PFX containing a certificate chain (uses first certificate with private key):**
```bash
CoseSignTool sign /p payload.txt /pfx certificates.pfx /pw password123 /sf signature.cose
```

**Sign with a specific certificate from a PFX chain using thumbprint:**
```bash
CoseSignTool sign /p payload.txt /pfx certificates.pfx /pw password123 /th A1B2C3D4E5F6789... /sf signature.cose
```

**Sign with embedded payload using PFX certificate chain:**
```bash
CoseSignTool sign /p payload.txt /pfx certificates.pfx /pw password123 /ep /sf signature.csm
```

When using these commands with a PFX file containing multiple certificates, CoseSignTool will automatically embed the complete certificate chain in the COSE signature, ensuring proper validation without requiring additional root certificates to be specified during validation.

## Validate
The **Validate** command validates that a COSE signature is properly constructed, matches the signed payload, and roots to a valid certificate chain.

You will need to specify:
* What to validate. This may be a file specified with the **/SignatureFile** option or you can pipe it in on the Standard Input channel when you call CoseSignTool. Piping in the content is generally considered more secure and performant option but large streams of > 2gb in length may be truncated, depending on what operating system and command shell you use.
* (For detached signatures only) the **/Payload** that was signed. If validating an embedded signature (including indirect signatures), skip this part as the payload/hash is embedded in the signature.

You may also want to specify:
* Some root certificates. By default, CoseSignTool will try to chain the signing certificate to whatever certificates are installed on the machine. If you want to chain to certificates that are not installed, use the **/Roots** option.
    * User-specified roots will be treated as "trusted" for purposes of validation.
    * Root certificates for validation do not have to include a private key, so .cer files are acceptable.
    * To supply multiple root certificates, separate the file paths with commas.
* Certificate Details. You can use the */ShowCertificateDetails** option to print out the details of the signing certificate chain.
* Verbosity. You can use the */Verbose** option to get more detailed output on validation failures.

And in some cases:
* **/RevocationMode** -- By default, CoseSignTool checks the signing certificate against an online database to see if it has been revoked. You can skip this check by setting **/RevocationMode** to **none**. RevocationMode.Offline is not yet implemented.
* **/CommonName** -- Forces validation to require that the signing certificate match a specific Common Name value.
* **/AllowUntrusted** -- Prevents CoseSignTool from failing validation when the certificate chain has an untrusted root. This is intended for test purposes and should not generally be used for production.
* **/AllowOutdated** -- Prevents CoseSignTool from failing validation when the certificate chain has an expired certificate, unless the expired certificate has a lifetime EKU.

Run *CoseSignTool validate /?* for the complete command line usage.

## Get
The **Get** command retrieves the payload from a COSE embed-signed file and writes the text to cosole or to a file. It also runs the Validate command and prints out any errors on the Standard Error pipe.

You will need to specify:
* What to validate. This may be an embed-signed file specified with the **/SignatureFile** option or you can pipe it in on the Standard Input channel when you call CoseSignTool.

You may also want to specify:
* A file to write the payload to. Use the **/SaveTo** option to specify a file path; otherwise the payload will be printed to Standard Out.
* **/Roots**, **/Verbosity**, **/RevocationMode**, **/CommonName**, **/AllowUntrusted**, and **/AllowOutdated** exactly as with the Validate command.

Run *CoseSignTool get /?* for the complete command line usage.
