# CoseSignTool Indirect Signature Plugin

The **Indirect Signature Plugin** provides the ability to create and verify indirect COSE Sign1 signatures that are compatible with Supply Chain Integrity Transparency and Trust ([SCITT](https://scitt.io/)) requirements.

## Installation

The Indirect Signature plugin is automatically included with CoseSignTool releases using the enhanced subdirectory architecture. The plugin is deployed to `plugins/CoseSignTool.IndirectSignature.Plugin/` as a self-contained unit with minimal dependencies, demonstrating the clean separation possible with the enhanced plugin architecture.

## Overview

Indirect signatures are a specialized form of COSE signatures where the payload is not embedded directly in the signature. Instead, a cryptographic hash of the payload is embedded, and the content type is modified to indicate this structure. This approach is particularly useful for:

- **Large payloads**: Avoiding the overhead of embedding large files in signatures
- **SCITT compliance**: Meeting requirements for transparency and trust in supply chains
- **Efficient verification**: Allowing verification without transferring the entire payload

## Commands

### `indirect-sign`

Creates an indirect COSE Sign1 signature for a payload file.

#### Syntax

```bash
CoseSignTool indirect-sign --payload <payload-file> --signature <signature-file> [options]
```

#### Required Arguments

- `--payload`: The file path to the payload to sign
- `--signature`: The file path where the COSE Sign1 signature file will be written

#### Certificate Options (one required)

- `--pfx`: Path to a private key certificate file (.pfx) to sign with
- `--password`: The password for the .pfx file if it has one
- `--thumbprint`: The SHA1 thumbprint of a certificate in the local certificate store
- `--store-name`: The name of the local certificate store (default: My)
- `--store-location`: The location of the local certificate store (default: CurrentUser)

#### SCITT Compliance Options

The indirect-sign command supports **SCITT (Supply Chain Integrity, Transparency, and Trust)** compliance through CWT (CBOR Web Token) Claims. SCITT is enabled by default when signing with certificates.

- `--enable-scitt`, `--scitt`: Enable or disable SCITT compliance (default: true)
- `--cwt-issuer`, `--cwt-iss`: Set the issuer claim (if not specified, DID:x509 is automatically generated from certificate)
- `--cwt-subject`, `--cwt-sub`: Set the subject claim (default: "unknown.intent")
- `--cwt-audience`, `--cwt-aud`: Set the audience claim
- `--cwt-claims`, `--cwt`: Add custom CWT claims in `label:value` format (can be specified multiple times)

**Standard CWT Claim Labels:**
- `iss` (1): Issuer - automatically set to DID:x509 from certificate chain
- `sub` (2): Subject - defaults to "unknown.intent"
- `aud` (3): Audience
- `exp` (4): Expiration Time - accepts ISO 8601 date/time strings or Unix timestamps
- `nbf` (5): Not Before - accepts ISO 8601 date/time strings or Unix timestamps
- `iat` (6): Issued At - accepts ISO 8601 date/time strings or Unix timestamps
- `cti` (7): CWT ID - unique identifier

For comprehensive SCITT documentation, see [SCITTCompliance.md](./SCITTCompliance.md).

#### Optional Arguments

- `--output`: File path where signing result will be written (JSON format)
- `--timeout`: Timeout in seconds for the operation (default: 30)
- `--content-type`: The content type of the payload (default: application/octet-stream)
- `--hash-algorithm`: The hash algorithm to use (SHA256, SHA384, SHA512, default: SHA256)
- `--signature-version`: The indirect signature version (CoseHashEnvelope, default: CoseHashEnvelope)

**Universal Logging Options** (available for all plugin commands):
- `--verbose`, `-v`: Enable verbose logging output (detailed diagnostic information)
- `--quiet`, `-q`: Suppress all non-error output

#### Examples

```bash
# Create indirect signature using PFX certificate (SCITT enabled by default)
CoseSignTool indirect-sign --payload myfile.txt --signature myfile.cose --pfx mycert.pfx

# Create indirect signature using certificate store
CoseSignTool indirect-sign --payload myfile.txt --signature myfile.cose --thumbprint ABC123...

# Create indirect signature with custom content type and hash algorithm
CoseSignTool indirect-sign --payload myfile.json --signature myfile.cose --pfx mycert.pfx --content-type application/json --hash-algorithm SHA384

# Create indirect signature with JSON output
CoseSignTool indirect-sign --payload myfile.txt --signature myfile.cose --pfx mycert.pfx --output result.json

# SCITT-compliant indirect signature with custom subject
CoseSignTool indirect-sign --payload myfile.txt --signature myfile.cose --pfx mycert.pfx --cwt-subject "software.release.v1.0"

# SCITT-compliant indirect signature with expiration
CoseSignTool indirect-sign --payload myfile.txt --signature myfile.cose --pfx mycert.pfx \
  --cwt-subject "container.image.prod" \
  --cwt-claims "exp:2025-12-31T23:59:59Z"

# Full SCITT indirect signature with custom claims
CoseSignTool indirect-sign --payload myfile.txt --signature myfile.cose --pfx mycert.pfx \
  --cwt-subject "document.approval" \
  --cwt-audience "production-systems" \
  --cwt-claims "exp:2025-06-30T23:59:59Z" \
  --cwt-claims "100:build-metadata"

# Disable SCITT compliance
CoseSignTool indirect-sign --payload myfile.txt --signature myfile.cose --pfx mycert.pfx --enable-scitt false
```

### `indirect-verify`

Verifies an indirect COSE Sign1 signature against a payload file.

#### Syntax

```bash
CoseSignTool indirect-verify --payload <payload-file> --signature <signature-file> [options]
```

#### Required Arguments

- `--payload`: The file path to the payload to verify
- `--signature`: The file path to the COSE Sign1 signature file

#### Validation Options

- `--roots`: Path to a file containing root certificates for validation
- `--allow-untrusted`: Allow signatures from untrusted certificate chains
- `--allow-outdated`: Allow signatures from outdated certificates
- `--common-name`: Expected common name in the signing certificate

#### Optional Arguments

- `--output`: File path where verification result will be written (JSON format)
- `--timeout`: Timeout in seconds for the operation (default: 30)

**Universal Logging Options** (available for all plugin commands):
- `--verbose`, `-v`: Enable verbose logging output (detailed diagnostic information)
- `--quiet`, `-q`: Suppress all non-error output

#### Examples

```bash
# Verify indirect signature
CoseSignTool indirect-verify --payload myfile.txt --signature myfile.cose

# Verify with custom root certificates
CoseSignTool indirect-verify --payload myfile.txt --signature myfile.cose --roots rootcerts.pem

# Verify allowing untrusted chains
CoseSignTool indirect-verify --payload myfile.txt --signature myfile.cose --allow-untrusted

# Verify with expected common name
CoseSignTool indirect-verify --payload myfile.txt --signature myfile.cose --common-name "My Company"

# Verify with verbose logging
CoseSignTool indirect-verify --payload myfile.txt --signature myfile.cose --verbose

# Verify with JSON output
CoseSignTool indirect-verify --payload myfile.txt --signature myfile.cose --output result.json
```

## Logging

The Indirect Signature plugin provides three logging levels to help diagnose issues:

### Normal Mode (Default)
Shows operation status and results:
```bash
CoseSignTool indirect-sign --payload file.txt --signature file.cose --pfx cert.pfx
# Output:
# Creating indirect COSE Sign1 message...
# Indirect signature created successfully (1234 bytes)
```

### Verbose Mode
Shows detailed diagnostic information including:
- File paths and sizes
- Certificate details (subject, thumbprint)
- Hash algorithm and signature version
- Each step of the signing/verification process
- Stack traces for exceptions

```bash
CoseSignTool indirect-sign --payload file.txt --signature file.cose --pfx cert.pfx --verbose
# Output includes:
# [VERBOSE] Starting indirect sign operation
# [VERBOSE] Reading payload from: file.txt
# [VERBOSE] Payload size: 1024 bytes
# [VERBOSE] Using certificate: CN=My Company
# [VERBOSE] Certificate thumbprint: ABC123...
# [VERBOSE] Creating indirect signature...
# [VERBOSE] Encoded signature size: 1234 bytes
# Creating indirect COSE Sign1 message...
# Indirect signature created successfully (1234 bytes)
```

**When to use verbose mode:**
- Diagnosing signing or verification failures
- Understanding certificate selection
- Troubleshooting payload or signature issues
- Reporting bugs with detailed context

### Quiet Mode
Suppresses all output except errors:
```bash
CoseSignTool indirect-sign --payload file.txt --signature file.cose --pfx cert.pfx --quiet
# Only errors are shown, ideal for scripting
```

**When to use quiet mode:**
- CI/CD pipelines where only failures matter
- Automated scripts that check exit codes
- Batch processing scenarios

## Indirect Signature Format

The plugin supports the **CoseHashEnvelope** format (recommended for new applications), which:

1. Computes a cryptographic hash of the payload using the specified hash algorithm
2. Embeds the hash value in the COSE message content field
3. Modifies the content type to include a "+cose-hash-envelope" suffix
4. Creates a detached signature that can be verified against the original payload

### Content Type Modification

When creating an indirect signature, the content type is automatically modified:
- Original: `application/json`
- Modified: `application/json+cose-hash-envelope`

This modification allows tools to identify indirect signatures and handle them appropriately.

## Exit Codes

The plugin extends the standard CoseSignTool exit codes with additional codes specific to indirect signature operations:

| Code | Name | Description |
|------|------|-------------|
| 0 | Success | Command completed successfully |
| 1 | HelpRequested | User requested help |
| 2 | MissingRequiredOption | Required command-line option missing |
| 3 | UnknownArgument | Unrecognized command-line option |
| 4 | InvalidArgumentValue | Option value is invalid format/range |
| 5 | MissingArgumentValue | Option provided without required value |
| 6 | UserSpecifiedFileNotFound | User-specified file doesn't exist |
| 7 | CertificateLoadFailure | Certificate loading failed during signing |
| 8 | PayloadReadError | Payload could not be read during signing |
| 9 | IndirectSignatureVerificationFailure | Indirect signature verification failed |
| 10 | UnknownError | Unexpected error occurred |

## JSON Output Format

When using the `--output` option, results are written in JSON format:

### Signing Result

```json
{
  "operation": "IndirectSign",
  "payloadPath": "/path/to/payload.txt",
  "signaturePath": "/path/to/signature.cose",
  "contentType": "text/plain+cose-hash-envelope",
  "hashAlgorithm": "SHA256",
  "signatureVersion": "CoseHashEnvelope",
  "signatureSize": 1234,
  "certificateThumbprint": "ABC123...",
  "creationTime": "2024-01-01T12:00:00Z"
}
```

### Verification Result

```json
{
  "operation": "IndirectVerify",
  "payloadPath": "/path/to/payload.txt",
  "signaturePath": "/path/to/signature.cose",
  "isValid": true,
  "payloadHashMatches": true,
  "certificateValidation": {
    "success": true,
    "errors": []
  },
  "signingCertificate": "CN=My Company",
  "certificateThumbprint": "ABC123...",
  "verificationTime": "2024-01-01T12:00:00Z"
}
```

## Error Handling

The plugin provides comprehensive error handling with specific error messages:

- **File not found**: Clear indication of which file is missing
- **Certificate errors**: Detailed information about certificate loading failures
- **Validation failures**: Specific reasons why verification failed
- **Parameter errors**: Clear guidance on invalid or missing parameters

## Performance Considerations

- **Hash algorithms**: SHA256 is recommended for most use cases. SHA384 and SHA512 provide stronger security at the cost of performance
- **Certificate storage**: Using certificate store lookups is generally faster than loading PFX files
- **Timeout values**: Default timeout of 30 seconds is suitable for most operations. Increase for very large files or slow storage

## Integration with SCITT

The indirect signature format created by this plugin is designed to be compatible with SCITT (Supply Chain Integrity Transparency and Trust) requirements:

- Uses standardized COSE message formats
- Supports hash-based payload references
- Maintains cryptographic integrity
- Provides verifiable certificate chains
- Enables transparency log integration

## Best Practices

1. **Certificate Management**: Use certificate stores when possible for better security
2. **Hash Algorithms**: Use SHA256 for most applications, stronger algorithms for high-security scenarios
3. **Content Types**: Always specify accurate content types for better interoperability
4. **Verification**: Always verify signatures before trusting signed content
5. **Error Handling**: Check exit codes and JSON output for comprehensive error information

## Troubleshooting

### Common Issues

1. **Certificate not found**: Verify certificate thumbprint and store location
2. **PFX password errors**: Ensure correct password or try without password for unprotected files
3. **File access errors**: Check file permissions and paths
4. **Hash mismatch**: Ensure payload file hasn't been modified since signing
5. **Certificate validation failures**: Use `--allow-untrusted` for testing with self-signed certificates

### Debugging

Enable detailed output by redirecting stderr to see specific error messages:

```bash
CoseSignTool indirect-sign --payload file.txt --signature file.cose --pfx cert.pfx 2> debug.log
```

Use the `--output` option to get structured JSON results for programmatic error handling.
