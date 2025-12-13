# Inspect Command

The `inspect` command displays detailed information about a COSE Sign1 signature, including protected headers, payload information, certificate chain details, and CWT claims.

## Usage

```bash
cosesigntool inspect <signature> [options]
```

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `<signature>` | Yes | Path to the COSE Sign1 signature file to inspect |

## Options

| Option | Alias | Description |
|--------|-------|-------------|
| `--output-format <format>` | `-o` | Output format: `text`, `json`, `xml`, `quiet` (default: `text`) |
| `--verbose` | `-v` | Enable verbose output with additional details |
| `--help` | `-h` | Show help and usage information |

## Examples

### Basic Inspection

```bash
# Inspect a signature with default text output
cosesigntool inspect signed.cose
```

### JSON Output for Automation

```bash
# Get structured JSON output
cosesigntool inspect signed.cose --output-format json

# Parse with jq
cosesigntool inspect signed.cose -o json | jq '.protectedHeaders.algorithm'
```

### Verbose Inspection

```bash
# Show additional details
cosesigntool inspect signed.cose --verbose
```

## Output Information

The inspect command displays the following information:

### Protected Headers

- **Algorithm**: The COSE algorithm used for signing (e.g., ES256, PS256)
- **Content Type**: The MIME type of the payload
- **Certificate Chain**: Number of certificates and thumbprint information
- **Critical Headers**: Any headers marked as critical
- **Payload Hash Algorithm**: For indirect signatures, the hash algorithm used
- **Preimage Content Type**: For indirect signatures, the original content type

### CWT Claims (SCITT)

If the signature includes CWT claims for SCITT compliance:

- **Issuer (iss)**: The DID:x509 or other issuer identifier
- **Subject (sub)**: The subject of the signed statement
- **Issued At (iat)**: When the signature was created
- **Not Before (nbf)**: Validity start time
- **Expiration (exp)**: When the signature expires
- **CWT ID (cti)**: Unique identifier for the CWT

### Payload Information

- **Embedded/Detached**: Whether the payload is included in the signature
- **Size**: Payload size in bytes
- **Content Type**: MIME type of the payload
- **Preview**: First portion of text payloads
- **SHA-256 Hash**: Hash of the payload for verification

### Certificate Chain

For each certificate in the chain:

- **Subject**: The certificate subject (CN, O, etc.)
- **Issuer**: The certificate issuer
- **Serial Number**: Certificate serial number
- **Thumbprint**: SHA-1 thumbprint
- **Validity**: Not Before and Not After dates
- **Expiration Status**: Whether the certificate has expired
- **Key Algorithm**: Public key algorithm (RSA, ECC, etc.)
- **Signature Algorithm**: Algorithm used to sign the certificate

## JSON Output Schema

For programmatic consumption, use `--output-format json`. The output follows this schema:

```json
{
  "file": {
    "path": "string",
    "sizeBytes": "number"
  },
  "protectedHeaders": {
    "algorithm": {
      "id": "number",
      "name": "string"
    },
    "contentType": "string",
    "criticalHeaders": ["string"],
    "certificateThumbprint": {
      "algorithm": "string",
      "value": "string"
    },
    "certificateChainLength": "number",
    "payloadHashAlgorithm": {
      "id": "number",
      "name": "string"
    },
    "preimageContentType": "string",
    "payloadLocation": "string",
    "otherHeaders": [
      {
        "label": "string",
        "labelId": "number",
        "value": "any",
        "valueType": "string",
        "lengthBytes": "number"
      }
    ]
  },
  "unprotectedHeaders": [
    {
      "label": "string",
      "labelId": "number",
      "value": "any",
      "valueType": "string",
      "lengthBytes": "number"
    }
  ],
  "cwtClaims": {
    "issuer": "string",
    "subject": "string",
    "audience": "string",
    "issuedAt": "string (ISO 8601)",
    "issuedAtUnix": "number",
    "notBefore": "string (ISO 8601)",
    "notBeforeUnix": "number",
    "expirationTime": "string (ISO 8601)",
    "expirationTimeUnix": "number",
    "isExpired": "boolean",
    "cwtId": "string",
    "customClaimsCount": "number"
  },
  "payload": {
    "isEmbedded": "boolean",
    "sizeBytes": "number",
    "contentType": "string",
    "isText": "boolean",
    "preview": "string",
    "sha256": "string"
  },
  "signature": {
    "totalSizeBytes": "number",
    "certificateChainLocation": "string"
  },
  "certificates": [
    {
      "subject": "string",
      "issuer": "string",
      "serialNumber": "string",
      "thumbprint": "string",
      "notBefore": "string (ISO 8601)",
      "notAfter": "string (ISO 8601)",
      "isExpired": "boolean",
      "keyAlgorithm": "string",
      "signatureAlgorithm": "string"
    }
  ]
}
```

### Notes on JSON Output

- Null values are omitted from the JSON output for cleaner results
- Timestamps are provided in both ISO 8601 format and Unix timestamp for flexibility
- The `isExpired` field is computed at inspection time
- Array lengths are provided instead of full array contents for large binary data
- Text payloads include a preview of the first ~100 characters

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success - inspection completed |
| 1 | Error - file not found or invalid COSE message |

## Use Cases

### Verify Signature Contents Before Validation

```bash
# Check what algorithm was used
cosesigntool inspect signed.cose -o json | jq '.protectedHeaders.algorithm.name'

# Check if payload is embedded
cosesigntool inspect signed.cose -o json | jq '.payload.isEmbedded'
```

### Check Certificate Expiration

```bash
# Check if any certificates have expired
cosesigntool inspect signed.cose -o json | jq '.certificates[] | select(.isExpired == true)'
```

### Verify SCITT Compliance

```bash
# Check for CWT claims presence
cosesigntool inspect signed.cose -o json | jq '.cwtClaims'

# Get the issuer DID
cosesigntool inspect signed.cose -o json | jq '.cwtClaims.issuer'
```

### Integration with CI/CD

```powershell
# PowerShell: Fail if certificate is expired
$result = cosesigntool inspect signed.cose -o json | ConvertFrom-Json
if ($result.certificates | Where-Object { $_.isExpired }) {
    Write-Error "Signature contains expired certificates!"
    exit 1
}
```

## See Also

- [Output Formats](output-formats.md) - Detailed documentation on output formats
- [Verify Command](verify.md) - Verify signature validity
- [Sign Commands](sign.md) - Create signatures
