# Output Formats

CoseSignTool supports multiple output formats to suit different use cases, from human-readable text to machine-parseable JSON.

## Available Formats

| Format | Option | Description |
|--------|--------|-------------|
| Text | `--output-format text` | Human-readable output with colors (default) |
| JSON | `--output-format json` | Structured JSON for programmatic consumption |
| XML | `--output-format xml` | XML output for integration with XML-based toolchains |
| Quiet | `--output-format quiet` | Minimal output, errors only |

## Using Output Formats

### Text Format (Default)

Text format provides human-readable output with section headers and key-value pairs:

```bash
cosesigntool inspect signed.cose
```

Output:
```
═════════════════════════════════════════════════════════════════════════════════
COSE Sign1 Inspection: signed.cose
═════════════════════════════════════════════════════════════════════════════════

Protected Headers
  Algorithm: ES256 (-7)
  Content Type: text/plain
  Certificate Chain: 1 certificate(s)

Payload (Embedded)
  Size: 13 bytes
  SHA256: a948904f2f0f479b8f8564cbf12dace4e19dcea3b870c906d1f8e5f2d...
  Preview: Hello, COSE!

Signature
  Size: 64 bytes
  Certificate Chain Location: Protected Headers
═════════════════════════════════════════════════════════════════════════════════
```

### JSON Format

JSON format provides fully structured output suitable for automation, scripting, and integration with other tools:

```bash
cosesigntool inspect signed.cose --output-format json
```

Output:
```json
{
  "file": {
    "path": "signed.cose",
    "sizeBytes": 512
  },
  "protectedHeaders": {
    "algorithm": {
      "id": -7,
      "name": "ES256"
    },
    "contentType": "text/plain",
    "certificateChainLength": 1
  },
  "payload": {
    "isEmbedded": true,
    "sizeBytes": 13,
    "isText": true,
    "preview": "Hello, COSE!",
    "sha256": "a948904f2f0f479b8f8564cbf12dace4e19dcea3b870c906d1f8e5f2d..."
  },
  "signature": {
    "totalSizeBytes": 64,
    "certificateChainLocation": "Protected Headers"
  },
  "certificates": [
    {
      "subject": "CN=Test Signer",
      "issuer": "CN=Test CA",
      "serialNumber": "1234567890",
      "thumbprint": "AB12CD34EF56...",
      "notBefore": "2024-01-01T00:00:00Z",
      "notAfter": "2025-12-31T23:59:59Z",
      "isExpired": false,
      "keyAlgorithm": "ECC",
      "signatureAlgorithm": "sha256ECDSA"
    }
  ]
}
```

### XML Format

XML format wraps the output in XML elements:

```bash
cosesigntool inspect signed.cose --output-format xml
```

### Quiet Format

Quiet format suppresses all output except errors, useful for scripts that only care about exit codes:

```bash
cosesigntool verify x509 signed.cose --output-format quiet
echo $?  # 0 = success, non-zero = failure
```

## JSON Output Structure

The JSON output for the `inspect` command provides a fully decoded view of the COSE Sign1 message structure.

### Top-Level Properties

| Property | Type | Description |
|----------|------|-------------|
| `file` | object | Information about the input file |
| `protectedHeaders` | object | Decoded protected headers |
| `unprotectedHeaders` | array | List of unprotected headers (if any) |
| `cwtClaims` | object | CWT Claims for SCITT compliance (if present) |
| `payload` | object | Payload information |
| `signature` | object | Signature metadata |
| `certificates` | array | Certificate chain details |

### File Information

```json
{
  "file": {
    "path": "string",      // Input file path
    "sizeBytes": 1234      // File size in bytes
  }
}
```

### Protected Headers

```json
{
  "protectedHeaders": {
    "algorithm": {
      "id": -7,            // COSE algorithm identifier
      "name": "ES256"      // Human-readable algorithm name
    },
    "contentType": "text/plain",
    "criticalHeaders": ["..."],          // Critical header labels
    "certificateThumbprint": {
      "algorithm": "SHA256",
      "value": "AB12CD34..."
    },
    "certificateChainLength": 1,
    "payloadHashAlgorithm": {            // For indirect signatures
      "id": -16,
      "name": "SHA-256"
    },
    "preimageContentType": "application/json",  // Original content type
    "payloadLocation": "...",
    "otherHeaders": [...]                // Other decoded headers
  }
}
```

### Algorithm ID Mapping

Common COSE algorithm identifiers and their names:

| ID | Name | Description |
|----|------|-------------|
| -7 | ES256 | ECDSA with SHA-256 on P-256 |
| -35 | ES384 | ECDSA with SHA-384 on P-384 |
| -36 | ES512 | ECDSA with SHA-512 on P-521 |
| -37 | PS256 | RSASSA-PSS with SHA-256 |
| -38 | PS384 | RSASSA-PSS with SHA-384 |
| -39 | PS512 | RSASSA-PSS with SHA-512 |
| -257 | RS256 | RSASSA-PKCS1-v1_5 with SHA-256 |
| -16 | SHA-256 | SHA-256 hash (for indirect signatures) |
| -43 | SHA-384 | SHA-384 hash |
| -44 | SHA-512 | SHA-512 hash |

### CWT Claims (SCITT Compliance)

For SCITT-compliant signatures, the CWT claims are decoded:

```json
{
  "cwtClaims": {
    "issuer": "did:x509:0:sha256:...",   // iss claim (1)
    "subject": "user@example.com",        // sub claim (2)
    "audience": "...",                    // aud claim (3)
    "issuedAt": "2024-06-01T12:00:00Z",  // iat claim (6) - formatted
    "issuedAtUnix": 1717243200,           // iat claim - raw Unix timestamp
    "notBefore": "2024-06-01T12:00:00Z", // nbf claim (5) - formatted
    "notBeforeUnix": 1717243200,          // nbf claim - raw Unix timestamp
    "expirationTime": "2025-06-01T12:00:00Z",  // exp claim (4)
    "expirationTimeUnix": 1748779200,
    "isExpired": false,                   // Computed: is exp in the past?
    "cwtId": "...",                        // cti claim (7)
    "customClaimsCount": 2                // Number of non-standard claims
  }
}
```

### Payload Information

```json
{
  "payload": {
    "isEmbedded": true,           // true if payload is in the message
    "sizeBytes": 1234,            // Payload size (null for detached)
    "contentType": "text/plain",  // Content type from headers
    "isText": true,               // true if payload appears to be text
    "preview": "Hello, COSE!",    // First ~100 chars for text payloads
    "sha256": "a948904f2f..."     // SHA-256 hash of payload
  }
}
```

### Signature Information

```json
{
  "signature": {
    "totalSizeBytes": 64,                    // Raw signature size
    "certificateChainLocation": "Protected Headers"  // Where certs are stored
  }
}
```

### Certificate Chain

Each certificate in the chain is fully decoded:

```json
{
  "certificates": [
    {
      "subject": "CN=My Signer, O=Contoso",
      "issuer": "CN=Contoso CA, O=Contoso",
      "serialNumber": "1234567890ABCDEF",
      "thumbprint": "AB12CD34EF56...",        // SHA-1 thumbprint
      "notBefore": "2024-01-01T00:00:00Z",
      "notAfter": "2025-12-31T23:59:59Z",
      "isExpired": false,                      // Computed at inspection time
      "keyAlgorithm": "ECC",                   // Public key algorithm
      "signatureAlgorithm": "sha256ECDSA"      // Certificate signature algorithm
    }
  ]
}
```

## Programmatic Usage Examples

### Using JSON Output in PowerShell

```powershell
# Parse the inspection output
$result = cosesigntool inspect signed.cose --output-format json | ConvertFrom-Json

# Check if payload is embedded
if ($result.payload.isEmbedded) {
    Write-Host "Embedded payload: $($result.payload.preview)"
}

# Check certificate expiration
foreach ($cert in $result.certificates) {
    if ($cert.isExpired) {
        Write-Warning "Certificate $($cert.subject) has expired!"
    }
}
```

### Using JSON Output in Bash

```bash
# Parse with jq
cosesigntool inspect signed.cose --output-format json | jq '.protectedHeaders.algorithm.name'

# Check for SCITT compliance
cosesigntool inspect signed.cose --output-format json | jq '.cwtClaims.issuer'

# Get certificate subjects
cosesigntool inspect signed.cose --output-format json | jq '.certificates[].subject'
```

### Using JSON Output in Python

```python
import subprocess
import json

result = subprocess.run(
    ['cosesigntool', 'inspect', 'signed.cose', '--output-format', 'json'],
    capture_output=True, text=True
)
data = json.loads(result.stdout)

# Access inspection data
algorithm = data['protectedHeaders']['algorithm']['name']
print(f"Signed with: {algorithm}")

# Check for CWT claims (SCITT)
if data.get('cwtClaims'):
    print(f"Issuer: {data['cwtClaims']['issuer']}")
```

## Output Format Interface (Library Usage)

The output formatting system is based on the `IOutputFormatter` interface:

```csharp
public interface IOutputFormatter
{
    void WriteInfo(string message);
    void WriteSuccess(string message);
    void WriteWarning(string message);
    void WriteError(string message);
    void WriteKeyValue(string key, string value);
    void BeginSection(string title);
    void EndSection();
    void WriteStructuredData<T>(T data) where T : class;
    void Flush();
}
```

### WriteStructuredData Method

The `WriteStructuredData<T>` method allows commands to provide rich, structured output. For the JSON formatter, this writes the object directly as JSON. For text formatters, this method is typically a no-op since they rely on `WriteKeyValue` and sections for output.

```csharp
// In a command implementation
formatter.WriteStructuredData(new CoseInspectionResult
{
    File = new FileInformation { Path = filePath, SizeBytes = fileSize },
    ProtectedHeaders = protectedHeaders,
    // ... other properties
});
```

## See Also

- [Inspect Command Reference](inspect.md)
- [Verify Command Reference](verify.md)
- [Quick Start Guide](../getting-started/quick-start.md)
