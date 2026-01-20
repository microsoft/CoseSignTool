# CoseSignTool.Local.Plugin

**Package**: `CoseSignTool.Local.Plugin`  
**Purpose**: Local certificate signing for the CoseSignTool CLI

## Overview

This plugin adds commands for signing with certificates stored on the local machine, including:
- PFX/PKCS#12 certificate files
- Windows certificate store
- PEM-encoded certificate and key files
- Linux certificate store

## Commands

### sign x509 pfx

Sign a payload using a PFX/PKCS#12 certificate file.

```bash
cosesigntool sign x509 pfx [payload] --pfx <path> [password-options] [options]
```

**Options**:
| Option | Required | Description |
|--------|----------|-------------|
| `--pfx` | Yes | Path to the PFX certificate file |
| `--pfx-password-file` | No | Path to a file containing the PFX password |
| `--pfx-password-env` | No | Environment variable name containing the password (default: `COSESIGNTOOL_PFX_PASSWORD`) |
| `--pfx-password-prompt` | No | Prompt for password interactively |
| `--output`, `-o` | No | Output path for signature file |
| `--signature-type`, `-t` | No | Signature type: `embedded`, `detached`, `indirect` (default: `indirect`) |
| `--content-type`, `-c` | No | MIME type of payload |

#### Password Security

⚠️ **Security Best Practice**: PFX passwords should NOT be passed directly on the command line, as they may be logged in shell history, process lists, and audit logs.

**Supported password input methods (in order of precedence)**:
1. **Environment variable** (CI/CD scenarios): Set `COSESIGNTOOL_PFX_PASSWORD` or use `--pfx-password-env` for a custom variable name
2. **Password file** (automation): Use `--pfx-password-file` to read from a secure file
3. **Interactive prompt**: Use `--pfx-password-prompt` or the tool will prompt automatically if no other method is used

**Examples**:
```bash
# Using environment variable (recommended for CI/CD)
export COSESIGNTOOL_PFX_PASSWORD=mypassword  # Linux/macOS
set COSESIGNTOOL_PFX_PASSWORD=mypassword     # Windows
cosesigntool sign x509 pfx document.json --pfx cert.pfx

# Using custom environment variable
export MY_PFX_PWD=mypassword
cosesigntool sign x509 pfx document.json --pfx cert.pfx --pfx-password-env MY_PFX_PWD

# Using password file (recommended for automation)
cosesigntool sign x509 pfx document.json --pfx cert.pfx --pfx-password-file /secure/path/password.txt

# Interactive prompt
cosesigntool sign x509 pfx document.json --pfx cert.pfx --pfx-password-prompt

# Create indirect signature (SCITT-compliant, payload referenced by hash)
cosesigntool sign x509 pfx document.json --pfx cert.pfx -t indirect

# Specify output file
cosesigntool sign x509 pfx document.json --pfx cert.pfx -o signed.cose
```

---

### sign x509 certstore

Sign using a certificate from the OS certificate store by thumbprint.

```bash
cosesigntool sign x509 certstore [payload] --thumbprint <thumbprint> [options]
```

This provider is platform-specific:
- **Windows**: uses the Windows certificate store.
- **Linux/macOS**: searches common certificate store paths.

#### Windows

**Provider options**:
| Option | Required | Description |
|--------|----------|-------------|
| `--thumbprint` | Yes | Certificate thumbprint (hex string) |
| `--store-name` | No | Store name (default: `My`) |
| `--store-location` | No | Store location: `CurrentUser` or `LocalMachine` (default: `CurrentUser`) |

**Examples**:
```bash
# Sign with certificate from CurrentUser\My store
cosesigntool sign x509 certstore document.json --thumbprint ABC123...

# Sign from LocalMachine\My store
cosesigntool sign x509 certstore document.json --thumbprint ABC123... --store-location LocalMachine
```

#### Linux/macOS

**Provider options**:
| Option | Required | Description |
|--------|----------|-------------|
| `--thumbprint` | Yes | Certificate thumbprint (hex string) |
| `--store-paths` | No | Custom search paths (defaults include `/etc/ssl/certs`, `/etc/pki/tls/certs`, `~/.certs`) |

**Examples**:
```bash
# Sign with certificate from default system paths
cosesigntool sign x509 certstore document.json --thumbprint ABC123...

# Add custom search paths
cosesigntool sign x509 certstore document.json --thumbprint ABC123... --store-paths /my/certs
```

---

### sign x509 pem

Sign using PEM-encoded certificate and key files.

```bash
cosesigntool sign x509 pem [payload] --cert-file <path> --key-file <path> [options]
```

**Options**:
| Option | Required | Description |
|--------|----------|-------------|
| `--cert-file` | Yes | Path to PEM certificate file |
| `--key-file` | Yes | Path to PEM private key file |

**Examples**:
```bash
# Sign with PEM files
cosesigntool sign x509 pem document.json --cert-file cert.pem --key-file key.pem
```

---

### sign x509 ephemeral

Sign using an ephemeral (in-memory) certificate generated on-the-fly. **For testing and development only.**

```bash
cosesigntool sign x509 ephemeral [payload] [--config <path>] [options]
```

By default, creates an RSA-4096 certificate with a full certificate chain (Root → Intermediate → Leaf) and CodeSigning EKU for maximum compatibility with COSE signing scenarios.

**Options**:
| Option | Required | Description |
|--------|----------|-------------|
| `--config` | No | Path to JSON configuration file |
| `--subject` | No | Certificate subject name (overrides config) |
| `--algorithm` | No | Key algorithm: RSA, ECDSA, MLDSA |
| `--key-size` | No | Key size in bits |
| `--validity-days` | No | Certificate validity period |
| `--no-chain` | No | Generate self-signed instead of chain |
| `--minimal` | No | Use minimal preset (RSA-2048, 1 day, self-signed) |
| `--pqc` | No | Use post-quantum preset (ML-DSA-65 with chain) ⚠️ Windows only |

> **Note**: The `--pqc` option and ML-DSA algorithm are **Windows only** in .NET 10. Linux and macOS do not currently support ML-DSA.

**Default Configuration**:
- Algorithm: RSA-4096
- Validity: 365 days
- Chain: Root → Intermediate → Leaf
- EKU: CodeSigning

**Examples**:
```bash
# Sign with default optimal settings (RSA-4096, full chain, CodeSigning)
cosesigntool sign x509 ephemeral document.json

# Quick test with minimal configuration
cosesigntool sign x509 ephemeral document.json --minimal

# Post-quantum signing with ML-DSA (Windows only)
cosesigntool sign x509 ephemeral document.json --pqc

# Custom configuration via JSON file
cosesigntool sign x509 ephemeral document.json --config cert-config.json

# Custom subject with ECDSA
cosesigntool sign x509 ephemeral document.json --subject "CN=My Test Signer" --algorithm ECDSA

# Self-signed certificate (no chain)
cosesigntool sign x509 ephemeral document.json --no-chain
```

**JSON Configuration File Format**:
```json
{
  "Subject": "CN=My Test Signer, O=My Organization",
  "Algorithm": "RSA",
  "KeySize": 4096,
  "ValidityDays": 365,
  "GenerateChain": true,
  "HashAlgorithm": "SHA384",
  "EnhancedKeyUsages": ["CodeSigning", "LifetimeSigning"],
  "Chain": {
    "RootSubject": "CN=My Root CA, O=My Organization",
    "IntermediateSubject": "CN=My Intermediate CA, O=My Organization",
    "RootValidityDays": 3650,
    "IntermediateValidityDays": 1825
  }
}
```

**Supported Algorithms**:
| Algorithm | Default Key Size | Description |
|-----------|-----------------|-------------|
| RSA | 4096 | RSA with RSASSA-PSS |
| ECDSA | 384 | ECDSA with NIST P-384 curve |
| MLDSA | 65 | ML-DSA-65 (post-quantum) |

**Enhanced Key Usage (EKU) Values**:
| Value | OID | Description |
|-------|-----|-------------|
| `CodeSigning` | 1.3.6.1.5.5.7.3.3 | Code signing |
| `LifetimeSigning` | 1.3.6.1.4.1.311.10.3.13 | Lifetime signing |
| `ServerAuth` | 1.3.6.1.5.5.7.3.1 | TLS server authentication |
| `ClientAuth` | 1.3.6.1.5.5.7.3.2 | TLS client authentication |
| `TimeStamping` | 1.3.6.1.5.5.7.3.8 | Time stamping |
| Custom OID | (e.g., `1.3.6.1.5.5.7.3.9`) | Any valid OID string |

> ⚠️ **Warning**: Ephemeral certificates are for testing only. Signatures cannot be verified by external parties because the certificate chain is not published or trusted.

## Pipeline Support

All signing commands support Unix-style pipelines:

```bash
# Sign from stdin, output to stdout
echo 'Hello World' | cosesigntool sign x509 pfx --pfx cert.pfx > signed.cose

# Chain with verification
cat document.json | cosesigntool sign x509 pfx --pfx cert.pfx | cosesigntool verify x509 -

# Batch signing
for file in *.json; do
  cosesigntool sign x509 pfx "$file" --pfx cert.pfx
done
```

## Security Considerations

1. **Password Protection**: Always use password-protected PFX files
2. **Secure Password Input**: Use environment variables, password files, or interactive prompts for PFX passwords - never pass passwords on the command line
3. **Key Storage**: Store private keys securely with appropriate file permissions
4. **Certificate Expiration**: Monitor certificate expiration dates
5. **Development Only**: The `sign x509 ephemeral` provider is for development only

### SecurePasswordProvider

The `SecurePasswordProvider` class in `CoseSignTool.Abstractions.Security` provides utilities for secure password handling:

```csharp
using CoseSignTool.Abstractions.Security;

// Get password from environment variable
SecureString? password = SecurePasswordProvider.GetPasswordFromEnvironment("COSESIGNTOOL_PFX_PASSWORD");

// Read password from file
SecureString password = SecurePasswordProvider.ReadPasswordFromFile("/secure/password.txt");

// Interactive console prompt (masked input)
SecureString password = SecurePasswordProvider.ReadPasswordFromConsole("Enter password: ");

// Get password with automatic fallback (env → file → prompt)
SecureString password = SecurePasswordProvider.GetPassword(
    passwordFilePath: "/path/to/password.txt",
    environmentVariableName: "COSESIGNTOOL_PFX_PASSWORD",
    prompt: "Enter PFX password: ");
```

## Supported Algorithms

The plugin automatically selects the appropriate COSE algorithm based on the certificate key:

| Key Type | Algorithm |
|----------|-----------|
| RSA 2048+ | PS256 (RSASSA-PSS with SHA-256) |
| RSA 3072+ | PS384 (RSASSA-PSS with SHA-384) |
| RSA 4096+ | PS512 (RSASSA-PSS with SHA-512) |
| ECDSA P-256 | ES256 |
| ECDSA P-384 | ES384 |
| ECDSA P-521 | ES512 |
| ML-DSA-44 | ML-DSA-44 (post-quantum) ⚠️ Windows only |
| ML-DSA-65 | ML-DSA-65 (post-quantum) ⚠️ Windows only |
| ML-DSA-87 | ML-DSA-87 (post-quantum) ⚠️ Windows only |

> **Platform Note**: ML-DSA algorithms are currently only supported on Windows in .NET 10.
