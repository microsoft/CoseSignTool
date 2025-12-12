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

### sign-pfx

Sign a payload using a PFX/PKCS#12 certificate file.

```bash
CoseSignTool sign-pfx <payload> --pfx <path> [--password <password>] [options]
```

**Options**:
| Option | Required | Description |
|--------|----------|-------------|
| `--pfx` | Yes | Path to the PFX certificate file |
| `--password` | No | Password for the PFX file |
| `--output`, `-o` | No | Output path for signature file |
| `--detached`, `-d` | No | Create detached signature |
| `--signature-type`, `-t` | No | Signature type: direct, embedded, indirect |
| `--content-type`, `-c` | No | MIME type of payload |

**Examples**:
```bash
# Sign with PFX file
CoseSignTool sign-pfx document.json --pfx cert.pfx --password mypassword

# Create detached indirect signature
CoseSignTool sign-pfx document.json --pfx cert.pfx -d -t indirect

# Specify output file
CoseSignTool sign-pfx document.json --pfx cert.pfx -o signed.cose
```

---

### sign-cert-store (Windows)

Sign using a certificate from the Windows certificate store.

```bash
CoseSignTool sign-cert-store <payload> --thumbprint <thumbprint> [options]
```

**Options**:
| Option | Required | Description |
|--------|----------|-------------|
| `--thumbprint` | Yes | Certificate thumbprint (SHA-1) |
| `--store-name` | No | Store name (default: My) |
| `--store-location` | No | Store location: CurrentUser, LocalMachine |

**Examples**:
```bash
# Sign with certificate from CurrentUser\My store
CoseSignTool sign-cert-store document.json --thumbprint ABC123...

# Sign from LocalMachine store
CoseSignTool sign-cert-store document.json --thumbprint ABC123... --store-location LocalMachine
```

---

### sign-pem

Sign using PEM-encoded certificate and key files.

```bash
CoseSignTool sign-pem <payload> --cert-file <path> --key-file <path> [options]
```

**Options**:
| Option | Required | Description |
|--------|----------|-------------|
| `--cert-file` | Yes | Path to PEM certificate file |
| `--key-file` | Yes | Path to PEM private key file |

**Examples**:
```bash
# Sign with PEM files
CoseSignTool sign-pem document.json --cert-file cert.pem --key-file key.pem
```

---

### sign-linux-store (Linux)

Sign using a certificate from the Linux certificate store.

```bash
CoseSignTool sign-linux-store <payload> --thumbprint <thumbprint> [options]
```

**Options**:
| Option | Required | Description |
|--------|----------|-------------|
| `--thumbprint` | Yes | Certificate thumbprint (SHA-256) |
| `--store-path` | No | Path to certificate store directory |
| `--store-paths` | No | Additional store paths to search |

**Examples**:
```bash
# Sign with certificate from default Linux store
CoseSignTool sign-linux-store document.json --thumbprint ABC123...

# Sign from custom store path
CoseSignTool sign-linux-store document.json --thumbprint ABC123... --store-path /etc/ssl/private
```

## Pipeline Support

All signing commands support Unix-style pipelines:

```bash
# Sign from stdin, output to stdout
echo 'Hello World' | CoseSignTool sign-pfx --pfx cert.pfx > signed.cose

# Chain with verification
cat document.json | CoseSignTool sign-pfx --pfx cert.pfx | CoseSignTool verify -

# Batch signing
for file in *.json; do
    CoseSignTool sign-pfx "$file" --pfx cert.pfx
done
```

## Security Considerations

1. **Password Protection**: Always use password-protected PFX files
2. **Key Storage**: Store private keys securely with appropriate file permissions
3. **Certificate Expiration**: Monitor certificate expiration dates
4. **Development Only**: The `sign-ephemeral` command is for development only

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
