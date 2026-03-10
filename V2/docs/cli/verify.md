# Verify Command

The `verify` command validates COSE Sign1 signatures.

## Synopsis

```bash
cosesigntool verify <root> [<signature>] [options]
```

Where `<root>` is one of:

- `x509` - Verify using X.509 trust and certificate policy
- `akv` - Verify Azure Key Vault key-only signatures (`kid` pattern validation)
- `mst` - Verify using MST receipt trust (requires pinned keys or trusted ledger allow-list)

`<signature>` is a positional argument (file path), `-` for stdin, or omit to read stdin.

## Common Options (all roots)

| Option | Description |
|--------|-------------|
| `-p`, `--payload <file>` | Payload file for detached/indirect verification |
| `--signature-only` | Verify signature only; skip payload/hash verification (indirect signatures) |
| `-f`, `--output-format <format>` | Output format: `text`, `json`, `xml`, `quiet` |

## verify x509

Verify a signature and apply X.509 trust/policy.

```bash
cosesigntool verify x509 [<signature>] [options]
```

X.509 options:

| Option | Description |
|--------|-------------|
| `--trust-roots <files>` | Custom trusted root certificate(s) in PEM or DER format (repeatable) |
| `--roots <files>` | Alias for `--trust-roots` |
| `--trust-pfx <file>` | Trusted roots from a PFX/PKCS#12 file |
| `--trust-pfx-password-file <file>` | Password file for `--trust-pfx` |
| `--trust-pfx-password-env <env>` | Env var name for `--trust-pfx` password (default: `COSESIGNTOOL_TRUST_PFX_PASSWORD`) |
| `--trust-system-roots <true|false>` | Trust system certificate store roots (default: `true`) |
| `--allow-untrusted` | Allow untrusted roots (signature is still cryptographically verified) |
| `--subject-name <name>` | Required certificate subject common-name (alias: `--cn`) |
| `--issuer-name <name>` | Required certificate issuer common-name (alias: `--issuer`) |
| `--revocation-mode <online|offline|none>` | Certificate revocation check mode (default: `online`) |

Examples:

```bash
# Basic verification
cosesigntool verify x509 signed.cose

# Detached signature
cosesigntool verify x509 signed.sig --payload payload.bin

# Custom trust roots
cosesigntool verify x509 signed.cose --trust-roots ca1.pem --trust-roots ca2.pem
```

## verify akv

Verify an Azure Key Vault key-only signature.

```bash
cosesigntool verify akv [<signature>] [options]
```

AKV options:

| Option | Description |
|--------|-------------|
| `--require-az-key` | Require an Azure Key Vault key signature (kid must be an AKV URI) |
| `--allowed-vaults <patterns...>` | Allowed Key Vault URI patterns (glob or `regex:` prefix). Repeat for multiple |

Example:

```bash
cosesigntool verify akv signature.cose --allowed-vaults "https://production-vault.vault.azure.net/keys/*"
```

## verify mst

Verify MST receipt trust.

```bash
cosesigntool verify mst [<signature>] [options]
```

MST options:

| Option | Description |
|--------|-------------|
| `--mst-offline-keys <path>` | Pinned MST signing keys JWKS JSON file for offline-only receipt verification (alias: `--offline_keys`) |
| `--mst-trust-ledger-instance <host-or-url>` | Allowed MST ledger instance(s) (issuer host allow-list). Repeatable |

At least one of `--mst-offline-keys` or `--mst-trust-ledger-instance` is required.

Examples:

```bash
# Trust a specific ledger instance (repeatable)
cosesigntool verify mst signed.cose --mst-trust-ledger-instance esrp-cts-cp.confidential-ledger.azure.com

# Offline-only receipt verification
cosesigntool verify mst signed.cose --mst-offline-keys esrp-cts-cp.confidential-ledger.azure.com.jwks.json
```

## See Also

- [Inspect Command](inspect.md)
- [Output Formats](output-formats.md)
- [CLI Reference](README.md)

