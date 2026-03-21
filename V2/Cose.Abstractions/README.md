# Cose.Abstractions

Generic COSE abstractions that are independent of any specific COSE message type (Sign1, Encrypt, MAC).

## Contents
- `CoseHeaderLocation` — Flags for searching protected/unprotected headers
- `IndirectSignatureHeaderLabels` — RFC 9054 header label constants
- `SignatureFormat` — Signature format enumeration

## Polyfills
- `Guard` — Cross-framework argument validation (ThrowIfNull, ThrowIfDisposed, etc.)
- Compiler support attributes for netstandard2.0 compatibility