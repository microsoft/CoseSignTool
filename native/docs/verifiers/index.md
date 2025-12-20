# Verifiers overview

This repo provides several verification entry points depending on your scenario:

- **COSE_Sign1 signature verification** (`cosesign1_signature`)
  - Low-level signature verification and basic validation result reporting.

- **COSE Hash Envelope payload-hash verification** (`cosesign1_signature`)
  - Verifies a “hash-in-payload” envelope where the COSE_Sign1 payload is expected to be a hash of external bytes.

- **X.509 / x5c verification** (`cosesign1_x509`)
  - Extracts key material from a COSE `x5c` header and verifies the signature.

- **MST verification** (`cosesign1_mst`)
  - Verifies transparency receipts embedded in a transparent statement.

## How to choose

- You have COSE_Sign1 bytes and a known public key → start with [COSE_Sign1 signature verifier](cose-sign1-signature.md).
- You have COSE_Sign1 bytes and the signer ships an `x5c` header → use [X.509 / x5c verifier](x5c-x509.md).
- You are verifying a “transparent statement” that contains receipts → use [MST verifier](mst.md).
- You have an envelope where the payload is a digest of some external bytes → use [COSE Hash Envelope verifier](cose-hash-envelope.md).
