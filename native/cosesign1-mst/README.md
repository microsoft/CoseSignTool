# cosesign1-mst

C++20 library for verifying Microsoft Signing Transparency (MST) receipts embedded in COSE_Sign1 transparent statements.

- Depends on: `cosesign1-signature` (base COSE_Sign1 verifier), OpenSSL, tinycbor, and nlohmann-json.
- Verifies receipt integrity and inclusion proofs (CCF Merkle tree receipts).

This package is intentionally focused on **offline receipt validation** given a set of trusted public keys.
