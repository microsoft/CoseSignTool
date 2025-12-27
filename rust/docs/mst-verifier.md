<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# MST verifier (cosesign1-mst)

This document describes how `cosesign1-mst` verifies receipts embedded in a “transparent statement” COSE_Sign1.

## Concepts

- **Transparent statement**: a COSE_Sign1 message that carries one or more MST receipts in its unprotected headers.
- **Receipt**: a COSE_Sign1 message that proves inclusion of the statement in a CCF structure.
- **Accumulator**: a SHA-256 hash derived from a leaf + proof path, used as the detached payload for receipt signature verification.

## Header labels used

These are the key labels used by the verifier:

- Statement unprotected header:
  - `394`: embedded receipts (array of `bstr`, each a receipt COSE_Sign1)

- Receipt protected headers:
  - `4`: `kid` (key identifier)
  - `395`: `vds` (verifiable data structure; must be `2` for CCF)
  - `15`: “CWT map” that may contain issuer
    - `1`: `iss` (issuer domain/host)

- Receipt unprotected headers:
  - `396`: `vdp` (verifiable data proof)
    - `-1`: inclusion proofs (array of `bstr`)

- Inclusion proof map keys:
  - `1`: leaf
  - `2`: path

## Verification algorithm (offline)

Given a transparent statement `S`:

1. Parse `S` as COSE_Sign1.
2. Read unprotected header `394` and collect receipt bytes.
3. Re-encode `S` with **empty unprotected headers** (`statement_without_unprotected_headers`).
4. For each receipt:
   1. Parse the receipt as COSE_Sign1.
   2. Determine issuer:
      - Try reading protected header `15` (map or CBOR-encoded bytes), then `iss` at label `1`.
      - If issuer cannot be read, treat it as unknown.
   3. Decide whether to verify based on:
      - `authorized_domains`
      - `UnauthorizedReceiptBehavior`
      - `AuthorizedReceiptBehavior`
   4. Resolve a key from `OfflineEcKeyStore` by `(issuer, kid)`.
   5. Validate receipt structure:
      - `kid` is present
      - `vds == 2` (CCF)
      - `vdp` contains at least one inclusion proof
   6. For each inclusion proof:
      - Decode to a map, extract `leaf` and `path`.
      - Compute accumulator using SHA-256.
      - Verify receipt signature **as detached**:
        - Re-encode the receipt with `payload = null`
        - Pass `external_payload = accumulator` to `cosesign1::verify_cose_sign1`
      - Check `leaf.data_hash == sha256(statement_without_unprotected_headers)`.

If any required receipt fails (based on behavior options), verification returns failures.

## Behavior knobs

- `UnauthorizedReceiptBehavior`
  - `FailIfPresent`: if any receipt’s issuer is not in `authorized_domains`, fail early.
  - `IgnoreAll`: ignore receipts from unauthorized issuers.
  - `VerifyAll`: attempt to verify unauthorized receipts too (failures are reported separately from authorized failures).

- `AuthorizedReceiptBehavior`
  - `VerifyAnyMatching`: if at least one authorized-domain receipt verifies, authorized failures are cleared.
  - `VerifyAllMatching`: if a domain had a receipt and it failed, report `MST_REQUIRED_DOMAIN_FAILED`.
  - `RequireAll`: every domain in `authorized_domains` must have at least one valid receipt.

## Online mode (JWKS)

`verify_transparent_statement_online` is a two-pass strategy:

1. Try offline verification using the current `OfflineEcKeyStore`.
2. If invalid and network fetch is allowed:
   - For each authorized issuer, fetch JWKS via `JwksFetcher`.
   - For each EC JWK, convert to SPKI DER and insert into the cache.
3. Re-run offline verification.

The crate does not perform HTTP; the application supplies a `JwksFetcher` implementation.
