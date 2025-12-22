<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# Sequence diagrams

These diagrams are intended to help new contributors understand the call flow and where to extend behavior.

## Basic COSE_Sign1 verification

```mermaid
sequenceDiagram
    autonumber
    participant App as Caller
    participant Facade as cosesign1
    participant Providers as SigningKeyProviders

    App->>Facade: CoseSign1::from_bytes(cose_bytes)
    Facade-->>App: CoseSign1
    App->>Facade: verify_signature(payload_to_verify, public_key_bytes?)
    alt public_key_bytes provided
        Facade->>Facade: verify signature
    else no public_key_bytes
        Facade->>Providers: resolve_signing_key(parsed)
        Providers-->>Facade: ResolvedSigningKey
        Facade->>Facade: verify signature
    end
    Facade-->>App: ValidationResult
```

## MST offline verification (transparent statement)

```mermaid
sequenceDiagram
    autonumber
    participant App as Caller
    participant MST as cosesign1-mst
    participant KS as OfflineEcKeyStore
    participant Val as cosesign1::validation

    App->>MST: verify_transparent_statement(name, statement, ks, opts)
    MST->>MST: parse COSE_Sign1 statement
    MST->>MST: read embedded receipts (hdr 394)
    MST->>MST: encode statement with empty unprotected

    loop For each receipt
        MST->>MST: parse COSE_Sign1 receipt
        MST->>MST: read issuer from protected CWT map (15/1)
        MST->>MST: read kid (label 4)
        MST->>KS: resolve(issuer, kid)
        KS-->>MST: ResolvedKey or None

        MST->>MST: read vds (395) and vdp (396/-1)

        loop For each inclusion proof
            MST->>MST: decode inclusion map, parse leaf/path
            MST->>MST: compute accumulator (sha256)
            MST->>MST: re-encode receipt payload as null
            MST->>Val: verify_cose_sign1("MstReceiptSignature", receipt_null_payload, external_payload=acc)
            Val-->>MST: ValidationResult
            MST->>MST: check leaf.data_hash == sha256(statement_without_unprotected)
        end
    end

    MST-->>App: ValidationResult
```

## MST online mode (JWKS fallback)

```mermaid
sequenceDiagram
    autonumber
    participant App as Caller
    participant MST as cosesign1-mst
    participant Cache as OfflineEcKeyStore
    participant Fetch as JwksFetcher

    App->>MST: verify_transparent_statement_online(name, stmt, cache, fetcher, opts)
    MST->>MST: verify_transparent_statement(...)
    alt Valid
        MST-->>App: success
    else Invalid and network allowed
        MST->>MST: build issuer set from opts.authorized_domains
        loop For each issuer
            MST->>Fetch: fetch_jwks(issuer, jwks_path, timeout)
            Fetch-->>MST: jwks bytes (or error)
            MST->>MST: parse JWKS JSON; filter EC keys; JWK->SPKI
            MST->>Cache: insert(issuer, kid, key)
        end
        MST->>MST: verify_transparent_statement(...) (second pass)
        MST-->>App: result
    end
```
