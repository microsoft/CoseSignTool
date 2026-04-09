<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# code_transparency_client

Rust REST client for the Azure Code Transparency Service.

## Overview

This crate provides a high-level HTTP client for interacting with the
[Azure Code Transparency](https://learn.microsoft.com/en-us/azure/confidential-ledger/code-transparency-overview)
service (formerly Microsoft Supply-chain Transparency, MST). It follows
canonical Azure SDK patterns — pipeline policies, long-running operation
polling, and structured error handling — to submit COSE_Sign1 messages for
transparent registration and retrieve receipts.

Key capabilities:

- **Entry submission** — `create_entry()` submits COSE_Sign1 messages and
  returns a `Poller<OperationStatus>` for async tracking
- **Convenience signing** — `make_transparent()` submits and polls to
  completion in a single call
- **Entry retrieval** — `get_entry()` / `get_entry_statement()` fetch
  registered entries and their original statements
- **Key management** — `get_public_keys()` / `resolve_signing_key()` fetch
  and resolve JWKS for receipt verification
- **Pipeline policies** — `ApiKeyAuthPolicy` for Bearer-token injection,
  `TransactionNotCachedPolicy` for fast 503 retries
- **CBOR error handling** — Parses RFC 9290 CBOR Problem Details from
  service error responses

## Architecture

```
┌──────────────────────────────────────────────────────┐
│              code_transparency_client                  │
├─────────────────────────┬────────────────────────────┤
│  client                 │  models                     │
│  ┌────────────────────┐ │  ┌────────────────────────┐ │
│  │CodeTransparency    │ │  │JsonWebKey              │ │
│  │  Client            │ │  │JwksDocument            │ │
│  │                    │ │  └────────────────────────┘ │
│  │ • create_entry()   │ │                             │
│  │ • make_transparent │ │  operation_status           │
│  │ • get_entry()      │ │  ┌────────────────────────┐ │
│  │ • get_public_keys()│ │  │OperationStatus         │ │
│  │ • resolve_signing  │ │  │  (StatusMonitor)       │ │
│  │     _key()         │ │  └────────────────────────┘ │
│  └────────────────────┘ │                             │
├─────────────────────────┼────────────────────────────┤
│  Pipeline Policies      │  Error Handling             │
│  ┌────────────────────┐ │  ┌────────────────────────┐ │
│  │ApiKeyAuthPolicy    │ │  │CodeTransparencyError   │ │
│  │TransactionNot      │ │  │CborProblemDetails      │ │
│  │  CachedPolicy      │ │  └────────────────────────┘ │
│  └────────────────────┘ │                             │
├─────────────────────────┴────────────────────────────┤
│  polling (DelayStrategy, MstPollingOptions)            │
│  mock_transport (SequentialMockTransport) [test-utils] │
└──────────────────────────────────────────────────────┘
        │                    │
        ▼                    ▼
  azure_core             cbor_primitives
  (Pipeline, Poller,     cose_sign1_primitives
   StatusMonitor)
```

## Modules

| Module | Description |
|--------|-------------|
| `client` | `CodeTransparencyClient` — main HTTP client with entry submission, retrieval, and key management |
| `models` | `JsonWebKey`, `JwksDocument` — JWKS types for receipt verification key resolution |
| `operation_status` | `OperationStatus` — `StatusMonitor` implementation for long-running operation polling |
| `polling` | `DelayStrategy` (fixed / exponential), `MstPollingOptions` — configurable polling behavior |
| `api_key_auth_policy` | `ApiKeyAuthPolicy` — pipeline policy injecting `Authorization: Bearer {key}` headers |
| `transaction_not_cached_policy` | `TransactionNotCachedPolicy` — fast-retry policy (250 ms × 8) for `TransactionNotCached` 503 errors |
| `cbor_problem_details` | `CborProblemDetails` — RFC 9290 CBOR Problem Details parser for structured error responses |
| `error` | `CodeTransparencyError` — structured errors with HTTP status codes and service messages |
| `mock_transport` | `SequentialMockTransport` — mock HTTP transport for unit tests (behind `test-utils` feature) |

## Key Types

### CodeTransparencyClient

```rust
use code_transparency_client::{CodeTransparencyClient, MstPollingOptions};

// Create a client with API key authentication
let client = CodeTransparencyClient::new(
    "https://my-instance.confidential-ledger.azure.com",
    Some("my-api-key".into()),
    None, // default options
)?;

// Submit a COSE_Sign1 message and wait for receipt
let transparent_bytes = client
    .make_transparent(&cose_sign1_bytes, None)
    .await?;
```

### Entry Submission with Polling

```rust
use code_transparency_client::CodeTransparencyClient;

let client = CodeTransparencyClient::new(endpoint, api_key, None)?;

// Start the long-running operation
let poller = client.create_entry(&cose_sign1_bytes).await?;

// Poll until complete (uses default delay strategy)
let status = poller.wait().await?;
let entry_id = status.entry_id.expect("entry registered");

// Retrieve the transparent entry
let entry_bytes = client.get_entry(&entry_id).await?;
```

### Receipt Key Resolution

```rust
use code_transparency_client::CodeTransparencyClient;

// Resolve a signing key by key ID (checks cache first, then fetches JWKS)
let jwk = client.resolve_signing_key("key-id-123", &jwks_cache).await?;
```

### Custom Polling Options

```rust
use code_transparency_client::{MstPollingOptions, DelayStrategy};
use std::time::Duration;

let options = MstPollingOptions {
    delay_strategy: DelayStrategy::Exponential {
        initial: Duration::from_secs(1),
        max: Duration::from_secs(30),
    },
    max_retries: Some(20),
};

let transparent = client
    .make_transparent(&cose_bytes, Some(options))
    .await?;
```

## Error Handling

All operations return `CodeTransparencyError`:

```rust
pub enum CodeTransparencyError {
    /// HTTP or network error from the Azure pipeline.
    HttpError(azure_core::Error),
    /// Service returned a structured CBOR Problem Details response.
    ServiceError {
        status: u16,
        details: Option<CborProblemDetails>,
        message: String,
    },
    /// Operation timed out or exceeded max retries.
    PollingTimeout,
    /// CBOR/COSE deserialization failure.
    DeserializationError(String),
}
```

The `TransactionNotCachedPolicy` automatically retries 503 responses with
a `TransactionNotCached` error code up to 8 times at 250 ms intervals before
surfacing the error to the caller.

## Memory Design

- **Pipeline-based I/O**: HTTP requests flow through an `azure_core::http::Pipeline`
  with configurable policies. Response bodies are read once and owned by the caller.
- **COSE bytes are borrowed**: `create_entry()` and `make_transparent()` accept
  `&[u8]`, avoiding copies of potentially large COSE_Sign1 messages.
- **JWKS caching**: `resolve_signing_key()` checks an in-memory cache before
  making network requests, avoiding redundant fetches.

## Dependencies

- `azure_core` — HTTP pipeline, `Poller`, `StatusMonitor`, retry policies
- `cbor_primitives` — CBOR decoding for problem details and configuration
- `cose_sign1_primitives` — COSE types shared with the signing/validation stack
- `serde` / `serde_json` — JSON deserialization for JWKS responses
- `tokio` — Async runtime for HTTP operations

## Testing

Enable the `test-utils` feature to access `SequentialMockTransport` for
unit tests without network access:

```toml
[dev-dependencies]
code_transparency_client = { path = ".", features = ["test-utils"] }
```

```rust
use code_transparency_client::mock_transport::SequentialMockTransport;

let transport = SequentialMockTransport::new(vec![
    mock_response(200, cose_bytes),
    mock_response(200, receipt_bytes),
]);
```

## See Also

- [extension_packs/mst/](../) — MST trust pack using this client for receipt validation
- [extension_packs/certificates/](../../certificates/) — Certificate trust pack
- [Azure Code Transparency docs](https://learn.microsoft.com/en-us/azure/confidential-ledger/code-transparency-overview)

## License

Licensed under the [MIT License](../../../../../LICENSE).