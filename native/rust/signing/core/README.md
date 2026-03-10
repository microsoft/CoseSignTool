# cose_sign1_signing

Core signing abstractions for COSE_Sign1 messages.

## Overview

This crate provides traits and types for building signing services and managing
signing operations with COSE_Sign1 messages. It maps V2 C# signing abstractions
to Rust.

## Features

- **SigningService trait** - Abstraction for signing services (local or remote)
- **SigningServiceKey trait** - Signing key with service context
- **HeaderContributor trait** - Extensible header management pattern
- **SigningContext** - Context for signing operations
- **CoseSigner** - Signer returned by signing service

## Key Traits

### SigningService

Maps V2 `ISigningService<TSigningOptions>`:

```rust
pub trait SigningService: Send + Sync {
    fn get_cose_signer(&self, context: &SigningContext) -> Result<CoseSigner, SigningError>;
    fn is_remote(&self) -> bool;
    fn service_metadata(&self) -> &SigningServiceMetadata;
    fn verify_signature(&self, message_bytes: &[u8], context: &SigningContext) -> Result<bool, SigningError>;
}
```

### HeaderContributor

Maps V2 `IHeaderContributor`:

```rust
pub trait HeaderContributor: Send + Sync {
    fn merge_strategy(&self) -> HeaderMergeStrategy;
    fn contribute_protected_headers(&self, headers: &mut CoseHeaderMap, context: &HeaderContributorContext);
    fn contribute_unprotected_headers(&self, headers: &mut CoseHeaderMap, context: &HeaderContributorContext);
}
```

## Modules

| Module | Description |
|--------|-------------|
| `traits` | Core signing traits |
| `context` | Signing context types |
| `options` | Signing options |
| `metadata` | Signing key/service metadata |
| `signer` | Signer types |
| `error` | Error types |
| `extensions` | Extension traits |

## Usage

```rust
use cose_sign1_signing::{SigningService, SigningContext, CoseSigner};

// Implement SigningService for your key provider
struct MySigningService { /* ... */ }

impl SigningService for MySigningService {
    fn get_cose_signer(&self, context: &SigningContext) -> Result<CoseSigner, SigningError> {
        // Return appropriate signer
    }
    // ...
}
```

## Dependencies

This crate has minimal dependencies:

- `cose_sign1_primitives` - Core COSE types
- `cbor_primitives` - CBOR provider abstraction
- `thiserror` - Error derive macros

## See Also

- [Signing Flow](../docs/signing_flow.md)
- [cose_sign1_factories](../cose_sign1_factories/) - Factory patterns using these traits