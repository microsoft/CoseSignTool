# cose_sign1_factories

Factory patterns for creating COSE_Sign1 messages with signing services.

## Overview

This crate provides factory implementations that map V2 C# factory patterns
for building COSE_Sign1 messages. It includes:

- **DirectSignatureFactory** - Signs payload directly (embedded or detached)
- **IndirectSignatureFactory** - Signs hash of payload (indirect signature pattern)
- **CoseSign1MessageFactory** - Router that delegates to appropriate factory

## Architecture

The factories follow V2's design where `IndirectSignatureFactory` wraps
`DirectSignatureFactory`:

1. `DirectSignatureFactory` accepts a `SigningService` that provides signers
2. `IndirectSignatureFactory` wraps a `DirectSignatureFactory` and delegates signing
3. Use `HeaderContributor` pattern for extensible header management
4. Perform post-sign verification after creating signatures
5. Support both embedded and detached payloads

## Usage

### Direct Signature

```rust
use cose_sign1_factories::{DirectSignatureFactory, DirectSignatureOptions};

let factory = DirectSignatureFactory::new(signing_service);

let options = DirectSignatureOptions::new()
    .with_embed_payload(true);

let message = factory.create(
    b"Hello, World!",
    "text/plain",
    Some(options)
)?;
```

### Indirect Signature

```rust
use cose_sign1_factories::{
    DirectSignatureFactory, IndirectSignatureFactory, 
    IndirectSignatureOptions, HashAlgorithm
};

// Option 1: Create from DirectSignatureFactory (recommended for sharing)
let direct_factory = DirectSignatureFactory::new(signing_service);
let factory = IndirectSignatureFactory::new(direct_factory);

// Option 2: Create from SigningService directly (convenience)
let factory = IndirectSignatureFactory::from_signing_service(signing_service);

let options = IndirectSignatureOptions::new()
    .with_algorithm(HashAlgorithm::Sha256);

let message = factory.create(
    b"Hello, World!",
    "text/plain",
    Some(options)
)?;
```

### Router Factory

```rust
use cose_sign1_factories::CoseSign1MessageFactory;

let factory = CoseSign1MessageFactory::new(signing_service);

// Creates direct signature
let direct = factory.create_direct(b"Hello, World!", "text/plain", None)?;

// Creates indirect signature
let indirect = factory.create_indirect(b"Hello, World!", "text/plain", None)?;
```
```

## Factory Types

### DirectSignatureFactory

- Signs the raw payload bytes
- Supports embedded payload (in message) or detached (nil payload)
- Uses `ContentTypeHeaderContributor` for content-type headers

### IndirectSignatureFactory

- Wraps a `DirectSignatureFactory` (V2 pattern)
- Computes hash of payload, signs the hash
- Supports SHA-256, SHA-384, SHA-512
- Uses `HashEnvelopeHeaderContributor` for hash envelope headers
- Delegates to the wrapped `DirectSignatureFactory` for actual signing
- Provides `direct_factory()` accessor for direct signing when needed

### CoseSign1MessageFactory

- Convenience router that owns an `IndirectSignatureFactory`
- Accesses the `DirectSignatureFactory` via the indirect factory
- Single entry point for message creation
- Routes based on method called (`create_direct` vs `create_indirect`)

## Post-sign Verification

All factories perform verification after signing:

```rust
// Internal to factory
let created_message = assemble_cose_sign1(headers, payload, signature);
if !signing_service.verify_signature(&created_message, context)? {
    return Err(FactoryError::PostSignVerificationFailed);
}
```

This catches configuration errors early (wrong algorithm, key mismatch, etc.).

## Dependencies

- `cose_sign1_signing` - Signing service traits
- `cose_sign1_primitives` - Core COSE types
- `cbor_primitives` - CBOR provider abstraction
- `sha2` - Hash algorithms
- `thiserror` - Error derive macros

## See Also

- [Signing Flow](../docs/signing_flow.md)
- [Architecture Overview](../docs/architecture.md)
- [cose_sign1_signing](../cose_sign1_signing/) - Signing traits used by factories