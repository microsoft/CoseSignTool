# Signing Flow

This document describes how COSE_Sign1 messages are created using the signing layer.

## Overview

The signing flow follows the V2 factory pattern:

```
Payload → SigningService → Factory → COSE_Sign1 Message
              │
              ├── SigningContext
              ├── HeaderContributors
              └── Post-sign verification
```

## Key Components

### SigningService

The `SigningService` trait provides signers and verification:

```rust
pub trait SigningService: Send + Sync {
    /// Gets a signer for the given signing context.
    fn get_cose_signer(&self, context: &SigningContext) -> Result<CoseSigner, SigningError>;

    /// Returns whether this is a remote signing service.
    fn is_remote(&self) -> bool;

    /// Verifies a signature on a message.
    fn verify_signature(
        &self,
        message_bytes: &[u8],
        context: &SigningContext,
    ) -> Result<bool, SigningError>;
}
```

### HeaderContributor

The `HeaderContributor` trait allows extensible header management:

```rust
pub trait HeaderContributor: Send + Sync {
    fn merge_strategy(&self) -> HeaderMergeStrategy;
    fn contribute_protected_headers(&self, headers: &mut CoseHeaderMap, context: &HeaderContributorContext);
    fn contribute_unprotected_headers(&self, headers: &mut CoseHeaderMap, context: &HeaderContributorContext);
}
```

## Factory Types

### DirectSignatureFactory

Signs the payload directly (embedded or detached):

```rust
let factory = DirectSignatureFactory::new(signing_service);
let message = factory.create(
    payload,
    "application/json",
    Some(DirectSignatureOptions::new().with_embed_payload(true))
)?;
```

### IndirectSignatureFactory

Signs a hash of the payload (indirect signature pattern). Wraps a `DirectSignatureFactory`:

```rust
// Option 1: Create from DirectSignatureFactory (shares instance)
let direct_factory = DirectSignatureFactory::new(signing_service);
let factory = IndirectSignatureFactory::new(direct_factory);

// Option 2: Create from SigningService (convenience)
let factory = IndirectSignatureFactory::from_signing_service(signing_service);

let message = factory.create(
    payload,
    "application/json",
    Some(IndirectSignatureOptions::new().with_algorithm(HashAlgorithm::Sha256))
)?;
```

### CoseSign1MessageFactory

Router that delegates to the appropriate sub-factory:

```rust
let factory = CoseSign1MessageFactory::new(signing_service);

// Direct signature
let direct_msg = factory.create_direct(payload, content_type, None)?;

// Indirect signature
let indirect_msg = factory.create_indirect(payload, content_type, None)?;
```

## Signing Sequence

1. **Context Creation**: Build `SigningContext` with payload metadata
2. **Signer Acquisition**: Call `signing_service.get_cose_signer(context)`
3. **Header Contribution**: Run header contributors to build protected/unprotected headers
4. **Sig_structure Build**: Construct RFC 9052 `Sig_structure`
5. **Signing**: Sign the serialized `Sig_structure`
6. **Message Assembly**: Combine headers, payload, signature into COSE_Sign1
7. **Post-sign Verification**: Verify the created signature (catches configuration errors)

## Post-sign Verification

The factory performs verification after signing to catch errors early:

```rust
// Internal to factory
let message_bytes = assemble_message(headers, payload, signature)?;
if !signing_service.verify_signature(&message_bytes, context)? {
    return Err(FactoryError::PostSignVerificationFailed);
}
```

## See Also

- [Architecture Overview](../../ARCHITECTURE.md)
- [FFI Guide](ffi_guide.md)
- [cose_sign1_signing README](../cose_sign1_signing/README.md)
- [cose_sign1_factories README](../cose_sign1_factories/README.md)