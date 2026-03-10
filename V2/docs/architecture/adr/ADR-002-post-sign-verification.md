# ADR-002: Post-Sign Verification

## Status

Accepted

## Context

After signing a payload with a COSE Sign1 message, the resulting signature must be valid before it is returned to the caller. A corrupted or invalid signature—caused by key mismatches, encoding errors, or transient infrastructure failures—would be costly to detect downstream and could compromise supply-chain integrity.

The .NET `CoseSigner` class does not expose its `CoseKey` as a public property; the key is internal to the signer and cannot be extracted by the factory after signing. This means the factory layer cannot independently perform cryptographic verification using the signer's key. Instead, verification must be delegated to a component that has access to the appropriate key material.

## Decision

The `DirectSignatureFactory` performs **post-sign verification** immediately after every signing operation by calling `ISigningService.VerifySignature(CoseSign1Message, SigningContext)`. If verification fails, a `SignatureVerificationException` is thrown and no signed message is returned.

### Method Signature

```csharp
/// <summary>
/// Verifies a signature created by this signing service.
/// Used by factories to perform post-sign verification.
/// </summary>
/// <param name="message">The COSE Sign1 message to verify.</param>
/// <param name="context">The signing context used to create the signature.</param>
/// <returns>True if the signature is valid; otherwise false.</returns>
bool VerifySignature(CoseSign1Message message, SigningContext context);
```

### Behavior

The `CertificateSigningService.VerifySignature` implementation handles three verification scenarios:

1. **Local signing with embedded payload** — Uses the signing key (`ISigningKey.GetCoseKey()`) to call `CoseSign1Message.VerifyEmbedded(CoseKey)`.
2. **Local signing with detached payload** — Uses the signing key to call `CoseSign1Message.VerifyDetached(CoseKey, byte[])`, obtaining the payload bytes from the `SigningContext`.
3. **Remote signing (e.g., Azure Key Vault)** — The signing key is not locally available. Verification uses the certificate's public key extracted from the COSE message headers via the `CoseSign1Message.VerifySignature` extension method.

## Rationale

- **CoseSigner doesn't expose CoseKey.** The `CoseKey` used during signing is an internal property of `CoseSigner`. The factory cannot access it directly, so it cannot verify the signature on its own.
- **The service owns both signing and verification.** The `ISigningService` is responsible for creating signatures and has direct access to the key material (or knows how to obtain it). Placing verification in the service ensures proper encapsulation—the key management details do not leak into the factory layer.
- **The service knows how to access its signing key.** Local services retrieve the `CoseKey` from their `ISigningKey` implementation. Remote services fall back to using the certificate public key from COSE headers. This distinction is transparent to the factory.
- **IndirectSignatureFactory inherits this behavior.** The `IndirectSignatureFactory` delegates signing to `DirectSignatureFactory`, so post-sign verification is applied consistently to both direct and indirect signatures without code duplication.

## Consequences

### Benefits

- **Guarantees signature validity.** Every signed message is verified before it leaves the factory. Callers never receive an invalid signature.
- **Fail-fast error detection.** Signing failures—key mismatches, encoding bugs, or remote service errors—are caught immediately rather than propagating to downstream verification.
- **Consistent across signing modes.** Both embedded and detached payloads, and both local and remote signing services, are verified through a single interface method.
- **Encapsulation preserved.** The factory does not need to know how keys are stored or accessed; it simply calls `VerifySignature` on the service.

### Trade-offs

- **Small performance overhead.** Each signing operation incurs an additional cryptographic verification. For local signing this is a fast in-process operation. For remote signing, the overhead is negligible relative to the network round-trip for signing itself.
- **Mock setup requirement.** Test mocks of `ISigningService` must set up `VerifySignature` to return `true`; otherwise, signing operations will throw `SignatureVerificationException`.

## Implementation

### Factory Integration

In `DirectSignatureFactory`, post-sign verification occurs immediately after `CoseSign1Message.SignEmbedded` or `CoseSign1Message.SignDetached`:

```csharp
// Post-sign verification
if (!SigningService.VerifySignature(CoseMessage.DecodeSign1(result), context))
{
    throw new SignatureVerificationException(
        ClassStrings.LogPostSignVerificationFailed, operationId);
}
```

### Key Components

| Component | Role |
|-----------|------|
| `ISigningService.VerifySignature` | Interface contract for post-sign verification |
| `CertificateSigningService.VerifySignature` | Concrete implementation handling local and remote keys |
| `DirectSignatureFactory` | Calls `VerifySignature` after every sign operation |
| `IndirectSignatureFactory` | Inherits verification via delegation to `DirectSignatureFactory` |
| `SignatureVerificationException` | Thrown when post-sign verification fails |