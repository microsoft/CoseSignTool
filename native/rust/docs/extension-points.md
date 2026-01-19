# Extension Points

The Rust port is designed to be “pack/resolver driven” like V2.

## Signing key resolution

Implement `SigningKeyResolver`:

- Input: parsed `CoseSign1` + `CoseSign1ValidationOptions`
- Output: `SigningKeyResolutionResult` (selected key + optional metadata)

Implement `SigningKey`:

- `verify(alg, sig_structure, signature)`
- Optional: override `verify_reader(...)` for streaming verification

## Counter-signatures

Counter-signatures are discovered via `CounterSignatureResolver` (resolver-driven discovery, not header parsing inside the validator).

A resolved `CounterSignature` includes:

- raw COSE_Signature bytes
- whether it was protected
- a required `signing_key()` (V2 parity)

Trust packs can target counter-signature subjects:

- `CounterSignature`
- `CounterSignatureSigningKey`

## Post-signature validators

Implement `PostSignatureValidator`:

- Input: `PostSignatureValidationContext`
  - message
  - trust decision
  - signature-stage metadata
  - resolved signing key (if any)

## Trust packs (fact producers)

Implement `cose_sign1_validation_trust::facts::TrustFactProducer`:

- You receive `TrustFactContext` containing:
  - current `TrustSubject`
  - optional message bytes / parsed message
  - header location option
- You can `observe(...)` facts for the current subject

Packs can be composed by passing multiple producers to the validator.

## Async entrypoints

Resolvers and validators have default async methods (they call the sync version by default).

This enables integrating with async environments without forcing a runtime choice into the library.
