# Validator Architecture

The Rust validator mirrors the V2 “staged pipeline” model:

1. **Key Material Resolution**
   - Runs one or more `SigningKeyResolver`s (typically contributed by trust packs).
   - Produces a single selected `SigningKey` (or fails).

2. **Signing Key Trust**
   - Evaluates a `CompiledTrustPlan` against a `TrustSubject` graph rooted at the message.
   - The compiled plan can be:
     - provided explicitly by the caller, or
     - derived from the configured trust packs' default plans.
   - Fact producers (often from packs) can observe the message and emit facts for the plan to use.

3. **Signature Verification**
   - Builds COSE `Sig_structure` and calls the selected `SigningKey`.
   - Supports detached payloads.
   - For large detached payloads with known length, can stream `Sig_structure` to reduce allocations.

4. **Post-Signature Validation**
   - Runs `PostSignatureValidator`s (e.g., policy checks that depend on trust decision + signature metadata).

## Result model

`CoseSign1ValidationResult` contains one `ValidationResult` per stage:

- `resolution`
- `trust`
- `signature`
- `post_signature_policy`
- `overall`

Each stage result can include:

- failures (with optional error codes)
- metadata (key/value)

## Bypass trust

Trust evaluation can be bypassed via `CoseSign1ValidationOptions.trust_evaluation_options.bypass_trust = true`.

This keeps signature verification enabled (useful for scenarios where trust is handled elsewhere).

## Detached payload

If the COSE message has `payload = nil`, the validator requires a detached payload via:

- `CoseSign1ValidationOptions { detached_payload: Some(DetachedPayload::Bytes(...)) }`, or
- `DetachedPayload::Provider` for a stream-like source.

See `detached-payloads.md`.
