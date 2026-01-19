# Trust Subjects + Stable IDs

A `TrustSubject` is the node identity the trust engine evaluates.

Subjects form a graph rooted at the message:

- `Message`
- `PrimarySigningKey` (derived from message)
- `CounterSignature` (derived from message + countersignature bytes)
- `CounterSignatureSigningKey` (derived from message + countersignature)

## Why subjects matter

- Facts are stored per subject, so packs can emit different facts for different subjects.
- Plans and rules can target specific subjects.

## Stable IDs

Subject IDs follow V2 parity semantics and are stable across runs:

- Message subject IDs are derived from SHA-256 hashes of input bytes (or caller-provided seed)
- Derived subjects (e.g., counter-signature) use SHA-256 of concatenations / raw bytes, matching V2 behavior

## Creating subjects

Prefer the constructor helpers:

- `TrustSubject::message(encoded_cose_sign1_bytes)`
- `TrustSubject::primary_signing_key(&message_subject)`
- `TrustSubject::counter_signature(&message_subject, raw_countersignature_bytes)`
- `TrustSubject::counter_signature_signing_key(&counter_signature_subject)`

These helpers ensure IDs match the stable V2-style derivation.

If you need a custom root subject (not derived from a message), use:

- `TrustSubject::root(kind, seed)`
