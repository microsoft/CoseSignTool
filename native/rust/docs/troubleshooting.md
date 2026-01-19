# Troubleshooting

## “NO_APPLICABLE_SIGNATURE_VALIDATOR”

The validator requires an `alg` value in the **protected** header (label `1`).

Ensure your COSE protected header map includes `1: <alg>`.

## “SIGNATURE_MISSING_PAYLOAD”

The COSE message has `payload = nil`.

Provide detached payload via `CoseSign1ValidationOptions.detached_payload`.

## Trust stage unexpectedly denies

- The default compiled plan denies if there are no trust sources configured.
- If you are experimenting, set `CoseSign1ValidationOptions.trust_evaluation_options.bypass_trust = true`.

## Streaming not used

Streaming `Sig_structure` construction is only used when:

- message payload is detached (payload is `nil`)
- you provided `DetachedPayload::Provider`
- the provider returns a `len_hint()`
- `len_hint() > LARGE_STREAM_THRESHOLD`

Also, to avoid buffering, your `SigningKey` should override `verify_reader`.
