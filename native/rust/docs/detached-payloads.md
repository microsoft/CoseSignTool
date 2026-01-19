# Detached Payloads + Streaming

## When detached payloads happen

COSE_Sign1 can be encoded with `payload = nil`, meaning the content is supplied out-of-band.

The validator treats `payload = nil` as “detached content required”.

## How to provide detached content

`CoseSign1ValidationOptions` supports:

- `DetachedPayload::Bytes(Arc<[u8]>)` for small payloads
- `DetachedPayload::Provider(Arc<dyn DetachedPayloadProvider>)` for stream-like sources

A provider must support opening a fresh `Read` each time the validator needs the payload.

## Streaming-friendly signature verification

Signature verification needs `Sig_structure`, which includes a CBOR byte-string that contains the payload.

For large payloads with a known length hint, the validator can build a streaming `Sig_structure` reader that:

- writes the CBOR structure framing
- streams the payload bytes into the byte string

To take advantage of this:

- Supply `DetachedPayload::Provider` with a correct `len_hint()`.
- Ensure `len_hint() > LARGE_STREAM_THRESHOLD`.
- Provide a `SigningKey` implementation that overrides `verify_reader(...)`.

If `verify_reader` is not overridden, the default implementation will buffer into memory.

## Example

See `cose_sign1_validation/examples/detached_payload_provider.rs`.
