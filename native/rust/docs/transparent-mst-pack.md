# Transparent MST Pack

Crate: `cose_sign1_validation_transparent_mst`

This pack reads MST receipt data from COSE headers and exposes facts usable in a trust plan.

## Typical use

- Add `MstTrustPack` to the list of trust fact producers.
- Add required facts + trust source rules to your `TrustPolicy`.

## Example

A minimal runnable example that embeds a receipt header and queries MST facts:

- `cose_sign1_validation_transparent_mst/examples/mst_receipt_present.rs`
