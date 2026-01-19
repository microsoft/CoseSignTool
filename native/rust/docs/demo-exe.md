# Demo Executable

Crate: `cose_sign1_validation_demo`

This is a small runnable example binary that demonstrates how to wire the validator.

## Build and run

From `native/rust/`:

- `cargo run -p cose_sign1_validation_demo -- --help`

## Safety note

The demo supports an explicit **insecure** mode that accepts any signature. This is only for demonstrating the pipeline wiring.

Use a real `SigningKey` implementation in production.

## Common commands

- Validate a COSE_Sign1 file (insecure signature acceptance):
  - `cargo run -p cose_sign1_validation_demo -- validate --insecure-accept-any-signature --cose path/to/message.cbor`

- Validate a detached payload message:
  - `cargo run -p cose_sign1_validation_demo -- validate --insecure-accept-any-signature --cose path/to/message.cbor --detached path/to/payload.bin`
