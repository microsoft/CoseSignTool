# Demo Executable

Crate: `cose_sign1_validation_demo`

This is a small runnable example binary that demonstrates how to wire the validator.

## Build and run

From `native/rust/`:

- `cargo run -p cose_sign1_validation_demo -- --help`

## Safety note
This demo validates real signatures using the certificates trust pack.

To keep the demo deterministic and OS-agnostic, it treats embedded `x5chain` as trusted by default
(see `CertificateTrustOptions.trust_embedded_chain_as_trusted`).

## Common commands

- Run an end-to-end self test (generate ephemeral ES256 cert, sign, validate, pin thumbprint):
  - `cargo run -p cose_sign1_validation_demo -- selftest`

- Validate a COSE_Sign1 file:
  - `cargo run -p cose_sign1_validation_demo -- validate --cose path/to/message.cbor`

- Validate a detached payload message:
  - `cargo run -p cose_sign1_validation_demo -- validate --cose path/to/message.cbor --detached path/to/payload.bin`

- Pin trust to a specific signing certificate thumbprint (SHA1 hex):
  - `cargo run -p cose_sign1_validation_demo -- validate --cose path/to/message.cbor --allow-thumbprint <SHA1_HEX>`
