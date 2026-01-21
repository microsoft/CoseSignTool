# Packs (C)

Packs are optional “trust evidence” providers (certificates, MST receipts, AKV KID rules, trust plan composition helpers).

Enable packs on a `cose_validator_builder_t*` before building the validator.

## Certificates pack

Header: `<cose/cose_certificates.h>`

- `cose_validator_builder_with_certificates_pack(builder)`
- `cose_validator_builder_with_certificates_pack_ex(builder, &options)`

## MST pack

Header: `<cose/cose_mst.h>`

- `cose_validator_builder_with_mst_pack(builder)`
- `cose_validator_builder_with_mst_pack_ex(builder, &options)`

## Azure Key Vault pack

Header: `<cose/cose_azure_key_vault.h>`

- `cose_validator_builder_with_akv_pack(builder)`
- `cose_validator_builder_with_akv_pack_ex(builder, &options)`

## Trust pack

Header: `<cose/cose_trust.h>`

The trust pack provides the trust-plan/policy authoring surface and compiled trust plan attachment.
