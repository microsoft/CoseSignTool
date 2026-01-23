# cose_sign1_validation_azure_key_vault

Trust pack that inspects the COSE `kid` header (label `4`) for Azure Key Vault key IDs and matches allow patterns.

## Example

- `cargo run -p cose_sign1_validation_azure_key_vault --example akv_kid_allowed`

Docs: [native/rust/docs/azure-key-vault-pack.md](../docs/azure-key-vault-pack.md).
