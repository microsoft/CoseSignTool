# Azure Key Vault Pack

Crate: `cose_sign1_validation_azure_key_vault`

This pack inspects the COSE `kid` header (label `4`) and emits facts related to Azure Key Vault key identifiers.

## What it produces (Message subject)

- `AzureKeyVaultKidDetectedFact` (does `kid` look like an AKV key id?)
- `AzureKeyVaultKidAllowedFact` (matches allowed patterns?)

Patterns support:

- simple wildcards (`*` and `?`)
- `regex:<pattern>` for full regex

## Example

A runnable example that sets a `kid` header and evaluates the facts:

- `cose_sign1_validation_azure_key_vault/examples/akv_kid_allowed.rs`
