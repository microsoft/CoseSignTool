# Packs (C++)

The convenience header `<cose/cose.hpp>` includes the core validator API plus any enabled pack headers.

Packs are enabled via vcpkg features and appear as:

- `COSE_HAS_CERTIFICATES_PACK` → `<cose/sign1/extension_packs/certificates.hpp>`
- `COSE_HAS_MST_PACK` → `<cose/sign1/extension_packs/mst.hpp>`
- `COSE_HAS_AKV_PACK` → `<cose/sign1/extension_packs/azure_key_vault.hpp>`
- `COSE_HAS_TRUST_PACK` → `<cose/sign1/trust.hpp>`

## Registering packs

Register packs on a `ValidatorBuilder` via composable free functions:

```cpp
cose::ValidatorBuilder builder;

// Default options
cose::WithCertificates(builder);

// Custom options
cose::CertificateOptions opts;
opts.trust_embedded_chain_as_trusted = true;
cose::WithCertificates(builder, opts);
```

Multiple packs can be registered on the same builder:

```cpp
cose::WithCertificates(builder);
cose::WithMst(builder);
cose::WithAzureKeyVault(builder);
```

## Pack-specific trust policy helpers

Each pack provides free functions that add requirements to a `TrustPolicyBuilder`:

```cpp
cose::TrustPolicyBuilder policy(builder);

// Core (message-scope) requirements are methods:
policy.RequireCwtClaimsPresent().And();

// Pack-specific requirements are free functions:
cose::RequireX509ChainTrusted(policy);
policy.And();
cose::RequireMstReceiptTrusted(policy);
```

Available helpers:

| Pack | Prefix | Example |
|------|--------|---------|
| Certificates | `RequireX509*`, `RequireSigningCertificate*`, `RequireChainElement*` | `RequireX509ChainTrusted(policy)` |
| MST | `RequireMst*` | `RequireMstReceiptTrusted(policy)` |
| AKV | `RequireAzureKeyVault*` | `RequireAzureKeyVaultKid(policy)` |

See each pack header for the full list of helpers.
