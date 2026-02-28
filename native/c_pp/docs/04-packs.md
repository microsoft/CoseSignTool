# Packs (C++)

The convenience header `<cose/cose.hpp>` includes the core validator API plus any enabled pack headers.

Packs are enabled via vcpkg features and appear as:

- `COSE_HAS_CERTIFICATES_PACK` → `<cose/sign1/extension_packs/certificates.hpp>`
- `COSE_HAS_MST_PACK` → `<cose/mst.hpp>`
- `COSE_HAS_AKV_PACK` → `<cose/azure_key_vault.hpp>`
- `COSE_HAS_TRUST_PACK` → `<cose/sign1/trust.hpp>`

Most pack APIs extend the builder surface via helper functions/classes.

If you're authoring/attaching compiled trust plans, start with `<cose/sign1/trust.hpp>` and the underlying C trust APIs in `<cose/sign1/trust.h>`.
