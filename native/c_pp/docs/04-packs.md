# Packs (C++)

The convenience header `<cose/cose.hpp>` includes the core validator API plus any enabled pack headers.

Packs are enabled via vcpkg features and appear as:

- `COSE_HAS_CERTIFICATES_PACK` → `<cose/certificates.hpp>`
- `COSE_HAS_MST_PACK` → `<cose/mst.hpp>`
- `COSE_HAS_AKV_PACK` → `<cose/azure_key_vault.hpp>`
- `COSE_HAS_TRUST_PACK` → `<cose/trust.hpp>`

Most pack APIs extend the builder surface via helper functions/classes.

If you’re authoring/attaching compiled trust plans, start with `<cose/trust.hpp>` and the underlying C trust APIs in `<cose/cose_trust.h>`.
