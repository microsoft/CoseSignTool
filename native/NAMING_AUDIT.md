# FFI Naming Convention — Reference

> **Status**: ✅ Audit complete — all symbols renamed. This document records the final convention.

## Two-Tier Prefix System

| Tier | Prefix | Scope | Examples |
|------|--------|-------|---------|
| 1 | `cose_` | Generic COSE (not Sign1-specific) | `cose_status_t`, `cose_string_free`, `cose_last_error_message_utf8`, `cose_headermap_*`, `cose_key_*`, `cose_crypto_*`, `cose_cwt_*`, `cose_cert_local_*`, `cose_akv_key_client_*`, `cose_mst_client_*` |
| 2 | `cose_sign1_` | Sign1-specific operations | `cose_sign1_message_*`, `cose_sign1_builder_*`, `cose_sign1_factory_*`, `cose_sign1_validator_*`, `cose_sign1_trust_*`, `cose_sign1_certificates_trust_policy_builder_require_*`, `cose_sign1_mst_trust_policy_builder_require_*` |
| — | `did_x509_` | DID:x509 (separate RFC domain) | `did_x509_parse`, `did_x509_validate`, `did_x509_resolve` |

## C++ Namespace Mapping

| Tier | Namespace | Examples |
|------|-----------|---------|
| 1 | `cose::` | `cose::CoseHeaderMap`, `cose::CoseKey`, `cose::cose_error`, `cose::CryptoProvider` |
| 2 | `cose::sign1::` | `cose::sign1::CoseSign1Message`, `cose::sign1::ValidatorBuilder`, `cose::sign1::CwtClaims` |

## C/C++ Header Mapping

| Rust FFI Crate | C Header | C++ Header |
|----------------|----------|------------|
| `cose_sign1_primitives_ffi` | `<cose/sign1.h>` | `<cose/sign1.hpp>` |
| `cose_sign1_crypto_openssl_ffi` | `<cose/crypto/openssl.h>` | `<cose/crypto/openssl.hpp>` |
| `cose_sign1_signing_ffi` | `<cose/sign1/signing.h>` | `<cose/sign1/signing.hpp>` |
| `cose_sign1_factories_ffi` | `<cose/sign1/factories.h>` | `<cose/sign1/factories.hpp>` |
| `cose_sign1_headers_ffi` | `<cose/sign1/cwt.h>` | `<cose/sign1/cwt.hpp>` |
| `cose_sign1_validation_ffi` | `<cose/sign1/validation.h>` | `<cose/sign1/validation.hpp>` |
| `cose_sign1_validation_primitives_ffi` | `<cose/sign1/trust.h>` | `<cose/sign1/trust.hpp>` |
| `cose_sign1_certificates_ffi` | `<cose/sign1/extension_packs/certificates.h>` | `<cose/sign1/extension_packs/certificates.hpp>` |
| `cose_sign1_certificates_local_ffi` | `<cose/sign1/extension_packs/certificates_local.h>` | `<cose/sign1/extension_packs/certificates_local.hpp>` |
| `cose_sign1_azure_key_vault_ffi` | `<cose/sign1/extension_packs/azure_key_vault.h>` | `<cose/sign1/extension_packs/azure_key_vault.hpp>` |
| `cose_sign1_transparent_mst_ffi` | `<cose/sign1/extension_packs/mst.h>` | `<cose/sign1/extension_packs/mst.hpp>` |
| `did_x509_ffi` | `<cose/did/x509.h>` | `<cose/did/x509.hpp>` |

## Decision Log

| Decision | Rationale |
|----------|-----------|
| Header maps use `cose_` (not `cose_sign1_`) | Header maps are a generic COSE concept from RFC 9052, not Sign1-specific |
| Keys use `cose_` | Keys are used across COSE structures, not just Sign1 |
| CWT claims use `cose_cwt_` | CWT (RFC 8392) is a generic CBOR token standard |
| Crypto providers use `cose_crypto_` | Crypto is a shared concern below the Sign1 layer |
| Trust policy builders use `cose_sign1_` | Trust policies evaluate Sign1 messages specifically |
| Pack-specific helpers use `cose_sign1_{pack}_` | They compose into Sign1 trust policies |
| DID:x509 uses `did_x509_` | DID is a separate W3C specification family |
