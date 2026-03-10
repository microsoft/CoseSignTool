// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file cose.hpp
 * @brief Convenience umbrella header — includes all available COSE C++ wrappers.
 *
 * Individual headers can be included directly for finer control:
 *   - `<cose/sign1.hpp>`                          — Sign1 message primitives
 *   - `<cose/sign1/validation.hpp>`               — Validator builder/runner
 *   - `<cose/sign1/trust.hpp>`                    — Trust plan/policy authoring
 *   - `<cose/sign1/signing.hpp>`                  — Builder, factory, signing service
 *   - `<cose/sign1/factories.hpp>`                — Multi-factory wrapper
 *   - `<cose/sign1/cwt.hpp>`                      — CWT claims builder
 *   - `<cose/sign1/extension_packs/certificates.hpp>`
 *   - `<cose/sign1/extension_packs/azure_key_vault.hpp>`
 *   - `<cose/sign1/extension_packs/mst.hpp>`
 *   - `<cose/crypto/openssl.hpp>`                 — OpenSSL crypto provider
 *   - `<cose/did/x509.hpp>`                       — DID:x509 utilities
 */

#ifndef COSE_HPP
#define COSE_HPP

// Always available — validation is the base layer
#include <cose/sign1/validation.hpp>

// Optional pack headers — include only when the corresponding FFI library is linked
#ifdef COSE_HAS_CERTIFICATES_PACK
#include <cose/sign1/extension_packs/certificates.hpp>
#endif

#ifdef COSE_HAS_MST_PACK
#include <cose/sign1/extension_packs/mst.hpp>
#endif

#ifdef COSE_HAS_AKV_PACK
#include <cose/sign1/extension_packs/azure_key_vault.hpp>
#endif

#ifdef COSE_HAS_ATS_PACK
#include <cose/sign1/extension_packs/azure_trusted_signing.hpp>
#endif

#ifdef COSE_HAS_TRUST_PACK
#include <cose/sign1/trust.hpp>
#endif

#ifdef COSE_HAS_SIGNING
#include <cose/sign1/signing.hpp>
#endif

#ifdef COSE_HAS_DID_X509
#include <cose/did/x509.hpp>
#endif

#ifdef COSE_HAS_PRIMITIVES
#include <cose/sign1.hpp>
#endif

#ifdef COSE_HAS_CERTIFICATES_LOCAL
#include <cose/sign1/extension_packs/certificates_local.hpp>
#endif

#ifdef COSE_HAS_CRYPTO_OPENSSL
#include <cose/crypto/openssl.hpp>
#endif

#ifdef COSE_HAS_FACTORIES
#include <cose/sign1/factories.hpp>
#endif

#ifdef COSE_HAS_CWT_HEADERS
#include <cose/sign1/cwt.hpp>
#endif

// Re-export cose::sign1 names into cose namespace for convenience.
// This allows callers to write cose::ValidatorBuilder instead of cose::sign1::ValidatorBuilder.
namespace cose { using namespace cose::sign1; }

#endif // COSE_HPP
