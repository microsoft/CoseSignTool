// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file cose_mst.h
 * @brief Microsoft Secure Transparency (MST) receipt verification pack for COSE Sign1
 */

#ifndef COSE_MST_H
#define COSE_MST_H

#include "cose_sign1.h"
#include "cose_trust.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Options for MST receipt verification
 */
typedef struct {
    /** If true, allow network fetching of JWKS when offline keys are missing */
    bool allow_network;
    
    /** Offline JWKS JSON string (NULL means no offline JWKS). Not owned by this struct. */
    const char* offline_jwks_json;
    
    /** Optional api-version for CodeTransparency /jwks endpoint (NULL means no api-version) */
    const char* jwks_api_version;
} cose_mst_trust_options_t;

/**
 * @brief Add MST receipt verification pack with default options (online mode)
 * 
 * Default options:
 * - allow_network: true
 * - No offline JWKS
 * - No api-version
 * 
 * @param builder Validator builder handle
 * @return COSE_OK on success, error code otherwise
 */
cose_status_t cose_validator_builder_with_mst_pack(
    cose_validator_builder_t* builder
);

/**
 * @brief Add MST receipt verification pack with custom options
 * 
 * @param builder Validator builder handle
 * @param options Options structure (NULL for defaults)
 * @return COSE_OK on success, error code otherwise
 */
cose_status_t cose_validator_builder_with_mst_pack_ex(
    cose_validator_builder_t* builder,
    const cose_mst_trust_options_t* options
);

/**
 * @brief Trust-policy helper: require that an MST receipt is present on at least one counter-signature.
 *
 * This API is provided by the MST pack FFI library and extends `cose_trust_policy_builder_t`.
 */
cose_status_t cose_mst_trust_policy_builder_require_receipt_present(
    cose_trust_policy_builder_t* policy_builder
);

/**
 * @brief Trust-policy helper: require that an MST receipt is not present on at least one counter-signature.
 *
 * This API is provided by the MST pack FFI library and extends `cose_trust_policy_builder_t`.
 */
cose_status_t cose_mst_trust_policy_builder_require_receipt_not_present(
    cose_trust_policy_builder_t* policy_builder
);

/**
 * @brief Trust-policy helper: require that the MST receipt signature verified.
 *
 * This API is provided by the MST pack FFI library and extends `cose_trust_policy_builder_t`.
 */
cose_status_t cose_mst_trust_policy_builder_require_receipt_signature_verified(
    cose_trust_policy_builder_t* policy_builder
);

/**
 * @brief Trust-policy helper: require that the MST receipt signature did not verify.
 *
 * This API is provided by the MST pack FFI library and extends `cose_trust_policy_builder_t`.
 */
cose_status_t cose_mst_trust_policy_builder_require_receipt_signature_not_verified(
    cose_trust_policy_builder_t* policy_builder
);

/**
 * @brief Trust-policy helper: require that the MST receipt issuer contains the provided substring.
 *
 * This API is provided by the MST pack FFI library and extends `cose_trust_policy_builder_t`.
 */
cose_status_t cose_mst_trust_policy_builder_require_receipt_issuer_contains(
    cose_trust_policy_builder_t* policy_builder,
    const char* needle_utf8
);

/**
 * @brief Trust-policy helper: require that the MST receipt issuer equals the provided value.
 *
 * This API is provided by the MST pack FFI library and extends `cose_trust_policy_builder_t`.
 */
cose_status_t cose_mst_trust_policy_builder_require_receipt_issuer_eq(
    cose_trust_policy_builder_t* policy_builder,
    const char* issuer_utf8
);

/**
 * @brief Trust-policy helper: require that the MST receipt key id (kid) equals the provided value.
 *
 * This API is provided by the MST pack FFI library and extends `cose_trust_policy_builder_t`.
 */
cose_status_t cose_mst_trust_policy_builder_require_receipt_kid_eq(
    cose_trust_policy_builder_t* policy_builder,
    const char* kid_utf8
);

/**
 * @brief Trust-policy helper: require that the MST receipt key id (kid) contains the provided substring.
 *
 * This API is provided by the MST pack FFI library and extends `cose_trust_policy_builder_t`.
 */
cose_status_t cose_mst_trust_policy_builder_require_receipt_kid_contains(
    cose_trust_policy_builder_t* policy_builder,
    const char* needle_utf8
);

/**
 * @brief Trust-policy helper: require that the MST receipt is trusted.
 *
 * This API is provided by the MST pack FFI library and extends `cose_trust_policy_builder_t`.
 */
cose_status_t cose_mst_trust_policy_builder_require_receipt_trusted(
    cose_trust_policy_builder_t* policy_builder
);

/**
 * @brief Trust-policy helper: require that the MST receipt is not trusted.
 *
 * This API is provided by the MST pack FFI library and extends `cose_trust_policy_builder_t`.
 */
cose_status_t cose_mst_trust_policy_builder_require_receipt_not_trusted(
    cose_trust_policy_builder_t* policy_builder
);

/**
 * @brief Trust-policy helper: require that the MST receipt is trusted and the issuer contains the provided substring.
 *
 * This API is provided by the MST pack FFI library and extends `cose_trust_policy_builder_t`.
 */
cose_status_t cose_mst_trust_policy_builder_require_receipt_trusted_from_issuer_contains(
    cose_trust_policy_builder_t* policy_builder,
    const char* needle_utf8
);

/**
 * @brief Trust-policy helper: require that the MST receipt statement SHA-256 equals the provided hex string.
 *
 * This API is provided by the MST pack FFI library and extends `cose_trust_policy_builder_t`.
 */
cose_status_t cose_mst_trust_policy_builder_require_receipt_statement_sha256_eq(
    cose_trust_policy_builder_t* policy_builder,
    const char* sha256_hex_utf8
);

/**
 * @brief Trust-policy helper: require that the MST receipt statement coverage equals the provided value.
 *
 * This API is provided by the MST pack FFI library and extends `cose_trust_policy_builder_t`.
 */
cose_status_t cose_mst_trust_policy_builder_require_receipt_statement_coverage_eq(
    cose_trust_policy_builder_t* policy_builder,
    const char* coverage_utf8
);

/**
 * @brief Trust-policy helper: require that the MST receipt statement coverage contains the provided substring.
 *
 * This API is provided by the MST pack FFI library and extends `cose_trust_policy_builder_t`.
 */
cose_status_t cose_mst_trust_policy_builder_require_receipt_statement_coverage_contains(
    cose_trust_policy_builder_t* policy_builder,
    const char* needle_utf8
);

#ifdef __cplusplus
}
#endif

#endif // COSE_MST_H
