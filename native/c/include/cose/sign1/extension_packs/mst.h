// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file mst.h
 * @brief Microsoft Secure Transparency (MST) receipt verification pack for COSE Sign1
 */

#ifndef COSE_SIGN1_MST_H
#define COSE_SIGN1_MST_H

#include <cose/sign1/validation.h>
#include <cose/sign1/trust.h>

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
cose_status_t cose_sign1_validator_builder_with_mst_pack(
    cose_sign1_validator_builder_t* builder
);

/**
 * @brief Add MST receipt verification pack with custom options
 * 
 * @param builder Validator builder handle
 * @param options Options structure (NULL for defaults)
 * @return COSE_OK on success, error code otherwise
 */
cose_status_t cose_sign1_validator_builder_with_mst_pack_ex(
    cose_sign1_validator_builder_t* builder,
    const cose_mst_trust_options_t* options
);

/**
 * @brief Trust-policy helper: require that an MST receipt is present on at least one counter-signature.
 *
 * This API is provided by the MST pack FFI library and extends `cose_sign1_trust_policy_builder_t`.
 */
cose_status_t cose_sign1_mst_trust_policy_builder_require_receipt_present(
    cose_sign1_trust_policy_builder_t* policy_builder
);

/**
 * @brief Trust-policy helper: require that an MST receipt is not present on at least one counter-signature.
 *
 * This API is provided by the MST pack FFI library and extends `cose_sign1_trust_policy_builder_t`.
 */
cose_status_t cose_sign1_mst_trust_policy_builder_require_receipt_not_present(
    cose_sign1_trust_policy_builder_t* policy_builder
);

/**
 * @brief Trust-policy helper: require that the MST receipt signature verified.
 *
 * This API is provided by the MST pack FFI library and extends `cose_sign1_trust_policy_builder_t`.
 */
cose_status_t cose_sign1_mst_trust_policy_builder_require_receipt_signature_verified(
    cose_sign1_trust_policy_builder_t* policy_builder
);

/**
 * @brief Trust-policy helper: require that the MST receipt signature did not verify.
 *
 * This API is provided by the MST pack FFI library and extends `cose_sign1_trust_policy_builder_t`.
 */
cose_status_t cose_sign1_mst_trust_policy_builder_require_receipt_signature_not_verified(
    cose_sign1_trust_policy_builder_t* policy_builder
);

/**
 * @brief Trust-policy helper: require that the MST receipt issuer contains the provided substring.
 *
 * This API is provided by the MST pack FFI library and extends `cose_sign1_trust_policy_builder_t`.
 */
cose_status_t cose_sign1_mst_trust_policy_builder_require_receipt_issuer_contains(
    cose_sign1_trust_policy_builder_t* policy_builder,
    const char* needle_utf8
);

/**
 * @brief Trust-policy helper: require that the MST receipt issuer equals the provided value.
 *
 * This API is provided by the MST pack FFI library and extends `cose_sign1_trust_policy_builder_t`.
 */
cose_status_t cose_sign1_mst_trust_policy_builder_require_receipt_issuer_eq(
    cose_sign1_trust_policy_builder_t* policy_builder,
    const char* issuer_utf8
);

/**
 * @brief Trust-policy helper: require that the MST receipt key id (kid) equals the provided value.
 *
 * This API is provided by the MST pack FFI library and extends `cose_sign1_trust_policy_builder_t`.
 */
cose_status_t cose_sign1_mst_trust_policy_builder_require_receipt_kid_eq(
    cose_sign1_trust_policy_builder_t* policy_builder,
    const char* kid_utf8
);

/**
 * @brief Trust-policy helper: require that the MST receipt key id (kid) contains the provided substring.
 *
 * This API is provided by the MST pack FFI library and extends `cose_sign1_trust_policy_builder_t`.
 */
cose_status_t cose_sign1_mst_trust_policy_builder_require_receipt_kid_contains(
    cose_sign1_trust_policy_builder_t* policy_builder,
    const char* needle_utf8
);

/**
 * @brief Trust-policy helper: require that the MST receipt is trusted.
 *
 * This API is provided by the MST pack FFI library and extends `cose_sign1_trust_policy_builder_t`.
 */
cose_status_t cose_sign1_mst_trust_policy_builder_require_receipt_trusted(
    cose_sign1_trust_policy_builder_t* policy_builder
);

/**
 * @brief Trust-policy helper: require that the MST receipt is not trusted.
 *
 * This API is provided by the MST pack FFI library and extends `cose_sign1_trust_policy_builder_t`.
 */
cose_status_t cose_sign1_mst_trust_policy_builder_require_receipt_not_trusted(
    cose_sign1_trust_policy_builder_t* policy_builder
);

/**
 * @brief Trust-policy helper: require that the MST receipt is trusted and the issuer contains the provided substring.
 *
 * This API is provided by the MST pack FFI library and extends `cose_sign1_trust_policy_builder_t`.
 */
cose_status_t cose_sign1_mst_trust_policy_builder_require_receipt_trusted_from_issuer_contains(
    cose_sign1_trust_policy_builder_t* policy_builder,
    const char* needle_utf8
);

/**
 * @brief Trust-policy helper: require that the MST receipt statement SHA-256 equals the provided hex string.
 *
 * This API is provided by the MST pack FFI library and extends `cose_sign1_trust_policy_builder_t`.
 */
cose_status_t cose_sign1_mst_trust_policy_builder_require_receipt_statement_sha256_eq(
    cose_sign1_trust_policy_builder_t* policy_builder,
    const char* sha256_hex_utf8
);

/**
 * @brief Trust-policy helper: require that the MST receipt statement coverage equals the provided value.
 *
 * This API is provided by the MST pack FFI library and extends `cose_sign1_trust_policy_builder_t`.
 */
cose_status_t cose_sign1_mst_trust_policy_builder_require_receipt_statement_coverage_eq(
    cose_sign1_trust_policy_builder_t* policy_builder,
    const char* coverage_utf8
);

/**
 * @brief Trust-policy helper: require that the MST receipt statement coverage contains the provided substring.
 *
 * This API is provided by the MST pack FFI library and extends `cose_sign1_trust_policy_builder_t`.
 */
cose_status_t cose_sign1_mst_trust_policy_builder_require_receipt_statement_coverage_contains(
    cose_sign1_trust_policy_builder_t* policy_builder,
    const char* needle_utf8
);

// ============================================================================
// MST Transparency Client Signing Support
// ============================================================================

/**
 * @brief Opaque handle for MST transparency client
 */
typedef struct MstClientHandle MstClientHandle;

/**
 * @brief Creates a new MST transparency client
 *
 * @param endpoint The base URL of the transparency service (required, null-terminated C string)
 * @param api_version Optional API version string (NULL = use default "2024-01-01")
 * @param api_key Optional API key for authentication (NULL = unauthenticated)
 * @param out_client Output pointer for the created client handle
 * @return COSE_OK on success, COSE_ERR on failure
 *
 * @note Caller must free the returned client with cose_mst_client_free()
 * @note Use cose_last_error_message_utf8() to get error details on failure
 */
cose_status_t cose_mst_client_new(
    const char* endpoint,
    const char* api_version,
    const char* api_key,
    MstClientHandle** out_client
);

/**
 * @brief Frees an MST transparency client handle
 *
 * @param client The client handle to free (NULL is safe)
 */
void cose_mst_client_free(MstClientHandle* client);

/**
 * @brief Makes a COSE_Sign1 message transparent by submitting it to the MST service
 *
 * This is a convenience function that combines create_entry and get_entry_statement.
 *
 * @param client The MST transparency client handle
 * @param cose_bytes The COSE_Sign1 message bytes to submit
 * @param cose_len Length of the COSE bytes
 * @param out_bytes Output pointer for the transparency statement bytes
 * @param out_len Output pointer for the statement length
 * @return COSE_OK on success, COSE_ERR on failure
 *
 * @note Caller must free the returned bytes with cose_mst_bytes_free()
 * @note Use cose_last_error_message_utf8() to get error details on failure
 */
cose_status_t cose_sign1_mst_make_transparent(
    const MstClientHandle* client,
    const uint8_t* cose_bytes,
    size_t cose_len,
    uint8_t** out_bytes,
    size_t* out_len
);

/**
 * @brief Creates a transparency entry by submitting a COSE_Sign1 message
 *
 * This function submits the COSE message, polls for completion, and returns
 * both the operation ID and the final entry ID.
 *
 * @param client The MST transparency client handle
 * @param cose_bytes The COSE_Sign1 message bytes to submit
 * @param cose_len Length of the COSE bytes
 * @param out_operation_id Output pointer for the operation ID string
 * @param out_entry_id Output pointer for the entry ID string
 * @return COSE_OK on success, COSE_ERR on failure
 *
 * @note Caller must free the returned strings with cose_mst_string_free()
 * @note Use cose_last_error_message_utf8() to get error details on failure
 */
cose_status_t cose_sign1_mst_create_entry(
    const MstClientHandle* client,
    const uint8_t* cose_bytes,
    size_t cose_len,
    char** out_operation_id,
    char** out_entry_id
);

/**
 * @brief Gets the transparency statement for an entry
 *
 * @param client The MST transparency client handle
 * @param entry_id The entry ID (null-terminated C string)
 * @param out_bytes Output pointer for the statement bytes
 * @param out_len Output pointer for the statement length
 * @return COSE_OK on success, COSE_ERR on failure
 *
 * @note Caller must free the returned bytes with cose_mst_bytes_free()
 * @note Use cose_last_error_message_utf8() to get error details on failure
 */
cose_status_t cose_sign1_mst_get_entry_statement(
    const MstClientHandle* client,
    const char* entry_id,
    uint8_t** out_bytes,
    size_t* out_len
);

/**
 * @brief Frees bytes previously returned by MST client functions
 *
 * @param ptr Pointer to bytes to free (NULL is safe)
 * @param len Length of the bytes
 */
void cose_mst_bytes_free(uint8_t* ptr, size_t len);

/**
 * @brief Frees a string previously returned by MST client functions
 *
 * @param s Pointer to string to free (NULL is safe)
 */
void cose_mst_string_free(char* s);

#ifdef __cplusplus
}
#endif

#endif // COSE_SIGN1_MST_H
