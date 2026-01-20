// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file cose_sign1.h
 * @brief C API for COSE Sign1 validation
 * 
 * This header provides the base validation API. To use specific trust packs,
 * include the corresponding pack header (cose_certificates.h, cose_mst.h, etc.)
 */

#ifndef COSE_SIGN1_H
#define COSE_SIGN1_H

#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ABI version for compatibility checking
#define COSE_ABI_VERSION 1

/**
 * @brief Status codes returned by COSE API functions
 */
typedef enum {
    COSE_OK = 0,           ///< Operation succeeded
    COSE_ERR = 1,          ///< Operation failed (check cose_last_error_message_utf8)
    COSE_PANIC = 2,        ///< Rust panic occurred (should not happen in normal usage)
    COSE_INVALID_ARG = 3   ///< Invalid argument passed (e.g., null pointer)
} cose_status_t;

/**
 * @brief Opaque handle to a validator builder
 */
typedef struct cose_validator_builder_t cose_validator_builder_t;

/**
 * @brief Opaque handle to a validator
 */
typedef struct cose_validator_t cose_validator_t;

/**
 * @brief Opaque handle to a validation result
 */
typedef struct cose_validation_result_t cose_validation_result_t;

/**
 * @brief Get the ABI version of this library
 * @return ABI version number (currently 1)
 */
unsigned int cose_ffi_abi_version(void);

/**
 * @brief Get the last error message for the current thread
 * 
 * This function returns a newly-allocated UTF-8 string containing the last error
 * message. The caller must free it using cose_string_free().
 * 
 * @return Newly-allocated error message string, or NULL if no error
 */
char* cose_last_error_message_utf8(void);

/**
 * @brief Clear the last error message for the current thread
 */
void cose_last_error_clear(void);

/**
 * @brief Free a string returned by this library
 * @param s String to free (can be NULL)
 */
void cose_string_free(char* s);

/**
 * @brief Create a new validator builder
 * @param out Output parameter for the builder handle
 * @return COSE_OK on success, error code otherwise
 */
cose_status_t cose_validator_builder_new(cose_validator_builder_t** out);

/**
 * @brief Free a validator builder
 * @param builder Builder to free (can be NULL)
 */
void cose_validator_builder_free(cose_validator_builder_t* builder);

/**
 * @brief Build a validator from the builder
 * @param builder Builder handle
 * @param out Output parameter for the validator handle
 * @return COSE_OK on success, error code otherwise
 */
cose_status_t cose_validator_builder_build(
    cose_validator_builder_t* builder,
    cose_validator_t** out
);

/**
 * @brief Free a validator
 * @param validator Validator to free (can be NULL)
 */
void cose_validator_free(cose_validator_t* validator);

/**
 * @brief Validate COSE Sign1 bytes
 * 
 * @param validator Validator handle
 * @param cose_bytes COSE Sign1 message bytes
 * @param cose_bytes_len Length of cose_bytes
 * @param detached_payload Detached payload bytes (NULL if embedded)
 * @param detached_payload_len Length of detached_payload (0 if embedded)
 * @param out_result Output parameter for the validation result
 * @return COSE_OK on success, error code otherwise
 */
cose_status_t cose_validator_validate_bytes(
    const cose_validator_t* validator,
    const unsigned char* cose_bytes,
    size_t cose_bytes_len,
    const unsigned char* detached_payload,
    size_t detached_payload_len,
    cose_validation_result_t** out_result
);

/**
 * @brief Free a validation result
 * @param result Result to free (can be NULL)
 */
void cose_validation_result_free(cose_validation_result_t* result);

/**
 * @brief Check if validation was successful
 * @param result Validation result handle
 * @param out_ok Output parameter for success status
 * @return COSE_OK on success, error code otherwise
 */
cose_status_t cose_validation_result_is_success(
    const cose_validation_result_t* result,
    bool* out_ok
);

/**
 * @brief Get failure message from validation result
 * 
 * Returns NULL if validation succeeded. The caller must free the returned
 * string using cose_string_free().
 * 
 * @param result Validation result handle
 * @return Newly-allocated failure message, or NULL if validation succeeded
 */
char* cose_validation_result_failure_message_utf8(
    const cose_validation_result_t* result
);

#ifdef __cplusplus
}
#endif

#endif // COSE_SIGN1_H
