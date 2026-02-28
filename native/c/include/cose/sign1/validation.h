// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file validation.h
 * @brief C API for COSE_Sign1 validation.
 *
 * Provides the validator builder/runner for verifying COSE_Sign1 messages.
 * To add trust packs, include the corresponding extension-pack header
 * (e.g., `<cose/sign1/extension_packs/certificates.h>`).
 *
 * Depends on: `<cose/cose.h>` (included automatically via `<cose/sign1.h>`).
 */

#ifndef COSE_SIGN1_VALIDATION_H
#define COSE_SIGN1_VALIDATION_H

#include <cose/cose.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================== */
/* ABI version                                                                */
/* ========================================================================== */

#define COSE_SIGN1_VALIDATION_ABI_VERSION 1

/* ========================================================================== */
/* Opaque handle types                                                        */
/* ========================================================================== */

/** @brief Opaque handle to a validator builder. Free with `cose_sign1_validator_builder_free()`. */
typedef struct cose_sign1_validator_builder_t cose_sign1_validator_builder_t;

/** @brief Opaque handle to a validator. Free with `cose_sign1_validator_free()`. */
typedef struct cose_sign1_validator_t cose_sign1_validator_t;

/** @brief Opaque handle to a validation result. Free with `cose_sign1_validation_result_free()`. */
typedef struct cose_sign1_validation_result_t cose_sign1_validation_result_t;

/* Forward declaration used by trust plan builder */
typedef struct cose_trust_policy_builder_t cose_trust_policy_builder_t;

/* ========================================================================== */
/* Validator builder                                                          */
/* ========================================================================== */

/** @brief Return the ABI version of the validation FFI library. */
unsigned int cose_sign1_validation_abi_version(void);

/** @brief Create a new validator builder. */
cose_status_t cose_sign1_validator_builder_new(cose_sign1_validator_builder_t** out);

/** @brief Free a validator builder (NULL is a safe no-op). */
void cose_sign1_validator_builder_free(cose_sign1_validator_builder_t* builder);

/** @brief Build a validator from the builder. */
cose_status_t cose_sign1_validator_builder_build(
    cose_sign1_validator_builder_t* builder,
    cose_sign1_validator_t** out
);

/* ========================================================================== */
/* Validator                                                                  */
/* ========================================================================== */

/** @brief Free a validator (NULL is a safe no-op). */
void cose_sign1_validator_free(cose_sign1_validator_t* validator);

/**
 * @brief Validate COSE_Sign1 message bytes.
 *
 * @param validator           Validator handle.
 * @param cose_bytes          Serialized COSE_Sign1 message.
 * @param cose_bytes_len      Length of cose_bytes.
 * @param detached_payload    Detached payload (NULL if embedded).
 * @param detached_payload_len Length of detached payload (0 if embedded).
 * @param out_result          Receives the validation result handle.
 * @return COSE_OK on success, error code otherwise.
 */
cose_status_t cose_sign1_validator_validate_bytes(
    const cose_sign1_validator_t* validator,
    const unsigned char* cose_bytes,
    size_t cose_bytes_len,
    const unsigned char* detached_payload,
    size_t detached_payload_len,
    cose_sign1_validation_result_t** out_result
);

/* ========================================================================== */
/* Validation result                                                          */
/* ========================================================================== */

/** @brief Free a validation result (NULL is a safe no-op). */
void cose_sign1_validation_result_free(cose_sign1_validation_result_t* result);

/**
 * @brief Check whether validation succeeded.
 *
 * @param result  Validation result handle.
 * @param out_ok  Receives true if validation passed.
 */
cose_status_t cose_sign1_validation_result_is_success(
    const cose_sign1_validation_result_t* result,
    bool* out_ok
);

/**
 * @brief Get the failure message.
 *
 * Returns NULL if validation succeeded. Caller must free with `cose_string_free()`.
 */
char* cose_sign1_validation_result_failure_message_utf8(
    const cose_sign1_validation_result_t* result
);

#ifdef __cplusplus
}
#endif

#endif /* COSE_SIGN1_VALIDATION_H */
