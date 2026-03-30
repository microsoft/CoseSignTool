// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file cwt.h
 * @brief C API for CWT (CBOR Web Token) claims creation and management.
 *
 * This header provides functions for building, serializing, and deserializing
 * CWT claims (RFC 8392) that can be embedded in COSE_Sign1 protected headers.
 *
 * ## Error Handling
 *
 * All functions return `int32_t` status codes (0 = success, negative = error).
 * Rich error details are available via `CoseCwtErrorHandle`.
 *
 * ## Memory Management
 *
 * - `cose_cwt_claims_free()` for claims handles.
 * - `cose_cwt_error_free()` for error handles.
 * - `cose_cwt_string_free()` for string pointers.
 * - `cose_cwt_bytes_free()` for byte buffer pointers.
 */

#ifndef COSE_SIGN1_CWT_H
#define COSE_SIGN1_CWT_H

#include <cose/cose.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================== */
/* ABI version                                                                */
/* ========================================================================== */

#define COSE_CWT_ABI_VERSION 1

/* ========================================================================== */
/* CWT-specific status codes                                                  */
/* ========================================================================== */

#define COSE_CWT_OK                     0
#define COSE_CWT_ERR_NULL_POINTER      -1
#define COSE_CWT_ERR_CBOR_ENCODE       -2
#define COSE_CWT_ERR_CBOR_DECODE       -3
#define COSE_CWT_ERR_INVALID_ARGUMENT  -5
#define COSE_CWT_ERR_PANIC            -99

/* ========================================================================== */
/* Opaque handle types                                                        */
/* ========================================================================== */

/** @brief Opaque handle to a CWT claims set. Free with `cose_cwt_claims_free()`. */
typedef struct CoseCwtClaimsHandle CoseCwtClaimsHandle;

/** @brief Opaque handle to a CWT error. Free with `cose_cwt_error_free()`. */
typedef struct CoseCwtErrorHandle CoseCwtErrorHandle;

/* ========================================================================== */
/* ABI version                                                                */
/* ========================================================================== */

/** @brief Return the ABI version of the CWT headers FFI library. */
uint32_t cose_cwt_claims_abi_version(void);

/* ========================================================================== */
/* Error handling                                                             */
/* ========================================================================== */

/** @brief Get the error code from a CWT error handle. */
int32_t cose_cwt_error_code(const CoseCwtErrorHandle* error);

/**
 * @brief Get the error message from a CWT error handle.
 *
 * Caller must free the returned string with `cose_cwt_string_free()`.
 * @return Allocated string, or NULL on failure.
 */
char* cose_cwt_error_message(const CoseCwtErrorHandle* error);

/** @brief Free a CWT error handle (NULL is a safe no-op). */
void cose_cwt_error_free(CoseCwtErrorHandle* error);

/** @brief Free a string returned by the CWT layer (NULL is a safe no-op). */
void cose_cwt_string_free(char* s);

/* ========================================================================== */
/* CWT Claims lifecycle                                                       */
/* ========================================================================== */

/**
 * @brief Create a new empty CWT claims set.
 *
 * @param out_handle  Receives the claims handle on success.
 * @param out_error   Receives an error handle on failure (caller must free).
 * @return 0 on success, negative error code on failure.
 */
int32_t cose_cwt_claims_create(
    CoseCwtClaimsHandle** out_handle,
    CoseCwtErrorHandle** out_error
);

/** @brief Free a CWT claims handle (NULL is a safe no-op). */
void cose_cwt_claims_free(CoseCwtClaimsHandle* handle);

/* ========================================================================== */
/* CWT Claims setters                                                         */
/* ========================================================================== */

/**
 * @brief Set the issuer (iss, label 1) claim.
 *
 * @param handle   Claims handle.
 * @param issuer   Null-terminated UTF-8 issuer string.
 * @param out_error Receives error handle on failure.
 */
int32_t cose_cwt_claims_set_issuer(
    CoseCwtClaimsHandle* handle,
    const char* issuer,
    CoseCwtErrorHandle** out_error
);

/**
 * @brief Set the subject (sub, label 2) claim.
 *
 * @param handle   Claims handle.
 * @param subject  Null-terminated UTF-8 subject string.
 * @param out_error Receives error handle on failure.
 */
int32_t cose_cwt_claims_set_subject(
    CoseCwtClaimsHandle* handle,
    const char* subject,
    CoseCwtErrorHandle** out_error
);

/**
 * @brief Set the audience (aud, label 3) claim.
 *
 * @param handle   Claims handle.
 * @param audience Null-terminated UTF-8 audience string.
 * @param out_error Receives error handle on failure.
 */
int32_t cose_cwt_claims_set_audience(
    CoseCwtClaimsHandle* handle,
    const char* audience,
    CoseCwtErrorHandle** out_error
);

/**
 * @brief Set the expiration time (exp, label 4) claim.
 *
 * @param handle          Claims handle.
 * @param unix_timestamp  Expiration time as Unix timestamp.
 * @param out_error       Receives error handle on failure.
 */
int32_t cose_cwt_claims_set_expiration(
    CoseCwtClaimsHandle* handle,
    int64_t unix_timestamp,
    CoseCwtErrorHandle** out_error
);

/**
 * @brief Set the not-before (nbf, label 5) claim.
 *
 * @param handle          Claims handle.
 * @param unix_timestamp  Not-before time as Unix timestamp.
 * @param out_error       Receives error handle on failure.
 */
int32_t cose_cwt_claims_set_not_before(
    CoseCwtClaimsHandle* handle,
    int64_t unix_timestamp,
    CoseCwtErrorHandle** out_error
);

/**
 * @brief Set the issued-at (iat, label 6) claim.
 *
 * @param handle          Claims handle.
 * @param unix_timestamp  Issued-at time as Unix timestamp.
 * @param out_error       Receives error handle on failure.
 */
int32_t cose_cwt_claims_set_issued_at(
    CoseCwtClaimsHandle* handle,
    int64_t unix_timestamp,
    CoseCwtErrorHandle** out_error
);

/* ========================================================================== */
/* CWT Claims getters                                                         */
/* ========================================================================== */

/**
 * @brief Get the issuer (iss) claim.
 *
 * If the claim is not set, `*out_issuer` is set to NULL and the function
 * returns 0 (success). Caller must free with `cose_cwt_string_free()`.
 *
 * @param handle     Claims handle.
 * @param out_issuer Receives the issuer string.
 * @param out_error  Receives error handle on failure.
 */
int32_t cose_cwt_claims_get_issuer(
    const CoseCwtClaimsHandle* handle,
    const char** out_issuer,
    CoseCwtErrorHandle** out_error
);

/**
 * @brief Get the subject (sub) claim.
 *
 * If the claim is not set, `*out_subject` is set to NULL and the function
 * returns 0 (success). Caller must free with `cose_cwt_string_free()`.
 *
 * @param handle      Claims handle.
 * @param out_subject Receives the subject string.
 * @param out_error   Receives error handle on failure.
 */
int32_t cose_cwt_claims_get_subject(
    const CoseCwtClaimsHandle* handle,
    const char** out_subject,
    CoseCwtErrorHandle** out_error
);

/* ========================================================================== */
/* Serialization                                                              */
/* ========================================================================== */

/**
 * @brief Serialize CWT claims to CBOR bytes.
 *
 * The caller owns the returned byte buffer and must free it with
 * `cose_cwt_bytes_free()`.
 *
 * @param handle    Claims handle.
 * @param out_bytes Receives a pointer to the CBOR bytes.
 * @param out_len   Receives the byte count.
 * @param out_error Receives error handle on failure.
 */
int32_t cose_cwt_claims_to_cbor(
    const CoseCwtClaimsHandle* handle,
    uint8_t** out_bytes,
    uint32_t* out_len,
    CoseCwtErrorHandle** out_error
);

/**
 * @brief Deserialize CWT claims from CBOR bytes.
 *
 * The caller owns the returned handle and must free it with
 * `cose_cwt_claims_free()`.
 *
 * @param cbor_data  CBOR-encoded claims bytes.
 * @param cbor_len   Length of cbor_data.
 * @param out_handle Receives the claims handle on success.
 * @param out_error  Receives error handle on failure.
 */
int32_t cose_cwt_claims_from_cbor(
    const uint8_t* cbor_data,
    uint32_t cbor_len,
    CoseCwtClaimsHandle** out_handle,
    CoseCwtErrorHandle** out_error
);

/* ========================================================================== */
/* Memory management                                                          */
/* ========================================================================== */

/**
 * @brief Free bytes returned by `cose_cwt_claims_to_cbor()`.
 *
 * @param ptr  Pointer returned by to_cbor (NULL is a safe no-op).
 * @param len  Length returned alongside the pointer.
 */
void cose_cwt_bytes_free(uint8_t* ptr, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif /* COSE_SIGN1_CWT_H */
