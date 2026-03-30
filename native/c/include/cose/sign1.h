// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file sign1.h
 * @brief C API for COSE_Sign1 message parsing, inspection, and verification.
 *
 * This header provides low-level primitives for COSE_Sign1 messages as defined
 * in RFC 9052 (with algorithms specified in RFC 9053). It includes `<cose/cose.h>` automatically.
 *
 * ## Error Handling
 *
 * Functions return `int32_t` status codes (0 = success, negative = error).
 * Rich error details are available via `CoseSign1ErrorHandle`.
 *
 * ## Memory Management
 *
 * - `cose_sign1_message_free()` for message handles.
 * - `cose_sign1_error_free()` for error handles.
 * - `cose_sign1_string_free()` for string pointers.
 * - `cose_headermap_free()` for header map handles (declared in `<cose/cose.h>`).
 * - `cose_key_free()` for key handles (declared in `<cose/cose.h>`).
 */

#ifndef COSE_SIGN1_H
#define COSE_SIGN1_H

#include <cose/cose.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================== */
/* ABI version                                                                */
/* ========================================================================== */

#define COSE_SIGN1_ABI_VERSION 1

/* ========================================================================== */
/* Sign1-specific status codes (primitives layer)                             */
/* ========================================================================== */

#define COSE_SIGN1_OK                       0
#define COSE_SIGN1_ERR_NULL_POINTER        -1
#define COSE_SIGN1_ERR_INVALID_ARGUMENT    -2
#define COSE_SIGN1_ERR_PANIC               -3
#define COSE_SIGN1_ERR_PARSE_FAILED        -4
#define COSE_SIGN1_ERR_VERIFY_FAILED       -5
#define COSE_SIGN1_ERR_PAYLOAD_MISSING     -6
#define COSE_SIGN1_ERR_PAYLOAD_ERROR       -7
#define COSE_SIGN1_ERR_HEADER_NOT_FOUND    -8

/* ========================================================================== */
/* Opaque handle types – Sign1-specific                                       */
/* ========================================================================== */

/** @brief Opaque handle to a parsed COSE_Sign1 message. Free with `cose_sign1_message_free()`. */
typedef struct CoseSign1MessageHandle CoseSign1MessageHandle;

/** @brief Opaque handle to a Sign1 error. Free with `cose_sign1_error_free()`. */
typedef struct CoseSign1ErrorHandle CoseSign1ErrorHandle;

/* ========================================================================== */
/* ABI version                                                                */
/* ========================================================================== */

/** @brief Return the ABI version of the primitives FFI library. */
uint32_t cose_sign1_ffi_abi_version(void);

/* ========================================================================== */
/* Error handling                                                             */
/* ========================================================================== */

/** @brief Get the error code from an error handle. */
int32_t cose_sign1_error_code(const CoseSign1ErrorHandle* error);

/**
 * @brief Get the error message from an error handle.
 *
 * Caller must free the returned string with `cose_sign1_string_free()`.
 * @return Allocated string, or NULL on failure.
 */
char* cose_sign1_error_message(const CoseSign1ErrorHandle* error);

/** @brief Free an error handle (NULL is a safe no-op). */
void cose_sign1_error_free(CoseSign1ErrorHandle* error);

/** @brief Free a string returned by the primitives layer (NULL is a safe no-op). */
void cose_sign1_string_free(char* s);

/* ========================================================================== */
/* Message parsing & inspection                                               */
/* ========================================================================== */

/**
 * @brief Parse a COSE_Sign1 message from bytes.
 *
 * @param data        Message bytes.
 * @param len         Length of data.
 * @param out_message Receives the parsed message handle on success.
 * @param out_error   Receives an error handle on failure (caller must free).
 * @return 0 on success, negative error code on failure.
 */
int32_t cose_sign1_message_parse(
    const uint8_t* data,
    size_t len,
    CoseSign1MessageHandle** out_message,
    CoseSign1ErrorHandle** out_error
);

/** @brief Free a message handle (NULL is a safe no-op). */
void cose_sign1_message_free(CoseSign1MessageHandle* message);

/**
 * @brief Get the algorithm from a message's protected headers.
 *
 * @param message Message handle.
 * @param out_alg Receives the COSE algorithm identifier.
 * @return 0 on success, negative error code on failure.
 */
int32_t cose_sign1_message_alg(
    const CoseSign1MessageHandle* message,
    int64_t* out_alg
);

/**
 * @brief Check whether the message has a detached payload.
 */
bool cose_sign1_message_is_detached(const CoseSign1MessageHandle* message);

/**
 * @brief Get the embedded payload.
 *
 * The returned pointer is borrowed and valid only while the message is alive.
 * Returns `COSE_SIGN1_ERR_PAYLOAD_MISSING` if the payload is detached.
 */
int32_t cose_sign1_message_payload(
    const CoseSign1MessageHandle* message,
    const uint8_t** out_payload,
    size_t* out_len
);

/**
 * @brief Get the serialized protected-headers bucket.
 *
 * The returned pointer is borrowed and valid while the message is alive.
 */
int32_t cose_sign1_message_protected_bytes(
    const CoseSign1MessageHandle* message,
    const uint8_t** out_bytes,
    size_t* out_len
);

/**
 * @brief Get the signature bytes.
 *
 * The returned pointer is borrowed and valid while the message is alive.
 */
int32_t cose_sign1_message_signature(
    const CoseSign1MessageHandle* message,
    const uint8_t** out_signature,
    size_t* out_len
);

/**
 * @brief Verify an embedded-payload COSE_Sign1 message.
 */
int32_t cose_sign1_message_verify(
    const CoseSign1MessageHandle* message,
    const CoseKeyHandle* key,
    const uint8_t* external_aad,
    size_t external_aad_len,
    bool* out_verified,
    CoseSign1ErrorHandle** out_error
);

/**
 * @brief Verify a detached-payload COSE_Sign1 message.
 */
int32_t cose_sign1_message_verify_detached(
    const CoseSign1MessageHandle* message,
    const CoseKeyHandle* key,
    const uint8_t* detached_payload,
    size_t detached_payload_len,
    const uint8_t* external_aad,
    size_t external_aad_len,
    bool* out_verified,
    CoseSign1ErrorHandle** out_error
);

/**
 * @brief Get the protected header map from a message.
 *
 * Caller owns the returned handle; free with `cose_headermap_free()`.
 */
int32_t cose_sign1_message_protected_headers(
    const CoseSign1MessageHandle* message,
    CoseHeaderMapHandle** out_headers
);

/**
 * @brief Get the unprotected header map from a message.
 *
 * Caller owns the returned handle; free with `cose_headermap_free()`.
 */
int32_t cose_sign1_message_unprotected_headers(
    const CoseSign1MessageHandle* message,
    CoseHeaderMapHandle** out_headers
);

#ifdef __cplusplus
}
#endif

#endif /* COSE_SIGN1_H */
