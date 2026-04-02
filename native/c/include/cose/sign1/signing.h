// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file signing.h
 * @brief C API for COSE Sign1 message signing operations.
 *
 * This header provides the signing API for creating COSE Sign1 messages from C/C++ code.
 * It wraps the Rust cose_sign1_signing_ffi crate and provides builder patterns,
 * callback-based key support, and factory methods for direct/indirect signatures.
 *
 * For validation operations, see cose_sign1.h in the cose/ directory.
 */

#ifndef COSE_SIGN1_SIGNING_H
#define COSE_SIGN1_SIGNING_H

#include <cose/cose.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// ABI version
// ============================================================================

/**
 * @brief ABI version for this library.
 *
 * Increment when making breaking changes to the FFI interface.
 */
#define COSE_SIGN1_SIGNING_ABI_VERSION 1

// ============================================================================
// Status codes
// ============================================================================

/**
 * @brief Status codes returned by signing API functions.
 *
 * Functions return 0 on success and negative values on error.
 */
#define COSE_SIGN1_SIGNING_OK                 0
#define COSE_SIGN1_SIGNING_ERR_NULL_POINTER  -1
#define COSE_SIGN1_SIGNING_ERR_SIGN_FAILED   -2
#define COSE_SIGN1_SIGNING_ERR_INVALID_ARG   -5
#define COSE_SIGN1_SIGNING_ERR_FACTORY_FAILED -12
#define COSE_SIGN1_SIGNING_ERR_PANIC         -99

// ============================================================================
// Opaque handle types
// ============================================================================

/**
 * @brief Opaque handle to a CoseSign1 message builder.
 */
typedef struct cose_sign1_builder_t cose_sign1_builder_t;

/**
 * @brief Opaque handle to a header map (alias for CoseHeaderMapHandle from cose.h).
 */
typedef CoseHeaderMapHandle cose_headermap_t;

/**
 * @brief Opaque handle to a signing key (alias for CoseKeyHandle from cose.h).
 */
typedef CoseKeyHandle cose_key_t;

/**
 * @brief Opaque handle to a signing service.
 */
typedef struct cose_sign1_signing_service_t cose_sign1_signing_service_t;

/**
 * @brief Opaque handle to a message factory.
 */
typedef struct cose_sign1_factory_t cose_sign1_factory_t;

/**
 * @brief Opaque handle to an error.
 */
typedef struct cose_sign1_signing_error_t cose_sign1_signing_error_t;

// ============================================================================
// Callback type for signing operations
// ============================================================================

/**
 * @brief Callback function type for signing operations.
 *
 * The callback receives the protected header bytes, payload, and optional external AAD,
 * and must produce a signature. The signature bytes must be allocated with malloc()
 * and will be freed by the library using free().
 *
 * @param protected_bytes The CBOR-encoded protected header bytes.
 * @param protected_len Length of protected_bytes.
 * @param payload The payload bytes.
 * @param payload_len Length of payload.
 * @param external_aad External AAD bytes (may be NULL).
 * @param external_aad_len Length of external_aad (0 if NULL).
 * @param out_sig Output pointer for signature bytes (caller must allocate with malloc).
 * @param out_sig_len Output pointer for signature length.
 * @param user_data User-provided context pointer.
 * @return 0 on success, non-zero on error.
 */
typedef int (*cose_sign1_sign_callback_t)(
    const uint8_t* protected_bytes,
    size_t protected_len,
    const uint8_t* payload,
    size_t payload_len,
    const uint8_t* external_aad,
    size_t external_aad_len,
    uint8_t** out_sig,
    size_t* out_sig_len,
    void* user_data
);

// ============================================================================
// ABI version function
// ============================================================================

/**
 * @brief Returns the ABI version of this library.
 * @return ABI version number.
 */
uint32_t cose_sign1_signing_abi_version(void);

// ============================================================================
// Error handling functions
// ============================================================================

/**
 * @brief Gets the error message from an error handle.
 *
 * @param error Error handle.
 * @return Newly-allocated error message string, or NULL. Caller must free with
 *         cose_sign1_string_free().
 */
char* cose_sign1_signing_error_message(const cose_sign1_signing_error_t* error);

/**
 * @brief Gets the error code from an error handle.
 *
 * @param error Error handle.
 * @return Error code, or 0 if error is NULL.
 */
int cose_sign1_signing_error_code(const cose_sign1_signing_error_t* error);

/**
 * @brief Frees an error handle.
 *
 * @param error Error handle to free (can be NULL).
 */
void cose_sign1_signing_error_free(cose_sign1_signing_error_t* error);

/**
 * @brief Frees a string returned by this library.
 *
 * @param s String to free (can be NULL).
 */
void cose_sign1_string_free(char* s);

// ============================================================================
// Header map functions
// ============================================================================

/**
 * @brief Creates a new empty header map.
 *
 * @param out_headers Output parameter for the header map handle.
 * @return COSE_SIGN1_SIGNING_OK on success, error code otherwise.
 */
int cose_headermap_new(cose_headermap_t** out_headers);

/**
 * @brief Sets an integer value in a header map by integer label.
 *
 * @param headers Header map handle.
 * @param label Integer label (e.g., 1 for algorithm, 3 for content type).
 * @param value Integer value to set.
 * @return COSE_SIGN1_SIGNING_OK on success, error code otherwise.
 */
int cose_headermap_set_int(
    cose_headermap_t* headers,
    int64_t label,
    int64_t value
);

/**
 * @brief Sets a byte string value in a header map by integer label.
 *
 * @param headers Header map handle.
 * @param label Integer label.
 * @param value Byte string value.
 * @param value_len Length of value.
 * @return COSE_SIGN1_SIGNING_OK on success, error code otherwise.
 */
int cose_headermap_set_bytes(
    cose_headermap_t* headers,
    int64_t label,
    const uint8_t* value,
    size_t value_len
);

/**
 * @brief Sets a text string value in a header map by integer label.
 *
 * @param headers Header map handle.
 * @param label Integer label.
 * @param value Null-terminated text string value.
 * @return COSE_SIGN1_SIGNING_OK on success, error code otherwise.
 */
int cose_headermap_set_text(
    cose_headermap_t* headers,
    int64_t label,
    const char* value
);

/**
 * @brief Returns the number of headers in the map.
 *
 * @param headers Header map handle.
 * @return Number of headers, or 0 if headers is NULL.
 */
size_t cose_headermap_len(const cose_headermap_t* headers);

/**
 * @brief Frees a header map handle.
 *
 * @param headers Header map handle to free (can be NULL).
 */
void cose_headermap_free(cose_headermap_t* headers);

// ============================================================================
// Builder functions
// ============================================================================

/**
 * @brief Creates a new CoseSign1 message builder.
 *
 * @param out_builder Output parameter for the builder handle.
 * @return COSE_SIGN1_SIGNING_OK on success, error code otherwise.
 */
int cose_sign1_builder_new(cose_sign1_builder_t** out_builder);

/**
 * @brief Sets whether the builder produces tagged COSE_Sign1 output.
 *
 * @param builder Builder handle.
 * @param tagged True for tagged output (default), false for untagged.
 * @return COSE_SIGN1_SIGNING_OK on success, error code otherwise.
 */
int cose_sign1_builder_set_tagged(
    cose_sign1_builder_t* builder,
    bool tagged
);

/**
 * @brief Sets whether the builder produces a detached payload.
 *
 * @param builder Builder handle.
 * @param detached True for detached payload, false for embedded (default).
 * @return COSE_SIGN1_SIGNING_OK on success, error code otherwise.
 */
int cose_sign1_builder_set_detached(
    cose_sign1_builder_t* builder,
    bool detached
);

/**
 * @brief Sets the protected headers for the builder.
 *
 * @param builder Builder handle.
 * @param headers Header map handle (copied, not consumed).
 * @return COSE_SIGN1_SIGNING_OK on success, error code otherwise.
 */
int cose_sign1_builder_set_protected(
    cose_sign1_builder_t* builder,
    const cose_headermap_t* headers
);

/**
 * @brief Sets the unprotected headers for the builder.
 *
 * @param builder Builder handle.
 * @param headers Header map handle (copied, not consumed).
 * @return COSE_SIGN1_SIGNING_OK on success, error code otherwise.
 */
int cose_sign1_builder_set_unprotected(
    cose_sign1_builder_t* builder,
    const cose_headermap_t* headers
);

/**
 * @brief Sets the protected headers by consuming (moving) the header map.
 *
 * Zero-copy alternative to cose_sign1_builder_set_protected. The header map
 * handle is consumed and must NOT be used or freed after this call.
 *
 * @param builder Builder handle.
 * @param headers Header map handle (consumed, not copied).
 * @return COSE_SIGN1_SIGNING_OK on success, error code otherwise.
 */
int cose_sign1_builder_consume_protected(
    cose_sign1_builder_t* builder,
    cose_headermap_t* headers
);

/**
 * @brief Sets the unprotected headers by consuming (moving) the header map.
 *
 * Zero-copy alternative to cose_sign1_builder_set_unprotected. The header map
 * handle is consumed and must NOT be used or freed after this call.
 *
 * @param builder Builder handle.
 * @param headers Header map handle (consumed, not copied).
 * @return COSE_SIGN1_SIGNING_OK on success, error code otherwise.
 */
int cose_sign1_builder_consume_unprotected(
    cose_sign1_builder_t* builder,
    cose_headermap_t* headers
);

/**
 * @brief Sets the external additional authenticated data for the builder.
 *
 * @param builder Builder handle.
 * @param aad External AAD bytes (can be NULL to clear).
 * @param aad_len Length of aad.
 * @return COSE_SIGN1_SIGNING_OK on success, error code otherwise.
 */
int cose_sign1_builder_set_external_aad(
    cose_sign1_builder_t* builder,
    const uint8_t* aad,
    size_t aad_len
);

/**
 * @brief Signs a payload using the builder configuration and a key.
 *
 * The builder is consumed by this call and must not be used afterwards.
 *
 * @param builder Builder handle (consumed on success or failure).
 * @param key Key handle.
 * @param payload Payload bytes.
 * @param payload_len Length of payload.
 * @param out_bytes Output parameter for COSE message bytes.
 * @param out_len Output parameter for COSE message length.
 * @param out_error Output parameter for error handle (can be NULL).
 * @return COSE_SIGN1_SIGNING_OK on success, error code otherwise.
 */
int cose_sign1_builder_sign(
    cose_sign1_builder_t* builder,
    const cose_key_t* key,
    const uint8_t* payload,
    size_t payload_len,
    uint8_t** out_bytes,
    size_t* out_len,
    cose_sign1_signing_error_t** out_error
);

/**
 * @brief Frees a builder handle.
 *
 * @param builder Builder handle to free (can be NULL).
 */
void cose_sign1_builder_free(cose_sign1_builder_t* builder);

/**
 * @brief Frees bytes returned by cose_sign1_builder_sign.
 *
 * @param bytes Bytes to free (can be NULL).
 * @param len Length of bytes.
 */
void cose_sign1_bytes_free(uint8_t* bytes, size_t len);

// ============================================================================
// Key functions
// ============================================================================

/**
 * @brief Creates a key handle from a signing callback.
 *
 * @param algorithm COSE algorithm identifier (e.g., -7 for ES256).
 * @param key_type Key type string (e.g., "EC2", "OKP").
 * @param sign_fn Signing callback function.
 * @param user_data User-provided context pointer (passed to callback).
 * @param out_key Output parameter for key handle.
 * @return COSE_SIGN1_SIGNING_OK on success, error code otherwise.
 */
int cose_key_from_callback(
    int64_t algorithm,
    const char* key_type,
    cose_sign1_sign_callback_t sign_fn,
    void* user_data,
    cose_key_t** out_key
);

/* cose_key_free() is declared in <cose/cose.h> — use CoseKeyHandle* or cose_key_t* */

// ============================================================================
// Signing service functions
// ============================================================================

/**
 * @brief Creates a signing service from a key handle.
 *
 * @param key Key handle.
 * @param out_service Output parameter for signing service handle.
 * @param out_error Output parameter for error handle (can be NULL).
 * @return COSE_SIGN1_SIGNING_OK on success, error code otherwise.
 */
int cose_sign1_signing_service_create(
    const cose_key_t* key,
    cose_sign1_signing_service_t** out_service,
    cose_sign1_signing_error_t** out_error
);

/**
 * @brief Creates a signing service directly from a crypto signer handle.
 *
 * This function eliminates the need for callback-based signing by accepting
 * a crypto signer handle directly from the crypto provider. The signer handle
 * is consumed by this function and must not be used afterwards.
 *
 * Requires the crypto_openssl FFI library to be linked.
 *
 * @param signer_handle Crypto signer handle from cose_crypto_openssl_signer_from_der.
 * @param out_service Output parameter for signing service handle.
 * @param out_error Output parameter for error handle (can be NULL).
 * @return COSE_SIGN1_SIGNING_OK on success, error code otherwise.
 */
int cose_sign1_signing_service_from_crypto_signer(
    void* signer_handle,
    cose_sign1_signing_service_t** out_service,
    cose_sign1_signing_error_t** out_error
);

/**
 * @brief Frees a signing service handle.
 *
 * @param service Signing service handle to free (can be NULL).
 */
void cose_sign1_signing_service_free(cose_sign1_signing_service_t* service);

// ============================================================================
// Factory functions
// ============================================================================

/**
 * @brief Creates a factory from a signing service handle.
 *
 * @param service Signing service handle.
 * @param out_factory Output parameter for factory handle.
 * @param out_error Output parameter for error handle (can be NULL).
 * @return COSE_SIGN1_SIGNING_OK on success, error code otherwise.
 */
int cose_sign1_factory_create(
    const cose_sign1_signing_service_t* service,
    cose_sign1_factory_t** out_factory,
    cose_sign1_signing_error_t** out_error
);

/**
 * @brief Creates a factory directly from a crypto signer handle.
 *
 * This is a convenience function that combines cose_sign1_signing_service_from_crypto_signer
 * and cose_sign1_factory_create in a single call. The signer handle is consumed
 * by this function and must not be used afterwards.
 *
 * Requires the crypto_openssl FFI library to be linked.
 *
 * @param signer_handle Crypto signer handle from cose_crypto_openssl_signer_from_der.
 * @param out_factory Output parameter for factory handle.
 * @param out_error Output parameter for error handle (can be NULL).
 * @return COSE_SIGN1_SIGNING_OK on success, error code otherwise.
 */
int cose_sign1_factory_from_crypto_signer(
    void* signer_handle,
    cose_sign1_factory_t** out_factory,
    cose_sign1_signing_error_t** out_error
);

/**
 * @brief Signs payload with direct signature (embedded payload).
 *
 * @param factory Factory handle.
 * @param payload Payload bytes.
 * @param payload_len Length of payload.
 * @param content_type Content type string.
 * @param out_cose_bytes Output parameter for COSE message bytes.
 * @param out_cose_len Output parameter for COSE message length.
 * @param out_error Output parameter for error handle (can be NULL).
 * @return COSE_SIGN1_SIGNING_OK on success, error code otherwise.
 */
int cose_sign1_factory_sign_direct(
    const cose_sign1_factory_t* factory,
    const uint8_t* payload,
    uint32_t payload_len,
    const char* content_type,
    uint8_t** out_cose_bytes,
    uint32_t* out_cose_len,
    cose_sign1_signing_error_t** out_error
);

/**
 * @brief Signs payload with indirect signature (hash envelope).
 *
 * @param factory Factory handle.
 * @param payload Payload bytes.
 * @param payload_len Length of payload.
 * @param content_type Content type string.
 * @param out_cose_bytes Output parameter for COSE message bytes.
 * @param out_cose_len Output parameter for COSE message length.
 * @param out_error Output parameter for error handle (can be NULL).
 * @return COSE_SIGN1_SIGNING_OK on success, error code otherwise.
 */
int cose_sign1_factory_sign_indirect(
    const cose_sign1_factory_t* factory,
    const uint8_t* payload,
    uint32_t payload_len,
    const char* content_type,
    uint8_t** out_cose_bytes,
    uint32_t* out_cose_len,
    cose_sign1_signing_error_t** out_error
);

// ============================================================================
// Streaming signature functions
// ============================================================================

/**
 * @brief Callback function type for streaming payload reading.
 *
 * The callback receives a buffer to fill and returns the number of bytes read.
 * Return 0 to indicate EOF, or a negative value to indicate an error.
 *
 * @param buffer Buffer to fill with payload data.
 * @param buffer_len Size of the buffer.
 * @param user_data User-provided context pointer.
 * @return Number of bytes read (0 = EOF, negative = error).
 */
typedef int64_t (*cose_sign1_read_callback_t)(
    uint8_t* buffer,
    size_t buffer_len,
    void* user_data
);

/**
 * @brief Signs a file directly without loading it into memory (direct signature).
 *
 * Creates a detached COSE_Sign1 signature over the file content.
 * The payload is not embedded in the signature.
 *
 * @param factory Factory handle.
 * @param file_path Path to file (null-terminated UTF-8 string).
 * @param content_type Content type string.
 * @param out_cose_bytes Output parameter for COSE message bytes.
 * @param out_cose_len Output parameter for COSE message length.
 * @param out_error Output parameter for error handle (can be NULL).
 * @return COSE_SIGN1_SIGNING_OK on success, error code otherwise.
 */
int cose_sign1_factory_sign_direct_file(
    const cose_sign1_factory_t* factory,
    const char* file_path,
    const char* content_type,
    uint8_t** out_cose_bytes,
    uint32_t* out_cose_len,
    cose_sign1_signing_error_t** out_error
);

/**
 * @brief Signs a file directly without loading it into memory (indirect signature).
 *
 * Creates a detached COSE_Sign1 signature over the file content hash.
 * The payload is not embedded in the signature.
 *
 * @param factory Factory handle.
 * @param file_path Path to file (null-terminated UTF-8 string).
 * @param content_type Content type string.
 * @param out_cose_bytes Output parameter for COSE message bytes.
 * @param out_cose_len Output parameter for COSE message length.
 * @param out_error Output parameter for error handle (can be NULL).
 * @return COSE_SIGN1_SIGNING_OK on success, error code otherwise.
 */
int cose_sign1_factory_sign_indirect_file(
    const cose_sign1_factory_t* factory,
    const char* file_path,
    const char* content_type,
    uint8_t** out_cose_bytes,
    uint32_t* out_cose_len,
    cose_sign1_signing_error_t** out_error
);

/**
 * @brief Signs with a streaming payload via callback (direct signature).
 *
 * The callback is invoked repeatedly with a buffer to fill.
 * payload_len must be the total payload size (for CBOR bstr header).
 * Creates a detached signature.
 *
 * @param factory Factory handle.
 * @param read_callback Callback function to read payload data.
 * @param payload_len Total size of the payload in bytes.
 * @param user_data User-provided context pointer (passed to callback).
 * @param content_type Content type string.
 * @param out_cose_bytes Output parameter for COSE message bytes.
 * @param out_cose_len Output parameter for COSE message length.
 * @param out_error Output parameter for error handle (can be NULL).
 * @return COSE_SIGN1_SIGNING_OK on success, error code otherwise.
 */
int cose_sign1_factory_sign_direct_streaming(
    const cose_sign1_factory_t* factory,
    cose_sign1_read_callback_t read_callback,
    uint64_t payload_len,
    void* user_data,
    const char* content_type,
    uint8_t** out_cose_bytes,
    uint32_t* out_cose_len,
    cose_sign1_signing_error_t** out_error
);

/**
 * @brief Signs with a streaming payload via callback (indirect signature).
 *
 * The callback is invoked repeatedly with a buffer to fill.
 * payload_len must be the total payload size (for CBOR bstr header).
 * Creates a detached signature over the payload hash.
 *
 * @param factory Factory handle.
 * @param read_callback Callback function to read payload data.
 * @param payload_len Total size of the payload in bytes.
 * @param user_data User-provided context pointer (passed to callback).
 * @param content_type Content type string.
 * @param out_cose_bytes Output parameter for COSE message bytes.
 * @param out_cose_len Output parameter for COSE message length.
 * @param out_error Output parameter for error handle (can be NULL).
 * @return COSE_SIGN1_SIGNING_OK on success, error code otherwise.
 */
int cose_sign1_factory_sign_indirect_streaming(
    const cose_sign1_factory_t* factory,
    cose_sign1_read_callback_t read_callback,
    uint64_t payload_len,
    void* user_data,
    const char* content_type,
    uint8_t** out_cose_bytes,
    uint32_t* out_cose_len,
    cose_sign1_signing_error_t** out_error
);

/**
 * @brief Frees a factory handle.
 *
 * @param factory Factory handle to free (can be NULL).
 */
void cose_sign1_factory_free(cose_sign1_factory_t* factory);

/**
 * @brief Frees COSE bytes allocated by factory functions.
 *
 * @param ptr Bytes to free (can be NULL).
 * @param len Length of bytes.
 */
void cose_sign1_cose_bytes_free(uint8_t* ptr, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif // COSE_SIGN1_SIGNING_H
