// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file factories.h
 * @brief C API for COSE Sign1 message factories.
 *
 * This header provides factory-based creation of COSE_Sign1 messages, supporting
 * both direct (embedded payload) and indirect (hash envelope) signatures.
 * Factories wrap signing services and provide convenience methods for common
 * signing workflows.
 */

#ifndef COSE_SIGN1_FACTORIES_FFI_H
#define COSE_SIGN1_FACTORIES_FFI_H

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
 * @brief Returns the ABI version for this library.
 *
 * Increment when making breaking changes to the FFI interface.
 */
uint32_t cose_sign1_factories_abi_version(void);

// ============================================================================
// Status codes
// ============================================================================

/**
 * @brief Status codes returned by factory functions.
 */
#define COSE_SIGN1_FACTORIES_OK                 0
#define COSE_SIGN1_FACTORIES_ERR_NULL_POINTER  -1
#define COSE_SIGN1_FACTORIES_ERR_INVALID_ARG   -5
#define COSE_SIGN1_FACTORIES_ERR_FACTORY_FAILED -12
#define COSE_SIGN1_FACTORIES_ERR_PANIC         -99

// ============================================================================
// Opaque handle types
// ============================================================================

/**
 * @brief Opaque handle to a factory.
 *
 * Freed with cose_sign1_factories_free().
 */
typedef struct CoseSign1FactoriesHandle CoseSign1FactoriesHandle;

/**
 * @brief Opaque handle to a signing service.
 *
 * Used when creating factories from signing services.
 */
typedef struct CoseSign1FactoriesSigningServiceHandle CoseSign1FactoriesSigningServiceHandle;

/**
 * @brief Opaque handle to a transparency provider.
 *
 * Used when creating factories with transparency support.
 */
typedef struct CoseSign1FactoriesTransparencyProviderHandle CoseSign1FactoriesTransparencyProviderHandle;

/**
 * @brief Opaque handle to a crypto signer.
 *
 * Imported from crypto layer.
 */
typedef struct CryptoSignerHandle CryptoSignerHandle;

/**
 * @brief Opaque handle to an error.
 *
 * Freed with cose_sign1_factories_error_free().
 */
typedef struct CoseSign1FactoriesErrorHandle CoseSign1FactoriesErrorHandle;

// ============================================================================
// Factory creation functions
// ============================================================================

/**
 * @brief Creates a factory from a signing service handle.
 *
 * @param service Signing service handle
 * @param out_factory Output parameter for factory handle
 * @param out_error Output parameter for error handle (optional, can be NULL)
 * @return COSE_SIGN1_FACTORIES_OK on success, error code on failure
 *
 * Caller owns the returned factory and must free it with cose_sign1_factories_free().
 */
int cose_sign1_factories_create_from_signing_service(
    const CoseSign1FactoriesSigningServiceHandle* service,
    CoseSign1FactoriesHandle** out_factory,
    CoseSign1FactoriesErrorHandle** out_error);

/**
 * @brief Creates a factory from a crypto signer in a single call.
 *
 * This is a convenience function that wraps the signer in a signing service
 * and creates a factory. Ownership of the signer handle is transferred.
 *
 * @param signer_handle Crypto signer handle (ownership transferred)
 * @param out_factory Output parameter for factory handle
 * @param out_error Output parameter for error handle (optional, can be NULL)
 * @return COSE_SIGN1_FACTORIES_OK on success, error code on failure
 *
 * The signer_handle must not be used after this call.
 * Caller owns the returned factory and must free it with cose_sign1_factories_free().
 */
int cose_sign1_factories_create_from_crypto_signer(
    CryptoSignerHandle* signer_handle,
    CoseSign1FactoriesHandle** out_factory,
    CoseSign1FactoriesErrorHandle** out_error);

/**
 * @brief Creates a factory with transparency providers.
 *
 * @param service Signing service handle
 * @param providers Array of transparency provider handles
 * @param providers_len Number of providers in the array
 * @param out_factory Output parameter for factory handle
 * @param out_error Output parameter for error handle (optional, can be NULL)
 * @return COSE_SIGN1_FACTORIES_OK on success, error code on failure
 *
 * Ownership of provider handles is transferred (caller must not free them).
 * Caller owns the returned factory and must free it with cose_sign1_factories_free().
 */
int cose_sign1_factories_create_with_transparency(
    const CoseSign1FactoriesSigningServiceHandle* service,
    const CoseSign1FactoriesTransparencyProviderHandle* const* providers,
    size_t providers_len,
    CoseSign1FactoriesHandle** out_factory,
    CoseSign1FactoriesErrorHandle** out_error);

/**
 * @brief Frees a factory handle.
 *
 * @param factory Factory handle to free (can be NULL)
 */
void cose_sign1_factories_free(CoseSign1FactoriesHandle* factory);

// ============================================================================
// Direct signature functions
// ============================================================================

/**
 * @brief Signs payload with direct signature (embedded payload).
 *
 * @param factory Factory handle
 * @param payload Payload bytes
 * @param payload_len Payload length
 * @param content_type Content type string (null-terminated)
 * @param out_cose_bytes Output parameter for COSE bytes
 * @param out_cose_len Output parameter for COSE length
 * @param out_error Output parameter for error handle (optional, can be NULL)
 * @return COSE_SIGN1_FACTORIES_OK on success, error code on failure
 *
 * Caller must free the returned bytes with cose_sign1_factories_bytes_free().
 */
int cose_sign1_factories_sign_direct(
    const CoseSign1FactoriesHandle* factory,
    const uint8_t* payload,
    uint32_t payload_len,
    const char* content_type,
    uint8_t** out_cose_bytes,
    uint32_t* out_cose_len,
    CoseSign1FactoriesErrorHandle** out_error);

/**
 * @brief Signs payload with direct signature in detached mode.
 *
 * @param factory Factory handle
 * @param payload Payload bytes
 * @param payload_len Payload length
 * @param content_type Content type string (null-terminated)
 * @param out_cose_bytes Output parameter for COSE bytes
 * @param out_cose_len Output parameter for COSE length
 * @param out_error Output parameter for error handle (optional, can be NULL)
 * @return COSE_SIGN1_FACTORIES_OK on success, error code on failure
 *
 * Caller must free the returned bytes with cose_sign1_factories_bytes_free().
 */
int cose_sign1_factories_sign_direct_detached(
    const CoseSign1FactoriesHandle* factory,
    const uint8_t* payload,
    uint32_t payload_len,
    const char* content_type,
    uint8_t** out_cose_bytes,
    uint32_t* out_cose_len,
    CoseSign1FactoriesErrorHandle** out_error);

/**
 * @brief Signs a file directly without loading it into memory (detached).
 *
 * @param factory Factory handle
 * @param file_path Path to file (null-terminated UTF-8)
 * @param content_type Content type string (null-terminated)
 * @param out_cose_bytes Output parameter for COSE bytes
 * @param out_cose_len Output parameter for COSE length
 * @param out_error Output parameter for error handle (optional, can be NULL)
 * @return COSE_SIGN1_FACTORIES_OK on success, error code on failure
 *
 * Creates a detached COSE_Sign1 signature over the file content.
 * Caller must free the returned bytes with cose_sign1_factories_bytes_free().
 */
int cose_sign1_factories_sign_direct_file(
    const CoseSign1FactoriesHandle* factory,
    const char* file_path,
    const char* content_type,
    uint8_t** out_cose_bytes,
    uint32_t* out_cose_len,
    CoseSign1FactoriesErrorHandle** out_error);

/**
 * @brief Callback type for streaming payload reading.
 *
 * @param buffer Buffer to fill with payload data
 * @param buffer_len Size of the buffer
 * @param user_data Opaque user data pointer
 * @return Number of bytes read (0 = EOF, negative = error)
 */
typedef int64_t (*CoseReadCallback)(uint8_t* buffer, size_t buffer_len, void* user_data);

/**
 * @brief Signs a streaming payload with direct signature (detached).
 *
 * @param factory Factory handle
 * @param read_callback Callback to read payload data
 * @param user_data Opaque pointer passed to callback
 * @param total_len Total length of the payload
 * @param content_type Content type string (null-terminated)
 * @param out_cose_bytes Output parameter for COSE bytes
 * @param out_cose_len Output parameter for COSE length
 * @param out_error Output parameter for error handle (optional, can be NULL)
 * @return COSE_SIGN1_FACTORIES_OK on success, error code on failure
 *
 * The callback will be invoked repeatedly to read payload data.
 * Caller must free the returned bytes with cose_sign1_factories_bytes_free().
 */
int cose_sign1_factories_sign_direct_streaming(
    const CoseSign1FactoriesHandle* factory,
    CoseReadCallback read_callback,
    void* user_data,
    uint64_t total_len,
    const char* content_type,
    uint8_t** out_cose_bytes,
    uint32_t* out_cose_len,
    CoseSign1FactoriesErrorHandle** out_error);

// ============================================================================
// Indirect signature functions
// ============================================================================

/**
 * @brief Signs payload with indirect signature (hash envelope).
 *
 * @param factory Factory handle
 * @param payload Payload bytes
 * @param payload_len Payload length
 * @param content_type Content type string (null-terminated)
 * @param out_cose_bytes Output parameter for COSE bytes
 * @param out_cose_len Output parameter for COSE length
 * @param out_error Output parameter for error handle (optional, can be NULL)
 * @return COSE_SIGN1_FACTORIES_OK on success, error code on failure
 *
 * Caller must free the returned bytes with cose_sign1_factories_bytes_free().
 */
int cose_sign1_factories_sign_indirect(
    const CoseSign1FactoriesHandle* factory,
    const uint8_t* payload,
    uint32_t payload_len,
    const char* content_type,
    uint8_t** out_cose_bytes,
    uint32_t* out_cose_len,
    CoseSign1FactoriesErrorHandle** out_error);

/**
 * @brief Signs a file with indirect signature (hash envelope).
 *
 * @param factory Factory handle
 * @param file_path Path to file (null-terminated UTF-8)
 * @param content_type Content type string (null-terminated)
 * @param out_cose_bytes Output parameter for COSE bytes
 * @param out_cose_len Output parameter for COSE length
 * @param out_error Output parameter for error handle (optional, can be NULL)
 * @return COSE_SIGN1_FACTORIES_OK on success, error code on failure
 *
 * Caller must free the returned bytes with cose_sign1_factories_bytes_free().
 */
int cose_sign1_factories_sign_indirect_file(
    const CoseSign1FactoriesHandle* factory,
    const char* file_path,
    const char* content_type,
    uint8_t** out_cose_bytes,
    uint32_t* out_cose_len,
    CoseSign1FactoriesErrorHandle** out_error);

/**
 * @brief Signs a streaming payload with indirect signature.
 *
 * @param factory Factory handle
 * @param read_callback Callback to read payload data
 * @param user_data Opaque pointer passed to callback
 * @param total_len Total length of the payload
 * @param content_type Content type string (null-terminated)
 * @param out_cose_bytes Output parameter for COSE bytes
 * @param out_cose_len Output parameter for COSE length
 * @param out_error Output parameter for error handle (optional, can be NULL)
 * @return COSE_SIGN1_FACTORIES_OK on success, error code on failure
 *
 * Caller must free the returned bytes with cose_sign1_factories_bytes_free().
 */
int cose_sign1_factories_sign_indirect_streaming(
    const CoseSign1FactoriesHandle* factory,
    CoseReadCallback read_callback,
    void* user_data,
    uint64_t total_len,
    const char* content_type,
    uint8_t** out_cose_bytes,
    uint32_t* out_cose_len,
    CoseSign1FactoriesErrorHandle** out_error);

// ============================================================================
// Memory management functions
// ============================================================================

/**
 * @brief Frees COSE bytes allocated by factory functions.
 *
 * @param ptr Pointer to bytes
 * @param len Length of bytes
 */
void cose_sign1_factories_bytes_free(uint8_t* ptr, uint32_t len);

// ============================================================================
// Error handling functions
// ============================================================================

/**
 * @brief Gets the error message from an error handle.
 *
 * @param handle Error handle
 * @return Error message string (null-terminated, owned by the error handle)
 *
 * Returns NULL if handle is NULL. The returned string is owned by the error
 * handle and is freed when cose_sign1_factories_error_free() is called.
 */
char* cose_sign1_factories_error_message(const CoseSign1FactoriesErrorHandle* handle);

/**
 * @brief Gets the error code from an error handle.
 *
 * @param handle Error handle
 * @return Error code (or 0 if handle is NULL)
 */
int cose_sign1_factories_error_code(const CoseSign1FactoriesErrorHandle* handle);

/**
 * @brief Frees an error handle.
 *
 * @param handle Error handle to free (can be NULL)
 */
void cose_sign1_factories_error_free(CoseSign1FactoriesErrorHandle* handle);

/**
 * @brief Frees a string returned by error functions.
 *
 * @param s String to free (can be NULL)
 */
void cose_sign1_factories_string_free(char* s);

#ifdef __cplusplus
}
#endif

#endif // COSE_SIGN1_FACTORIES_FFI_H
