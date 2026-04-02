// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file certificates_local.h
 * @brief Local certificate creation and loading for COSE Sign1
 */

#ifndef COSE_SIGN1_CERTIFICATES_LOCAL_H
#define COSE_SIGN1_CERTIFICATES_LOCAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <cose/cose.h>

#ifdef __cplusplus
extern "C" {
#endif

// Forward declarations
typedef struct cose_cert_local_factory_t cose_cert_local_factory_t;
typedef struct cose_cert_local_chain_t cose_cert_local_chain_t;

/**
 * @brief Key algorithms for certificate generation
 */
typedef enum {
    COSE_KEY_ALG_RSA = 0,
    COSE_KEY_ALG_ECDSA = 1,
    COSE_KEY_ALG_MLDSA = 2,
} cose_key_algorithm_t;

// ============================================================================
// ABI version
// ============================================================================

/**
 * @brief Returns the ABI version for this library
 * @return ABI version number
 */
uint32_t cose_cert_local_ffi_abi_version(void);

// ============================================================================
// Error handling
// ============================================================================

/**
 * @brief Returns the last error message for the current thread
 * 
 * @return UTF-8 null-terminated error string (must be freed with cose_cert_local_string_free)
 */
char* cose_cert_local_last_error_message_utf8(void);

/**
 * @brief Clears the last error for the current thread
 */
void cose_cert_local_last_error_clear(void);

/**
 * @brief Frees a string previously returned by this library
 * 
 * @param s String to free (may be null)
 */
void cose_cert_local_string_free(char* s);

// ============================================================================
// Factory operations
// ============================================================================

/**
 * @brief Creates a new ephemeral certificate factory
 * 
 * @param out Output pointer to receive the factory handle
 * @return COSE_OK on success, error code otherwise
 */
cose_status_t cose_cert_local_factory_new(cose_cert_local_factory_t** out);

/**
 * @brief Frees an ephemeral certificate factory
 * 
 * @param factory Factory handle to free (may be null)
 */
void cose_cert_local_factory_free(cose_cert_local_factory_t* factory);

/**
 * @brief Creates a certificate with custom options
 * 
 * @param factory Factory handle
 * @param subject Certificate subject name (UTF-8 null-terminated)
 * @param algorithm Key algorithm (0=RSA, 1=ECDSA, 2=MlDsa)
 * @param key_size Key size in bits
 * @param validity_secs Certificate validity period in seconds
 * @param out_cert_der Output pointer for certificate DER bytes
 * @param out_cert_len Output pointer for certificate length
 * @param out_key_der Output pointer for private key DER bytes
 * @param out_key_len Output pointer for private key length
 * @return COSE_OK on success, error code otherwise
 */
cose_status_t cose_cert_local_factory_create_cert(
    const cose_cert_local_factory_t* factory,
    const char* subject,
    uint32_t algorithm,
    uint32_t key_size,
    uint64_t validity_secs,
    uint8_t** out_cert_der,
    size_t* out_cert_len,
    uint8_t** out_key_der,
    size_t* out_key_len
);

/**
 * @brief Creates a self-signed certificate with default options
 * 
 * @param factory Factory handle
 * @param out_cert_der Output pointer for certificate DER bytes
 * @param out_cert_len Output pointer for certificate length
 * @param out_key_der Output pointer for private key DER bytes
 * @param out_key_len Output pointer for private key length
 * @return COSE_OK on success, error code otherwise
 */
cose_status_t cose_cert_local_factory_create_self_signed(
    const cose_cert_local_factory_t* factory,
    uint8_t** out_cert_der,
    size_t* out_cert_len,
    uint8_t** out_key_der,
    size_t* out_key_len
);

// ============================================================================
// Certificate chain operations
// ============================================================================

/**
 * @brief Creates a new certificate chain factory
 * 
 * @param out Output pointer to receive the chain factory handle
 * @return COSE_OK on success, error code otherwise
 */
cose_status_t cose_cert_local_chain_new(cose_cert_local_chain_t** out);

/**
 * @brief Frees a certificate chain factory
 * 
 * @param chain_factory Chain factory handle to free (may be null)
 */
void cose_cert_local_chain_free(cose_cert_local_chain_t* chain_factory);

/**
 * @brief Creates a certificate chain
 * 
 * @param chain_factory Chain factory handle
 * @param algorithm Key algorithm (0=RSA, 1=ECDSA, 2=MlDsa)
 * @param include_intermediate If true, include an intermediate CA in the chain
 * @param out_certs_data Output array of certificate DER byte pointers
 * @param out_certs_lengths Output array of certificate lengths
 * @param out_certs_count Output number of certificates in the chain
 * @param out_keys_data Output array of private key DER byte pointers
 * @param out_keys_lengths Output array of private key lengths
 * @param out_keys_count Output number of private keys in the chain
 * @return COSE_OK on success, error code otherwise
 */
cose_status_t cose_cert_local_chain_create(
    const cose_cert_local_chain_t* chain_factory,
    uint32_t algorithm,
    bool include_intermediate,
    uint8_t*** out_certs_data,
    size_t** out_certs_lengths,
    size_t* out_certs_count,
    uint8_t*** out_keys_data,
    size_t** out_keys_lengths,
    size_t* out_keys_count
);

// ============================================================================
// Certificate loading operations
// ============================================================================

/**
 * @brief Loads a certificate from PEM-encoded data
 * 
 * @param pem_data Pointer to PEM-encoded data
 * @param pem_len Length of PEM data in bytes
 * @param out_cert_der Output pointer for certificate DER bytes
 * @param out_cert_len Output pointer for certificate length
 * @param out_key_der Output pointer for private key DER bytes (may be null if no key present)
 * @param out_key_len Output pointer for private key length (will be 0 if no key present)
 * @return COSE_OK on success, error code otherwise
 */
cose_status_t cose_cert_local_load_pem(
    const uint8_t* pem_data,
    size_t pem_len,
    uint8_t** out_cert_der,
    size_t* out_cert_len,
    uint8_t** out_key_der,
    size_t* out_key_len
);

/**
 * @brief Loads a certificate from DER-encoded data
 * 
 * @param cert_data Pointer to DER-encoded certificate data
 * @param cert_len Length of certificate data in bytes
 * @param out_cert_der Output pointer for certificate DER bytes
 * @param out_cert_len Output pointer for certificate length
 * @return COSE_OK on success, error code otherwise
 */
cose_status_t cose_cert_local_load_der(
    const uint8_t* cert_data,
    size_t cert_len,
    uint8_t** out_cert_der,
    size_t* out_cert_len
);

// ============================================================================
// Memory management
// ============================================================================

/**
 * @brief Frees bytes allocated by this library
 * 
 * @param ptr Pointer to bytes to free (may be null)
 * @param len Length of the byte buffer
 */
void cose_cert_local_bytes_free(uint8_t* ptr, size_t len);

/**
 * @brief Frees arrays of pointers allocated by chain functions
 * 
 * @param ptr Pointer to array to free (may be null)
 * @param len Length of the array
 */
void cose_cert_local_array_free(uint8_t** ptr, size_t len);

/**
 * @brief Frees arrays of size_t values allocated by chain functions
 * 
 * @param ptr Pointer to array to free (may be null)
 * @param len Length of the array
 */
void cose_cert_local_lengths_array_free(size_t* ptr, size_t len);

#ifdef __cplusplus
}
#endif

#endif // COSE_SIGN1_CERTIFICATES_LOCAL_H
