// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file openssl.h
 * @brief OpenSSL crypto provider for COSE Sign1
 */

#ifndef COSE_CRYPTO_OPENSSL_H
#define COSE_CRYPTO_OPENSSL_H

#include <cose/cose.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Forward declarations
typedef struct cose_crypto_provider_t cose_crypto_provider_t;
typedef struct cose_crypto_signer_t cose_crypto_signer_t;
typedef struct cose_crypto_verifier_t cose_crypto_verifier_t;

// ============================================================================
// ABI version
// ============================================================================

/**
 * @brief Returns the ABI version for this library
 * @return ABI version number
 */
uint32_t cose_crypto_openssl_abi_version(void);

// ============================================================================
// Error handling
// ============================================================================

/**
 * @brief Returns the last error message for the current thread
 * 
 * @return UTF-8 null-terminated error string (must be freed with cose_string_free)
 */
char* cose_last_error_message_utf8(void);

/**
 * @brief Clears the last error message for the current thread
 */
void cose_last_error_clear(void);

/**
 * @brief Frees a string previously returned by this library
 * 
 * @param s String to free (may be null)
 */
void cose_string_free(char* s);

// ============================================================================
// Provider operations
// ============================================================================

/**
 * @brief Creates a new OpenSSL crypto provider instance
 * 
 * @param out Output pointer to receive the provider handle
 * @return COSE_OK on success, error code otherwise
 */
cose_status_t cose_crypto_openssl_provider_new(cose_crypto_provider_t** out);

/**
 * @brief Frees an OpenSSL crypto provider instance
 * 
 * @param provider Provider handle to free (may be null)
 */
void cose_crypto_openssl_provider_free(cose_crypto_provider_t* provider);

// ============================================================================
// Signer operations
// ============================================================================

/**
 * @brief Creates a signer from a DER-encoded private key
 * 
 * @param provider Provider handle
 * @param private_key_der Pointer to DER-encoded private key bytes
 * @param len Length of private key data in bytes
 * @param out_signer Output pointer to receive the signer handle
 * @return COSE_OK on success, error code otherwise
 */
cose_status_t cose_crypto_openssl_signer_from_der(
    const cose_crypto_provider_t* provider,
    const uint8_t* private_key_der,
    size_t len,
    cose_crypto_signer_t** out_signer
);

/**
 * @brief Creates a signer from a PEM-encoded private key
 *
 * @param provider Provider handle
 * @param private_key_pem Pointer to PEM-encoded private key bytes
 * @param len Length of private key data in bytes
 * @param out_signer Output pointer to receive the signer handle
 * @return COSE_OK on success, error code otherwise
 */
cose_status_t cose_crypto_openssl_signer_from_pem(
    const cose_crypto_provider_t* provider,
    const uint8_t* private_key_pem,
    size_t len,
    cose_crypto_signer_t** out_signer
);

/**
 * @brief Sign data using the given signer
 * 
 * @param signer Signer handle
 * @param data Pointer to data to sign
 * @param data_len Length of data in bytes
 * @param out_sig Output pointer to receive signature bytes
 * @param out_sig_len Output pointer to receive signature length
 * @return COSE_OK on success, error code otherwise
 */
cose_status_t cose_crypto_signer_sign(
    const cose_crypto_signer_t* signer,
    const uint8_t* data,
    size_t data_len,
    uint8_t** out_sig,
    size_t* out_sig_len
);

/**
 * @brief Get the COSE algorithm identifier for the signer
 * 
 * @param signer Signer handle
 * @return COSE algorithm identifier (0 if signer is null)
 */
int64_t cose_crypto_signer_algorithm(const cose_crypto_signer_t* signer);

/**
 * @brief Frees a signer instance
 * 
 * @param signer Signer handle to free (may be null)
 */
void cose_crypto_signer_free(cose_crypto_signer_t* signer);

// ============================================================================
// Verifier operations
// ============================================================================

/**
 * @brief Creates a verifier from a DER-encoded public key
 * 
 * @param provider Provider handle
 * @param public_key_der Pointer to DER-encoded public key bytes
 * @param len Length of public key data in bytes
 * @param out_verifier Output pointer to receive the verifier handle
 * @return COSE_OK on success, error code otherwise
 */
cose_status_t cose_crypto_openssl_verifier_from_der(
    const cose_crypto_provider_t* provider,
    const uint8_t* public_key_der,
    size_t len,
    cose_crypto_verifier_t** out_verifier
);

/**
 * @brief Creates a verifier from a PEM-encoded public key
 *
 * @param provider Provider handle
 * @param public_key_pem Pointer to PEM-encoded public key bytes
 * @param len Length of public key data in bytes
 * @param out_verifier Output pointer to receive the verifier handle
 * @return COSE_OK on success, error code otherwise
 */
cose_status_t cose_crypto_openssl_verifier_from_pem(
    const cose_crypto_provider_t* provider,
    const uint8_t* public_key_pem,
    size_t len,
    cose_crypto_verifier_t** out_verifier
);

/**
 * @brief Verify a signature using the given verifier
 * 
 * @param verifier Verifier handle
 * @param data Pointer to data that was signed
 * @param data_len Length of data in bytes
 * @param sig Pointer to signature bytes
 * @param sig_len Length of signature in bytes
 * @param out_valid Output pointer to receive verification result (true=valid, false=invalid)
 * @return COSE_OK on success, error code otherwise
 */
cose_status_t cose_crypto_verifier_verify(
    const cose_crypto_verifier_t* verifier,
    const uint8_t* data,
    size_t data_len,
    const uint8_t* sig,
    size_t sig_len,
    bool* out_valid
);

/**
 * @brief Frees a verifier instance
 * 
 * @param verifier Verifier handle to free (may be null)
 */
void cose_crypto_verifier_free(cose_crypto_verifier_t* verifier);

// ============================================================================
// JWK verifier factory
// ============================================================================

/**
 * @brief Creates a verifier from EC JWK public key fields
 *
 * Accepts base64url-encoded x/y coordinates (per RFC 7518) and a COSE algorithm
 * identifier. The resulting verifier can be used with cose_crypto_verifier_verify().
 *
 * @param crv  Curve name: "P-256", "P-384", or "P-521"
 * @param x    Base64url-encoded x-coordinate
 * @param y    Base64url-encoded y-coordinate
 * @param kid  Key ID (may be NULL)
 * @param cose_algorithm  COSE algorithm identifier (e.g. -7 for ES256)
 * @param out_verifier  Output pointer to receive verifier handle
 * @return COSE_OK on success, error code otherwise
 */
cose_status_t cose_crypto_openssl_jwk_verifier_from_ec(
    const char* crv,
    const char* x,
    const char* y,
    const char* kid,
    int64_t cose_algorithm,
    cose_crypto_verifier_t** out_verifier
);

/**
 * @brief Creates a verifier from RSA JWK public key fields
 *
 * Accepts base64url-encoded modulus (n) and exponent (e) per RFC 7518.
 *
 * @param n    Base64url-encoded RSA modulus
 * @param e    Base64url-encoded RSA public exponent
 * @param kid  Key ID (may be NULL)
 * @param cose_algorithm  COSE algorithm identifier (e.g. -37 for PS256)
 * @param out_verifier  Output pointer to receive verifier handle
 * @return COSE_OK on success, error code otherwise
 */
cose_status_t cose_crypto_openssl_jwk_verifier_from_rsa(
    const char* n,
    const char* e,
    const char* kid,
    int64_t cose_algorithm,
    cose_crypto_verifier_t** out_verifier
);

// ============================================================================
// Memory management
// ============================================================================

/**
 * @brief Frees a byte buffer previously returned by this library
 * 
 * @param ptr Pointer to bytes to free (may be null)
 * @param len Length of the byte buffer
 */
void cose_crypto_bytes_free(uint8_t* ptr, size_t len);

#ifdef __cplusplus
}
#endif

#endif // COSE_CRYPTO_OPENSSL_H
