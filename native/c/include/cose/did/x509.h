// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file x509.h
 * @brief C API for DID:X509 parsing, building, validation and resolution.
 *
 * This header provides the C API for the did_x509_ffi crate, which implements
 * DID:X509 identifier operations according to the specification at:
 * https://github.com/microsoft/did-x509/blob/main/specification.md
 *
 * DID:X509 provides a cryptographically verifiable decentralized identifier
 * based on X.509 PKI, enabling interoperability between traditional PKI and
 * decentralized identity systems.
 *
 * @section error_handling Error Handling
 *
 * All functions follow a consistent error handling pattern:
 * - Return value: 0 = success, negative = error code
 * - out_error parameter: Set to error handle on failure (caller must free)
 * - Output parameters: Only valid if return is 0
 *
 * @section memory_management Memory Management
 *
 * Handles and strings returned by this library must be freed using the corresponding *_free function:
 * - did_x509_parsed_free for parsed identifier handles
 * - did_x509_error_free for error handles
 * - did_x509_string_free for string pointers
 *
 * @section example Example
 *
 * @code{.c}
 * const uint8_t* ca_cert_der = ...;
 * uint32_t ca_cert_len = ...;
 * const char* eku_oids[] = {"1.3.6.1.5.5.7.3.1"};
 * char* did_string = NULL;
 * DidX509ErrorHandle* error = NULL;
 *
 * int result = did_x509_build_with_eku(
 *     ca_cert_der, ca_cert_len,
 *     eku_oids, 1,
 *     &did_string,
 *     &error);
 *
 * if (result == DID_X509_OK) {
 *     printf("Generated DID: %s\n", did_string);
 *     did_x509_string_free(did_string);
 * } else {
 *     char* msg = did_x509_error_message(error);
 *     fprintf(stderr, "Error: %s\n", msg);
 *     did_x509_string_free(msg);
 *     did_x509_error_free(error);
 * }
 * @endcode
 */

#ifndef COSE_DID_X509_H
#define COSE_DID_X509_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Status codes
// ============================================================================

/**
 * @brief Operation succeeded.
 */
#define DID_X509_OK                     0

/**
 * @brief A required argument was NULL.
 */
#define DID_X509_ERR_NULL_POINTER       -1

/**
 * @brief Parsing failed (invalid DID format).
 */
#define DID_X509_ERR_PARSE_FAILED       -2

/**
 * @brief Building failed (invalid certificate data).
 */
#define DID_X509_ERR_BUILD_FAILED       -3

/**
 * @brief Validation failed.
 */
#define DID_X509_ERR_VALIDATE_FAILED    -4

/**
 * @brief Resolution failed.
 */
#define DID_X509_ERR_RESOLVE_FAILED     -5

/**
 * @brief Invalid argument provided.
 */
#define DID_X509_ERR_INVALID_ARGUMENT   -6

/**
 * @brief Internal error or panic occurred.
 */
#define DID_X509_ERR_PANIC              -99

// ============================================================================
// Opaque handle types
// ============================================================================

/**
 * @brief Opaque handle to a parsed DID:X509 identifier.
 */
typedef struct DidX509ParsedHandle DidX509ParsedHandle;

/**
 * @brief Opaque handle to an error.
 */
typedef struct DidX509ErrorHandle DidX509ErrorHandle;

// ============================================================================
// ABI versioning
// ============================================================================

/**
 * @brief Returns the ABI version for this library.
 *
 * Increment when making breaking changes to the FFI interface.
 *
 * @return ABI version number.
 */
uint32_t did_x509_abi_version(void);

// ============================================================================
// Parsing functions
// ============================================================================

/**
 * @brief Parse a DID:X509 string into components.
 *
 * @param did_string Null-terminated DID string to parse.
 * @param out_handle Output parameter for the parsed handle. Caller must free with did_x509_parsed_free().
 * @param out_error Output parameter for error handle. Caller must free with did_x509_error_free() on failure.
 * @return DID_X509_OK on success, error code otherwise.
 */
int did_x509_parse(
    const char* did_string,
    DidX509ParsedHandle** out_handle,
    DidX509ErrorHandle** out_error
);

/**
 * @brief Get CA fingerprint hex from parsed DID.
 *
 * @param handle Parsed DID handle.
 * @param out_fingerprint Output parameter for fingerprint string. Caller must free with did_x509_string_free().
 * @param out_error Output parameter for error handle. Caller must free with did_x509_error_free() on failure.
 * @return DID_X509_OK on success, error code otherwise.
 */
int did_x509_parsed_get_fingerprint(
    const DidX509ParsedHandle* handle,
    char** out_fingerprint,
    DidX509ErrorHandle** out_error
);

/**
 * @brief Get hash algorithm from parsed DID.
 *
 * @param handle Parsed DID handle.
 * @param out_algorithm Output parameter for algorithm string. Caller must free with did_x509_string_free().
 * @param out_error Output parameter for error handle. Caller must free with did_x509_error_free() on failure.
 * @return DID_X509_OK on success, error code otherwise.
 */
int did_x509_parsed_get_hash_algorithm(
    const DidX509ParsedHandle* handle,
    char** out_algorithm,
    DidX509ErrorHandle** out_error
);

/**
 * @brief Get policy count from parsed DID.
 *
 * @param handle Parsed DID handle.
 * @param out_count Output parameter for policy count.
 * @return DID_X509_OK on success, error code otherwise.
 */
int did_x509_parsed_get_policy_count(
    const DidX509ParsedHandle* handle,
    uint32_t* out_count
);

/**
 * @brief Frees a parsed DID handle.
 *
 * @param handle Parsed DID handle to free (can be NULL).
 */
void did_x509_parsed_free(DidX509ParsedHandle* handle);

// ============================================================================
// Building functions
// ============================================================================

/**
 * @brief Build DID:X509 from CA certificate DER and EKU OIDs.
 *
 * @param ca_cert_der DER-encoded CA certificate bytes.
 * @param ca_cert_len Length of ca_cert_der.
 * @param eku_oids Array of null-terminated EKU OID strings.
 * @param eku_count Number of EKU OIDs.
 * @param out_did_string Output parameter for the generated DID string. Caller must free with did_x509_string_free().
 * @param out_error Output parameter for error handle. Caller must free with did_x509_error_free() on failure.
 * @return DID_X509_OK on success, error code otherwise.
 */
int did_x509_build_with_eku(
    const uint8_t* ca_cert_der,
    uint32_t ca_cert_len,
    const char** eku_oids,
    uint32_t eku_count,
    char** out_did_string,
    DidX509ErrorHandle** out_error
);

/**
 * @brief Build DID:X509 from certificate chain (leaf-first) with automatic EKU extraction.
 *
 * @param chain_certs Array of pointers to DER-encoded certificate data.
 * @param chain_cert_lens Array of certificate lengths.
 * @param chain_count Number of certificates in the chain.
 * @param out_did_string Output parameter for the generated DID string. Caller must free with did_x509_string_free().
 * @param out_error Output parameter for error handle. Caller must free with did_x509_error_free() on failure.
 * @return DID_X509_OK on success, error code otherwise.
 */
int did_x509_build_from_chain(
    const uint8_t** chain_certs,
    const uint32_t* chain_cert_lens,
    uint32_t chain_count,
    char** out_did_string,
    DidX509ErrorHandle** out_error
);

// ============================================================================
// Validation functions
// ============================================================================

/**
 * @brief Validate DID against certificate chain.
 *
 * Verifies that the DID was correctly generated from the given certificate chain.
 *
 * @param did_string Null-terminated DID string to validate.
 * @param chain_certs Array of pointers to DER-encoded certificate data.
 * @param chain_cert_lens Array of certificate lengths.
 * @param chain_count Number of certificates in the chain.
 * @param out_is_valid Output parameter set to 1 if valid, 0 if invalid.
 * @param out_error Output parameter for error handle. Caller must free with did_x509_error_free() on failure.
 * @return DID_X509_OK on success, error code otherwise.
 */
int did_x509_validate(
    const char* did_string,
    const uint8_t** chain_certs,
    const uint32_t* chain_cert_lens,
    uint32_t chain_count,
    int* out_is_valid,
    DidX509ErrorHandle** out_error
);

// ============================================================================
// Resolution functions
// ============================================================================

/**
 * @brief Resolve DID to JSON DID Document.
 *
 * @param did_string Null-terminated DID string to resolve.
 * @param chain_certs Array of pointers to DER-encoded certificate data.
 * @param chain_cert_lens Array of certificate lengths.
 * @param chain_count Number of certificates in the chain.
 * @param out_did_document_json Output parameter for JSON DID document. Caller must free with did_x509_string_free().
 * @param out_error Output parameter for error handle. Caller must free with did_x509_error_free() on failure.
 * @return DID_X509_OK on success, error code otherwise.
 */
int did_x509_resolve(
    const char* did_string,
    const uint8_t** chain_certs,
    const uint32_t* chain_cert_lens,
    uint32_t chain_count,
    char** out_did_document_json,
    DidX509ErrorHandle** out_error
);

// ============================================================================
// Error handling functions
// ============================================================================

/**
 * @brief Gets the error message as a C string.
 *
 * @param handle Error handle (can be NULL).
 * @return Error message string or NULL. Caller must free with did_x509_string_free().
 */
char* did_x509_error_message(const DidX509ErrorHandle* handle);

/**
 * @brief Gets the error code.
 *
 * @param handle Error handle (can be NULL).
 * @return Error code or 0 if handle is NULL.
 */
int did_x509_error_code(const DidX509ErrorHandle* handle);

/**
 * @brief Frees an error handle.
 *
 * @param handle Error handle to free (can be NULL).
 */
void did_x509_error_free(DidX509ErrorHandle* handle);

/**
 * @brief Frees a string returned by this library.
 *
 * @param s String to free (can be NULL).
 */
void did_x509_string_free(char* s);

#ifdef __cplusplus
}
#endif

#endif // COSE_DID_X509_H
