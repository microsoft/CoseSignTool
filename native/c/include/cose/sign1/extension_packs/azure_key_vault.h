// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file azure_key_vault.h
 * @brief Azure Key Vault KID validation pack for COSE Sign1
 */

#ifndef COSE_SIGN1_AKV_H
#define COSE_SIGN1_AKV_H

#include <cose/sign1/validation.h>
#include <cose/sign1/trust.h>

#ifdef __cplusplus
extern "C" {
#endif

// Forward declaration for signing key handle
typedef struct cose_key_t cose_key_t;

/**
 * @brief Options for Azure Key Vault KID validation
 */
typedef struct {
    /** If true, require the KID to look like an Azure Key Vault identifier */
    bool require_azure_key_vault_kid;
    
    /** NULL-terminated array of allowed KID pattern strings (supports wildcards * and ?).
     *  NULL means use default patterns (*.vault.azure.net/keys/*, *.managedhsm.azure.net/keys/*). */
    const char* const* allowed_kid_patterns;
} cose_akv_trust_options_t;

/**
 * @brief Add Azure Key Vault KID validation pack with default options
 * 
 * Default options (secure-by-default):
 * - require_azure_key_vault_kid: true
 * - allowed_kid_patterns: 
 *   - https://*.vault.azure.net/keys/*
 *   - https://*.managedhsm.azure.net/keys/*
 * 
 * @param builder Validator builder handle
 * @return COSE_OK on success, error code otherwise
 */
cose_status_t cose_sign1_validator_builder_with_akv_pack(
    cose_sign1_validator_builder_t* builder
);

/**
 * @brief Add Azure Key Vault KID validation pack with custom options
 * 
 * @param builder Validator builder handle
 * @param options Options structure (NULL for defaults)
 * @return COSE_OK on success, error code otherwise
 */
cose_status_t cose_sign1_validator_builder_with_akv_pack_ex(
    cose_sign1_validator_builder_t* builder,
    const cose_akv_trust_options_t* options
);

/**
 * @brief Trust-policy helper: require that the message `kid` looks like an Azure Key Vault key identifier.
 *
 * This API is provided by the AKV pack FFI library and extends `cose_sign1_trust_policy_builder_t`.
 */
cose_status_t cose_sign1_akv_trust_policy_builder_require_azure_key_vault_kid(
    cose_sign1_trust_policy_builder_t* policy_builder
);

/**
 * @brief Trust-policy helper: require that the message `kid` does not look like an Azure Key Vault key identifier.
 *
 * This API is provided by the AKV pack FFI library and extends `cose_sign1_trust_policy_builder_t`.
 */
cose_status_t cose_sign1_akv_trust_policy_builder_require_not_azure_key_vault_kid(
    cose_sign1_trust_policy_builder_t* policy_builder
);

/**
 * @brief Trust-policy helper: require that the message `kid` is allowlisted by the AKV pack configuration.
 *
 * This API is provided by the AKV pack FFI library and extends `cose_sign1_trust_policy_builder_t`.
 */
cose_status_t cose_sign1_akv_trust_policy_builder_require_azure_key_vault_kid_allowed(
    cose_sign1_trust_policy_builder_t* policy_builder
);

/**
 * @brief Trust-policy helper: require that the message `kid` is not allowlisted by the AKV pack configuration.
 *
 * This API is provided by the AKV pack FFI library and extends `cose_sign1_trust_policy_builder_t`.
 */
cose_status_t cose_sign1_akv_trust_policy_builder_require_azure_key_vault_kid_not_allowed(
    cose_sign1_trust_policy_builder_t* policy_builder
);

/**
 * @brief Opaque handle to an Azure Key Vault key client
 */
typedef struct cose_akv_key_client_handle_t cose_akv_key_client_handle_t;

/**
 * @brief Create an AKV key client using DeveloperToolsCredential (for local dev)
 * 
 * @param vault_url Null-terminated UTF-8 vault URL (e.g. "https://myvault.vault.azure.net")
 * @param key_name Null-terminated UTF-8 key name
 * @param key_version Null-terminated UTF-8 key version, or NULL for latest
 * @param out_client Output pointer for the created client handle
 * @return COSE_OK on success, error code otherwise
 */
cose_status_t cose_akv_key_client_new_dev(
    const char* vault_url,
    const char* key_name,
    const char* key_version,
    cose_akv_key_client_handle_t** out_client
);

/**
 * @brief Create an AKV key client using ClientSecretCredential
 * 
 * @param vault_url Null-terminated UTF-8 vault URL (e.g. "https://myvault.vault.azure.net")
 * @param key_name Null-terminated UTF-8 key name
 * @param key_version Null-terminated UTF-8 key version, or NULL for latest
 * @param tenant_id Null-terminated UTF-8 Azure AD tenant ID
 * @param client_id Null-terminated UTF-8 Azure AD client (application) ID
 * @param client_secret Null-terminated UTF-8 Azure AD client secret
 * @param out_client Output pointer for the created client handle
 * @return COSE_OK on success, error code otherwise
 */
cose_status_t cose_akv_key_client_new_client_secret(
    const char* vault_url,
    const char* key_name,
    const char* key_version,
    const char* tenant_id,
    const char* client_id,
    const char* client_secret,
    cose_akv_key_client_handle_t** out_client
);

/**
 * @brief Free an AKV key client
 * 
 * @param client Client handle to free (NULL is safe)
 */
void cose_akv_key_client_free(cose_akv_key_client_handle_t* client);

/**
 * @brief Create a CoseKey (signing key handle) from an AKV key client
 * 
 * The returned key can be used with the signing FFI (cose_sign1_* functions).
 * 
 * @param akv_client AKV client handle (consumed - no longer valid after this call)
 * @param out_key Output pointer for the created signing key handle
 * @return COSE_OK on success, error code otherwise
 * 
 * @note The akv_client is consumed by this call and must not be used or freed afterward.
 *       The returned key must be freed with cose_key_free.
 */
cose_status_t cose_sign1_akv_create_signing_key(
    cose_akv_key_client_handle_t* akv_client,
    cose_key_t** out_key
);

/* ========================================================================== */
/* AKV Signing Service                                                        */
/* ========================================================================== */

/**
 * @brief Opaque handle to an AKV signing service
 * 
 * Free with `cose_sign1_akv_signing_service_free()`.
 */
typedef struct cose_akv_signing_service_handle_t cose_akv_signing_service_handle_t;

/**
 * @brief Create an AKV signing service from a key client
 * 
 * The signing service provides a high-level interface for COSE_Sign1 message creation
 * using Azure Key Vault for cryptographic operations.
 *
 * @param client       AKV key client handle (consumed - no longer valid after this call)
 * @param out          Receives the signing service handle
 * @return COSE_OK on success, error code otherwise
 * 
 * @note The client handle is consumed by this call and must not be used or freed afterward.
 *       The returned service must be freed with cose_sign1_akv_signing_service_free.
 */
cose_status_t cose_sign1_akv_create_signing_service(
    cose_akv_key_client_handle_t* client,
    cose_akv_signing_service_handle_t** out
);

/**
 * @brief Free an AKV signing service handle
 * 
 * @param handle Handle to free (NULL is a safe no-op)
 */
void cose_sign1_akv_signing_service_free(cose_akv_signing_service_handle_t* handle);

#ifdef __cplusplus
}
#endif

#endif // COSE_SIGN1_AKV_H
