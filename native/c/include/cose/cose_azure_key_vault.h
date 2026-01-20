// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file cose_azure_key_vault.h
 * @brief Azure Key Vault KID validation pack for COSE Sign1
 */

#ifndef COSE_AZURE_KEY_VAULT_H
#define COSE_AZURE_KEY_VAULT_H

#include "cose_sign1.h"

#ifdef __cplusplus
extern "C" {
#endif

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
cose_status_t cose_validator_builder_with_akv_pack(
    cose_validator_builder_t* builder
);

/**
 * @brief Add Azure Key Vault KID validation pack with custom options
 * 
 * @param builder Validator builder handle
 * @param options Options structure (NULL for defaults)
 * @return COSE_OK on success, error code otherwise
 */
cose_status_t cose_validator_builder_with_akv_pack_ex(
    cose_validator_builder_t* builder,
    const cose_akv_trust_options_t* options
);

#ifdef __cplusplus
}
#endif

#endif // COSE_AZURE_KEY_VAULT_H
