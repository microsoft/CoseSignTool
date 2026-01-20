// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file cose_mst.h
 * @brief Microsoft Secure Transparency (MST) receipt verification pack for COSE Sign1
 */

#ifndef COSE_MST_H
#define COSE_MST_H

#include "cose_sign1.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Options for MST receipt verification
 */
typedef struct {
    /** If true, allow network fetching of JWKS when offline keys are missing */
    bool allow_network;
    
    /** Offline JWKS JSON string (NULL means no offline JWKS). Not owned by this struct. */
    const char* offline_jwks_json;
    
    /** Optional api-version for CodeTransparency /jwks endpoint (NULL means no api-version) */
    const char* jwks_api_version;
} cose_mst_trust_options_t;

/**
 * @brief Add MST receipt verification pack with default options (online mode)
 * 
 * Default options:
 * - allow_network: true
 * - No offline JWKS
 * - No api-version
 * 
 * @param builder Validator builder handle
 * @return COSE_OK on success, error code otherwise
 */
cose_status_t cose_validator_builder_with_mst_pack(
    cose_validator_builder_t* builder
);

/**
 * @brief Add MST receipt verification pack with custom options
 * 
 * @param builder Validator builder handle
 * @param options Options structure (NULL for defaults)
 * @return COSE_OK on success, error code otherwise
 */
cose_status_t cose_validator_builder_with_mst_pack_ex(
    cose_validator_builder_t* builder,
    const cose_mst_trust_options_t* options
);

#ifdef __cplusplus
}
#endif

#endif // COSE_MST_H
