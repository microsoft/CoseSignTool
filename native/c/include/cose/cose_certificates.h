// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file cose_certificates.h
 * @brief X.509 certificate validation pack for COSE Sign1
 */

#ifndef COSE_CERTIFICATES_H
#define COSE_CERTIFICATES_H

#include "cose_sign1.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Options for X.509 certificate validation
 */
typedef struct {
    /** If true, treat well-formed embedded x5chain as trusted (for tests/pinned roots) */
    bool trust_embedded_chain_as_trusted;
    
    /** If true, enable identity pinning based on allowed_thumbprints */
    bool identity_pinning_enabled;
    
    /** NULL-terminated array of allowed certificate thumbprints (case/whitespace insensitive).
     *  NULL means no thumbprint filtering. */
    const char* const* allowed_thumbprints;
    
    /** NULL-terminated array of PQC algorithm OID strings.
     *  NULL means no custom PQC OIDs. */
    const char* const* pqc_algorithm_oids;
} cose_certificate_trust_options_t;

/**
 * @brief Add X.509 certificate validation pack with default options
 * 
 * Default options:
 * - trust_embedded_chain_as_trusted: false
 * - identity_pinning_enabled: false
 * - No thumbprint filtering
 * - No custom PQC OIDs
 * 
 * @param builder Validator builder handle
 * @return COSE_OK on success, error code otherwise
 */
cose_status_t cose_validator_builder_with_certificates_pack(
    cose_validator_builder_t* builder
);

/**
 * @brief Add X.509 certificate validation pack with custom options
 * 
 * @param builder Validator builder handle
 * @param options Options structure (NULL for defaults)
 * @return COSE_OK on success, error code otherwise
 */
cose_status_t cose_validator_builder_with_certificates_pack_ex(
    cose_validator_builder_t* builder,
    const cose_certificate_trust_options_t* options
);

#ifdef __cplusplus
}
#endif

#endif // COSE_CERTIFICATES_H
