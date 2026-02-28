// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file azure_trusted_signing.h
 * @brief Azure Trusted Signing trust pack for COSE Sign1
 */

#ifndef COSE_SIGN1_ATS_H
#define COSE_SIGN1_ATS_H

#include <cose/sign1/validation.h>
#include <cose/sign1/trust.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Options for Azure Trusted Signing trust pack
 */
typedef struct {
    /** ATS endpoint URL (null-terminated UTF-8) */
    const char* endpoint;
    /** ATS account name (null-terminated UTF-8) */
    const char* account_name;
    /** Certificate profile name (null-terminated UTF-8) */
    const char* certificate_profile_name;
} cose_ats_trust_options_t;

/**
 * @brief Add Azure Trusted Signing trust pack with default options.
 * @param builder Validator builder handle.
 * @return COSE_OK on success, error code otherwise.
 */
cose_status_t cose_sign1_validator_builder_with_ats_pack(
    cose_sign1_validator_builder_t* builder
);

/**
 * @brief Add Azure Trusted Signing trust pack with custom options.
 * @param builder Validator builder handle.
 * @param options Options structure (NULL for defaults).
 * @return COSE_OK on success, error code otherwise.
 */
cose_status_t cose_sign1_validator_builder_with_ats_pack_ex(
    cose_sign1_validator_builder_t* builder,
    const cose_ats_trust_options_t* options
);

#ifdef __cplusplus
}
#endif

#endif /* COSE_SIGN1_ATS_H */