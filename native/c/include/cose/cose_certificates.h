// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file cose_certificates.h
 * @brief X.509 certificate validation pack for COSE Sign1
 */

#ifndef COSE_CERTIFICATES_H
#define COSE_CERTIFICATES_H

#include "cose_sign1.h"
#include "cose_trust.h"

#include <stddef.h>
#include <stdint.h>

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

/**
 * @brief Trust-policy helper: require that the X.509 chain is trusted.
 *
 * This API is provided by the certificates pack FFI library and extends `cose_trust_policy_builder_t`.
 */
cose_status_t cose_certificates_trust_policy_builder_require_x509_chain_trusted(
    cose_trust_policy_builder_t* policy_builder
);

/**
 * @brief Trust-policy helper: require that the X.509 chain is not trusted.
 *
 * This API is provided by the certificates pack FFI library and extends `cose_trust_policy_builder_t`.
 */
cose_status_t cose_certificates_trust_policy_builder_require_x509_chain_not_trusted(
    cose_trust_policy_builder_t* policy_builder
);

/**
 * @brief Trust-policy helper: require that the X.509 chain could be built (pack observed at least one element).
 *
 * This API is provided by the certificates pack FFI library and extends `cose_trust_policy_builder_t`.
 */
cose_status_t cose_certificates_trust_policy_builder_require_x509_chain_built(
    cose_trust_policy_builder_t* policy_builder
);

/**
 * @brief Trust-policy helper: require that the X.509 chain could not be built.
 *
 * This API is provided by the certificates pack FFI library and extends `cose_trust_policy_builder_t`.
 */
cose_status_t cose_certificates_trust_policy_builder_require_x509_chain_not_built(
    cose_trust_policy_builder_t* policy_builder
);

/**
 * @brief Trust-policy helper: require that the X.509 chain element count equals `expected`.
 *
 * This API is provided by the certificates pack FFI library and extends `cose_trust_policy_builder_t`.
 */
cose_status_t cose_certificates_trust_policy_builder_require_x509_chain_element_count_eq(
    cose_trust_policy_builder_t* policy_builder,
    size_t expected
);

/**
 * @brief Trust-policy helper: require that the X.509 chain status flags equal `expected`.
 *
 * This API is provided by the certificates pack FFI library and extends `cose_trust_policy_builder_t`.
 */
cose_status_t cose_certificates_trust_policy_builder_require_x509_chain_status_flags_eq(
    cose_trust_policy_builder_t* policy_builder,
    uint32_t expected
);

/**
 * @brief Trust-policy helper: require that the leaf chain element (index 0) has a non-empty thumbprint.
 */
cose_status_t cose_certificates_trust_policy_builder_require_leaf_chain_thumbprint_present(
    cose_trust_policy_builder_t* policy_builder
);

/**
 * @brief Trust-policy helper: require that a signing certificate identity fact is present.
 */
cose_status_t cose_certificates_trust_policy_builder_require_signing_certificate_present(
    cose_trust_policy_builder_t* policy_builder
);

/**
 * @brief Trust-policy helper: pin the leaf certificate subject name (chain element index 0).
 */
cose_status_t cose_certificates_trust_policy_builder_require_leaf_subject_eq(
    cose_trust_policy_builder_t* policy_builder,
    const char* subject_utf8
);

/**
 * @brief Trust-policy helper: pin the issuer certificate subject name (chain element index 1).
 */
cose_status_t cose_certificates_trust_policy_builder_require_issuer_subject_eq(
    cose_trust_policy_builder_t* policy_builder,
    const char* subject_utf8
);

/**
 * @brief Trust-policy helper: require that the signing certificate subject/issuer matches the leaf chain element.
 */
cose_status_t cose_certificates_trust_policy_builder_require_signing_certificate_subject_issuer_matches_leaf_chain_element(
    cose_trust_policy_builder_t* policy_builder
);

/**
 * @brief Trust-policy helper: if the issuer element (index 1) is missing, allow; otherwise require issuer chaining.
 */
cose_status_t cose_certificates_trust_policy_builder_require_leaf_issuer_is_next_chain_subject_optional(
    cose_trust_policy_builder_t* policy_builder
);

/**
 * @brief Trust-policy helper: require the leaf signing certificate thumbprint to equal the provided value.
 */
cose_status_t cose_certificates_trust_policy_builder_require_signing_certificate_thumbprint_eq(
    cose_trust_policy_builder_t* policy_builder,
    const char* thumbprint_utf8
);

/**
 * @brief Trust-policy helper: require that the leaf signing certificate thumbprint is present and non-empty.
 */
cose_status_t cose_certificates_trust_policy_builder_require_signing_certificate_thumbprint_present(
    cose_trust_policy_builder_t* policy_builder
);

/**
 * @brief Trust-policy helper: require the leaf signing certificate subject to equal the provided value.
 */
cose_status_t cose_certificates_trust_policy_builder_require_signing_certificate_subject_eq(
    cose_trust_policy_builder_t* policy_builder,
    const char* subject_utf8
);

/**
 * @brief Trust-policy helper: require the leaf signing certificate issuer to equal the provided value.
 */
cose_status_t cose_certificates_trust_policy_builder_require_signing_certificate_issuer_eq(
    cose_trust_policy_builder_t* policy_builder,
    const char* issuer_utf8
);

/**
 * @brief Trust-policy helper: require the leaf signing certificate serial number to equal the provided value.
 */
cose_status_t cose_certificates_trust_policy_builder_require_signing_certificate_serial_number_eq(
    cose_trust_policy_builder_t* policy_builder,
    const char* serial_number_utf8
);

/**
 * @brief Trust-policy helper: require that the signing certificate is expired at or before `now_unix_seconds`.
 */
cose_status_t cose_certificates_trust_policy_builder_require_signing_certificate_expired_at_or_before(
    cose_trust_policy_builder_t* policy_builder,
    int64_t now_unix_seconds
);

/**
 * @brief Trust-policy helper: require that the leaf signing certificate is valid at `now_unix_seconds`.
 */
cose_status_t cose_certificates_trust_policy_builder_require_signing_certificate_valid_at(
    cose_trust_policy_builder_t* policy_builder,
    int64_t now_unix_seconds
);

/**
 * @brief Trust-policy helper: require signing certificate not-before <= `max_unix_seconds`.
 */
cose_status_t cose_certificates_trust_policy_builder_require_signing_certificate_not_before_le(
    cose_trust_policy_builder_t* policy_builder,
    int64_t max_unix_seconds
);

/**
 * @brief Trust-policy helper: require signing certificate not-before >= `min_unix_seconds`.
 */
cose_status_t cose_certificates_trust_policy_builder_require_signing_certificate_not_before_ge(
    cose_trust_policy_builder_t* policy_builder,
    int64_t min_unix_seconds
);

/**
 * @brief Trust-policy helper: require signing certificate not-after <= `max_unix_seconds`.
 */
cose_status_t cose_certificates_trust_policy_builder_require_signing_certificate_not_after_le(
    cose_trust_policy_builder_t* policy_builder,
    int64_t max_unix_seconds
);

/**
 * @brief Trust-policy helper: require signing certificate not-after >= `min_unix_seconds`.
 */
cose_status_t cose_certificates_trust_policy_builder_require_signing_certificate_not_after_ge(
    cose_trust_policy_builder_t* policy_builder,
    int64_t min_unix_seconds
);

/**
 * @brief Trust-policy helper: require that the X.509 chain element at `index` has subject equal to the provided value.
 */
cose_status_t cose_certificates_trust_policy_builder_require_chain_element_subject_eq(
    cose_trust_policy_builder_t* policy_builder,
    size_t index,
    const char* subject_utf8
);

/**
 * @brief Trust-policy helper: require that the X.509 chain element at `index` has issuer equal to the provided value.
 */
cose_status_t cose_certificates_trust_policy_builder_require_chain_element_issuer_eq(
    cose_trust_policy_builder_t* policy_builder,
    size_t index,
    const char* issuer_utf8
);

/**
 * @brief Trust-policy helper: require that the X.509 chain element at `index` has thumbprint equal to the provided value.
 */
cose_status_t cose_certificates_trust_policy_builder_require_chain_element_thumbprint_eq(
    cose_trust_policy_builder_t* policy_builder,
    size_t index,
    const char* thumbprint_utf8
);

/**
 * @brief Trust-policy helper: require that the X.509 chain element at `index` has a non-empty thumbprint.
 */
cose_status_t cose_certificates_trust_policy_builder_require_chain_element_thumbprint_present(
    cose_trust_policy_builder_t* policy_builder,
    size_t index
);

/**
 * @brief Trust-policy helper: require that the X.509 chain element at `index` is valid at `now_unix_seconds`.
 */
cose_status_t cose_certificates_trust_policy_builder_require_chain_element_valid_at(
    cose_trust_policy_builder_t* policy_builder,
    size_t index,
    int64_t now_unix_seconds
);

/**
 * @brief Trust-policy helper: require chain element not-before <= `max_unix_seconds`.
 */
cose_status_t cose_certificates_trust_policy_builder_require_chain_element_not_before_le(
    cose_trust_policy_builder_t* policy_builder,
    size_t index,
    int64_t max_unix_seconds
);

/**
 * @brief Trust-policy helper: require chain element not-before >= `min_unix_seconds`.
 */
cose_status_t cose_certificates_trust_policy_builder_require_chain_element_not_before_ge(
    cose_trust_policy_builder_t* policy_builder,
    size_t index,
    int64_t min_unix_seconds
);

/**
 * @brief Trust-policy helper: require chain element not-after <= `max_unix_seconds`.
 */
cose_status_t cose_certificates_trust_policy_builder_require_chain_element_not_after_le(
    cose_trust_policy_builder_t* policy_builder,
    size_t index,
    int64_t max_unix_seconds
);

/**
 * @brief Trust-policy helper: require chain element not-after >= `min_unix_seconds`.
 */
cose_status_t cose_certificates_trust_policy_builder_require_chain_element_not_after_ge(
    cose_trust_policy_builder_t* policy_builder,
    size_t index,
    int64_t min_unix_seconds
);

/**
 * @brief Trust-policy helper: deny if a PQC algorithm is explicitly detected; allow if missing.
 */
cose_status_t cose_certificates_trust_policy_builder_require_not_pqc_algorithm_or_missing(
    cose_trust_policy_builder_t* policy_builder
);

/**
 * @brief Trust-policy helper: require that the X.509 public key algorithm fact has thumbprint equal to the provided value.
 */
cose_status_t cose_certificates_trust_policy_builder_require_x509_public_key_algorithm_thumbprint_eq(
    cose_trust_policy_builder_t* policy_builder,
    const char* thumbprint_utf8
);

/**
 * @brief Trust-policy helper: require that the X.509 public key algorithm OID equals the provided value.
 */
cose_status_t cose_certificates_trust_policy_builder_require_x509_public_key_algorithm_oid_eq(
    cose_trust_policy_builder_t* policy_builder,
    const char* oid_utf8
);

/**
 * @brief Trust-policy helper: require that the X.509 public key algorithm is flagged as PQC.
 */
cose_status_t cose_certificates_trust_policy_builder_require_x509_public_key_algorithm_is_pqc(
    cose_trust_policy_builder_t* policy_builder
);

/**
 * @brief Trust-policy helper: require that the X.509 public key algorithm is not flagged as PQC.
 */
cose_status_t cose_certificates_trust_policy_builder_require_x509_public_key_algorithm_is_not_pqc(
    cose_trust_policy_builder_t* policy_builder
);

#ifdef __cplusplus
}
#endif

#endif // COSE_CERTIFICATES_H
