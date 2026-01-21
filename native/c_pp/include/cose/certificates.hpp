// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file certificates.hpp
 * @brief C++ wrappers for X.509 certificate validation pack
 */

#ifndef COSE_CERTIFICATES_HPP
#define COSE_CERTIFICATES_HPP

#include <cose/validator.hpp>
#include <cose/trust.hpp>
#include <cose/cose_certificates.h>
#include <vector>
#include <string>

namespace cose {

/**
 * @brief Options for X.509 certificate validation
 */
struct CertificateOptions {
    /** If true, treat well-formed embedded x5chain as trusted (for tests/pinned roots) */
    bool trust_embedded_chain_as_trusted = false;
    
    /** If true, enable identity pinning based on allowed_thumbprints */
    bool identity_pinning_enabled = false;
    
    /** Allowed certificate thumbprints (case/whitespace insensitive) */
    std::vector<std::string> allowed_thumbprints;
    
    /** PQC algorithm OID strings */
    std::vector<std::string> pqc_algorithm_oids;
};

/**
 * @brief ValidatorBuilder extension for certificates pack
 */
class ValidatorBuilderWithCertificates : public ValidatorBuilder {
public:
    ValidatorBuilderWithCertificates() = default;
    
    /**
     * @brief Add X.509 certificate validation pack with default options
     * @return Reference to this builder for chaining
     */
    ValidatorBuilderWithCertificates& WithCertificates() {
        CheckBuilder();
        cose_status_t status = cose_validator_builder_with_certificates_pack(builder_);
        if (status != COSE_OK) {
            throw cose_error(status);
        }
        return *this;
    }
    
    /**
     * @brief Add X.509 certificate validation pack with custom options
     * @param options Certificate validation options
     * @return Reference to this builder for chaining
     */
    ValidatorBuilderWithCertificates& WithCertificates(const CertificateOptions& options) {
        CheckBuilder();
        
        // Convert C++ strings to C string arrays
        std::vector<const char*> thumbprints_ptrs;
        for (const auto& s : options.allowed_thumbprints) {
            thumbprints_ptrs.push_back(s.c_str());
        }
        thumbprints_ptrs.push_back(nullptr);  // NULL-terminated
        
        std::vector<const char*> oids_ptrs;
        for (const auto& s : options.pqc_algorithm_oids) {
            oids_ptrs.push_back(s.c_str());
        }
        oids_ptrs.push_back(nullptr);  // NULL-terminated
        
        cose_certificate_trust_options_t c_opts = {
            options.trust_embedded_chain_as_trusted,
            options.identity_pinning_enabled,
            options.allowed_thumbprints.empty() ? nullptr : thumbprints_ptrs.data(),
            options.pqc_algorithm_oids.empty() ? nullptr : oids_ptrs.data()
        };
        
        cose_status_t status = cose_validator_builder_with_certificates_pack_ex(builder_, &c_opts);
        if (status != COSE_OK) {
            throw cose_error(status);
        }
        
        return *this;
    }
};

/**
 * @brief Trust-policy helper: require that the X.509 chain is trusted.
 */
inline TrustPolicyBuilder& RequireX509ChainTrusted(TrustPolicyBuilder& policy) {
    cose_status_t status = cose_certificates_trust_policy_builder_require_x509_chain_trusted(
        policy.native_handle()
    );
    if (status != COSE_OK) {
        throw cose_error(status);
    }
    return policy;
}

/**
 * @brief Trust-policy helper: require that the X.509 chain is not trusted.
 */
inline TrustPolicyBuilder& RequireX509ChainNotTrusted(TrustPolicyBuilder& policy) {
    cose_status_t status = cose_certificates_trust_policy_builder_require_x509_chain_not_trusted(
        policy.native_handle()
    );
    if (status != COSE_OK) {
        throw cose_error(status);
    }
    return policy;
}

/**
 * @brief Trust-policy helper: require that the X.509 chain could be built (pack observed at least one element).
 */
inline TrustPolicyBuilder& RequireX509ChainBuilt(TrustPolicyBuilder& policy) {
    cose_status_t status = cose_certificates_trust_policy_builder_require_x509_chain_built(
        policy.native_handle()
    );
    if (status != COSE_OK) {
        throw cose_error(status);
    }
    return policy;
}

/**
 * @brief Trust-policy helper: require that the X.509 chain could not be built.
 */
inline TrustPolicyBuilder& RequireX509ChainNotBuilt(TrustPolicyBuilder& policy) {
    cose_status_t status = cose_certificates_trust_policy_builder_require_x509_chain_not_built(
        policy.native_handle()
    );
    if (status != COSE_OK) {
        throw cose_error(status);
    }
    return policy;
}

/**
 * @brief Trust-policy helper: require that the X.509 chain element count equals `expected`.
 */
inline TrustPolicyBuilder& RequireX509ChainElementCountEq(TrustPolicyBuilder& policy, size_t expected) {
    cose_status_t status = cose_certificates_trust_policy_builder_require_x509_chain_element_count_eq(
        policy.native_handle(),
        expected
    );
    if (status != COSE_OK) {
        throw cose_error(status);
    }
    return policy;
}

/**
 * @brief Trust-policy helper: require that the X.509 chain status flags equal `expected`.
 */
inline TrustPolicyBuilder& RequireX509ChainStatusFlagsEq(TrustPolicyBuilder& policy, uint32_t expected) {
    cose_status_t status = cose_certificates_trust_policy_builder_require_x509_chain_status_flags_eq(
        policy.native_handle(),
        expected
    );
    if (status != COSE_OK) {
        throw cose_error(status);
    }
    return policy;
}

/**
 * @brief Trust-policy helper: require that the leaf chain element (index 0) has a non-empty thumbprint.
 */
inline TrustPolicyBuilder& RequireLeafChainThumbprintPresent(TrustPolicyBuilder& policy) {
    cose_status_t status = cose_certificates_trust_policy_builder_require_leaf_chain_thumbprint_present(
        policy.native_handle()
    );
    if (status != COSE_OK) {
        throw cose_error(status);
    }
    return policy;
}

/**
 * @brief Trust-policy helper: require that a signing certificate identity fact is present.
 */
inline TrustPolicyBuilder& RequireSigningCertificatePresent(TrustPolicyBuilder& policy) {
    cose_status_t status = cose_certificates_trust_policy_builder_require_signing_certificate_present(
        policy.native_handle()
    );
    if (status != COSE_OK) {
        throw cose_error(status);
    }
    return policy;
}

/**
 * @brief Trust-policy helper: pin the leaf certificate subject name (chain element index 0).
 */
inline TrustPolicyBuilder& RequireLeafSubjectEq(TrustPolicyBuilder& policy, const std::string& subject) {
    cose_status_t status = cose_certificates_trust_policy_builder_require_leaf_subject_eq(
        policy.native_handle(),
        subject.c_str()
    );
    if (status != COSE_OK) {
        throw cose_error(status);
    }
    return policy;
}

/**
 * @brief Trust-policy helper: pin the issuer certificate subject name (chain element index 1).
 */
inline TrustPolicyBuilder& RequireIssuerSubjectEq(TrustPolicyBuilder& policy, const std::string& subject) {
    cose_status_t status = cose_certificates_trust_policy_builder_require_issuer_subject_eq(
        policy.native_handle(),
        subject.c_str()
    );
    if (status != COSE_OK) {
        throw cose_error(status);
    }
    return policy;
}

/**
 * @brief Trust-policy helper: require that the signing certificate subject/issuer matches the leaf chain element.
 */
inline TrustPolicyBuilder& RequireSigningCertificateSubjectIssuerMatchesLeafChainElement(TrustPolicyBuilder& policy) {
    cose_status_t status =
        cose_certificates_trust_policy_builder_require_signing_certificate_subject_issuer_matches_leaf_chain_element(
            policy.native_handle()
        );
    if (status != COSE_OK) {
        throw cose_error(status);
    }
    return policy;
}

/**
 * @brief Trust-policy helper: if the issuer element (index 1) is missing, allow; otherwise require issuer chaining.
 */
inline TrustPolicyBuilder& RequireLeafIssuerIsNextChainSubjectOptional(TrustPolicyBuilder& policy) {
    cose_status_t status =
        cose_certificates_trust_policy_builder_require_leaf_issuer_is_next_chain_subject_optional(
            policy.native_handle()
        );
    if (status != COSE_OK) {
        throw cose_error(status);
    }
    return policy;
}

/**
 * @brief Trust-policy helper: require the leaf signing certificate thumbprint to equal the provided value.
 */
inline TrustPolicyBuilder& RequireSigningCertificateThumbprintEq(TrustPolicyBuilder& policy, const std::string& thumbprint) {
    cose_status_t status = cose_certificates_trust_policy_builder_require_signing_certificate_thumbprint_eq(
        policy.native_handle(),
        thumbprint.c_str()
    );
    if (status != COSE_OK) {
        throw cose_error(status);
    }
    return policy;
}

/**
 * @brief Trust-policy helper: require that the leaf signing certificate thumbprint is present and non-empty.
 */
inline TrustPolicyBuilder& RequireSigningCertificateThumbprintPresent(TrustPolicyBuilder& policy) {
    cose_status_t status = cose_certificates_trust_policy_builder_require_signing_certificate_thumbprint_present(
        policy.native_handle()
    );
    if (status != COSE_OK) {
        throw cose_error(status);
    }
    return policy;
}

/**
 * @brief Trust-policy helper: require the leaf signing certificate subject to equal the provided value.
 */
inline TrustPolicyBuilder& RequireSigningCertificateSubjectEq(TrustPolicyBuilder& policy, const std::string& subject) {
    cose_status_t status = cose_certificates_trust_policy_builder_require_signing_certificate_subject_eq(
        policy.native_handle(),
        subject.c_str()
    );
    if (status != COSE_OK) {
        throw cose_error(status);
    }
    return policy;
}

/**
 * @brief Trust-policy helper: require the leaf signing certificate issuer to equal the provided value.
 */
inline TrustPolicyBuilder& RequireSigningCertificateIssuerEq(TrustPolicyBuilder& policy, const std::string& issuer) {
    cose_status_t status = cose_certificates_trust_policy_builder_require_signing_certificate_issuer_eq(
        policy.native_handle(),
        issuer.c_str()
    );
    if (status != COSE_OK) {
        throw cose_error(status);
    }
    return policy;
}

/**
 * @brief Trust-policy helper: require the leaf signing certificate serial number to equal the provided value.
 */
inline TrustPolicyBuilder& RequireSigningCertificateSerialNumberEq(
    TrustPolicyBuilder& policy,
    const std::string& serial_number
) {
    cose_status_t status = cose_certificates_trust_policy_builder_require_signing_certificate_serial_number_eq(
        policy.native_handle(),
        serial_number.c_str()
    );
    if (status != COSE_OK) {
        throw cose_error(status);
    }
    return policy;
}

/**
 * @brief Trust-policy helper: require that the signing certificate is expired at or before `now_unix_seconds`.
 */
inline TrustPolicyBuilder& RequireSigningCertificateExpiredAtOrBefore(TrustPolicyBuilder& policy, int64_t now_unix_seconds) {
    cose_status_t status = cose_certificates_trust_policy_builder_require_signing_certificate_expired_at_or_before(
        policy.native_handle(),
        now_unix_seconds
    );
    if (status != COSE_OK) {
        throw cose_error(status);
    }
    return policy;
}

/**
 * @brief Trust-policy helper: require that the leaf signing certificate is valid at `now_unix_seconds`.
 */
inline TrustPolicyBuilder& RequireSigningCertificateValidAt(TrustPolicyBuilder& policy, int64_t now_unix_seconds) {
    cose_status_t status = cose_certificates_trust_policy_builder_require_signing_certificate_valid_at(
        policy.native_handle(),
        now_unix_seconds
    );
    if (status != COSE_OK) {
        throw cose_error(status);
    }
    return policy;
}

/**
 * @brief Trust-policy helper: require signing certificate not-before <= `max_unix_seconds`.
 */
inline TrustPolicyBuilder& RequireSigningCertificateNotBeforeLe(TrustPolicyBuilder& policy, int64_t max_unix_seconds) {
    cose_status_t status = cose_certificates_trust_policy_builder_require_signing_certificate_not_before_le(
        policy.native_handle(),
        max_unix_seconds
    );
    if (status != COSE_OK) {
        throw cose_error(status);
    }
    return policy;
}

/**
 * @brief Trust-policy helper: require signing certificate not-before >= `min_unix_seconds`.
 */
inline TrustPolicyBuilder& RequireSigningCertificateNotBeforeGe(TrustPolicyBuilder& policy, int64_t min_unix_seconds) {
    cose_status_t status = cose_certificates_trust_policy_builder_require_signing_certificate_not_before_ge(
        policy.native_handle(),
        min_unix_seconds
    );
    if (status != COSE_OK) {
        throw cose_error(status);
    }
    return policy;
}

/**
 * @brief Trust-policy helper: require signing certificate not-after <= `max_unix_seconds`.
 */
inline TrustPolicyBuilder& RequireSigningCertificateNotAfterLe(TrustPolicyBuilder& policy, int64_t max_unix_seconds) {
    cose_status_t status = cose_certificates_trust_policy_builder_require_signing_certificate_not_after_le(
        policy.native_handle(),
        max_unix_seconds
    );
    if (status != COSE_OK) {
        throw cose_error(status);
    }
    return policy;
}

/**
 * @brief Trust-policy helper: require signing certificate not-after >= `min_unix_seconds`.
 */
inline TrustPolicyBuilder& RequireSigningCertificateNotAfterGe(TrustPolicyBuilder& policy, int64_t min_unix_seconds) {
    cose_status_t status = cose_certificates_trust_policy_builder_require_signing_certificate_not_after_ge(
        policy.native_handle(),
        min_unix_seconds
    );
    if (status != COSE_OK) {
        throw cose_error(status);
    }
    return policy;
}

/**
 * @brief Trust-policy helper: require that the X.509 chain element at `index` has subject equal to the provided value.
 */
inline TrustPolicyBuilder& RequireChainElementSubjectEq(
    TrustPolicyBuilder& policy,
    size_t index,
    const std::string& subject
) {
    cose_status_t status = cose_certificates_trust_policy_builder_require_chain_element_subject_eq(
        policy.native_handle(),
        index,
        subject.c_str()
    );
    if (status != COSE_OK) {
        throw cose_error(status);
    }
    return policy;
}

/**
 * @brief Trust-policy helper: require that the X.509 chain element at `index` has issuer equal to the provided value.
 */
inline TrustPolicyBuilder& RequireChainElementIssuerEq(
    TrustPolicyBuilder& policy,
    size_t index,
    const std::string& issuer
) {
    cose_status_t status = cose_certificates_trust_policy_builder_require_chain_element_issuer_eq(
        policy.native_handle(),
        index,
        issuer.c_str()
    );
    if (status != COSE_OK) {
        throw cose_error(status);
    }
    return policy;
}

/**
 * @brief Trust-policy helper: require that the X.509 chain element at `index` has thumbprint equal to the provided value.
 */
inline TrustPolicyBuilder& RequireChainElementThumbprintEq(
    TrustPolicyBuilder& policy,
    size_t index,
    const std::string& thumbprint
) {
    cose_status_t status = cose_certificates_trust_policy_builder_require_chain_element_thumbprint_eq(
        policy.native_handle(),
        index,
        thumbprint.c_str()
    );
    if (status != COSE_OK) {
        throw cose_error(status);
    }
    return policy;
}

/**
 * @brief Trust-policy helper: require that the X.509 chain element at `index` has a non-empty thumbprint.
 */
inline TrustPolicyBuilder& RequireChainElementThumbprintPresent(
    TrustPolicyBuilder& policy,
    size_t index
) {
    cose_status_t status = cose_certificates_trust_policy_builder_require_chain_element_thumbprint_present(
        policy.native_handle(),
        index
    );
    if (status != COSE_OK) {
        throw cose_error(status);
    }
    return policy;
}

/**
 * @brief Trust-policy helper: require that the X.509 chain element at `index` is valid at `now_unix_seconds`.
 */
inline TrustPolicyBuilder& RequireChainElementValidAt(
    TrustPolicyBuilder& policy,
    size_t index,
    int64_t now_unix_seconds
) {
    cose_status_t status = cose_certificates_trust_policy_builder_require_chain_element_valid_at(
        policy.native_handle(),
        index,
        now_unix_seconds
    );
    if (status != COSE_OK) {
        throw cose_error(status);
    }
    return policy;
}

/**
 * @brief Trust-policy helper: require chain element not-before <= `max_unix_seconds`.
 */
inline TrustPolicyBuilder& RequireChainElementNotBeforeLe(
    TrustPolicyBuilder& policy,
    size_t index,
    int64_t max_unix_seconds
) {
    cose_status_t status = cose_certificates_trust_policy_builder_require_chain_element_not_before_le(
        policy.native_handle(),
        index,
        max_unix_seconds
    );
    if (status != COSE_OK) {
        throw cose_error(status);
    }
    return policy;
}

/**
 * @brief Trust-policy helper: require chain element not-before >= `min_unix_seconds`.
 */
inline TrustPolicyBuilder& RequireChainElementNotBeforeGe(
    TrustPolicyBuilder& policy,
    size_t index,
    int64_t min_unix_seconds
) {
    cose_status_t status = cose_certificates_trust_policy_builder_require_chain_element_not_before_ge(
        policy.native_handle(),
        index,
        min_unix_seconds
    );
    if (status != COSE_OK) {
        throw cose_error(status);
    }
    return policy;
}

/**
 * @brief Trust-policy helper: require chain element not-after <= `max_unix_seconds`.
 */
inline TrustPolicyBuilder& RequireChainElementNotAfterLe(
    TrustPolicyBuilder& policy,
    size_t index,
    int64_t max_unix_seconds
) {
    cose_status_t status = cose_certificates_trust_policy_builder_require_chain_element_not_after_le(
        policy.native_handle(),
        index,
        max_unix_seconds
    );
    if (status != COSE_OK) {
        throw cose_error(status);
    }
    return policy;
}

/**
 * @brief Trust-policy helper: require chain element not-after >= `min_unix_seconds`.
 */
inline TrustPolicyBuilder& RequireChainElementNotAfterGe(
    TrustPolicyBuilder& policy,
    size_t index,
    int64_t min_unix_seconds
) {
    cose_status_t status = cose_certificates_trust_policy_builder_require_chain_element_not_after_ge(
        policy.native_handle(),
        index,
        min_unix_seconds
    );
    if (status != COSE_OK) {
        throw cose_error(status);
    }
    return policy;
}

/**
 * @brief Trust-policy helper: deny if a PQC algorithm is explicitly detected; allow if missing.
 */
inline TrustPolicyBuilder& RequireNotPqcAlgorithmOrMissing(TrustPolicyBuilder& policy) {
    cose_status_t status = cose_certificates_trust_policy_builder_require_not_pqc_algorithm_or_missing(
        policy.native_handle()
    );
    if (status != COSE_OK) {
        throw cose_error(status);
    }
    return policy;
}

/**
 * @brief Trust-policy helper: require that the X.509 public key algorithm fact has thumbprint equal to the provided value.
 */
inline TrustPolicyBuilder& RequireX509PublicKeyAlgorithmThumbprintEq(TrustPolicyBuilder& policy, const std::string& thumbprint) {
    cose_status_t status = cose_certificates_trust_policy_builder_require_x509_public_key_algorithm_thumbprint_eq(
        policy.native_handle(),
        thumbprint.c_str()
    );
    if (status != COSE_OK) {
        throw cose_error(status);
    }
    return policy;
}

/**
 * @brief Trust-policy helper: require that the X.509 public key algorithm OID equals the provided value.
 */
inline TrustPolicyBuilder& RequireX509PublicKeyAlgorithmOidEq(TrustPolicyBuilder& policy, const std::string& oid) {
    cose_status_t status = cose_certificates_trust_policy_builder_require_x509_public_key_algorithm_oid_eq(
        policy.native_handle(),
        oid.c_str()
    );
    if (status != COSE_OK) {
        throw cose_error(status);
    }
    return policy;
}

/**
 * @brief Trust-policy helper: require that the X.509 public key algorithm is flagged as PQC.
 */
inline TrustPolicyBuilder& RequireX509PublicKeyAlgorithmIsPqc(TrustPolicyBuilder& policy) {
    cose_status_t status = cose_certificates_trust_policy_builder_require_x509_public_key_algorithm_is_pqc(
        policy.native_handle()
    );
    if (status != COSE_OK) {
        throw cose_error(status);
    }
    return policy;
}

/**
 * @brief Trust-policy helper: require that the X.509 public key algorithm is not flagged as PQC.
 */
inline TrustPolicyBuilder& RequireX509PublicKeyAlgorithmIsNotPqc(TrustPolicyBuilder& policy) {
    cose_status_t status = cose_certificates_trust_policy_builder_require_x509_public_key_algorithm_is_not_pqc(
        policy.native_handle()
    );
    if (status != COSE_OK) {
        throw cose_error(status);
    }
    return policy;
}

} // namespace cose

#endif // COSE_CERTIFICATES_HPP
