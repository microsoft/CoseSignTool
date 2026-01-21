// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file mst.hpp
 * @brief C++ wrappers for MST receipt verification pack
 */

#ifndef COSE_MST_HPP
#define COSE_MST_HPP

#include <cose/validator.hpp>
#include <cose/trust.hpp>
#include <cose/cose_mst.h>
#include <string>

namespace cose {

/**
 * @brief Options for MST receipt verification
 */
struct MstOptions {
    /** If true, allow network fetching of JWKS when offline keys are missing */
    bool allow_network = true;
    
    /** Offline JWKS JSON string (empty means no offline JWKS) */
    std::string offline_jwks_json;
    
    /** Optional api-version for CodeTransparency /jwks endpoint (empty means no api-version) */
    std::string jwks_api_version;
};

/**
 * @brief ValidatorBuilder extension for MST pack
 */
class ValidatorBuilderWithMst : public ValidatorBuilder {
public:
    ValidatorBuilderWithMst() = default;
    
    /**
     * @brief Add MST receipt verification pack with default options (online mode)
     * @return Reference to this builder for chaining
     */
    ValidatorBuilderWithMst& WithMst() {
        CheckBuilder();
        detail::ThrowIfNotOk(cose_validator_builder_with_mst_pack(builder_));
        return *this;
    }
    
    /**
     * @brief Add MST receipt verification pack with custom options
     * @param options MST verification options
     * @return Reference to this builder for chaining
     */
    ValidatorBuilderWithMst& WithMst(const MstOptions& options) {
        CheckBuilder();
        
        cose_mst_trust_options_t c_opts = {
            options.allow_network,
            options.offline_jwks_json.empty() ? nullptr : options.offline_jwks_json.c_str(),
            options.jwks_api_version.empty() ? nullptr : options.jwks_api_version.c_str()
        };
        
        detail::ThrowIfNotOk(cose_validator_builder_with_mst_pack_ex(builder_, &c_opts));
        
        return *this;
    }
};

/**
 * @brief Trust-policy helper: require that an MST receipt is present on at least one counter-signature.
 */
inline TrustPolicyBuilder& RequireMstReceiptPresent(TrustPolicyBuilder& policy) {
    detail::ThrowIfNotOk(
        cose_mst_trust_policy_builder_require_receipt_present(policy.native_handle())
    );
    return policy;
}

inline TrustPolicyBuilder& RequireMstReceiptNotPresent(TrustPolicyBuilder& policy) {
    detail::ThrowIfNotOk(
        cose_mst_trust_policy_builder_require_receipt_not_present(policy.native_handle())
    );
    return policy;
}

/**
 * @brief Trust-policy helper: require that the MST receipt signature verified.
 */
inline TrustPolicyBuilder& RequireMstReceiptSignatureVerified(TrustPolicyBuilder& policy) {
    detail::ThrowIfNotOk(
        cose_mst_trust_policy_builder_require_receipt_signature_verified(policy.native_handle())
    );
    return policy;
}

inline TrustPolicyBuilder& RequireMstReceiptSignatureNotVerified(TrustPolicyBuilder& policy) {
    detail::ThrowIfNotOk(
        cose_mst_trust_policy_builder_require_receipt_signature_not_verified(policy.native_handle())
    );
    return policy;
}

/**
 * @brief Trust-policy helper: require that the MST receipt issuer contains the provided substring.
 */
inline TrustPolicyBuilder& RequireMstReceiptIssuerContains(TrustPolicyBuilder& policy, const std::string& needle) {
    detail::ThrowIfNotOk(
        cose_mst_trust_policy_builder_require_receipt_issuer_contains(
            policy.native_handle(),
            needle.c_str()
        )
    );
    return policy;
}

inline TrustPolicyBuilder& RequireMstReceiptIssuerEq(TrustPolicyBuilder& policy, const std::string& issuer) {
    detail::ThrowIfNotOk(
        cose_mst_trust_policy_builder_require_receipt_issuer_eq(policy.native_handle(), issuer.c_str())
    );
    return policy;
}

/**
 * @brief Trust-policy helper: require that the MST receipt key id (kid) equals the provided value.
 */
inline TrustPolicyBuilder& RequireMstReceiptKidEq(TrustPolicyBuilder& policy, const std::string& kid) {
    detail::ThrowIfNotOk(
        cose_mst_trust_policy_builder_require_receipt_kid_eq(policy.native_handle(), kid.c_str())
    );
    return policy;
}

inline TrustPolicyBuilder& RequireMstReceiptKidContains(TrustPolicyBuilder& policy, const std::string& needle) {
    detail::ThrowIfNotOk(
        cose_mst_trust_policy_builder_require_receipt_kid_contains(policy.native_handle(), needle.c_str())
    );
    return policy;
}

inline TrustPolicyBuilder& RequireMstReceiptTrusted(TrustPolicyBuilder& policy) {
    detail::ThrowIfNotOk(cose_mst_trust_policy_builder_require_receipt_trusted(policy.native_handle()));
    return policy;
}

inline TrustPolicyBuilder& RequireMstReceiptNotTrusted(TrustPolicyBuilder& policy) {
    detail::ThrowIfNotOk(cose_mst_trust_policy_builder_require_receipt_not_trusted(policy.native_handle()));
    return policy;
}

inline TrustPolicyBuilder& RequireMstReceiptTrustedFromIssuerContains(TrustPolicyBuilder& policy, const std::string& needle) {
    detail::ThrowIfNotOk(
        cose_mst_trust_policy_builder_require_receipt_trusted_from_issuer_contains(
            policy.native_handle(),
            needle.c_str()
        )
    );
    return policy;
}

inline TrustPolicyBuilder& RequireMstReceiptStatementSha256Eq(TrustPolicyBuilder& policy, const std::string& sha256Hex) {
    detail::ThrowIfNotOk(
        cose_mst_trust_policy_builder_require_receipt_statement_sha256_eq(
            policy.native_handle(),
            sha256Hex.c_str()
        )
    );
    return policy;
}

inline TrustPolicyBuilder& RequireMstReceiptStatementCoverageEq(TrustPolicyBuilder& policy, const std::string& coverage) {
    detail::ThrowIfNotOk(
        cose_mst_trust_policy_builder_require_receipt_statement_coverage_eq(
            policy.native_handle(),
            coverage.c_str()
        )
    );
    return policy;
}

inline TrustPolicyBuilder& RequireMstReceiptStatementCoverageContains(TrustPolicyBuilder& policy, const std::string& needle) {
    detail::ThrowIfNotOk(
        cose_mst_trust_policy_builder_require_receipt_statement_coverage_contains(
            policy.native_handle(),
            needle.c_str()
        )
    );
    return policy;
}

} // namespace cose

#endif // COSE_MST_HPP
