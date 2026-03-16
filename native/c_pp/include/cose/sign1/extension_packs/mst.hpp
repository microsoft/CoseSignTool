// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file mst.hpp
 * @brief C++ wrappers for MST receipt verification pack
 */

#ifndef COSE_SIGN1_MST_HPP
#define COSE_SIGN1_MST_HPP

#include <cose/sign1/validation.hpp>
#include <cose/sign1/trust.hpp>
#include <cose/sign1/extension_packs/mst.h>
#include <string>

namespace cose::sign1 {

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
        cose::detail::ThrowIfNotOk(cose_sign1_validator_builder_with_mst_pack(builder_));
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
        
        cose::detail::ThrowIfNotOk(cose_sign1_validator_builder_with_mst_pack_ex(builder_, &c_opts));
        
        return *this;
    }
};

/**
 * @brief Trust-policy helper: require that an MST receipt is present on at least one counter-signature.
 */
inline TrustPolicyBuilder& RequireMstReceiptPresent(TrustPolicyBuilder& policy) {
    cose::detail::ThrowIfNotOk(
        cose_sign1_mst_trust_policy_builder_require_receipt_present(policy.native_handle())
    );
    return policy;
}

inline TrustPolicyBuilder& RequireMstReceiptNotPresent(TrustPolicyBuilder& policy) {
    cose::detail::ThrowIfNotOk(
        cose_sign1_mst_trust_policy_builder_require_receipt_not_present(policy.native_handle())
    );
    return policy;
}

/**
 * @brief Trust-policy helper: require that the MST receipt signature verified.
 */
inline TrustPolicyBuilder& RequireMstReceiptSignatureVerified(TrustPolicyBuilder& policy) {
    cose::detail::ThrowIfNotOk(
        cose_sign1_mst_trust_policy_builder_require_receipt_signature_verified(policy.native_handle())
    );
    return policy;
}

inline TrustPolicyBuilder& RequireMstReceiptSignatureNotVerified(TrustPolicyBuilder& policy) {
    cose::detail::ThrowIfNotOk(
        cose_sign1_mst_trust_policy_builder_require_receipt_signature_not_verified(policy.native_handle())
    );
    return policy;
}

/**
 * @brief Trust-policy helper: require that the MST receipt issuer contains the provided substring.
 */
inline TrustPolicyBuilder& RequireMstReceiptIssuerContains(TrustPolicyBuilder& policy, const std::string& needle) {
    cose::detail::ThrowIfNotOk(
        cose_sign1_mst_trust_policy_builder_require_receipt_issuer_contains(
            policy.native_handle(),
            needle.c_str()
        )
    );
    return policy;
}

inline TrustPolicyBuilder& RequireMstReceiptIssuerEq(TrustPolicyBuilder& policy, const std::string& issuer) {
    cose::detail::ThrowIfNotOk(
        cose_sign1_mst_trust_policy_builder_require_receipt_issuer_eq(policy.native_handle(), issuer.c_str())
    );
    return policy;
}

/**
 * @brief Trust-policy helper: require that the MST receipt key id (kid) equals the provided value.
 */
inline TrustPolicyBuilder& RequireMstReceiptKidEq(TrustPolicyBuilder& policy, const std::string& kid) {
    cose::detail::ThrowIfNotOk(
        cose_sign1_mst_trust_policy_builder_require_receipt_kid_eq(policy.native_handle(), kid.c_str())
    );
    return policy;
}

inline TrustPolicyBuilder& RequireMstReceiptKidContains(TrustPolicyBuilder& policy, const std::string& needle) {
    cose::detail::ThrowIfNotOk(
        cose_sign1_mst_trust_policy_builder_require_receipt_kid_contains(policy.native_handle(), needle.c_str())
    );
    return policy;
}

inline TrustPolicyBuilder& RequireMstReceiptTrusted(TrustPolicyBuilder& policy) {
    cose::detail::ThrowIfNotOk(cose_sign1_mst_trust_policy_builder_require_receipt_trusted(policy.native_handle()));
    return policy;
}

inline TrustPolicyBuilder& RequireMstReceiptNotTrusted(TrustPolicyBuilder& policy) {
    cose::detail::ThrowIfNotOk(cose_sign1_mst_trust_policy_builder_require_receipt_not_trusted(policy.native_handle()));
    return policy;
}

inline TrustPolicyBuilder& RequireMstReceiptTrustedFromIssuerContains(TrustPolicyBuilder& policy, const std::string& needle) {
    cose::detail::ThrowIfNotOk(
        cose_sign1_mst_trust_policy_builder_require_receipt_trusted_from_issuer_contains(
            policy.native_handle(),
            needle.c_str()
        )
    );
    return policy;
}

inline TrustPolicyBuilder& RequireMstReceiptStatementSha256Eq(TrustPolicyBuilder& policy, const std::string& sha256Hex) {
    cose::detail::ThrowIfNotOk(
        cose_sign1_mst_trust_policy_builder_require_receipt_statement_sha256_eq(
            policy.native_handle(),
            sha256Hex.c_str()
        )
    );
    return policy;
}

inline TrustPolicyBuilder& RequireMstReceiptStatementCoverageEq(TrustPolicyBuilder& policy, const std::string& coverage) {
    cose::detail::ThrowIfNotOk(
        cose_sign1_mst_trust_policy_builder_require_receipt_statement_coverage_eq(
            policy.native_handle(),
            coverage.c_str()
        )
    );
    return policy;
}

inline TrustPolicyBuilder& RequireMstReceiptStatementCoverageContains(TrustPolicyBuilder& policy, const std::string& needle) {
    cose::detail::ThrowIfNotOk(
        cose_sign1_mst_trust_policy_builder_require_receipt_statement_coverage_contains(
            policy.native_handle(),
            needle.c_str()
        )
    );
    return policy;
}

/**
 * @brief Add MST receipt verification pack with default options (online mode).
 * @param builder The validator builder to configure
 * @return Reference to the builder for chaining.
 */
inline ValidatorBuilder& WithMst(ValidatorBuilder& builder) {
    cose::detail::ThrowIfNotOk(cose_sign1_validator_builder_with_mst_pack(builder.native_handle()));
    return builder;
}

/**
 * @brief Add MST receipt verification pack with custom options.
 * @param builder The validator builder to configure
 * @param options MST verification options
 * @return Reference to the builder for chaining.
 */
inline ValidatorBuilder& WithMst(ValidatorBuilder& builder, const MstOptions& options) {
    cose_mst_trust_options_t c_opts = {
        options.allow_network,
        options.offline_jwks_json.empty() ? nullptr : options.offline_jwks_json.c_str(),
        options.jwks_api_version.empty() ? nullptr : options.jwks_api_version.c_str()
    };

    cose::detail::ThrowIfNotOk(cose_sign1_validator_builder_with_mst_pack_ex(builder.native_handle(), &c_opts));
    return builder;
}

// ============================================================================
// MST Transparency Client Signing Support
// ============================================================================

/**
 * @brief Result from creating a transparency entry
 */
struct CreateEntryResult {
    std::string operation_id;
    std::string entry_id;
};

/**
 * @brief RAII wrapper for MST transparency client
 */
class MstTransparencyClient {
public:
    /**
     * @brief Creates a new MST transparency client
     * @param endpoint The base URL of the transparency service
     * @param api_version Optional API version (empty = use default "2024-01-01")
     * @param api_key Optional API key for authentication (empty = unauthenticated)
     * @return A new MstTransparencyClient instance
     * @throws std::runtime_error on failure
     */
    static MstTransparencyClient New(
        const std::string& endpoint,
        const std::string& api_version = "",
        const std::string& api_key = ""
    ) {
        MstClientHandle* handle = nullptr;
        cose_status_t status = cose_mst_client_new(
            endpoint.c_str(),
            api_version.empty() ? nullptr : api_version.c_str(),
            api_key.empty() ? nullptr : api_key.c_str(),
            &handle
        );

        if (status != cose_status_t::COSE_OK) {
            char* err = cose_last_error_message_utf8();
            std::string error_msg = err ? err : "Unknown error creating MST client";
            cose_string_free(err);
            throw std::runtime_error(error_msg);
        }

        return MstTransparencyClient(handle);
    }

    /**
     * @brief Destructor - frees the client handle
     */
    ~MstTransparencyClient() {
        if (handle_) {
            cose_mst_client_free(handle_);
        }
    }

    // Move constructor and assignment
    MstTransparencyClient(MstTransparencyClient&& other) noexcept : handle_(other.handle_) {
        other.handle_ = nullptr;
    }

    MstTransparencyClient& operator=(MstTransparencyClient&& other) noexcept {
        if (this != &other) {
            if (handle_) {
                cose_mst_client_free(handle_);
            }
            handle_ = other.handle_;
            other.handle_ = nullptr;
        }
        return *this;
    }

    // Delete copy constructor and assignment
    MstTransparencyClient(const MstTransparencyClient&) = delete;
    MstTransparencyClient& operator=(const MstTransparencyClient&) = delete;

    /**
     * @brief Makes a COSE_Sign1 message transparent
     * @param cose_bytes The COSE_Sign1 message bytes to submit
     * @return The transparency statement as bytes
     * @throws std::runtime_error on failure
     */
    std::vector<uint8_t> MakeTransparent(const std::vector<uint8_t>& cose_bytes) {
        uint8_t* out_bytes = nullptr;
        size_t out_len = 0;

        cose_status_t status = cose_sign1_mst_make_transparent(
            handle_,
            cose_bytes.data(),
            cose_bytes.size(),
            &out_bytes,
            &out_len
        );

        if (status != cose_status_t::COSE_OK) {
            char* err = cose_last_error_message_utf8();
            std::string error_msg = err ? err : "Unknown error making transparent";
            cose_string_free(err);
            throw std::runtime_error(error_msg);
        }

        std::vector<uint8_t> result(out_bytes, out_bytes + out_len);
        cose_mst_bytes_free(out_bytes, out_len);
        return result;
    }

    /**
     * @brief Creates a transparency entry
     * @param cose_bytes The COSE_Sign1 message bytes to submit
     * @return CreateEntryResult with operation_id and entry_id
     * @throws std::runtime_error on failure
     */
    CreateEntryResult CreateEntry(const std::vector<uint8_t>& cose_bytes) {
        char* op_id = nullptr;
        char* entry_id = nullptr;

        cose_status_t status = cose_sign1_mst_create_entry(
            handle_,
            cose_bytes.data(),
            cose_bytes.size(),
            &op_id,
            &entry_id
        );

        if (status != cose_status_t::COSE_OK) {
            char* err = cose_last_error_message_utf8();
            std::string error_msg = err ? err : "Unknown error creating entry";
            cose_string_free(err);
            throw std::runtime_error(error_msg);
        }

        CreateEntryResult result;
        result.operation_id = op_id;
        result.entry_id = entry_id;

        cose_mst_string_free(op_id);
        cose_mst_string_free(entry_id);

        return result;
    }

    /**
     * @brief Gets the transparency statement for an entry
     * @param entry_id The entry ID
     * @return The transparency statement as bytes
     * @throws std::runtime_error on failure
     */
    std::vector<uint8_t> GetEntryStatement(const std::string& entry_id) {
        uint8_t* out_bytes = nullptr;
        size_t out_len = 0;

        cose_status_t status = cose_sign1_mst_get_entry_statement(
            handle_,
            entry_id.c_str(),
            &out_bytes,
            &out_len
        );

        if (status != cose_status_t::COSE_OK) {
            char* err = cose_last_error_message_utf8();
            std::string error_msg = err ? err : "Unknown error getting entry statement";
            cose_string_free(err);
            throw std::runtime_error(error_msg);
        }

        std::vector<uint8_t> result(out_bytes, out_bytes + out_len);
        cose_mst_bytes_free(out_bytes, out_len);
        return result;
    }

private:
    explicit MstTransparencyClient(MstClientHandle* handle) : handle_(handle) {}

    MstClientHandle* handle_ = nullptr;
};

} // namespace cose::sign1

#endif // COSE_SIGN1_MST_HPP
