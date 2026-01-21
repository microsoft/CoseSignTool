// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file azure_key_vault.hpp
 * @brief C++ wrappers for Azure Key Vault KID validation pack
 */

#ifndef COSE_AZURE_KEY_VAULT_HPP
#define COSE_AZURE_KEY_VAULT_HPP

#include <cose/validator.hpp>
#include <cose/trust.hpp>
#include <cose/cose_azure_key_vault.h>
#include <vector>
#include <string>

namespace cose {

/**
 * @brief Options for Azure Key Vault KID validation
 */
struct AzureKeyVaultOptions {
    /** If true, require the KID to look like an Azure Key Vault identifier */
    bool require_azure_key_vault_kid = true;
    
    /** Allowed KID pattern strings (supports wildcards * and ?).
     *  Empty vector means use defaults (*.vault.azure.net/keys/*, *.managedhsm.azure.net/keys/*) */
    std::vector<std::string> allowed_kid_patterns;
};

/**
 * @brief ValidatorBuilder extension for Azure Key Vault pack
 */
class ValidatorBuilderWithAzureKeyVault : public ValidatorBuilder {
public:
    ValidatorBuilderWithAzureKeyVault() = default;
    
    /**
     * @brief Add Azure Key Vault KID validation pack with default options
     * @return Reference to this builder for chaining
     */
    ValidatorBuilderWithAzureKeyVault& WithAzureKeyVault() {
        CheckBuilder();
        cose_status_t status = cose_validator_builder_with_akv_pack(builder_);
        if (status != COSE_OK) {
            throw cose_error(status);
        }
        return *this;
    }
    
    /**
     * @brief Add Azure Key Vault KID validation pack with custom options
     * @param options Azure Key Vault validation options
     * @return Reference to this builder for chaining
     */
    ValidatorBuilderWithAzureKeyVault& WithAzureKeyVault(const AzureKeyVaultOptions& options) {
        CheckBuilder();
        
        // Convert C++ strings to C string array
        std::vector<const char*> patterns_ptrs;
        for (const auto& s : options.allowed_kid_patterns) {
            patterns_ptrs.push_back(s.c_str());
        }
        patterns_ptrs.push_back(nullptr);  // NULL-terminated
        
        cose_akv_trust_options_t c_opts = {
            options.require_azure_key_vault_kid,
            options.allowed_kid_patterns.empty() ? nullptr : patterns_ptrs.data()
        };
        
        cose_status_t status = cose_validator_builder_with_akv_pack_ex(builder_, &c_opts);
        if (status != COSE_OK) {
            throw cose_error(status);
        }
        
        return *this;
    }
};

/**
 * @brief Trust-policy helper: require that the message `kid` looks like an Azure Key Vault key identifier.
 */
inline TrustPolicyBuilder& RequireAzureKeyVaultKid(TrustPolicyBuilder& policy) {
    cose_status_t status = cose_akv_trust_policy_builder_require_azure_key_vault_kid(
        policy.native_handle()
    );
    if (status != COSE_OK) {
        throw cose_error(status);
    }
    return policy;
}

/**
 * @brief Trust-policy helper: require that the message `kid` does not look like an Azure Key Vault key identifier.
 */
inline TrustPolicyBuilder& RequireNotAzureKeyVaultKid(TrustPolicyBuilder& policy) {
    cose_status_t status = cose_akv_trust_policy_builder_require_not_azure_key_vault_kid(
        policy.native_handle()
    );
    if (status != COSE_OK) {
        throw cose_error(status);
    }
    return policy;
}

/**
 * @brief Trust-policy helper: require that the message `kid` is allowlisted by the AKV pack configuration.
 */
inline TrustPolicyBuilder& RequireAzureKeyVaultKidAllowed(TrustPolicyBuilder& policy) {
    cose_status_t status = cose_akv_trust_policy_builder_require_azure_key_vault_kid_allowed(
        policy.native_handle()
    );
    if (status != COSE_OK) {
        throw cose_error(status);
    }
    return policy;
}

/**
 * @brief Trust-policy helper: require that the message `kid` is not allowlisted by the AKV pack configuration.
 */
inline TrustPolicyBuilder& RequireAzureKeyVaultKidNotAllowed(TrustPolicyBuilder& policy) {
    cose_status_t status = cose_akv_trust_policy_builder_require_azure_key_vault_kid_not_allowed(
        policy.native_handle()
    );
    if (status != COSE_OK) {
        throw cose_error(status);
    }
    return policy;
}

} // namespace cose

#endif // COSE_AZURE_KEY_VAULT_HPP
