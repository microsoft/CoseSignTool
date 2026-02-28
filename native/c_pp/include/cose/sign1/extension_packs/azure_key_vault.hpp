// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file azure_key_vault.hpp
 * @brief C++ wrappers for Azure Key Vault KID validation pack
 */

#ifndef COSE_SIGN1_AKV_HPP
#define COSE_SIGN1_AKV_HPP

#include <cose/sign1/validation.hpp>
#include <cose/sign1/trust.hpp>
#include <cose/sign1/extension_packs/azure_key_vault.h>
#include <vector>
#include <string>

namespace cose::sign1 {

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
        cose::detail::ThrowIfNotOk(cose_sign1_validator_builder_with_akv_pack(builder_));
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
        
        cose::detail::ThrowIfNotOk(cose_sign1_validator_builder_with_akv_pack_ex(builder_, &c_opts));
        
        return *this;
    }
};

/**
 * @brief Trust-policy helper: require that the message `kid` looks like an Azure Key Vault key identifier.
 */
inline TrustPolicyBuilder& RequireAzureKeyVaultKid(TrustPolicyBuilder& policy) {
    cose::detail::ThrowIfNotOk(
        cose_sign1_akv_trust_policy_builder_require_azure_key_vault_kid(policy.native_handle())
    );
    return policy;
}

/**
 * @brief Trust-policy helper: require that the message `kid` does not look like an Azure Key Vault key identifier.
 */
inline TrustPolicyBuilder& RequireNotAzureKeyVaultKid(TrustPolicyBuilder& policy) {
    cose::detail::ThrowIfNotOk(
        cose_sign1_akv_trust_policy_builder_require_not_azure_key_vault_kid(policy.native_handle())
    );
    return policy;
}

/**
 * @brief Trust-policy helper: require that the message `kid` is allowlisted by the AKV pack configuration.
 */
inline TrustPolicyBuilder& RequireAzureKeyVaultKidAllowed(TrustPolicyBuilder& policy) {
    cose::detail::ThrowIfNotOk(
        cose_sign1_akv_trust_policy_builder_require_azure_key_vault_kid_allowed(policy.native_handle())
    );
    return policy;
}

/**
 * @brief Trust-policy helper: require that the message `kid` is not allowlisted by the AKV pack configuration.
 */
inline TrustPolicyBuilder& RequireAzureKeyVaultKidNotAllowed(TrustPolicyBuilder& policy) {
    cose::detail::ThrowIfNotOk(
        cose_sign1_akv_trust_policy_builder_require_azure_key_vault_kid_not_allowed(policy.native_handle())
    );
    return policy;
}

/**
 * @brief RAII wrapper for Azure Key Vault key client
 */
class AkvKeyClient {
public:
    /**
     * @brief Create an AKV key client using DeveloperToolsCredential (for local dev)
     * @param vault_url Vault URL (e.g. "https://myvault.vault.azure.net")
     * @param key_name Key name in the vault
     * @param key_version Key version (empty string or default for latest)
     * @return New AkvKeyClient instance
     * @throws std::runtime_error on failure
     */
    static AkvKeyClient NewDev(
        const std::string& vault_url,
        const std::string& key_name,
        const std::string& key_version = ""
    ) {
        cose_akv_key_client_handle_t* client = nullptr;
        cose_status_t status = cose_akv_key_client_new_dev(
            vault_url.c_str(),
            key_name.c_str(),
            key_version.empty() ? nullptr : key_version.c_str(),
            &client
        );
        if (status != cose_status_t::COSE_OK || !client) {
            throw std::runtime_error("Failed to create AKV key client with DeveloperToolsCredential");
        }
        return AkvKeyClient(client);
    }

    /**
     * @brief Create an AKV key client using ClientSecretCredential
     * @param vault_url Vault URL (e.g. "https://myvault.vault.azure.net")
     * @param key_name Key name in the vault
     * @param key_version Key version (empty string or default for latest)
     * @param tenant_id Azure AD tenant ID
     * @param client_id Azure AD client (application) ID
     * @param client_secret Azure AD client secret
     * @return New AkvKeyClient instance
     * @throws std::runtime_error on failure
     */
    static AkvKeyClient NewClientSecret(
        const std::string& vault_url,
        const std::string& key_name,
        const std::string& key_version,
        const std::string& tenant_id,
        const std::string& client_id,
        const std::string& client_secret
    ) {
        cose_akv_key_client_handle_t* client = nullptr;
        cose_status_t status = cose_akv_key_client_new_client_secret(
            vault_url.c_str(),
            key_name.c_str(),
            key_version.empty() ? nullptr : key_version.c_str(),
            tenant_id.c_str(),
            client_id.c_str(),
            client_secret.c_str(),
            &client
        );
        if (status != cose_status_t::COSE_OK || !client) {
            throw std::runtime_error("Failed to create AKV key client with ClientSecretCredential");
        }
        return AkvKeyClient(client);
    }

    ~AkvKeyClient() {
        if (handle_) {
            cose_akv_key_client_free(handle_);
        }
    }

    // Non-copyable
    AkvKeyClient(const AkvKeyClient&) = delete;
    AkvKeyClient& operator=(const AkvKeyClient&) = delete;

    // Movable
    AkvKeyClient(AkvKeyClient&& other) noexcept : handle_(other.handle_) {
        other.handle_ = nullptr;
    }

    AkvKeyClient& operator=(AkvKeyClient&& other) noexcept {
        if (this != &other) {
            if (handle_) {
                cose_akv_key_client_free(handle_);
            }
            handle_ = other.handle_;
            other.handle_ = nullptr;
        }
        return *this;
    }

    /**
     * @brief Create a signing key from this AKV client
     * 
     * This method consumes the AKV client. After calling this method,
     * the AkvKeyClient object is no longer valid and should not be used.
     * 
     * @return A CoseKey that can be used for signing operations
     * @throws std::runtime_error on failure
     * 
     * @note Requires inclusion of cose/signing.hpp to use the returned CoseKey type
     */
#ifdef COSE_HAS_SIGNING
    cose::CoseKey CreateSigningKey() {
        if (!handle_) {
            throw std::runtime_error("AkvKeyClient handle is null");
        }
        
        cose_key_t* key = nullptr;
        cose_status_t status = cose_sign1_akv_create_signing_key(handle_, &key);
        
        // The client is consumed by cose_sign1_akv_create_signing_key
        handle_ = nullptr;
        
        if (status != cose_status_t::COSE_OK || !key) {
            throw std::runtime_error("Failed to create signing key from AKV client");
        }
        
        return cose::CoseKey(key);
    }
#else
    /**
     * @brief Create a signing key handle from this AKV client (raw handle version)
     * 
     * This method consumes the AKV client. After calling this method,
     * the AkvKeyClient object is no longer valid and should not be used.
     * 
     * @return A raw handle to a signing key (must be freed with cose_key_free)
     * @throws std::runtime_error on failure
     */
    cose_key_t* CreateSigningKeyHandle() {
        if (!handle_) {
            throw std::runtime_error("AkvKeyClient handle is null");
        }
        
        cose_key_t* key = nullptr;
        cose_status_t status = cose_sign1_akv_create_signing_key(handle_, &key);
        
        // The client is consumed by cose_sign1_akv_create_signing_key
        handle_ = nullptr;
        
        if (status != cose_status_t::COSE_OK || !key) {
            throw std::runtime_error("Failed to create signing key from AKV client");
        }
        
        return key;
    }
#endif

private:
    explicit AkvKeyClient(cose_akv_key_client_handle_t* handle) : handle_(handle) {}
    
    cose_akv_key_client_handle_t* handle_;
    
    // Allow AkvSigningService to access handle_ for consumption
    friend class AkvSigningService;
};

/**
 * @brief RAII wrapper for AKV signing service
 */
class AkvSigningService {
public:
    /**
     * @brief Create an AKV signing service from a key client
     * 
     * @param client AKV key client (will be consumed)
     * @throws cose::cose_error on failure
     */
    static AkvSigningService New(AkvKeyClient&& client) {
        cose_akv_signing_service_handle_t* handle = nullptr;
        
        // Extract the handle from the client
        auto* client_handle = client.handle_;
        if (!client_handle) {
            throw cose::cose_error("AkvKeyClient handle is null");
        }
        
        cose::detail::ThrowIfNotOk(
            cose_sign1_akv_create_signing_service(
                client_handle,
                &handle));
        
        // Mark the client as consumed (the C function consumes it)
        const_cast<AkvKeyClient&>(client).handle_ = nullptr;
        
        return AkvSigningService(handle);
    }

    ~AkvSigningService() {
        if (handle_) cose_sign1_akv_signing_service_free(handle_);
    }

    // Move-only
    AkvSigningService(AkvSigningService&& other) noexcept
        : handle_(std::exchange(other.handle_, nullptr)) {}
    AkvSigningService& operator=(AkvSigningService&& other) noexcept {
        if (this != &other) {
            if (handle_) cose_sign1_akv_signing_service_free(handle_);
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }
    AkvSigningService(const AkvSigningService&) = delete;
    AkvSigningService& operator=(const AkvSigningService&) = delete;

    cose_akv_signing_service_handle_t* native_handle() const { return handle_; }

private:
    explicit AkvSigningService(cose_akv_signing_service_handle_t* h) : handle_(h) {}
    cose_akv_signing_service_handle_t* handle_;
    
    // Allow AkvKeyClient to access handle_ for consumption
    friend class AkvKeyClient;
};

} // namespace cose::sign1

#endif // COSE_SIGN1_AKV_HPP
