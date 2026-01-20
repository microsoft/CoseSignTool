// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file mst.hpp
 * @brief C++ wrappers for MST receipt verification pack
 */

#ifndef COSE_MST_HPP
#define COSE_MST_HPP

#include <cose/validator.hpp>
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
        cose_status_t status = cose_validator_builder_with_mst_pack(builder_);
        if (status != COSE_OK) {
            throw cose_error(status);
        }
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
        
        cose_status_t status = cose_validator_builder_with_mst_pack_ex(builder_, &c_opts);
        if (status != COSE_OK) {
            throw cose_error(status);
        }
        
        return *this;
    }
};

} // namespace cose

#endif // COSE_MST_HPP
