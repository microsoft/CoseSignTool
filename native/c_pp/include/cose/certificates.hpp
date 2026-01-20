// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file certificates.hpp
 * @brief C++ wrappers for X.509 certificate validation pack
 */

#ifndef COSE_CERTIFICATES_HPP
#define COSE_CERTIFICATES_HPP

#include <cose/validator.hpp>
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

} // namespace cose

#endif // COSE_CERTIFICATES_HPP
