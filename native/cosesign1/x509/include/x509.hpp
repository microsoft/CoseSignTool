#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "abstractions.hpp"
#include "cosesign1/x509.h"

namespace cosesign1 {

class X509Result : public Result<
                      cosesign1_x509_result,
                      cosesign1_x509_result_free,
                      cosesign1_x509_result_is_valid,
                      cosesign1_x509_result_validator_name,
                      cosesign1_x509_result_failure_count,
                      cosesign1_x509_result_failure_at,
                      cosesign1_x509_result_metadata_count,
                      cosesign1_x509_result_metadata_at> {
public:
    using Result::Result;
};

struct X509ChainOptions {
    int32_t trust_mode = 0;
    int32_t revocation_mode = 1;
    bool allow_untrusted_roots = false;
};

class X509ChainVerifier {
public:
    static X509Result ValidateX5cChain(
        const std::vector<std::vector<std::uint8_t>>& certs,
        const std::vector<std::vector<std::uint8_t>>* trusted_roots,
        const X509ChainOptions& options)
    {
        std::vector<cosesign1_byte_view> cert_views;
        cert_views.reserve(certs.size());
        for (const auto& c : certs) {
            cert_views.push_back(cosesign1_byte_view{ c.data(), c.size() });
        }

        std::vector<cosesign1_byte_view> root_views;
        const cosesign1_byte_view* roots_ptr = nullptr;
        size_t roots_len = 0;
        if (trusted_roots) {
            root_views.reserve(trusted_roots->size());
            for (const auto& r : *trusted_roots) {
                root_views.push_back(cosesign1_byte_view{ r.data(), r.size() });
            }
            roots_ptr = root_views.data();
            roots_len = root_views.size();
        }

        cosesign1_x509_chain_options opt{};
        opt.trust_mode = options.trust_mode;
        opt.revocation_mode = options.revocation_mode;
        opt.allow_untrusted_roots = options.allow_untrusted_roots;

        return X509Result(cosesign1_x509_validate_x5c_chain(
            cert_views.data(), cert_views.size(), roots_ptr, roots_len, opt));
    }
};

} // namespace cosesign1
