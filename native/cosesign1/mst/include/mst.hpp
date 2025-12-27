#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "abstractions.hpp"
#include "cosesign1/mst.h"

namespace cosesign1 {

enum class AuthorizedReceiptBehavior : int32_t {
    VerifyAnyMatching = 0,
    VerifyAllMatching = 1,
    RequireAll = 2,
};

enum class UnauthorizedReceiptBehavior : int32_t {
    VerifyAll = 0,
    IgnoreAll = 1,
    FailIfPresent = 2,
};

class MstResult : public Result<
                     cosesign1_mst_result,
                     cosesign1_mst_result_free,
                     cosesign1_mst_result_is_valid,
                     cosesign1_mst_result_validator_name,
                     cosesign1_mst_result_failure_count,
                     cosesign1_mst_result_failure_at,
                     cosesign1_mst_result_metadata_count,
                     cosesign1_mst_result_metadata_at> {
public:
    using Result::Result;
};

class KeyStore {
public:
    KeyStore() : p_(cosesign1_mst_keystore_new()) {}
    ~KeyStore() { reset(); }

    KeyStore(const KeyStore&) = delete;
    KeyStore& operator=(const KeyStore&) = delete;

    KeyStore(KeyStore&& other) noexcept : p_(other.p_) { other.p_ = nullptr; }
    KeyStore& operator=(KeyStore&& other) noexcept {
        if (this != &other) {
            reset();
            p_ = other.p_;
            other.p_ = nullptr;
        }
        return *this;
    }

    bool valid() const noexcept { return p_ != nullptr; }

    const cosesign1_mst_keystore* native_handle() const noexcept { return p_; }
    cosesign1_mst_keystore* native_handle() noexcept { return p_; }

    MstResult AddIssuerJwks(const std::string& issuer_host, const std::vector<std::uint8_t>& jwks_json) {
        return MstResult(cosesign1_mst_keystore_add_issuer_jwks(
            p_, issuer_host.c_str(), jwks_json.data(), jwks_json.size()));
    }

    MstResult VerifyTransparentStatement(
        const std::vector<std::uint8_t>& transparent_statement,
        const std::vector<std::string>& authorized_domains,
        AuthorizedReceiptBehavior authorized_behavior,
        UnauthorizedReceiptBehavior unauthorized_behavior)
    {
        std::vector<cosesign1_string_view> views;
        views.reserve(authorized_domains.size());
        for (const auto& d : authorized_domains) {
            views.push_back(cosesign1_string_view{ d.c_str() });
        }

        cosesign1_mst_verification_options opt{};
        opt.authorized_receipt_behavior = static_cast<int32_t>(authorized_behavior);
        opt.unauthorized_receipt_behavior = static_cast<int32_t>(unauthorized_behavior);

        return MstResult(cosesign1_mst_verify_transparent_statement(
            p_,
            transparent_statement.data(),
            transparent_statement.size(),
            views.empty() ? nullptr : views.data(),
            views.size(),
            opt));
    }

    void reset() noexcept {
        if (p_) {
            cosesign1_mst_keystore_free(p_);
            p_ = nullptr;
        }
    }

private:
    cosesign1_mst_keystore* p_ = nullptr;
};

} // namespace cosesign1
