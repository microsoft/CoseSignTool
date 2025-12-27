#pragma once

#include <cstdint>
#include <istream>
#include <string>
#include <unordered_map>
#include <vector>

#include "abstractions.hpp"
#include "cosesign1.h"
#include "mst.hpp"
#include "x509.hpp"

namespace cosesign1 {

namespace detail {

struct IstreamReaderCtx {
    std::istream* s;
};

inline int32_t istream_read(void* p, std::uint8_t* out, size_t out_len, size_t* bytes_read) {
    auto* c = static_cast<IstreamReaderCtx*>(p);
    c->s->read(reinterpret_cast<char*>(out), static_cast<std::streamsize>(out_len));
    const auto got = c->s->gcount();
    if (got < 0) return 1;
    *bytes_read = static_cast<size_t>(got);
    return c->s->bad() ? 1 : 0;
}

inline int32_t istream_seek(void* p, int64_t offset, int32_t origin, uint64_t* new_pos) {
    auto* c = static_cast<IstreamReaderCtx*>(p);
    std::ios_base::seekdir dir;
    switch (origin) {
    case 0: dir = std::ios_base::beg; break;
    case 1: dir = std::ios_base::cur; break;
    case 2: dir = std::ios_base::end; break;
    default: return 1;
    }

    c->s->clear();
    c->s->seekg(static_cast<std::streamoff>(offset), dir);
    if (c->s->fail()) return 1;

    const auto pos = c->s->tellg();
    if (pos < 0) return 1;
    *new_pos = static_cast<uint64_t>(pos);
    return 0;
}

} // namespace detail

class ValidationResult : public Result<
                            cosesign1_validation_result,
                            cosesign1_validation_result_free,
                            cosesign1_validation_result_is_valid,
                            cosesign1_validation_result_validator_name,
                            cosesign1_validation_result_failure_count,
                            cosesign1_validation_result_failure_at,
                            cosesign1_validation_result_metadata_count,
                            cosesign1_validation_result_metadata_at> {
public:
    using Result::Result;
};

class Verifier {
public:
    static ValidationResult VerifySignature(
        const std::vector<std::uint8_t>& cose,
        const std::vector<std::uint8_t>* payload,
        const std::vector<std::uint8_t>* public_key)
    {
        const std::uint8_t* payload_ptr = payload ? payload->data() : nullptr;
        const size_t payload_len = payload ? payload->size() : 0;
        const std::uint8_t* pk_ptr = public_key ? public_key->data() : nullptr;
        const size_t pk_len = public_key ? public_key->size() : 0;

        return ValidationResult(cosesign1_validation_verify_signature(
            cose.data(), cose.size(), payload_ptr, payload_len, pk_ptr, pk_len));
    }

    static ValidationResult VerifyDetachedSignature(
        const std::vector<std::uint8_t>& cose,
        std::istream& payload_stream,
        const std::vector<std::uint8_t>* public_key)
    {
        detail::IstreamReaderCtx ctx{ &payload_stream };

        cosesign1_reader rdr{};
        rdr.ctx = &ctx;
        rdr.read = detail::istream_read;
        rdr.seek = detail::istream_seek;

        const std::uint8_t* pk_ptr = public_key ? public_key->data() : nullptr;
        const size_t pk_len = public_key ? public_key->size() : 0;

        return ValidationResult(cosesign1_validation_verify_signature_with_payload_reader(
            cose.data(), cose.size(), rdr, pk_ptr, pk_len));
    }
};

struct VerificationSettings {
    bool require_cose_signature = true;

    // If set, verify as "x5c" pipeline: signature verification + x5c chain trust.
    bool enable_x5c_chain_validator = false;
    X509ChainOptions x5c_chain_options{};
    std::vector<std::vector<std::uint8_t>> x5c_trusted_roots_der;

    // If set, verify as MST receipt pipeline (does not require COSE signing key trust).
    const KeyStore* mst_store = nullptr;
    std::vector<std::string> mst_authorized_domains;
    AuthorizedReceiptBehavior mst_authorized_behavior = AuthorizedReceiptBehavior::RequireAll;
    UnauthorizedReceiptBehavior mst_unauthorized_behavior = UnauthorizedReceiptBehavior::FailIfPresent;

    static VerificationSettings Default() { return VerificationSettings{}; }

    VerificationSettings without_cose_signature() const {
        auto copy = *this;
        copy.require_cose_signature = false;
        return copy;
    }

    VerificationSettings with_x5c_chain_validation_options(
        const X509ChainOptions& opt,
        std::vector<std::vector<std::uint8_t>> trusted_roots_der = {}) const
    {
        auto copy = *this;
        copy.enable_x5c_chain_validator = true;
        copy.x5c_chain_options = opt;
        copy.x5c_trusted_roots_der = std::move(trusted_roots_der);
        return copy;
    }

    VerificationSettings with_mst_validation_options(
        const KeyStore& store,
        std::vector<std::string> authorized_domains,
        AuthorizedReceiptBehavior authorized_behavior = AuthorizedReceiptBehavior::RequireAll,
        UnauthorizedReceiptBehavior unauthorized_behavior = UnauthorizedReceiptBehavior::FailIfPresent) const
    {
        auto copy = *this;
        copy.mst_store = &store;
        copy.mst_authorized_domains = std::move(authorized_domains);
        copy.mst_authorized_behavior = authorized_behavior;
        copy.mst_unauthorized_behavior = unauthorized_behavior;
        return copy;
    }
};

class CoseSign1 {
public:
    static CoseSign1 from_bytes(std::vector<std::uint8_t>&& cose_bytes) { return CoseSign1(std::move(cose_bytes)); }
    static CoseSign1 from_bytes(const std::vector<std::uint8_t>& cose_bytes) { return CoseSign1(cose_bytes); }

    // Mirrors Rust: msg.verify_signature(payload_opt, public_key_opt)
    ValidationResult verify_signature(
        const std::vector<std::uint8_t>* payload,
        const std::vector<std::uint8_t>* public_key) const
    {
        return Verifier::VerifySignature(cose_, payload, public_key);
    }

    // Mirrors Rust: msg.verify(payload_opt, public_key_opt, &settings)
    ValidationResult verify(
        const std::vector<std::uint8_t>* payload,
        const std::vector<std::uint8_t>* public_key,
        const VerificationSettings& settings) const
    {
        // MST pipeline: use the existing MST verifier on the message bytes.
        if (settings.mst_store) {
            std::vector<cosesign1_string_view> domains;
            domains.reserve(settings.mst_authorized_domains.size());
            for (const auto& d : settings.mst_authorized_domains) {
                domains.push_back(cosesign1_string_view{ d.c_str() });
            }

            cosesign1_mst_verification_options opt{};
            opt.authorized_receipt_behavior = static_cast<int32_t>(settings.mst_authorized_behavior);
            opt.unauthorized_receipt_behavior = static_cast<int32_t>(settings.mst_unauthorized_behavior);

            // NOTE: This returns a cosesign1_mst_result*, which is ABI-compatible with cosesign1_validation_result*.
            auto* raw = cosesign1_mst_verify_transparent_statement(
                settings.mst_store->native_handle(),
                cose_.data(),
                cose_.size(),
                domains.empty() ? nullptr : domains.data(),
                domains.size(),
                opt);
            return ValidationResult(reinterpret_cast<cosesign1_validation_result*>(raw));
        }

        // x5c pipeline: signature verification + chain trust using embedded x5c.
        if (settings.enable_x5c_chain_validator) {
            std::vector<cosesign1_byte_view> root_views;
            root_views.reserve(settings.x5c_trusted_roots_der.size());
            for (const auto& r : settings.x5c_trusted_roots_der) {
                root_views.push_back(cosesign1_byte_view{ r.data(), r.size() });
            }

            const std::uint8_t* payload_ptr = payload ? payload->data() : nullptr;
            const size_t payload_len = payload ? payload->size() : 0;

            // NOTE: This returns a cosesign1_x509_result*, which is ABI-compatible with cosesign1_validation_result*.
            auto* raw = cosesign1_x509_verify_cose_sign1_with_x5c_chain(
                cose_.data(),
                cose_.size(),
                payload_ptr,
                payload_len,
                root_views.empty() ? nullptr : root_views.data(),
                root_views.size(),
                cosesign1_x509_chain_options{
                    settings.x5c_chain_options.trust_mode,
                    settings.x5c_chain_options.revocation_mode,
                    settings.x5c_chain_options.allow_untrusted_roots,
                });

            return ValidationResult(reinterpret_cast<cosesign1_validation_result*>(raw));
        }

        // Default: signature verification only.
        if (!settings.require_cose_signature) {
            // No validators configured, and signature verification disabled.
            // Mirror Rust behavior: treat as "valid" no-op.
            // We don't currently have a native constructor for success results; fall back to signature verify.
        }
        return verify_signature(payload, public_key);
    }

    bool is_detached_payload() const { return cosesign1::is_detached_payload(cose_); }

private:
    explicit CoseSign1(std::vector<std::uint8_t> cose_bytes) : cose_(std::move(cose_bytes)) {}
    std::vector<std::uint8_t> cose_;
};

} // namespace cosesign1
