// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file cwt.hpp
 * @brief C++ RAII wrapper for CWT (CBOR Web Token) claims.
 *
 * Provides a fluent, exception-safe interface for building and serializing
 * CWT claims (RFC 8392). The claims can then be embedded in COSE_Sign1
 * protected headers.
 *
 * @code
 * #include <cose/sign1/cwt.hpp>
 *
 * auto claims = cose::sign1::CwtClaims::New();
 * claims.SetIssuer("did:x509:...");
 * claims.SetSubject("my-subject");
 * claims.SetIssuedAt(std::time(nullptr));
 * auto cbor = claims.ToCbor();
 * @endcode
 */

#ifndef COSE_SIGN1_CWT_HPP
#define COSE_SIGN1_CWT_HPP

#include <cose/sign1/cwt.h>
#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <stdexcept>
#include <utility>

namespace cose::sign1 {

/**
 * @brief Exception thrown by CWT claims operations.
 */
class cwt_error : public std::runtime_error {
public:
    explicit cwt_error(const std::string& msg) : std::runtime_error(msg) {}

    explicit cwt_error(CoseCwtErrorHandle* error)
        : std::runtime_error(get_message(error)) {
        if (error) {
            cose_cwt_error_free(error);
        }
    }

private:
    static std::string get_message(CoseCwtErrorHandle* error) {
        if (error) {
            char* msg = cose_cwt_error_message(error);
            if (msg) {
                std::string result(msg);
                cose_cwt_string_free(msg);
                return result;
            }
            int32_t code = cose_cwt_error_code(error);
            return "CWT error (code=" + std::to_string(code) + ")";
        }
        return "CWT error (unknown)";
    }
};

namespace detail {

inline void CwtThrowIfNotOk(int32_t status, CoseCwtErrorHandle* error) {
    if (status != COSE_CWT_OK) {
        throw cwt_error(error);
    }
}

} // namespace detail

/**
 * @brief RAII wrapper for CWT claims.
 *
 * Move-only. Fluent setters return `*this` for chaining.
 */
class CwtClaims {
public:
    /**
     * @brief Create a new empty CWT claims set.
     * @throws cwt_error on failure.
     */
    static CwtClaims New() {
        CoseCwtClaimsHandle* handle = nullptr;
        CoseCwtErrorHandle* error = nullptr;
        int32_t status = cose_cwt_claims_create(&handle, &error);
        detail::CwtThrowIfNotOk(status, error);
        return CwtClaims(handle);
    }

    /**
     * @brief Deserialize CWT claims from CBOR bytes.
     * @throws cwt_error on failure.
     */
    static CwtClaims FromCbor(const uint8_t* data, uint32_t len) {
        CoseCwtClaimsHandle* handle = nullptr;
        CoseCwtErrorHandle* error = nullptr;
        int32_t status = cose_cwt_claims_from_cbor(data, len, &handle, &error);
        detail::CwtThrowIfNotOk(status, error);
        return CwtClaims(handle);
    }

    /** @brief Deserialize from a byte vector. */
    static CwtClaims FromCbor(const std::vector<uint8_t>& data) {
        return FromCbor(data.data(), static_cast<uint32_t>(data.size()));
    }

    ~CwtClaims() {
        if (handle_) cose_cwt_claims_free(handle_);
    }

    // Move-only
    CwtClaims(CwtClaims&& other) noexcept
        : handle_(std::exchange(other.handle_, nullptr)) {}

    CwtClaims& operator=(CwtClaims&& other) noexcept {
        if (this != &other) {
            if (handle_) cose_cwt_claims_free(handle_);
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    CwtClaims(const CwtClaims&) = delete;
    CwtClaims& operator=(const CwtClaims&) = delete;

    // ====================================================================
    // Setters (fluent)
    // ====================================================================

    /** @brief Set the issuer (iss) claim. */
    CwtClaims& SetIssuer(const char* issuer) {
        CoseCwtErrorHandle* error = nullptr;
        int32_t status = cose_cwt_claims_set_issuer(handle_, issuer, &error);
        detail::CwtThrowIfNotOk(status, error);
        return *this;
    }

    CwtClaims& SetIssuer(const std::string& issuer) {
        return SetIssuer(issuer.c_str());
    }

    /** @brief Set the subject (sub) claim. */
    CwtClaims& SetSubject(const char* subject) {
        CoseCwtErrorHandle* error = nullptr;
        int32_t status = cose_cwt_claims_set_subject(handle_, subject, &error);
        detail::CwtThrowIfNotOk(status, error);
        return *this;
    }

    CwtClaims& SetSubject(const std::string& subject) {
        return SetSubject(subject.c_str());
    }

    /** @brief Set the audience (aud) claim. */
    CwtClaims& SetAudience(const char* audience) {
        CoseCwtErrorHandle* error = nullptr;
        int32_t status = cose_cwt_claims_set_audience(handle_, audience, &error);
        detail::CwtThrowIfNotOk(status, error);
        return *this;
    }

    CwtClaims& SetAudience(const std::string& audience) {
        return SetAudience(audience.c_str());
    }

    /** @brief Set the expiration time (exp) claim. */
    CwtClaims& SetExpiration(int64_t unix_timestamp) {
        CoseCwtErrorHandle* error = nullptr;
        int32_t status = cose_cwt_claims_set_expiration(handle_, unix_timestamp, &error);
        detail::CwtThrowIfNotOk(status, error);
        return *this;
    }

    /** @brief Set the not-before (nbf) claim. */
    CwtClaims& SetNotBefore(int64_t unix_timestamp) {
        CoseCwtErrorHandle* error = nullptr;
        int32_t status = cose_cwt_claims_set_not_before(handle_, unix_timestamp, &error);
        detail::CwtThrowIfNotOk(status, error);
        return *this;
    }

    /** @brief Set the issued-at (iat) claim. */
    CwtClaims& SetIssuedAt(int64_t unix_timestamp) {
        CoseCwtErrorHandle* error = nullptr;
        int32_t status = cose_cwt_claims_set_issued_at(handle_, unix_timestamp, &error);
        detail::CwtThrowIfNotOk(status, error);
        return *this;
    }

    // ====================================================================
    // Getters
    // ====================================================================

    /**
     * @brief Get the issuer (iss) claim.
     * @return The issuer string, or std::nullopt if not set.
     */
    std::optional<std::string> GetIssuer() const {
        const char* issuer = nullptr;
        CoseCwtErrorHandle* error = nullptr;
        int32_t status = cose_cwt_claims_get_issuer(handle_, &issuer, &error);
        detail::CwtThrowIfNotOk(status, error);
        if (issuer) {
            std::string result(issuer);
            cose_cwt_string_free(const_cast<char*>(issuer));
            return result;
        }
        return std::nullopt;
    }

    /**
     * @brief Get the subject (sub) claim.
     * @return The subject string, or std::nullopt if not set.
     */
    std::optional<std::string> GetSubject() const {
        const char* subject = nullptr;
        CoseCwtErrorHandle* error = nullptr;
        int32_t status = cose_cwt_claims_get_subject(handle_, &subject, &error);
        detail::CwtThrowIfNotOk(status, error);
        if (subject) {
            std::string result(subject);
            cose_cwt_string_free(const_cast<char*>(subject));
            return result;
        }
        return std::nullopt;
    }

    // ====================================================================
    // Serialization
    // ====================================================================

    /**
     * @brief Serialize to CBOR bytes.
     * @return CBOR-encoded claims.
     * @throws cwt_error on failure.
     */
    std::vector<uint8_t> ToCbor() const {
        uint8_t* bytes = nullptr;
        uint32_t len = 0;
        CoseCwtErrorHandle* error = nullptr;
        int32_t status = cose_cwt_claims_to_cbor(handle_, &bytes, &len, &error);
        detail::CwtThrowIfNotOk(status, error);
        std::vector<uint8_t> result(bytes, bytes + len);
        cose_cwt_bytes_free(bytes, len);
        return result;
    }

    /** @brief Access the native handle (for interop). */
    CoseCwtClaimsHandle* native_handle() const { return handle_; }

private:
    explicit CwtClaims(CoseCwtClaimsHandle* h) : handle_(h) {}
    CoseCwtClaimsHandle* handle_;
};

} // namespace cose::sign1

#endif // COSE_SIGN1_CWT_HPP
