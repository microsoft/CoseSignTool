// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COSESIGN1_SIGNING_HPP
#define COSESIGN1_SIGNING_HPP

#include "cosesign1_signing.h"
#include <vector>
#include <string>
#include <stdexcept>
#include <cstring>

namespace cosesign1 {

/// Exception thrown on signing API errors.
class SigningException : public std::runtime_error {
public:
    explicit SigningException(int32_t code, const char* message)
        : std::runtime_error(message ? message : "Unknown signing error"),
          error_code_(code) {}
    int32_t code() const noexcept { return error_code_; }
private:
    int32_t error_code_;
};

namespace detail {
    inline void check_error(int32_t result, CoseImplErrorHandle error) {
        if (result != COSESIGN1_SIGNING_OK) {
            std::string msg;
            int32_t code = result;
            if (error) {
                const char* m = cosesign1_impl_error_message(error);
                code = cosesign1_impl_error_code(error);
                if (m) msg = m;
                cosesign1_impl_error_free(error);
            }
            throw SigningException(code, msg.c_str());
        }
    }
} // namespace detail

/// RAII wrapper for CertificateSigningService.
class CertificateSigningService {
public:
    /// Create from local DER certificate bytes.
    static CertificateSigningService CreateLocal(
        const uint8_t* cert_data, uint32_t cert_len,
        const uint8_t* chain_data = nullptr, uint32_t chain_len = 0)
    {
        CoseImplCertSigningServiceHandle h = nullptr;
        CoseImplErrorHandle err = nullptr;
        auto rc = cosesign1_cert_signing_service_create_local(
            cert_data, cert_len, chain_data, chain_len, &h, &err);
        detail::check_error(rc, err);
        return CertificateSigningService(h);
    }

    ~CertificateSigningService() {
        if (handle_) cosesign1_cert_signing_service_free(handle_);
    }

    // Move-only
    CertificateSigningService(CertificateSigningService&& o) noexcept : handle_(o.handle_) { o.handle_ = nullptr; }
    CertificateSigningService& operator=(CertificateSigningService&& o) noexcept {
        if (this != &o) { if (handle_) cosesign1_cert_signing_service_free(handle_); handle_ = o.handle_; o.handle_ = nullptr; }
        return *this;
    }
    CertificateSigningService(const CertificateSigningService&) = delete;
    CertificateSigningService& operator=(const CertificateSigningService&) = delete;

    CoseImplCertSigningServiceHandle handle() const noexcept { return handle_; }

private:
    explicit CertificateSigningService(CoseImplCertSigningServiceHandle h) : handle_(h) {}
    CoseImplCertSigningServiceHandle handle_;
};

/// RAII wrapper for SignatureFactory.
class SignatureFactory {
public:
    explicit SignatureFactory(const CertificateSigningService& service) {
        CoseImplErrorHandle err = nullptr;
        auto rc = cosesign1_factory_create(service.handle(), &handle_, &err);
        detail::check_error(rc, err);
    }

    ~SignatureFactory() {
        if (handle_) cosesign1_factory_free(handle_);
    }

    // Move-only
    SignatureFactory(SignatureFactory&& o) noexcept : handle_(o.handle_) { o.handle_ = nullptr; }
    SignatureFactory& operator=(SignatureFactory&& o) noexcept {
        if (this != &o) { if (handle_) cosesign1_factory_free(handle_); handle_ = o.handle_; o.handle_ = nullptr; }
        return *this;
    }
    SignatureFactory(const SignatureFactory&) = delete;
    SignatureFactory& operator=(const SignatureFactory&) = delete;

    /// Sign payload with direct signature.
    std::vector<uint8_t> SignDirect(const uint8_t* payload, uint32_t len, const char* content_type) {
        uint8_t* out = nullptr;
        uint32_t out_len = 0;
        CoseImplErrorHandle err = nullptr;
        auto rc = cosesign1_factory_sign_direct(handle_, payload, len, content_type, &out, &out_len, &err);
        detail::check_error(rc, err);
        std::vector<uint8_t> result(out, out + out_len);
        cosesign1_impl_cose_bytes_free(out, out_len);
        return result;
    }

    /// Sign payload with indirect signature (hash envelope).
    std::vector<uint8_t> SignIndirect(const uint8_t* payload, uint32_t len, const char* content_type) {
        uint8_t* out = nullptr;
        uint32_t out_len = 0;
        CoseImplErrorHandle err = nullptr;
        auto rc = cosesign1_factory_sign_indirect(handle_, payload, len, content_type, &out, &out_len, &err);
        detail::check_error(rc, err);
        std::vector<uint8_t> result(out, out + out_len);
        cosesign1_impl_cose_bytes_free(out, out_len);
        return result;
    }

private:
    CoseImplFactoryHandle handle_ = nullptr;
};

} // namespace cosesign1

#endif // COSESIGN1_SIGNING_HPP
