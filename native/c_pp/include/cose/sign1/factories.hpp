// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file factories.hpp
 * @brief C++ RAII wrappers for COSE Sign1 factories
 */

#ifndef COSE_SIGN1_FACTORIES_HPP
#define COSE_SIGN1_FACTORIES_HPP

#include <cose/sign1/factories.h>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>
#include <stdexcept>
#include <utility>

namespace cose::sign1 {

/**
 * @brief Exception thrown by factory operations
 */
class FactoryError : public std::runtime_error {
public:
    explicit FactoryError(int code, const std::string& msg) 
        : std::runtime_error(msg), error_code_(code) {}
    
    int code() const noexcept { return error_code_; }
    
private:
    int error_code_;
};

} // namespace cose::sign1

namespace cose::detail {

/**
 * @brief Checks factory status and throws on error
 */
inline void ThrowIfNotOkFactory(int status, CoseSign1FactoriesErrorHandle* error) {
    if (status != COSE_SIGN1_FACTORIES_OK) {
        std::string msg;
        int code = status;
        if (error) {
            char* m = cose_sign1_factories_error_message(error);
            code = cose_sign1_factories_error_code(error);
            if (m) {
                msg = m;
                cose_sign1_factories_string_free(m);
            }
            cose_sign1_factories_error_free(error);
        }
        if (msg.empty()) {
            msg = "Factory operation failed with status " + std::to_string(status);
        }
        throw cose::sign1::FactoryError(code, msg);
    }
    if (error) {
        cose_sign1_factories_error_free(error);
    }
}

/**
 * @brief Trampoline for streaming callback
 */
inline int64_t StreamTrampoline(uint8_t* buf, size_t len, void* user_data) {
    auto* fn = static_cast<std::function<size_t(uint8_t*, size_t)>*>(user_data);
    return static_cast<int64_t>((*fn)(buf, len));
}

} // namespace cose::detail

namespace cose::sign1 {

/**
 * @brief RAII wrapper for COSE Sign1 message factory
 * 
 * Provides convenient methods for creating direct and indirect signatures
 * with various payload types (memory, file, streaming).
 */
class Factory {
public:
    /**
     * @brief Creates a factory from a signing service handle
     * 
     * @param service Signing service handle
     * @return Factory instance
     * @throws FactoryError on failure
     */
    static Factory FromSigningService(const CoseSign1FactoriesSigningServiceHandle* service) {
        CoseSign1FactoriesHandle* h = nullptr;
        CoseSign1FactoriesErrorHandle* err = nullptr;
        int status = cose_sign1_factories_create_from_signing_service(service, &h, &err);
        cose::detail::ThrowIfNotOkFactory(status, err);
        return Factory(h);
    }

    /**
     * @brief Creates a factory from a crypto signer handle
     * 
     * Ownership of the signer handle is transferred to the factory.
     * 
     * @param signer_handle Crypto signer handle (ownership transferred)
     * @return Factory instance
     * @throws FactoryError on failure
     */
    static Factory FromCryptoSigner(CryptoSignerHandle* signer_handle) {
        CoseSign1FactoriesHandle* h = nullptr;
        CoseSign1FactoriesErrorHandle* err = nullptr;
        int status = cose_sign1_factories_create_from_crypto_signer(signer_handle, &h, &err);
        cose::detail::ThrowIfNotOkFactory(status, err);
        return Factory(h);
    }

    /**
     * @brief Destructor - frees the factory handle
     */
    ~Factory() {
        if (handle_) {
            cose_sign1_factories_free(handle_);
        }
    }

    // Move-only semantics
    Factory(Factory&& other) noexcept : handle_(std::exchange(other.handle_, nullptr)) {}
    
    Factory& operator=(Factory&& other) noexcept {
        if (this != &other) {
            if (handle_) {
                cose_sign1_factories_free(handle_);
            }
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    Factory(const Factory&) = delete;
    Factory& operator=(const Factory&) = delete;

    /**
     * @brief Gets the native handle (for interop)
     */
    const CoseSign1FactoriesHandle* native_handle() const noexcept { return handle_; }

    // ========================================================================
    // Direct signature methods
    // ========================================================================

    /**
     * @brief Signs payload with direct signature (embedded payload)
     * 
     * @param payload Payload bytes
     * @param content_type Content type string
     * @return COSE_Sign1 message bytes
     * @throws FactoryError on failure
     */
    std::vector<uint8_t> SignDirect(
        const std::vector<uint8_t>& payload,
        const std::string& content_type) const
    {
        return SignDirect(payload.data(), static_cast<uint32_t>(payload.size()), content_type);
    }

    /**
     * @brief Signs payload with direct signature (embedded payload)
     * 
     * @param payload Payload data pointer
     * @param payload_len Payload length
     * @param content_type Content type string
     * @return COSE_Sign1 message bytes
     * @throws FactoryError on failure
     */
    std::vector<uint8_t> SignDirect(
        const uint8_t* payload,
        uint32_t payload_len,
        const std::string& content_type) const
    {
        uint8_t* out = nullptr;
        uint32_t out_len = 0;
        CoseSign1FactoriesErrorHandle* err = nullptr;
        
        int status = cose_sign1_factories_sign_direct(
            handle_, payload, payload_len, content_type.c_str(),
            &out, &out_len, &err);
        
        cose::detail::ThrowIfNotOkFactory(status, err);
        
        std::vector<uint8_t> result(out, out + out_len);
        cose_sign1_factories_bytes_free(out, out_len);
        return result;
    }

    /**
     * @brief Signs payload with direct signature in detached mode
     * 
     * @param payload Payload bytes
     * @param content_type Content type string
     * @return COSE_Sign1 message bytes (without embedded payload)
     * @throws FactoryError on failure
     */
    std::vector<uint8_t> SignDirectDetached(
        const std::vector<uint8_t>& payload,
        const std::string& content_type) const
    {
        return SignDirectDetached(payload.data(), static_cast<uint32_t>(payload.size()), content_type);
    }

    /**
     * @brief Signs payload with direct signature in detached mode
     * 
     * @param payload Payload data pointer
     * @param payload_len Payload length
     * @param content_type Content type string
     * @return COSE_Sign1 message bytes (without embedded payload)
     * @throws FactoryError on failure
     */
    std::vector<uint8_t> SignDirectDetached(
        const uint8_t* payload,
        uint32_t payload_len,
        const std::string& content_type) const
    {
        uint8_t* out = nullptr;
        uint32_t out_len = 0;
        CoseSign1FactoriesErrorHandle* err = nullptr;
        
        int status = cose_sign1_factories_sign_direct_detached(
            handle_, payload, payload_len, content_type.c_str(),
            &out, &out_len, &err);
        
        cose::detail::ThrowIfNotOkFactory(status, err);
        
        std::vector<uint8_t> result(out, out + out_len);
        cose_sign1_factories_bytes_free(out, out_len);
        return result;
    }

    /**
     * @brief Signs a file with direct signature (detached)
     * 
     * The file is not loaded into memory - streaming I/O is used.
     * 
     * @param file_path Path to file
     * @param content_type Content type string
     * @return COSE_Sign1 message bytes (without embedded payload)
     * @throws FactoryError on failure
     */
    std::vector<uint8_t> SignDirectFile(
        const std::string& file_path,
        const std::string& content_type) const
    {
        uint8_t* out = nullptr;
        uint32_t out_len = 0;
        CoseSign1FactoriesErrorHandle* err = nullptr;
        
        int status = cose_sign1_factories_sign_direct_file(
            handle_, file_path.c_str(), content_type.c_str(),
            &out, &out_len, &err);
        
        cose::detail::ThrowIfNotOkFactory(status, err);
        
        std::vector<uint8_t> result(out, out + out_len);
        cose_sign1_factories_bytes_free(out, out_len);
        return result;
    }

    /**
     * @brief Signs a streaming payload with direct signature (detached)
     * 
     * @param read_callback Callback to read payload data (returns bytes read, 0=EOF)
     * @param total_len Total length of the payload
     * @param content_type Content type string
     * @return COSE_Sign1 message bytes (without embedded payload)
     * @throws FactoryError on failure
     */
    std::vector<uint8_t> SignDirectStreaming(
        std::function<size_t(uint8_t*, size_t)> read_callback,
        uint64_t total_len,
        const std::string& content_type) const
    {
        uint8_t* out = nullptr;
        uint32_t out_len = 0;
        CoseSign1FactoriesErrorHandle* err = nullptr;
        
        int status = cose_sign1_factories_sign_direct_streaming(
            handle_,
            cose::detail::StreamTrampoline,
            &read_callback,
            total_len,
            content_type.c_str(),
            &out, &out_len, &err);
        
        cose::detail::ThrowIfNotOkFactory(status, err);
        
        std::vector<uint8_t> result(out, out + out_len);
        cose_sign1_factories_bytes_free(out, out_len);
        return result;
    }

    // ========================================================================
    // Indirect signature methods
    // ========================================================================

    /**
     * @brief Signs payload with indirect signature (hash envelope)
     * 
     * @param payload Payload bytes
     * @param content_type Content type string
     * @return COSE_Sign1 message bytes
     * @throws FactoryError on failure
     */
    std::vector<uint8_t> SignIndirect(
        const std::vector<uint8_t>& payload,
        const std::string& content_type) const
    {
        return SignIndirect(payload.data(), static_cast<uint32_t>(payload.size()), content_type);
    }

    /**
     * @brief Signs payload with indirect signature (hash envelope)
     * 
     * @param payload Payload data pointer
     * @param payload_len Payload length
     * @param content_type Content type string
     * @return COSE_Sign1 message bytes
     * @throws FactoryError on failure
     */
    std::vector<uint8_t> SignIndirect(
        const uint8_t* payload,
        uint32_t payload_len,
        const std::string& content_type) const
    {
        uint8_t* out = nullptr;
        uint32_t out_len = 0;
        CoseSign1FactoriesErrorHandle* err = nullptr;
        
        int status = cose_sign1_factories_sign_indirect(
            handle_, payload, payload_len, content_type.c_str(),
            &out, &out_len, &err);
        
        cose::detail::ThrowIfNotOkFactory(status, err);
        
        std::vector<uint8_t> result(out, out + out_len);
        cose_sign1_factories_bytes_free(out, out_len);
        return result;
    }

    /**
     * @brief Signs a file with indirect signature (hash envelope)
     * 
     * The file is not loaded into memory - streaming I/O is used.
     * 
     * @param file_path Path to file
     * @param content_type Content type string
     * @return COSE_Sign1 message bytes
     * @throws FactoryError on failure
     */
    std::vector<uint8_t> SignIndirectFile(
        const std::string& file_path,
        const std::string& content_type) const
    {
        uint8_t* out = nullptr;
        uint32_t out_len = 0;
        CoseSign1FactoriesErrorHandle* err = nullptr;
        
        int status = cose_sign1_factories_sign_indirect_file(
            handle_, file_path.c_str(), content_type.c_str(),
            &out, &out_len, &err);
        
        cose::detail::ThrowIfNotOkFactory(status, err);
        
        std::vector<uint8_t> result(out, out + out_len);
        cose_sign1_factories_bytes_free(out, out_len);
        return result;
    }

    /**
     * @brief Signs a streaming payload with indirect signature
     * 
     * @param read_callback Callback to read payload data (returns bytes read, 0=EOF)
     * @param total_len Total length of the payload
     * @param content_type Content type string
     * @return COSE_Sign1 message bytes
     * @throws FactoryError on failure
     */
    std::vector<uint8_t> SignIndirectStreaming(
        std::function<size_t(uint8_t*, size_t)> read_callback,
        uint64_t total_len,
        const std::string& content_type) const
    {
        uint8_t* out = nullptr;
        uint32_t out_len = 0;
        CoseSign1FactoriesErrorHandle* err = nullptr;
        
        int status = cose_sign1_factories_sign_indirect_streaming(
            handle_,
            cose::detail::StreamTrampoline,
            &read_callback,
            total_len,
            content_type.c_str(),
            &out, &out_len, &err);
        
        cose::detail::ThrowIfNotOkFactory(status, err);
        
        std::vector<uint8_t> result(out, out + out_len);
        cose_sign1_factories_bytes_free(out, out_len);
        return result;
    }

private:
    explicit Factory(CoseSign1FactoriesHandle* h) : handle_(h) {}
    
    CoseSign1FactoriesHandle* handle_;
};

} // namespace cose::sign1

#endif // COSE_SIGN1_FACTORIES_HPP
