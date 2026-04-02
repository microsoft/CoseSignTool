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

#ifdef COSE_HAS_PRIMITIVES
#include <cose/sign1.hpp>
#endif

#ifdef COSE_HAS_CRYPTO_OPENSSL
#include <cose/crypto/openssl.hpp>
#endif

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
     * @param signer Crypto signer handle (ownership transferred)
     * @return Factory instance
     * @throws FactoryError on failure
     */
#ifdef COSE_HAS_CRYPTO_OPENSSL
    static Factory FromCryptoSigner(cose::CryptoSignerHandle& signer) {
        CoseSign1FactoriesHandle* h = nullptr;
        CoseSign1FactoriesErrorHandle* err = nullptr;
        // Cast between equivalent opaque handle types from different FFI crates
        auto* raw = reinterpret_cast<::CryptoSignerHandle*>(signer.native_handle());
        int status = cose_sign1_factories_create_from_crypto_signer(raw, &h, &err);
        signer.release();
        cose::detail::ThrowIfNotOkFactory(status, err);
        return Factory(h);
    }
#endif

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

#ifdef COSE_HAS_PRIMITIVES
    /**
     * @brief Signs payload with direct signature (embedded payload) and returns a message handle
     *
     * @param payload Payload bytes
     * @param content_type Content type string
     * @return CoseSign1Message wrapping the signed message
     * @throws FactoryError on failure
     */
    CoseSign1Message SignDirectToMessage(
        const std::vector<uint8_t>& payload,
        const std::string& content_type) const
    {
        return SignDirectToMessage(payload.data(), static_cast<uint32_t>(payload.size()), content_type);
    }

    /**
     * @brief Signs payload with direct signature (embedded payload) and returns a message handle
     *
     * @param payload Payload data pointer
     * @param payload_len Payload length
     * @param content_type Content type string
     * @return CoseSign1Message wrapping the signed message
     * @throws FactoryError on failure
     */
    CoseSign1Message SignDirectToMessage(
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
        
        CoseSign1Message msg = CoseSign1Message::Parse(out, out_len);
        cose_sign1_factories_bytes_free(out, out_len);
        return msg;
    }
#endif

    /**
     * @brief Signs payload with direct signature (embedded payload)
     * 
     * Returns a copy of the signed bytes as a vector. For zero-copy access
     * to the signed message, prefer SignDirectToMessage() which returns a
     * CoseSign1Message handle with borrowed ByteView accessors.
     * 
     * @param payload Payload bytes
     * @param content_type Content type string
     * @return COSE_Sign1 message bytes (caller-owned copy)
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
     * Returns a copy of the signed bytes as a vector. For zero-copy access
     * to the signed message, prefer SignDirectToMessage() which returns a
     * CoseSign1Message handle with borrowed ByteView accessors.
     * 
     * @param payload Payload data pointer
     * @param payload_len Payload length
     * @param content_type Content type string
     * @return COSE_Sign1 message bytes (caller-owned copy)
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

#ifdef COSE_HAS_PRIMITIVES
    /**
     * @brief Signs payload with direct signature in detached mode and returns a message handle
     *
     * @param payload Payload bytes
     * @param content_type Content type string
     * @return CoseSign1Message wrapping the signed message (without embedded payload)
     * @throws FactoryError on failure
     */
    CoseSign1Message SignDirectDetachedToMessage(
        const std::vector<uint8_t>& payload,
        const std::string& content_type) const
    {
        return SignDirectDetachedToMessage(payload.data(), static_cast<uint32_t>(payload.size()), content_type);
    }

    /**
     * @brief Signs payload with direct signature in detached mode and returns a message handle
     *
     * @param payload Payload data pointer
     * @param payload_len Payload length
     * @param content_type Content type string
     * @return CoseSign1Message wrapping the signed message (without embedded payload)
     * @throws FactoryError on failure
     */
    CoseSign1Message SignDirectDetachedToMessage(
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
        
        CoseSign1Message msg = CoseSign1Message::Parse(out, out_len);
        cose_sign1_factories_bytes_free(out, out_len);
        return msg;
    }
#endif

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

#ifdef COSE_HAS_PRIMITIVES
    /**
     * @brief Signs a file with direct signature (detached) and returns a message handle
     *
     * @param file_path Path to file
     * @param content_type Content type string
     * @return CoseSign1Message wrapping the signed message
     * @throws FactoryError on failure
     */
    CoseSign1Message SignDirectFileToMessage(
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
        
        CoseSign1Message msg = CoseSign1Message::Parse(out, out_len);
        cose_sign1_factories_bytes_free(out, out_len);
        return msg;
    }
#endif

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

#ifdef COSE_HAS_PRIMITIVES
    /**
     * @brief Signs a streaming payload with direct signature (detached) and returns a message handle
     *
     * @param read_callback Callback to read payload data (returns bytes read, 0=EOF)
     * @param total_len Total length of the payload
     * @param content_type Content type string
     * @return CoseSign1Message wrapping the signed message
     * @throws FactoryError on failure
     */
    CoseSign1Message SignDirectStreamingToMessage(
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
        
        CoseSign1Message msg = CoseSign1Message::Parse(out, out_len);
        cose_sign1_factories_bytes_free(out, out_len);
        return msg;
    }
#endif

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

#ifdef COSE_HAS_PRIMITIVES
    /**
     * @brief Signs payload with indirect signature (hash envelope) and returns a message handle
     *
     * @param payload Payload bytes
     * @param content_type Content type string
     * @return CoseSign1Message wrapping the signed message
     * @throws FactoryError on failure
     */
    CoseSign1Message SignIndirectToMessage(
        const std::vector<uint8_t>& payload,
        const std::string& content_type) const
    {
        return SignIndirectToMessage(payload.data(), static_cast<uint32_t>(payload.size()), content_type);
    }

    /**
     * @brief Signs payload with indirect signature (hash envelope) and returns a message handle
     *
     * @param payload Payload data pointer
     * @param payload_len Payload length
     * @param content_type Content type string
     * @return CoseSign1Message wrapping the signed message
     * @throws FactoryError on failure
     */
    CoseSign1Message SignIndirectToMessage(
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
        
        CoseSign1Message msg = CoseSign1Message::Parse(out, out_len);
        cose_sign1_factories_bytes_free(out, out_len);
        return msg;
    }
#endif

    /**
     * @brief Signs payload with indirect signature (hash envelope)
     * 
     * Returns a copy of the signed bytes as a vector. For zero-copy access,
     * prefer the ToMessage variants when available.
     * 
     * @param payload Payload bytes
     * @param content_type Content type string
     * @return COSE_Sign1 message bytes (caller-owned copy)
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
     * Returns a copy of the signed bytes as a vector. For zero-copy access,
     * prefer the ToMessage variants when available.
     * 
     * @param payload Payload data pointer
     * @param payload_len Payload length
     * @param content_type Content type string
     * @return COSE_Sign1 message bytes (caller-owned copy)
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

#ifdef COSE_HAS_PRIMITIVES
    /**
     * @brief Signs a file with indirect signature (hash envelope) and returns a message handle
     *
     * @param file_path Path to file
     * @param content_type Content type string
     * @return CoseSign1Message wrapping the signed message
     * @throws FactoryError on failure
     */
    CoseSign1Message SignIndirectFileToMessage(
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
        
        CoseSign1Message msg = CoseSign1Message::Parse(out, out_len);
        cose_sign1_factories_bytes_free(out, out_len);
        return msg;
    }
#endif

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

#ifdef COSE_HAS_PRIMITIVES
    /**
     * @brief Signs a streaming payload with indirect signature and returns a message handle
     *
     * @param read_callback Callback to read payload data (returns bytes read, 0=EOF)
     * @param total_len Total length of the payload
     * @param content_type Content type string
     * @return CoseSign1Message wrapping the signed message
     * @throws FactoryError on failure
     */
    CoseSign1Message SignIndirectStreamingToMessage(
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
        
        CoseSign1Message msg = CoseSign1Message::Parse(out, out_len);
        cose_sign1_factories_bytes_free(out, out_len);
        return msg;
    }
#endif

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
