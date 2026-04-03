// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file signing.hpp
 * @brief C++ RAII wrappers for COSE Sign1 signing operations
 */

#ifndef COSE_SIGN1_SIGNING_HPP
#define COSE_SIGN1_SIGNING_HPP

#include <cose/sign1/signing.h>
#include <cose/cose.h>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>
#include <stdexcept>

#ifdef COSE_HAS_PRIMITIVES
#include <cose/sign1.hpp>
#endif

#ifdef COSE_HAS_CRYPTO_OPENSSL
#include <cose/crypto/openssl.hpp>
#endif

namespace cose {

/**
 * @brief Exception thrown by COSE signing operations
 */
class SigningError : public std::runtime_error {
public:
    explicit SigningError(int code, const std::string& msg) 
        : std::runtime_error(msg), error_code_(code) {}
    
    int code() const noexcept { return error_code_; }
    
private:
    int error_code_;
};

namespace detail {

inline void ThrowIfNotOkSigning(int status, cose_sign1_signing_error_t* error) {
    if (status != COSE_SIGN1_SIGNING_OK) {
        std::string msg;
        int code = status;
        if (error) {
            char* m = cose_sign1_signing_error_message(error);
            code = cose_sign1_signing_error_code(error);
            if (m) {
                msg = m;
                cose_sign1_string_free(m);
            }
            cose_sign1_signing_error_free(error);
        }
        if (msg.empty()) {
            msg = "Signing operation failed with status " + std::to_string(status);
        }
        throw SigningError(code, msg);
    }
    if (error) {
        cose_sign1_signing_error_free(error);
    }
}

/**
 * @brief Trampoline callback to bridge C++ std::function to C callback
 * 
 * @param buf Buffer to fill with payload data
 * @param len Size of the buffer
 * @param user_data Pointer to std::function<size_t(uint8_t*, size_t)>
 * @return Number of bytes read (0 = EOF, negative = error)
 */
inline int64_t stream_trampoline(uint8_t* buf, size_t len, void* user_data) {
    auto* fn = static_cast<std::function<size_t(uint8_t*, size_t)>*>(user_data);
    return static_cast<int64_t>((*fn)(buf, len));
}

} // namespace detail

/**
 * @brief RAII wrapper for header map
 */
class HeaderMap {
public:
    /**
     * @brief Create a new empty header map
     */
    static HeaderMap New() {
        cose_headermap_t* h = nullptr;
        int status = cose_headermap_new(&h);
        if (status != COSE_SIGN1_SIGNING_OK || !h) {
            throw SigningError(status, "Failed to create header map");
        }
        return HeaderMap(h);
    }
    
    ~HeaderMap() {
        if (handle_) {
            cose_headermap_free(handle_);
        }
    }
    
    // Non-copyable
    HeaderMap(const HeaderMap&) = delete;
    HeaderMap& operator=(const HeaderMap&) = delete;
    
    // Movable
    HeaderMap(HeaderMap&& other) noexcept : handle_(other.handle_) {
        other.handle_ = nullptr;
    }
    
    HeaderMap& operator=(HeaderMap&& other) noexcept {
        if (this != &other) {
            if (handle_) {
                cose_headermap_free(handle_);
            }
            handle_ = other.handle_;
            other.handle_ = nullptr;
        }
        return *this;
    }
    
    /**
     * @brief Set an integer value in the header map
     * @param label Integer label
     * @param value Integer value
     * @return Reference to this for method chaining
     */
    HeaderMap& SetInt(int64_t label, int64_t value) {
        int status = cose_headermap_set_int(handle_, label, value);
        if (status != COSE_SIGN1_SIGNING_OK) {
            throw SigningError(status, "Failed to set int header");
        }
        return *this;
    }
    
    /**
     * @brief Set a byte string value in the header map
     * @param label Integer label
     * @param data Byte data
     * @param len Length of data
     * @return Reference to this for method chaining
     */
    HeaderMap& SetBytes(int64_t label, const uint8_t* data, size_t len) {
        int status = cose_headermap_set_bytes(handle_, label, data, len);
        if (status != COSE_SIGN1_SIGNING_OK) {
            throw SigningError(status, "Failed to set bytes header");
        }
        return *this;
    }
    
    /**
     * @brief Set a text string value in the header map
     * @param label Integer label
     * @param text Null-terminated text string
     * @return Reference to this for method chaining
     */
    HeaderMap& SetText(int64_t label, const char* text) {
        int status = cose_headermap_set_text(handle_, label, text);
        if (status != COSE_SIGN1_SIGNING_OK) {
            throw SigningError(status, "Failed to set text header");
        }
        return *this;
    }
    
    /**
     * @brief Get the number of headers in the map
     * @return Number of headers
     */
    size_t Len() const {
        return cose_headermap_len(handle_);
    }
    
    /**
     * @brief Get the native handle
     * @return Native C handle
     */
    const cose_headermap_t* native_handle() const {
        return handle_;
    }

    /**
     * @brief Release ownership of the native handle.
     *
     * Returns the raw handle and relinquishes ownership. The caller is
     * responsible for the handle's lifetime after this call. Used by
     * ConsumeProtected() / ConsumeUnprotected() to transfer ownership
     * into the builder without copying.
     *
     * @return Raw C handle (caller owns)
     */
    cose_headermap_t* release() {
        cose_headermap_t* h = handle_;
        handle_ = nullptr;
        return h;
    }
    
private:
    explicit HeaderMap(cose_headermap_t* h) : handle_(h) {}
    cose_headermap_t* handle_;
};

/**
 * @brief RAII wrapper for signing key
 */
class CoseKey {
public:
    /**
     * @brief Create a key from a signing callback
     * @param algorithm COSE algorithm identifier (e.g., -7 for ES256)
     * @param key_type Key type string (e.g., "EC2", "OKP")
     * @param sign_fn Signing callback function
     * @param user_data User-provided context pointer
     * @return CoseKey instance
     */
    static CoseKey FromCallback(
        int64_t algorithm,
        const char* key_type,
        cose_sign1_sign_callback_t sign_fn,
        void* user_data
    ) {
        cose_key_t* k = nullptr;
        int status = cose_key_from_callback(algorithm, key_type, sign_fn, user_data, &k);
        if (status != COSE_SIGN1_SIGNING_OK || !k) {
            throw SigningError(status, "Failed to create key from callback");
        }
        return CoseKey(k);
    }
    
    /**
     * @brief Create a key from a DER-encoded X.509 certificate's public key
     * 
     * The returned key can be used for verification operations.
     * Requires the certificates FFI library to be linked.
     * 
     * @param cert_der DER-encoded X.509 certificate bytes
     * @return CoseKey instance
     */
    static CoseKey FromCertificateDer(const std::vector<uint8_t>& cert_der);
    
    ~CoseKey() {
        if (handle_) {
            cose_key_free(handle_);
        }
    }
    
    // Non-copyable
    CoseKey(const CoseKey&) = delete;
    CoseKey& operator=(const CoseKey&) = delete;
    
    // Movable
    CoseKey(CoseKey&& other) noexcept : handle_(other.handle_) {
        other.handle_ = nullptr;
    }
    
    CoseKey& operator=(CoseKey&& other) noexcept {
        if (this != &other) {
            if (handle_) {
                cose_key_free(handle_);
            }
            handle_ = other.handle_;
            other.handle_ = nullptr;
        }
        return *this;
    }
    
    /**
     * @brief Create a CoseKey from a raw handle (takes ownership)
     * 
     * Used by extension pack wrappers that obtain a raw cose_key_t handle
     * from C FFI functions.
     * 
     * @param k Raw key handle (ownership transferred)
     * @return CoseKey instance
     */
    static CoseKey FromRawHandle(cose_key_t* k) {
        if (!k) {
            throw SigningError(0, "Null key handle");
        }
        return CoseKey(k);
    }

    /**
     * @brief Get the native handle
     * @return Native C handle
     */
    const cose_key_t* native_handle() const {
        return handle_;
    }
    
private:
    explicit CoseKey(cose_key_t* k) : handle_(k) {}
    cose_key_t* handle_;
};

} // namespace cose

namespace cose::sign1 {

/**
 * @brief RAII wrapper for CoseSign1 message builder
 */
class CoseSign1Builder {
public:
    /**
     * @brief Create a new builder
     */
    static CoseSign1Builder New() {
        cose_sign1_builder_t* b = nullptr;
        int status = cose_sign1_builder_new(&b);
        if (status != COSE_SIGN1_SIGNING_OK || !b) {
            throw cose::SigningError(status, "Failed to create builder");
        }
        return CoseSign1Builder(b);
    }
    
    ~CoseSign1Builder() {
        if (handle_) {
            cose_sign1_builder_free(handle_);
        }
    }
    
    // Non-copyable
    CoseSign1Builder(const CoseSign1Builder&) = delete;
    CoseSign1Builder& operator=(const CoseSign1Builder&) = delete;
    
    // Movable
    CoseSign1Builder(CoseSign1Builder&& other) noexcept : handle_(other.handle_) {
        other.handle_ = nullptr;
    }
    
    CoseSign1Builder& operator=(CoseSign1Builder&& other) noexcept {
        if (this != &other) {
            if (handle_) {
                cose_sign1_builder_free(handle_);
            }
            handle_ = other.handle_;
            other.handle_ = nullptr;
        }
        return *this;
    }
    
    /**
     * @brief Set whether the builder produces tagged output
     * @param tagged True for tagged COSE_Sign1, false for untagged
     * @return Reference to this for method chaining
     */
    CoseSign1Builder& SetTagged(bool tagged) {
        int status = cose_sign1_builder_set_tagged(handle_, tagged);
        if (status != COSE_SIGN1_SIGNING_OK) {
            throw cose::SigningError(status, "Failed to set tagged");
        }
        return *this;
    }
    
    /**
     * @brief Set whether the builder produces detached payload
     * @param detached True for detached payload, false for embedded
     * @return Reference to this for method chaining
     */
    CoseSign1Builder& SetDetached(bool detached) {
        int status = cose_sign1_builder_set_detached(handle_, detached);
        if (status != COSE_SIGN1_SIGNING_OK) {
            throw cose::SigningError(status, "Failed to set detached");
        }
        return *this;
    }
    
    /**
     * @brief Set the protected headers
     * @param headers Header map (copied, not consumed)
     * @return Reference to this for method chaining
     * @see ConsumeProtected() for zero-copy alternative that moves instead of copying
     */
    CoseSign1Builder& SetProtected(const HeaderMap& headers) {
        int status = cose_sign1_builder_set_protected(handle_, headers.native_handle());
        if (status != COSE_SIGN1_SIGNING_OK) {
            throw cose::SigningError(status, "Failed to set protected headers");
        }
        return *this;
    }

    /**
     * @brief Set the protected headers by consuming (moving) the header map.
     *
     * Zero-copy alternative to SetProtected(). The header map is moved into the
     * builder and must NOT be used after this call.
     *
     * @param headers Header map (consumed — moved, not copied)
     * @return Reference to this for method chaining
     */
    CoseSign1Builder& ConsumeProtected(HeaderMap&& headers) {
        int status = cose_sign1_builder_consume_protected(handle_, headers.release());
        if (status != COSE_SIGN1_SIGNING_OK) {
            throw cose::SigningError(status, "Failed to consume protected headers");
        }
        return *this;
    }
    
    /**
     * @brief Set the unprotected headers
     * @param headers Header map (copied, not consumed)
     * @return Reference to this for method chaining
     * @see ConsumeUnprotected() for zero-copy alternative that moves instead of copying
     */
    CoseSign1Builder& SetUnprotected(const HeaderMap& headers) {
        int status = cose_sign1_builder_set_unprotected(handle_, headers.native_handle());
        if (status != COSE_SIGN1_SIGNING_OK) {
            throw cose::SigningError(status, "Failed to set unprotected headers");
        }
        return *this;
    }

    /**
     * @brief Set the unprotected headers by consuming (moving) the header map.
     *
     * Zero-copy alternative to SetUnprotected(). The header map is moved into the
     * builder and must NOT be used after this call.
     *
     * @param headers Header map (consumed — moved, not copied)
     * @return Reference to this for method chaining
     */
    CoseSign1Builder& ConsumeUnprotected(HeaderMap&& headers) {
        int status = cose_sign1_builder_consume_unprotected(handle_, headers.release());
        if (status != COSE_SIGN1_SIGNING_OK) {
            throw cose::SigningError(status, "Failed to consume unprotected headers");
        }
        return *this;
    }
    
    /**
     * @brief Set the external AAD
     * @param data AAD bytes
     * @param len Length of AAD
     * @return Reference to this for method chaining
     */
    CoseSign1Builder& SetExternalAad(const uint8_t* data, size_t len) {
        int status = cose_sign1_builder_set_external_aad(handle_, data, len);
        if (status != COSE_SIGN1_SIGNING_OK) {
            throw cose::SigningError(status, "Failed to set external AAD");
        }
        return *this;
    }
    
    /**
     * @brief Sign the payload and produce a COSE Sign1 message
     * 
     * The builder is consumed by this call and must not be used afterwards.
     * Returns a CoseSign1Message RAII wrapper; access bytes via Payload(),
     * ProtectedBytes(), Signature() without additional copies.
     * 
     * @param key Signing key
     * @param payload Payload bytes
     * @param len Length of payload
     * @return CoseSign1Message wrapping the signed message
     */
    CoseSign1Message Sign(const CoseKey& key, const uint8_t* payload, size_t len) {
        if (!handle_) {
            throw cose::SigningError(COSE_SIGN1_SIGNING_ERR_INVALID_ARG, "Builder already consumed");
        }
        
        CoseSign1MessageHandle* out_msg = nullptr;
        cose_sign1_signing_error_t* err = nullptr;
        
        int status = cose_sign1_builder_sign_to_message(
            handle_,
            key.native_handle(),
            payload,
            len,
            &out_msg,
            &err
        );
        
        // Builder is consumed regardless of success or failure
        handle_ = nullptr;
        
        cose::detail::ThrowIfNotOkSigning(status, err);
        
        return CoseSign1Message(out_msg);
    }

    /**
     * @brief Sign and return raw bytes (backward-compatible convenience overload)
     * 
     * Prefer Sign() which returns a CoseSign1Message for zero-copy access.
     * 
     * @param key Signing key
     * @param payload Payload bytes
     * @param len Length of payload
     * @return COSE Sign1 message bytes
     */
    std::vector<uint8_t> SignToBytes(const CoseKey& key, const uint8_t* payload, size_t len) {
        if (!handle_) {
            throw cose::SigningError(COSE_SIGN1_SIGNING_ERR_INVALID_ARG, "Builder already consumed");
        }
        
        uint8_t* out = nullptr;
        size_t out_len = 0;
        cose_sign1_signing_error_t* err = nullptr;
        
        int status = cose_sign1_builder_sign(
            handle_,
            key.native_handle(),
            payload,
            len,
            &out,
            &out_len,
            &err
        );
        
        // Builder is consumed regardless of success or failure
        handle_ = nullptr;
        
        cose::detail::ThrowIfNotOkSigning(status, err);
        
        std::vector<uint8_t> result(out, out + out_len);
        cose_sign1_bytes_free(out, out_len);
        return result;
    }
    
    /**
     * @brief Get the native handle
     * @return Native C handle
     */
    cose_sign1_builder_t* native_handle() const {
        return handle_;
    }
    
private:
    explicit CoseSign1Builder(cose_sign1_builder_t* b) : handle_(b) {}
    cose_sign1_builder_t* handle_;
};

/**
 * @brief RAII wrapper for signing service
 */
class SigningService {
public:
    /**
     * @brief Create a signing service from a key
     * @param key Signing key
     * @return SigningService instance
     */
    static SigningService Create(const CoseKey& key) {
        cose_sign1_signing_service_t* s = nullptr;
        cose_sign1_signing_error_t* err = nullptr;
        
        int status = cose_sign1_signing_service_create(key.native_handle(), &s, &err);
        cose::detail::ThrowIfNotOkSigning(status, err);
        
        if (!s) {
            throw cose::SigningError(status, "Failed to create signing service");
        }
        
        return SigningService(s);
    }
    
#ifdef COSE_HAS_CRYPTO_OPENSSL
    /**
     * @brief Create signing service directly from a CryptoSigner (no callback needed)
     * 
     * This eliminates the need for manual callback bridging. The signer handle is
     * consumed by this call and must not be used afterwards.
     * 
     * Requires COSE_HAS_CRYPTO_OPENSSL to be defined.
     * 
     * @param signer Crypto signer handle (ownership transferred)
     * @return SigningService instance
     */
    static SigningService FromCryptoSigner(CryptoSignerHandle& signer) {
        cose_sign1_signing_service_t* s = nullptr;
        cose_sign1_signing_error_t* err = nullptr;
        
        int status = cose_sign1_signing_service_from_crypto_signer(
            signer.native_handle(), &s, &err);
        
        // Ownership of signer was transferred - prevent double free
        signer.release();
        
        cose::detail::ThrowIfNotOkSigning(status, err);
        
        if (!s) {
            throw cose::SigningError(status, "Failed to create signing service from crypto signer");
        }
        
        return SigningService(s);
    }
#endif
    
    ~SigningService() {
        if (handle_) {
            cose_sign1_signing_service_free(handle_);
        }
    }
    
    // Non-copyable
    SigningService(const SigningService&) = delete;
    SigningService& operator=(const SigningService&) = delete;
    
    // Movable
    SigningService(SigningService&& other) noexcept : handle_(other.handle_) {
        other.handle_ = nullptr;
    }
    
    SigningService& operator=(SigningService&& other) noexcept {
        if (this != &other) {
            if (handle_) {
                cose_sign1_signing_service_free(handle_);
            }
            handle_ = other.handle_;
            other.handle_ = nullptr;
        }
        return *this;
    }
    
    /**
     * @brief Get the native handle
     * @return Native C handle
     */
    const cose_sign1_signing_service_t* native_handle() const {
        return handle_;
    }
    
private:
    explicit SigningService(cose_sign1_signing_service_t* s) : handle_(s) {}
    cose_sign1_signing_service_t* handle_;
};

/**
 * @brief RAII wrapper for signature factory
 */
class SignatureFactory {
public:
    /**
     * @brief Create a factory from a signing service
     * @param service Signing service
     * @return SignatureFactory instance
     */
    static SignatureFactory Create(const SigningService& service) {
        cose_sign1_factory_t* f = nullptr;
        cose_sign1_signing_error_t* err = nullptr;
        
        int status = cose_sign1_factory_create(service.native_handle(), &f, &err);
        cose::detail::ThrowIfNotOkSigning(status, err);
        
        if (!f) {
            throw cose::SigningError(status, "Failed to create signature factory");
        }
        
        return SignatureFactory(f);
    }
    
#ifdef COSE_HAS_CRYPTO_OPENSSL
    /**
     * @brief Create factory directly from a CryptoSigner (simplest path)
     * 
     * This is the most convenient method for creating a factory - it combines
     * creating a signing service and factory in a single call, eliminating the
     * need for manual callback bridging. The signer handle is consumed by this
     * call and must not be used afterwards.
     * 
     * Requires COSE_HAS_CRYPTO_OPENSSL to be defined.
     * 
     * @param signer Crypto signer handle (ownership transferred)
     * @return SignatureFactory instance
     */
    static SignatureFactory FromCryptoSigner(CryptoSignerHandle& signer) {
        cose_sign1_factory_t* f = nullptr;
        cose_sign1_signing_error_t* err = nullptr;
        
        int status = cose_sign1_factory_from_crypto_signer(
            signer.native_handle(), &f, &err);
        
        // Ownership of signer was transferred - prevent double free
        signer.release();
        
        cose::detail::ThrowIfNotOkSigning(status, err);
        
        if (!f) {
            throw cose::SigningError(status, "Failed to create factory from crypto signer");
        }
        
        return SignatureFactory(f);
    }
#endif
    
    ~SignatureFactory() {
        if (handle_) {
            cose_sign1_factory_free(handle_);
        }
    }
    
    // Non-copyable
    SignatureFactory(const SignatureFactory&) = delete;
    SignatureFactory& operator=(const SignatureFactory&) = delete;
    
    // Movable
    SignatureFactory(SignatureFactory&& other) noexcept : handle_(other.handle_) {
        other.handle_ = nullptr;
    }
    
    SignatureFactory& operator=(SignatureFactory&& other) noexcept {
        if (this != &other) {
            if (handle_) {
                cose_sign1_factory_free(handle_);
            }
            handle_ = other.handle_;
            other.handle_ = nullptr;
        }
        return *this;
    }

#ifdef COSE_HAS_PRIMITIVES
    /**
     * @brief Sign payload with direct signature (embedded payload) and return a message handle
     *
     * Access message components via Payload(), ProtectedBytes(), Signature()
     * without additional memory copies.
     *
     * @param payload Payload bytes
     * @param len Length of payload
     * @param content_type Content type string
     * @return CoseSign1Message wrapping the signed message
     */
    CoseSign1Message SignDirectToMessage(const uint8_t* payload, uint32_t len, const char* content_type) {
        uint8_t* out = nullptr;
        uint32_t out_len = 0;
        cose_sign1_signing_error_t* err = nullptr;
        
        int status = cose_sign1_factory_sign_direct(
            handle_,
            payload,
            len,
            content_type,
            &out,
            &out_len,
            &err
        );
        
        cose::detail::ThrowIfNotOkSigning(status, err);
        
        CoseSign1Message msg = CoseSign1Message::Parse(out, out_len);
        cose_sign1_cose_bytes_free(out, out_len);
        return msg;
    }
#endif

    /**
     * @brief Sign payload with direct signature (embedded payload) and return bytes
     * @param payload Payload bytes
     * @param len Length of payload
     * @param content_type Content type string
     * @return COSE Sign1 message bytes
     */
    std::vector<uint8_t> SignDirectBytes(const uint8_t* payload, uint32_t len, const char* content_type) {
        uint8_t* out = nullptr;
        uint32_t out_len = 0;
        cose_sign1_signing_error_t* err = nullptr;
        
        int status = cose_sign1_factory_sign_direct(
            handle_,
            payload,
            len,
            content_type,
            &out,
            &out_len,
            &err
        );
        
        cose::detail::ThrowIfNotOkSigning(status, err);
        
        std::vector<uint8_t> result(out, out + out_len);
        cose_sign1_cose_bytes_free(out, out_len);
        return result;
    }
    
#ifdef COSE_HAS_PRIMITIVES
    /**
     * @brief Sign payload with indirect signature (hash envelope) and return a message handle
     *
     * Access message components via Payload(), ProtectedBytes(), Signature()
     * without additional memory copies.
     *
     * @param payload Payload bytes
     * @param len Length of payload
     * @param content_type Content type string
     * @return CoseSign1Message wrapping the signed message
     */
    CoseSign1Message SignIndirectToMessage(const uint8_t* payload, uint32_t len, const char* content_type) {
        uint8_t* out = nullptr;
        uint32_t out_len = 0;
        cose_sign1_signing_error_t* err = nullptr;
        
        int status = cose_sign1_factory_sign_indirect(
            handle_,
            payload,
            len,
            content_type,
            &out,
            &out_len,
            &err
        );
        
        cose::detail::ThrowIfNotOkSigning(status, err);
        
        CoseSign1Message msg = CoseSign1Message::Parse(out, out_len);
        cose_sign1_cose_bytes_free(out, out_len);
        return msg;
    }
#endif

    /**
     * @brief Sign payload with indirect signature (hash envelope) and return bytes
     * @param payload Payload bytes
     * @param len Length of payload
     * @param content_type Content type string
     * @return COSE Sign1 message bytes
     */
    std::vector<uint8_t> SignIndirectBytes(const uint8_t* payload, uint32_t len, const char* content_type) {
        uint8_t* out = nullptr;
        uint32_t out_len = 0;
        cose_sign1_signing_error_t* err = nullptr;
        
        int status = cose_sign1_factory_sign_indirect(
            handle_,
            payload,
            len,
            content_type,
            &out,
            &out_len,
            &err
        );
        
        cose::detail::ThrowIfNotOkSigning(status, err);
        
        std::vector<uint8_t> result(out, out + out_len);
        cose_sign1_cose_bytes_free(out, out_len);
        return result;
    }
    
#ifdef COSE_HAS_PRIMITIVES
    /**
     * @brief Sign a file directly without loading into memory (streaming, detached)
     * and return a message handle
     * 
     * @param file_path Path to file to sign
     * @param content_type Content type string
     * @return CoseSign1Message wrapping the signed message
     */
    CoseSign1Message SignDirectFileToMessage(const std::string& file_path, const std::string& content_type) {
        uint8_t* out = nullptr;
        uint32_t out_len = 0;
        cose_sign1_signing_error_t* err = nullptr;
        
        int status = cose_sign1_factory_sign_direct_file(
            handle_,
            file_path.c_str(),
            content_type.c_str(),
            &out,
            &out_len,
            &err
        );
        
        cose::detail::ThrowIfNotOkSigning(status, err);
        
        CoseSign1Message msg = CoseSign1Message::Parse(out, out_len);
        cose_sign1_cose_bytes_free(out, out_len);
        return msg;
    }
#endif

    /**
     * @brief Sign a file directly without loading into memory (streaming, detached signature)
     * 
     * The file is never fully loaded into memory. Creates a detached COSE_Sign1 signature.
     * 
     * @param file_path Path to file to sign
     * @param content_type Content type string
     * @return COSE Sign1 message bytes
     */
    std::vector<uint8_t> SignDirectFile(const std::string& file_path, const std::string& content_type) {
        uint8_t* out = nullptr;
        uint32_t out_len = 0;
        cose_sign1_signing_error_t* err = nullptr;
        
        int status = cose_sign1_factory_sign_direct_file(
            handle_,
            file_path.c_str(),
            content_type.c_str(),
            &out,
            &out_len,
            &err
        );
        
        cose::detail::ThrowIfNotOkSigning(status, err);
        
        std::vector<uint8_t> result(out, out + out_len);
        cose_sign1_cose_bytes_free(out, out_len);
        return result;
    }
    
#ifdef COSE_HAS_PRIMITIVES
    /**
     * @brief Sign with a streaming reader callback (direct signature, detached)
     * and return a message handle
     * 
     * @param reader Callback function that reads payload data
     * @param total_size Total size of the payload in bytes
     * @param content_type Content type string
     * @return CoseSign1Message wrapping the signed message
     */
    CoseSign1Message SignDirectStreamingToMessage(
        std::function<size_t(uint8_t*, size_t)> reader,
        uint64_t total_size,
        const std::string& content_type
    ) {
        uint8_t* out = nullptr;
        uint32_t out_len = 0;
        cose_sign1_signing_error_t* err = nullptr;
        
        int status = cose_sign1_factory_sign_direct_streaming(
            handle_,
            cose::detail::stream_trampoline,
            total_size,
            &reader,
            content_type.c_str(),
            &out,
            &out_len,
            &err
        );
        
        cose::detail::ThrowIfNotOkSigning(status, err);
        
        CoseSign1Message msg = CoseSign1Message::Parse(out, out_len);
        cose_sign1_cose_bytes_free(out, out_len);
        return msg;
    }
#endif

    /**
     * @brief Sign with a streaming reader callback (direct signature, detached)
     * 
     * The reader callback is invoked repeatedly to read payload chunks.
     * Creates a detached COSE_Sign1 signature.
     * 
     * @param reader Callback function that reads payload data: size_t reader(uint8_t* buf, size_t len)
     * @param total_size Total size of the payload in bytes
     * @param content_type Content type string
     * @return COSE Sign1 message bytes
     */
    std::vector<uint8_t> SignDirectStreaming(
        std::function<size_t(uint8_t*, size_t)> reader,
        uint64_t total_size,
        const std::string& content_type
    ) {
        uint8_t* out = nullptr;
        uint32_t out_len = 0;
        cose_sign1_signing_error_t* err = nullptr;
        
        int status = cose_sign1_factory_sign_direct_streaming(
            handle_,
            cose::detail::stream_trampoline,
            total_size,
            &reader,
            content_type.c_str(),
            &out,
            &out_len,
            &err
        );
        
        cose::detail::ThrowIfNotOkSigning(status, err);
        
        std::vector<uint8_t> result(out, out + out_len);
        cose_sign1_cose_bytes_free(out, out_len);
        return result;
    }
    
#ifdef COSE_HAS_PRIMITIVES
    /**
     * @brief Sign a file with indirect signature (hash envelope) without loading
     * into memory, and return a message handle
     * 
     * @param file_path Path to file to sign
     * @param content_type Content type string
     * @return CoseSign1Message wrapping the signed message
     */
    CoseSign1Message SignIndirectFileToMessage(const std::string& file_path, const std::string& content_type) {
        uint8_t* out = nullptr;
        uint32_t out_len = 0;
        cose_sign1_signing_error_t* err = nullptr;
        
        int status = cose_sign1_factory_sign_indirect_file(
            handle_,
            file_path.c_str(),
            content_type.c_str(),
            &out,
            &out_len,
            &err
        );
        
        cose::detail::ThrowIfNotOkSigning(status, err);
        
        CoseSign1Message msg = CoseSign1Message::Parse(out, out_len);
        cose_sign1_cose_bytes_free(out, out_len);
        return msg;
    }
#endif

    /**
     * @brief Sign a file with indirect signature (hash envelope) without loading into memory
     * 
     * The file is never fully loaded into memory. Creates a detached signature over the file hash.
     * 
     * @param file_path Path to file to sign
     * @param content_type Content type string
     * @return COSE Sign1 message bytes
     */
    std::vector<uint8_t> SignIndirectFile(const std::string& file_path, const std::string& content_type) {
        uint8_t* out = nullptr;
        uint32_t out_len = 0;
        cose_sign1_signing_error_t* err = nullptr;
        
        int status = cose_sign1_factory_sign_indirect_file(
            handle_,
            file_path.c_str(),
            content_type.c_str(),
            &out,
            &out_len,
            &err
        );
        
        cose::detail::ThrowIfNotOkSigning(status, err);
        
        std::vector<uint8_t> result(out, out + out_len);
        cose_sign1_cose_bytes_free(out, out_len);
        return result;
    }
    
#ifdef COSE_HAS_PRIMITIVES
    /**
     * @brief Sign with a streaming reader callback (indirect signature, detached)
     * and return a message handle
     * 
     * @param reader Callback function that reads payload data
     * @param total_size Total size of the payload in bytes
     * @param content_type Content type string
     * @return CoseSign1Message wrapping the signed message
     */
    CoseSign1Message SignIndirectStreamingToMessage(
        std::function<size_t(uint8_t*, size_t)> reader,
        uint64_t total_size,
        const std::string& content_type
    ) {
        uint8_t* out = nullptr;
        uint32_t out_len = 0;
        cose_sign1_signing_error_t* err = nullptr;
        
        int status = cose_sign1_factory_sign_indirect_streaming(
            handle_,
            cose::detail::stream_trampoline,
            total_size,
            &reader,
            content_type.c_str(),
            &out,
            &out_len,
            &err
        );
        
        cose::detail::ThrowIfNotOkSigning(status, err);
        
        CoseSign1Message msg = CoseSign1Message::Parse(out, out_len);
        cose_sign1_cose_bytes_free(out, out_len);
        return msg;
    }
#endif

    /**
     * @brief Sign with a streaming reader callback (indirect signature, detached)
     * 
     * The reader callback is invoked repeatedly to read payload chunks.
     * Creates a detached signature over the payload hash.
     * 
     * @param reader Callback function that reads payload data: size_t reader(uint8_t* buf, size_t len)
     * @param total_size Total size of the payload in bytes
     * @param content_type Content type string
     * @return COSE Sign1 message bytes
     */
    std::vector<uint8_t> SignIndirectStreaming(
        std::function<size_t(uint8_t*, size_t)> reader,
        uint64_t total_size,
        const std::string& content_type
    ) {
        uint8_t* out = nullptr;
        uint32_t out_len = 0;
        cose_sign1_signing_error_t* err = nullptr;
        
        int status = cose_sign1_factory_sign_indirect_streaming(
            handle_,
            cose::detail::stream_trampoline,
            total_size,
            &reader,
            content_type.c_str(),
            &out,
            &out_len,
            &err
        );
        
        cose::detail::ThrowIfNotOkSigning(status, err);
        
        std::vector<uint8_t> result(out, out + out_len);
        cose_sign1_cose_bytes_free(out, out_len);
        return result;
    }

#ifdef COSE_HAS_PRIMITIVES
    /**
     * @brief Sign payload with direct signature (embedded payload)
     * @param payload Payload bytes
     * @param len Length of payload
     * @param content_type Content type string
     * @return CoseSign1Message wrapping the signed message
     */
    CoseSign1Message SignDirect(const uint8_t* payload, uint32_t len, const char* content_type) {
        return SignDirectToMessage(payload, len, content_type);
    }

    /**
     * @brief Sign payload with indirect signature (hash envelope)
     * @param payload Payload bytes
     * @param len Length of payload
     * @param content_type Content type string
     * @return CoseSign1Message wrapping the signed message
     */
    CoseSign1Message SignIndirect(const uint8_t* payload, uint32_t len, const char* content_type) {
        return SignIndirectToMessage(payload, len, content_type);
    }
#endif
    
    /**
     * @brief Get the native handle
     * @return Native C handle
     */
    const cose_sign1_factory_t* native_handle() const {
        return handle_;
    }
    
private:
    explicit SignatureFactory(cose_sign1_factory_t* f) : handle_(f) {}
    cose_sign1_factory_t* handle_;
};

} // namespace cose::sign1

// ============================================================================
// Forward declaration for certificates FFI function (global namespace).
// Declared here so signing.hpp can provide CoseKey::FromCertificateDer()
// without requiring the caller to include the certificates extension header.
// ============================================================================
#ifdef COSE_HAS_CERTIFICATES_PACK
extern "C" cose_status_t cose_sign1_certificates_key_from_cert_der(
    const uint8_t* cert_der,
    size_t cert_der_len,
    cose_key_t** out_key
);
#endif

namespace cose {

#ifdef COSE_HAS_CERTIFICATES_PACK
inline CoseKey CoseKey::FromCertificateDer(const std::vector<uint8_t>& cert_der) {
    cose_key_t* k = nullptr;
    ::cose_status_t status = ::cose_sign1_certificates_key_from_cert_der(
        cert_der.data(),
        cert_der.size(),
        &k
    );
    if (status != ::COSE_OK || !k) {
        throw SigningError(static_cast<int>(status), "Failed to create key from certificate DER");
    }
    return CoseKey(k);
}
#endif

} // namespace cose

#endif // COSE_SIGN1_SIGNING_HPP
