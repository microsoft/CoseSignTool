// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file openssl.hpp
 * @brief C++ RAII wrappers for OpenSSL crypto provider
 */

#ifndef COSE_CRYPTO_OPENSSL_HPP
#define COSE_CRYPTO_OPENSSL_HPP

#include <cose/crypto/openssl.h>
#include <cose/sign1/validation.hpp>
#include <vector>
#include <string>
#include <stdexcept>
#include <utility>

namespace cose {

// Forward declarations
class CryptoSignerHandle;
class CryptoVerifierHandle;

/**
 * @brief RAII wrapper for OpenSSL crypto provider
 */
class CryptoProvider {
public:
    /**
     * @brief Create a new OpenSSL crypto provider instance
     */
    static CryptoProvider New() {
        cose_crypto_provider_t* handle = nullptr;
        detail::ThrowIfNotOk(cose_crypto_openssl_provider_new(&handle));
        if (!handle) {
            throw cose_error("Failed to create crypto provider");
        }
        return CryptoProvider(handle);
    }
    
    ~CryptoProvider() {
        if (handle_) {
            cose_crypto_openssl_provider_free(handle_);
        }
    }
    
    // Non-copyable
    CryptoProvider(const CryptoProvider&) = delete;
    CryptoProvider& operator=(const CryptoProvider&) = delete;
    
    // Movable
    CryptoProvider(CryptoProvider&& other) noexcept 
        : handle_(std::exchange(other.handle_, nullptr)) {}
    
    CryptoProvider& operator=(CryptoProvider&& other) noexcept {
        if (this != &other) {
            if (handle_) {
                cose_crypto_openssl_provider_free(handle_);
            }
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }
    
    /**
     * @brief Create a signer from a DER-encoded private key
     * @param private_key_der DER-encoded private key bytes
     * @return CryptoSignerHandle for signing operations
     */
    CryptoSignerHandle SignerFromDer(const std::vector<uint8_t>& private_key_der) const;
    
    /**
     * @brief Create a verifier from a DER-encoded public key
     * @param public_key_der DER-encoded public key bytes
     * @return CryptoVerifierHandle for verification operations
     */
    CryptoVerifierHandle VerifierFromDer(const std::vector<uint8_t>& public_key_der) const;
    
    /**
     * @brief Get native handle for C API interop
     */
    cose_crypto_provider_t* native_handle() const { return handle_; }
    
private:
    explicit CryptoProvider(cose_crypto_provider_t* h) : handle_(h) {}
    cose_crypto_provider_t* handle_;
};

/**
 * @brief RAII wrapper for crypto signer handle
 */
class CryptoSignerHandle {
public:
    ~CryptoSignerHandle() {
        if (handle_) {
            cose_crypto_signer_free(handle_);
        }
    }
    
    // Non-copyable
    CryptoSignerHandle(const CryptoSignerHandle&) = delete;
    CryptoSignerHandle& operator=(const CryptoSignerHandle&) = delete;
    
    // Movable
    CryptoSignerHandle(CryptoSignerHandle&& other) noexcept 
        : handle_(std::exchange(other.handle_, nullptr)) {}
    
    CryptoSignerHandle& operator=(CryptoSignerHandle&& other) noexcept {
        if (this != &other) {
            if (handle_) {
                cose_crypto_signer_free(handle_);
            }
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }
    
    /**
     * @brief Sign data using this signer
     * @param data Data to sign
     * @return Signature bytes
     */
    std::vector<uint8_t> Sign(const std::vector<uint8_t>& data) const {
        uint8_t* sig = nullptr;
        size_t sig_len = 0;
        
        cose_status_t status = cose_crypto_signer_sign(
            handle_,
            data.data(),
            data.size(),
            &sig,
            &sig_len
        );
        
        if (status != COSE_OK) {
            if (sig) cose_crypto_bytes_free(sig, sig_len);
            detail::ThrowIfNotOk(status);
        }
        
        std::vector<uint8_t> result;
        if (sig && sig_len > 0) {
            result.assign(sig, sig + sig_len);
            cose_crypto_bytes_free(sig, sig_len);
        }
        
        return result;
    }
    
    /**
     * @brief Get the COSE algorithm identifier for this signer
     * @return COSE algorithm identifier
     */
    int64_t Algorithm() const {
        return cose_crypto_signer_algorithm(handle_);
    }
    
    /**
     * @brief Get native handle for C API interop
     */
    cose_crypto_signer_t* native_handle() const { return handle_; }
    
    /**
     * @brief Release ownership of the handle without freeing
     * Used when transferring ownership to another object
     */
    void release() { handle_ = nullptr; }
    
private:
    friend class CryptoProvider;
    explicit CryptoSignerHandle(cose_crypto_signer_t* h) : handle_(h) {}
    cose_crypto_signer_t* handle_;
};

/**
 * @brief RAII wrapper for crypto verifier handle
 */
class CryptoVerifierHandle {
public:
    ~CryptoVerifierHandle() {
        if (handle_) {
            cose_crypto_verifier_free(handle_);
        }
    }
    
    // Non-copyable
    CryptoVerifierHandle(const CryptoVerifierHandle&) = delete;
    CryptoVerifierHandle& operator=(const CryptoVerifierHandle&) = delete;
    
    // Movable
    CryptoVerifierHandle(CryptoVerifierHandle&& other) noexcept 
        : handle_(std::exchange(other.handle_, nullptr)) {}
    
    CryptoVerifierHandle& operator=(CryptoVerifierHandle&& other) noexcept {
        if (this != &other) {
            if (handle_) {
                cose_crypto_verifier_free(handle_);
            }
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }
    
    /**
     * @brief Verify a signature using this verifier
     * @param data Data that was signed
     * @param signature Signature bytes
     * @return true if signature is valid, false otherwise
     */
    bool Verify(const std::vector<uint8_t>& data, const std::vector<uint8_t>& signature) const {
        bool valid = false;
        
        cose_status_t status = cose_crypto_verifier_verify(
            handle_,
            data.data(),
            data.size(),
            signature.data(),
            signature.size(),
            &valid
        );
        
        detail::ThrowIfNotOk(status);
        return valid;
    }
    
    /**
     * @brief Get native handle for C API interop
     */
    cose_crypto_verifier_t* native_handle() const { return handle_; }
    
private:
    friend class CryptoProvider;
    explicit CryptoVerifierHandle(cose_crypto_verifier_t* h) : handle_(h) {}
    cose_crypto_verifier_t* handle_;
};

// CryptoProvider method implementations

inline CryptoSignerHandle CryptoProvider::SignerFromDer(const std::vector<uint8_t>& private_key_der) const {
    cose_crypto_signer_t* signer = nullptr;
    detail::ThrowIfNotOk(cose_crypto_openssl_signer_from_der(
        handle_,
        private_key_der.data(),
        private_key_der.size(),
        &signer
    ));
    if (!signer) {
        throw cose_error("Failed to create signer from DER");
    }
    return CryptoSignerHandle(signer);
}

inline CryptoVerifierHandle CryptoProvider::VerifierFromDer(const std::vector<uint8_t>& public_key_der) const {
    cose_crypto_verifier_t* verifier = nullptr;
    detail::ThrowIfNotOk(cose_crypto_openssl_verifier_from_der(
        handle_,
        public_key_der.data(),
        public_key_der.size(),
        &verifier
    ));
    if (!verifier) {
        throw cose_error("Failed to create verifier from DER");
    }
    return CryptoVerifierHandle(verifier);
}

} // namespace cose

#endif // COSE_CRYPTO_OPENSSL_HPP
