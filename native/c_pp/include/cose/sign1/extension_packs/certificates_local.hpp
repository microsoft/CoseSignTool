// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file certificates_local.hpp
 * @brief C++ RAII wrappers for local certificate creation and loading
 */

#ifndef COSE_SIGN1_CERTIFICATES_LOCAL_HPP
#define COSE_SIGN1_CERTIFICATES_LOCAL_HPP

#include <cose/sign1/validation.hpp>
#include <vector>
#include <string>
#include <stdexcept>
#include <utility>

// We cannot include <cose/sign1/extension_packs/certificates_local.h> directly
// because it redefines cose_status_t and its enumerators without the
// COSE_STATUS_T_DEFINED guard, conflicting with <cose/cose.h>.
// Instead, forward-declare the types and functions we need.
extern "C" {

typedef struct cose_cert_local_factory_t cose_cert_local_factory_t;
typedef struct cose_cert_local_chain_t cose_cert_local_chain_t;

uint32_t cose_cert_local_ffi_abi_version(void);

char* cose_cert_local_last_error_message_utf8(void);
void cose_cert_local_last_error_clear(void);
void cose_cert_local_string_free(char* s);

cose_status_t cose_cert_local_factory_new(cose_cert_local_factory_t** out);
void cose_cert_local_factory_free(cose_cert_local_factory_t* factory);

cose_status_t cose_cert_local_factory_create_cert(
    const cose_cert_local_factory_t* factory,
    const char* subject,
    uint32_t algorithm,
    uint32_t key_size,
    uint64_t validity_secs,
    uint8_t** out_cert_der,
    size_t* out_cert_len,
    uint8_t** out_key_der,
    size_t* out_key_len
);

cose_status_t cose_cert_local_factory_create_self_signed(
    const cose_cert_local_factory_t* factory,
    uint8_t** out_cert_der,
    size_t* out_cert_len,
    uint8_t** out_key_der,
    size_t* out_key_len
);

cose_status_t cose_cert_local_chain_new(cose_cert_local_chain_t** out);
void cose_cert_local_chain_free(cose_cert_local_chain_t* chain_factory);

cose_status_t cose_cert_local_chain_create(
    const cose_cert_local_chain_t* chain_factory,
    uint32_t algorithm,
    bool include_intermediate,
    uint8_t*** out_certs_data,
    size_t** out_certs_lengths,
    size_t* out_certs_count,
    uint8_t*** out_keys_data,
    size_t** out_keys_lengths,
    size_t* out_keys_count
);

cose_status_t cose_cert_local_load_pem(
    const uint8_t* pem_data,
    size_t pem_len,
    uint8_t** out_cert_der,
    size_t* out_cert_len,
    uint8_t** out_key_der,
    size_t* out_key_len
);

cose_status_t cose_cert_local_load_der(
    const uint8_t* cert_data,
    size_t cert_len,
    uint8_t** out_cert_der,
    size_t* out_cert_len
);

void cose_cert_local_bytes_free(uint8_t* ptr, size_t len);
void cose_cert_local_array_free(uint8_t** ptr, size_t len);
void cose_cert_local_lengths_array_free(size_t* ptr, size_t len);

} // extern "C"

namespace cose {

/**
 * @brief Certificate and private key pair
 */
struct Certificate {
    std::vector<uint8_t> cert_der;
    std::vector<uint8_t> key_der;
};

/**
 * @brief RAII wrapper for ephemeral certificate factory
 */
class EphemeralCertificateFactory {
public:
    /**
     * @brief Create a new ephemeral certificate factory
     */
    static EphemeralCertificateFactory New() {
        cose_cert_local_factory_t* handle = nullptr;
        detail::ThrowIfNotOk(cose_cert_local_factory_new(&handle));
        if (!handle) {
            throw cose_error("Failed to create certificate factory");
        }
        return EphemeralCertificateFactory(handle);
    }
    
    ~EphemeralCertificateFactory() {
        if (handle_) {
            cose_cert_local_factory_free(handle_);
        }
    }
    
    // Non-copyable
    EphemeralCertificateFactory(const EphemeralCertificateFactory&) = delete;
    EphemeralCertificateFactory& operator=(const EphemeralCertificateFactory&) = delete;
    
    // Movable
    EphemeralCertificateFactory(EphemeralCertificateFactory&& other) noexcept 
        : handle_(std::exchange(other.handle_, nullptr)) {}
    
    EphemeralCertificateFactory& operator=(EphemeralCertificateFactory&& other) noexcept {
        if (this != &other) {
            if (handle_) {
                cose_cert_local_factory_free(handle_);
            }
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }
    
    /**
     * @brief Create a certificate with custom options
     * @param subject Certificate subject name
     * @param algorithm Key algorithm (0=RSA, 1=ECDSA, 2=MlDsa)
     * @param key_size Key size in bits
     * @param validity_secs Certificate validity period in seconds
     * @return Certificate with DER-encoded certificate and private key
     */
    Certificate CreateCertificate(
        const std::string& subject,
        uint32_t algorithm,
        uint32_t key_size,
        uint64_t validity_secs
    ) const {
        uint8_t* cert_der = nullptr;
        size_t cert_len = 0;
        uint8_t* key_der = nullptr;
        size_t key_len = 0;
        
        cose_status_t status = cose_cert_local_factory_create_cert(
            handle_,
            subject.c_str(),
            algorithm,
            key_size,
            validity_secs,
            &cert_der,
            &cert_len,
            &key_der,
            &key_len
        );
        
        if (status != COSE_OK) {
            if (cert_der) cose_cert_local_bytes_free(cert_der, cert_len);
            if (key_der) cose_cert_local_bytes_free(key_der, key_len);
            detail::ThrowIfNotOk(status);
        }
        
        Certificate result;
        if (cert_der && cert_len > 0) {
            result.cert_der.assign(cert_der, cert_der + cert_len);
            cose_cert_local_bytes_free(cert_der, cert_len);
        }
        if (key_der && key_len > 0) {
            result.key_der.assign(key_der, key_der + key_len);
            cose_cert_local_bytes_free(key_der, key_len);
        }
        
        return result;
    }
    
    /**
     * @brief Create a self-signed certificate with default options
     * @return Certificate with DER-encoded certificate and private key
     */
    Certificate CreateSelfSigned() const {
        uint8_t* cert_der = nullptr;
        size_t cert_len = 0;
        uint8_t* key_der = nullptr;
        size_t key_len = 0;
        
        cose_status_t status = cose_cert_local_factory_create_self_signed(
            handle_,
            &cert_der,
            &cert_len,
            &key_der,
            &key_len
        );
        
        if (status != COSE_OK) {
            if (cert_der) cose_cert_local_bytes_free(cert_der, cert_len);
            if (key_der) cose_cert_local_bytes_free(key_der, key_len);
            detail::ThrowIfNotOk(status);
        }
        
        Certificate result;
        if (cert_der && cert_len > 0) {
            result.cert_der.assign(cert_der, cert_der + cert_len);
            cose_cert_local_bytes_free(cert_der, cert_len);
        }
        if (key_der && key_len > 0) {
            result.key_der.assign(key_der, key_der + key_len);
            cose_cert_local_bytes_free(key_der, key_len);
        }
        
        return result;
    }
    
    /**
     * @brief Get native handle for C API interop
     */
    cose_cert_local_factory_t* native_handle() const { return handle_; }

    /**
     * @brief Release ownership of the underlying handle without freeing it.
     * @return The raw handle pointer. Caller is responsible for calling
     *         cose_cert_local_factory_free() when done.
     */
    cose_cert_local_factory_t* release() noexcept {
        return std::exchange(handle_, nullptr);
    }
    
private:
    explicit EphemeralCertificateFactory(cose_cert_local_factory_t* h) : handle_(h) {}
    cose_cert_local_factory_t* handle_;
};

/**
 * @brief RAII wrapper for certificate chain factory
 */
class CertificateChainFactory {
public:
    /**
     * @brief Create a new certificate chain factory
     */
    static CertificateChainFactory New() {
        cose_cert_local_chain_t* handle = nullptr;
        detail::ThrowIfNotOk(cose_cert_local_chain_new(&handle));
        if (!handle) {
            throw cose_error("Failed to create certificate chain factory");
        }
        return CertificateChainFactory(handle);
    }
    
    ~CertificateChainFactory() {
        if (handle_) {
            cose_cert_local_chain_free(handle_);
        }
    }
    
    // Non-copyable
    CertificateChainFactory(const CertificateChainFactory&) = delete;
    CertificateChainFactory& operator=(const CertificateChainFactory&) = delete;
    
    // Movable
    CertificateChainFactory(CertificateChainFactory&& other) noexcept 
        : handle_(std::exchange(other.handle_, nullptr)) {}
    
    CertificateChainFactory& operator=(CertificateChainFactory&& other) noexcept {
        if (this != &other) {
            if (handle_) {
                cose_cert_local_chain_free(handle_);
            }
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }
    
    /**
     * @brief Create a certificate chain
     * @param algorithm Key algorithm (0=RSA, 1=ECDSA, 2=MlDsa)
     * @param include_intermediate If true, include an intermediate CA in the chain
     * @return Vector of certificates in the chain
     */
    std::vector<Certificate> CreateChain(uint32_t algorithm, bool include_intermediate) const {
        uint8_t** certs_data = nullptr;
        size_t* certs_lengths = nullptr;
        size_t certs_count = 0;
        uint8_t** keys_data = nullptr;
        size_t* keys_lengths = nullptr;
        size_t keys_count = 0;
        
        cose_status_t status = cose_cert_local_chain_create(
            handle_,
            algorithm,
            include_intermediate,
            &certs_data,
            &certs_lengths,
            &certs_count,
            &keys_data,
            &keys_lengths,
            &keys_count
        );
        
        if (status != COSE_OK) {
            if (certs_data) cose_cert_local_array_free(certs_data, certs_count);
            if (certs_lengths) cose_cert_local_lengths_array_free(certs_lengths, certs_count);
            if (keys_data) cose_cert_local_array_free(keys_data, keys_count);
            if (keys_lengths) cose_cert_local_lengths_array_free(keys_lengths, keys_count);
            detail::ThrowIfNotOk(status);
        }
        
        std::vector<Certificate> result;
        for (size_t i = 0; i < certs_count; ++i) {
            Certificate cert;
            if (certs_data[i] && certs_lengths[i] > 0) {
                cert.cert_der.assign(certs_data[i], certs_data[i] + certs_lengths[i]);
                cose_cert_local_bytes_free(certs_data[i], certs_lengths[i]);
            }
            if (i < keys_count && keys_data[i] && keys_lengths[i] > 0) {
                cert.key_der.assign(keys_data[i], keys_data[i] + keys_lengths[i]);
                cose_cert_local_bytes_free(keys_data[i], keys_lengths[i]);
            }
            result.push_back(std::move(cert));
        }
        
        cose_cert_local_array_free(certs_data, certs_count);
        cose_cert_local_lengths_array_free(certs_lengths, certs_count);
        cose_cert_local_array_free(keys_data, keys_count);
        cose_cert_local_lengths_array_free(keys_lengths, keys_count);
        
        return result;
    }
    
    /**
     * @brief Get native handle for C API interop
     */
    cose_cert_local_chain_t* native_handle() const { return handle_; }

    /**
     * @brief Release ownership of the underlying handle without freeing it.
     * @return The raw handle pointer. Caller is responsible for calling
     *         cose_cert_local_chain_free() when done.
     */
    cose_cert_local_chain_t* release() noexcept {
        return std::exchange(handle_, nullptr);
    }
    
private:
    explicit CertificateChainFactory(cose_cert_local_chain_t* h) : handle_(h) {}
    cose_cert_local_chain_t* handle_;
};

/**
 * @brief Load a certificate from PEM-encoded data
 * @param pem_data PEM-encoded data
 * @return Certificate with DER-encoded certificate and optional private key
 */
inline Certificate LoadFromPem(const std::vector<uint8_t>& pem_data) {
    uint8_t* cert_der = nullptr;
    size_t cert_len = 0;
    uint8_t* key_der = nullptr;
    size_t key_len = 0;
    
    cose_status_t status = cose_cert_local_load_pem(
        pem_data.data(),
        pem_data.size(),
        &cert_der,
        &cert_len,
        &key_der,
        &key_len
    );
    
    if (status != COSE_OK) {
        if (cert_der) cose_cert_local_bytes_free(cert_der, cert_len);
        if (key_der) cose_cert_local_bytes_free(key_der, key_len);
        detail::ThrowIfNotOk(status);
    }
    
    Certificate result;
    if (cert_der && cert_len > 0) {
        result.cert_der.assign(cert_der, cert_der + cert_len);
        cose_cert_local_bytes_free(cert_der, cert_len);
    }
    if (key_der && key_len > 0) {
        result.key_der.assign(key_der, key_der + key_len);
        cose_cert_local_bytes_free(key_der, key_len);
    }
    
    return result;
}

/**
 * @brief Load a certificate from DER-encoded data
 * @param cert_data DER-encoded certificate data
 * @return Certificate with DER-encoded certificate (no private key)
 */
inline Certificate LoadFromDer(const std::vector<uint8_t>& cert_data) {
    uint8_t* cert_der = nullptr;
    size_t cert_len = 0;
    
    cose_status_t status = cose_cert_local_load_der(
        cert_data.data(),
        cert_data.size(),
        &cert_der,
        &cert_len
    );
    
    if (status != COSE_OK) {
        if (cert_der) cose_cert_local_bytes_free(cert_der, cert_len);
        detail::ThrowIfNotOk(status);
    }
    
    Certificate result;
    if (cert_der && cert_len > 0) {
        result.cert_der.assign(cert_der, cert_der + cert_len);
        cose_cert_local_bytes_free(cert_der, cert_len);
    }
    
    return result;
}

} // namespace cose

#endif // COSE_SIGN1_CERTIFICATES_LOCAL_HPP
