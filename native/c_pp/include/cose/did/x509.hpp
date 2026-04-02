// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file x509.hpp
 * @brief C++ RAII wrappers for DID:X509 operations
 */

#ifndef COSE_DID_X509_HPP
#define COSE_DID_X509_HPP

#include <cose/did/x509.h>
#include <memory>
#include <string>
#include <vector>
#include <utility>
#include <stdexcept>

namespace cose {

/**
 * @brief Exception thrown by DID:X509 operations
 */
class DidX509Error : public std::runtime_error {
public:
    explicit DidX509Error(const std::string& msg) : std::runtime_error(msg) {}
    explicit DidX509Error(int code, DidX509ErrorHandle* error_handle) 
        : std::runtime_error(get_error_message(error_handle)), code_(code) {
        if (error_handle) {
            did_x509_error_free(error_handle);
        }
    }
    
    int code() const { return code_; }
    
private:
    int code_ = DID_X509_OK;
    
    static std::string get_error_message(DidX509ErrorHandle* error_handle) {
        if (error_handle) {
            char* msg = did_x509_error_message(error_handle);
            if (msg) {
                std::string result(msg);
                did_x509_string_free(msg);
                return result;
            }
        }
        return "DID:X509 error";
    }
};

namespace detail {

inline void ThrowIfNotOk(int status, DidX509ErrorHandle* error_handle) {
    if (status != DID_X509_OK) {
        throw DidX509Error(status, error_handle);
    }
    if (error_handle) {
        did_x509_error_free(error_handle);
    }
}

} // namespace detail

/**
 * @brief RAII wrapper for parsed DID:X509 identifier
 */
class ParsedDid {
public:
    explicit ParsedDid(DidX509ParsedHandle* handle) : handle_(handle) {
        if (!handle_) {
            throw DidX509Error("Null parsed DID handle");
        }
    }
    
    ~ParsedDid() {
        if (handle_) {
            did_x509_parsed_free(handle_);
        }
    }
    
    // Non-copyable
    ParsedDid(const ParsedDid&) = delete;
    ParsedDid& operator=(const ParsedDid&) = delete;
    
    // Movable
    ParsedDid(ParsedDid&& other) noexcept : handle_(other.handle_) {
        other.handle_ = nullptr;
    }
    
    ParsedDid& operator=(ParsedDid&& other) noexcept {
        if (this != &other) {
            if (handle_) {
                did_x509_parsed_free(handle_);
            }
            handle_ = other.handle_;
            other.handle_ = nullptr;
        }
        return *this;
    }
    
    /**
     * @brief Get the root CA fingerprint (hash) as hex string
     * @return Root hash hex string
     */
    std::string RootHash() const {
        char* fingerprint = nullptr;
        DidX509ErrorHandle* error = nullptr;
        
        int status = did_x509_parsed_get_fingerprint(handle_, &fingerprint, &error);
        if (status != DID_X509_OK || !fingerprint) {
            throw DidX509Error(status, error);
        }
        
        std::string result(fingerprint);
        did_x509_string_free(fingerprint);
        if (error) {
            did_x509_error_free(error);
        }
        
        return result;
    }
    
    /**
     * @brief Get the hash algorithm name
     * @return Hash algorithm string (e.g., "sha256")
     */
    std::string HashAlgorithm() const {
        char* algorithm = nullptr;
        DidX509ErrorHandle* error = nullptr;
        
        int status = did_x509_parsed_get_hash_algorithm(handle_, &algorithm, &error);
        if (status != DID_X509_OK || !algorithm) {
            throw DidX509Error(status, error);
        }
        
        std::string result(algorithm);
        did_x509_string_free(algorithm);
        if (error) {
            did_x509_error_free(error);
        }
        
        return result;
    }
    
    /**
     * @brief Get the number of policy elements
     * @return Policy count
     */
    size_t SubjectCount() const {
        uint32_t count = 0;
        int status = did_x509_parsed_get_policy_count(handle_, &count);
        if (status != DID_X509_OK) {
            throw DidX509Error("Failed to get policy count");
        }
        return static_cast<size_t>(count);
    }
    
private:
    DidX509ParsedHandle* handle_;
};

/**
 * @brief Generate DID:X509 from leaf certificate and root certificate
 * 
 * @param leaf_cert DER-encoded leaf certificate
 * @param leaf_len Length of leaf certificate
 * @param root_cert DER-encoded root certificate
 * @param root_len Length of root certificate
 * @return Generated DID:X509 string
 * @throws DidX509Error on failure
 */
inline std::string DidX509Generate(
    const uint8_t* leaf_cert,
    size_t leaf_len,
    const uint8_t* root_cert,
    size_t root_len
) {
    const uint8_t* certs[] = { leaf_cert, root_cert };
    uint32_t lens[] = { static_cast<uint32_t>(leaf_len), static_cast<uint32_t>(root_len) };
    
    char* did_string = nullptr;
    DidX509ErrorHandle* error = nullptr;
    
    int status = did_x509_build_from_chain(certs, lens, 2, &did_string, &error);
    if (status != DID_X509_OK || !did_string) {
        throw DidX509Error(status, error);
    }
    
    std::string result(did_string);
    did_x509_string_free(did_string);
    if (error) {
        did_x509_error_free(error);
    }
    
    return result;
}

/**
 * @brief Generate DID:X509 from certificate chain
 * 
 * @param certs Array of pointers to DER-encoded certificates (leaf-first)
 * @param lens Array of certificate lengths
 * @param count Number of certificates
 * @return Generated DID:X509 string
 * @throws DidX509Error on failure
 */
inline std::string DidX509GenerateFromChain(
    const uint8_t** certs,
    const uint32_t* lens,
    size_t count
) {
    char* did_string = nullptr;
    DidX509ErrorHandle* error = nullptr;
    
    int status = did_x509_build_from_chain(certs, lens, static_cast<uint32_t>(count), &did_string, &error);
    if (status != DID_X509_OK || !did_string) {
        throw DidX509Error(status, error);
    }
    
    std::string result(did_string);
    did_x509_string_free(did_string);
    if (error) {
        did_x509_error_free(error);
    }
    
    return result;
}

/**
 * @brief Validate DID:X509 string format
 * 
 * @param did DID:X509 string to validate
 * @return true if valid format, false otherwise
 * @throws DidX509Error on parsing error
 */
inline bool DidX509Validate(const std::string& did) {
    DidX509ParsedHandle* handle = nullptr;
    DidX509ErrorHandle* error = nullptr;
    
    int status = did_x509_parse(did.c_str(), &handle, &error);
    
    if (handle) {
        did_x509_parsed_free(handle);
    }
    if (error) {
        did_x509_error_free(error);
    }
    
    return status == DID_X509_OK;
}

/**
 * @brief Validate DID:X509 against certificate chain
 * 
 * @param did DID:X509 string to validate
 * @param certs Array of pointers to DER-encoded certificates
 * @param lens Array of certificate lengths
 * @param count Number of certificates
 * @return true if DID matches the chain, false otherwise
 * @throws DidX509Error on validation error
 */
inline bool DidX509ValidateAgainstChain(
    const std::string& did,
    const uint8_t** certs,
    const uint32_t* lens,
    size_t count
) {
    int is_valid = 0;
    DidX509ErrorHandle* error = nullptr;
    
    int status = did_x509_validate(
        did.c_str(),
        certs,
        lens,
        static_cast<uint32_t>(count),
        &is_valid,
        &error
    );
    
    if (status != DID_X509_OK) {
        throw DidX509Error(status, error);
    }
    
    if (error) {
        did_x509_error_free(error);
    }
    
    return is_valid != 0;
}

/**
 * @brief Parse DID:X509 string into components
 * 
 * @param did DID:X509 string to parse
 * @return ParsedDid object
 * @throws DidX509Error on parsing failure
 */
inline ParsedDid DidX509Parse(const std::string& did) {
    DidX509ParsedHandle* handle = nullptr;
    DidX509ErrorHandle* error = nullptr;
    
    int status = did_x509_parse(did.c_str(), &handle, &error);
    if (status != DID_X509_OK || !handle) {
        throw DidX509Error(status, error);
    }
    
    if (error) {
        did_x509_error_free(error);
    }
    
    return ParsedDid(handle);
}

/**
 * @brief Build DID:X509 from certificate chain with explicit EKU
 * 
 * @param chain Array of pointers to DER-encoded certificates
 * @param lens Array of certificate lengths
 * @param count Number of certificates
 * @param eku_oid EKU OID string
 * @return Generated DID:X509 string
 * @throws DidX509Error on failure
 */
inline std::string DidX509BuildWithEku(
    const uint8_t** chain,
    const uint32_t* lens,
    size_t count,
    const std::string& eku_oid
) {
    // Get CA certificate (last in chain)
    if (count == 0) {
        throw DidX509Error("Empty certificate chain");
    }
    
    const uint8_t* ca_cert = chain[count - 1];
    uint32_t ca_len = lens[count - 1];
    
    const char* eku_oids[] = { eku_oid.c_str() };
    
    char* did_string = nullptr;
    DidX509ErrorHandle* error = nullptr;
    
    int status = did_x509_build_with_eku(ca_cert, ca_len, eku_oids, 1, &did_string, &error);
    if (status != DID_X509_OK || !did_string) {
        throw DidX509Error(status, error);
    }
    
    std::string result(did_string);
    did_x509_string_free(did_string);
    if (error) {
        did_x509_error_free(error);
    }
    
    return result;
}

/**
 * @brief Build DID:X509 from certificate chain
 * 
 * @param chain Array of pointers to DER-encoded certificates
 * @param lens Array of certificate lengths
 * @param count Number of certificates
 * @return Generated DID:X509 string
 * @throws DidX509Error on failure
 */
inline std::string DidX509BuildFromChain(
    const uint8_t** chain,
    const uint32_t* lens,
    size_t count
) {
    char* did_string = nullptr;
    DidX509ErrorHandle* error = nullptr;
    
    int status = did_x509_build_from_chain(chain, lens, static_cast<uint32_t>(count), &did_string, &error);
    if (status != DID_X509_OK || !did_string) {
        throw DidX509Error(status, error);
    }
    
    std::string result(did_string);
    did_x509_string_free(did_string);
    if (error) {
        did_x509_error_free(error);
    }
    
    return result;
}

/**
 * @brief Resolve DID:X509 to JSON DID Document
 * 
 * @param did DID:X509 string to resolve
 * @param chain Array of pointers to DER-encoded certificates
 * @param lens Array of certificate lengths
 * @param count Number of certificates
 * @return JSON DID document string
 * @throws DidX509Error on resolution failure
 */
inline std::string DidX509Resolve(
    const std::string& did,
    const uint8_t** chain,
    const uint32_t* lens,
    size_t count
) {
    char* did_document = nullptr;
    DidX509ErrorHandle* error = nullptr;
    
    int status = did_x509_resolve(
        did.c_str(),
        chain,
        lens,
        static_cast<uint32_t>(count),
        &did_document,
        &error
    );
    
    if (status != DID_X509_OK || !did_document) {
        throw DidX509Error(status, error);
    }
    
    std::string result(did_document);
    did_x509_string_free(did_document);
    if (error) {
        did_x509_error_free(error);
    }
    
    return result;
}

} // namespace cose

#endif // COSE_DID_X509_HPP
