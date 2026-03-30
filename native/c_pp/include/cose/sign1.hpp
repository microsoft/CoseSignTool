// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file sign1.hpp
 * @brief C++ RAII wrappers for COSE Sign1 message primitives
 */

#ifndef COSE_SIGN1_HPP
#define COSE_SIGN1_HPP

#include <cose/sign1.h>
#include <memory>
#include <string>
#include <vector>
#include <optional>
#include <stdexcept>

namespace cose::sign1 {

/**
 * @brief Exception thrown by COSE primitives operations
 */
class primitives_error : public std::runtime_error {
public:
    explicit primitives_error(const std::string& msg) : std::runtime_error(msg) {}
    
    explicit primitives_error(CoseSign1ErrorHandle* error)
        : std::runtime_error(get_error_message(error)) {
        if (error) {
            cose_sign1_error_free(error);
        }
    }

private:
    static std::string get_error_message(CoseSign1ErrorHandle* error) {
        if (error) {
            char* msg = cose_sign1_error_message(error);
            if (msg) {
                std::string result(msg);
                cose_sign1_string_free(msg);
                return result;
            }
            int32_t code = cose_sign1_error_code(error);
            return "COSE primitives error (code=" + std::to_string(code) + ")";
        }
        return "COSE primitives error (unknown)";
    }
};

namespace detail {

inline void ThrowIfNotOk(int32_t status, CoseSign1ErrorHandle* error) {
    if (status != COSE_SIGN1_OK) {
        throw primitives_error(error);
    }
}

} // namespace detail

} // namespace cose::sign1

namespace cose {

/**
 * @brief RAII wrapper for COSE header map
 */
class CoseHeaderMap {
public:
    explicit CoseHeaderMap(CoseHeaderMapHandle* handle) : handle_(handle) {
        if (!handle_) {
            throw sign1::primitives_error("Null header map handle");
        }
    }

    ~CoseHeaderMap() {
        if (handle_) {
            cose_headermap_free(handle_);
        }
    }

    // Non-copyable
    CoseHeaderMap(const CoseHeaderMap&) = delete;
    CoseHeaderMap& operator=(const CoseHeaderMap&) = delete;

    // Movable
    CoseHeaderMap(CoseHeaderMap&& other) noexcept : handle_(other.handle_) {
        other.handle_ = nullptr;
    }

    CoseHeaderMap& operator=(CoseHeaderMap&& other) noexcept {
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
     * @brief Get an integer value from the header map
     * 
     * @param label Integer label for the header
     * @return Optional containing the integer value if found, empty otherwise
     */
    std::optional<int64_t> GetInt(int64_t label) const {
        int64_t value = 0;
        int32_t status = cose_headermap_get_int(handle_, label, &value);
        if (status == COSE_SIGN1_OK) {
            return value;
        }
        return std::nullopt;
    }

    /**
     * @brief Get a byte string value from the header map
     * 
     * @param label Integer label for the header
     * @return Optional containing the byte vector if found, empty otherwise
     */
    std::optional<std::vector<uint8_t>> GetBytes(int64_t label) const {
        const uint8_t* bytes = nullptr;
        size_t len = 0;
        int32_t status = cose_headermap_get_bytes(handle_, label, &bytes, &len);
        if (status == COSE_SIGN1_OK && bytes) {
            return std::vector<uint8_t>(bytes, bytes + len);
        }
        return std::nullopt;
    }

    /**
     * @brief Get a text string value from the header map
     * 
     * @param label Integer label for the header
     * @return Optional containing the text string if found, empty otherwise
     */
    std::optional<std::string> GetText(int64_t label) const {
        char* text = cose_headermap_get_text(handle_, label);
        if (text) {
            std::string result(text);
            cose_sign1_string_free(text);
            return result;
        }
        return std::nullopt;
    }

    /**
     * @brief Check if a header exists in the map
     * 
     * @param label Integer label for the header
     * @return true if the header exists, false otherwise
     */
    bool Contains(int64_t label) const {
        return cose_headermap_contains(handle_, label);
    }

    /**
     * @brief Get the number of headers in the map
     * 
     * @return Number of headers
     */
    size_t Len() const {
        return cose_headermap_len(handle_);
    }

private:
    CoseHeaderMapHandle* handle_;
};

} // namespace cose

namespace cose::sign1 {

/**
 * @brief RAII wrapper for COSE Sign1 message
 */
class CoseSign1Message {
public:
    explicit CoseSign1Message(CoseSign1MessageHandle* handle) : handle_(handle) {
        if (!handle_) {
            throw primitives_error("Null message handle");
        }
    }

    ~CoseSign1Message() {
        if (handle_) {
            cose_sign1_message_free(handle_);
        }
    }

    // Non-copyable
    CoseSign1Message(const CoseSign1Message&) = delete;
    CoseSign1Message& operator=(const CoseSign1Message&) = delete;

    // Movable
    CoseSign1Message(CoseSign1Message&& other) noexcept : handle_(other.handle_) {
        other.handle_ = nullptr;
    }

    CoseSign1Message& operator=(CoseSign1Message&& other) noexcept {
        if (this != &other) {
            if (handle_) {
                cose_sign1_message_free(handle_);
            }
            handle_ = other.handle_;
            other.handle_ = nullptr;
        }
        return *this;
    }

    /**
     * @brief Parse a COSE Sign1 message from bytes
     * 
     * @param data Message bytes
     * @param len Length of message bytes
     * @return CoseSign1Message object
     * @throws primitives_error if parsing fails
     */
    static CoseSign1Message Parse(const uint8_t* data, size_t len) {
        CoseSign1MessageHandle* message = nullptr;
        CoseSign1ErrorHandle* error = nullptr;
        
        int32_t status = cose_sign1_message_parse(data, len, &message, &error);
        detail::ThrowIfNotOk(status, error);
        
        return CoseSign1Message(message);
    }

    /**
     * @brief Parse a COSE Sign1 message from a vector of bytes
     * 
     * @param data Message bytes vector
     * @return CoseSign1Message object
     * @throws primitives_error if parsing fails
     */
    static CoseSign1Message Parse(const std::vector<uint8_t>& data) {
        return Parse(data.data(), data.size());
    }

    /**
     * @brief Get the protected headers from the message
     * 
     * @return CoseHeaderMap object
     * @throws primitives_error if operation fails
     */
    CoseHeaderMap ProtectedHeaders() const {
        CoseHeaderMapHandle* headers = nullptr;
        int32_t status = cose_sign1_message_protected_headers(handle_, &headers);
        if (status != COSE_SIGN1_OK || !headers) {
            throw primitives_error("Failed to get protected headers");
        }
        return CoseHeaderMap(headers);
    }

    /**
     * @brief Get the unprotected headers from the message
     * 
     * @return CoseHeaderMap object
     * @throws primitives_error if operation fails
     */
    CoseHeaderMap UnprotectedHeaders() const {
        CoseHeaderMapHandle* headers = nullptr;
        int32_t status = cose_sign1_message_unprotected_headers(handle_, &headers);
        if (status != COSE_SIGN1_OK || !headers) {
            throw primitives_error("Failed to get unprotected headers");
        }
        return CoseHeaderMap(headers);
    }

    /**
     * @brief Get the algorithm from the message's protected headers
     * 
     * @return Optional containing the algorithm identifier if found, empty otherwise
     */
    std::optional<int64_t> Algorithm() const {
        int64_t alg = 0;
        int32_t status = cose_sign1_message_alg(handle_, &alg);
        if (status == COSE_SIGN1_OK) {
            return alg;
        }
        return std::nullopt;
    }

    /**
     * @brief Check if the message has a detached payload
     * 
     * @return true if the payload is detached, false if embedded
     */
    bool IsDetached() const {
        return cose_sign1_message_is_detached(handle_);
    }

    /**
     * @brief Get the embedded payload from the message
     * 
     * @return Optional containing the payload bytes if embedded, empty if detached
     * @throws primitives_error if an error occurs (other than detached payload)
     */
    std::optional<std::vector<uint8_t>> Payload() const {
        const uint8_t* payload = nullptr;
        size_t len = 0;
        
        int32_t status = cose_sign1_message_payload(handle_, &payload, &len);
        if (status == COSE_SIGN1_OK && payload) {
            return std::vector<uint8_t>(payload, payload + len);
        }
        
        // If payload is missing (detached), return empty optional
        if (status == COSE_SIGN1_ERR_PAYLOAD_MISSING) {
            return std::nullopt;
        }
        
        // Other errors should throw
        if (status != COSE_SIGN1_OK) {
            throw primitives_error("Failed to get payload (code=" + std::to_string(status) + ")");
        }
        
        return std::nullopt;
    }

    /**
     * @brief Get the protected headers bytes from the message
     * 
     * @return Vector containing the protected headers bytes
     * @throws primitives_error if operation fails
     */
    std::vector<uint8_t> ProtectedBytes() const {
        const uint8_t* bytes = nullptr;
        size_t len = 0;
        
        int32_t status = cose_sign1_message_protected_bytes(handle_, &bytes, &len);
        if (status != COSE_SIGN1_OK) {
            throw primitives_error("Failed to get protected bytes (code=" + std::to_string(status) + ")");
        }
        
        if (!bytes) {
            throw primitives_error("Protected bytes pointer is null");
        }
        
        return std::vector<uint8_t>(bytes, bytes + len);
    }

    /**
     * @brief Get the signature bytes from the message
     * 
     * @return Vector containing the signature bytes
     * @throws primitives_error if operation fails
     */
    std::vector<uint8_t> Signature() const {
        const uint8_t* signature = nullptr;
        size_t len = 0;
        
        int32_t status = cose_sign1_message_signature(handle_, &signature, &len);
        if (status != COSE_SIGN1_OK) {
            throw primitives_error("Failed to get signature (code=" + std::to_string(status) + ")");
        }
        
        if (!signature) {
            throw primitives_error("Signature pointer is null");
        }
        
        return std::vector<uint8_t>(signature, signature + len);
    }

private:
    CoseSign1MessageHandle* handle_;
};

} // namespace cose::sign1

#endif // COSE_SIGN1_HPP
