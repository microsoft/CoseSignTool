// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file validator.hpp
 * @brief C++ RAII wrappers for COSE Sign1 validation
 */

#ifndef COSE_VALIDATOR_HPP
#define COSE_VALIDATOR_HPP

#include <cose/cose_sign1.h>
#include <memory>
#include <string>
#include <vector>
#include <stdexcept>

namespace cose {

/**
 * @brief Exception thrown by COSE validation operations
 */
class cose_error : public std::runtime_error {
public:
    explicit cose_error(const std::string& msg) : std::runtime_error(msg) {}
    explicit cose_error(cose_status_t status) 
        : std::runtime_error(get_error_message(status)) {}
    
private:
    static std::string get_error_message(cose_status_t status) {
        char* msg = cose_last_error_message_utf8();
        if (msg) {
            std::string result(msg);
            cose_string_free(msg);
            return result;
        }
        return "COSE error (status=" + std::to_string(static_cast<int>(status)) + ")";
    }
};

/**
 * @brief RAII wrapper for validation result
 */
class ValidationResult {
public:
    explicit ValidationResult(cose_validation_result_t* result) : result_(result) {
        if (!result_) {
            throw cose_error("Null validation result");
        }
    }
    
    ~ValidationResult() {
        if (result_) {
            cose_validation_result_free(result_);
        }
    }
    
    // Non-copyable
    ValidationResult(const ValidationResult&) = delete;
    ValidationResult& operator=(const ValidationResult&) = delete;
    
    // Movable
    ValidationResult(ValidationResult&& other) noexcept : result_(other.result_) {
        other.result_ = nullptr;
    }
    
    ValidationResult& operator=(ValidationResult&& other) noexcept {
        if (this != &other) {
            if (result_) {
                cose_validation_result_free(result_);
            }
            result_ = other.result_;
            other.result_ = nullptr;
        }
        return *this;
    }
    
    /**
     * @brief Check if validation was successful
     * @return true if validation succeeded, false otherwise
     */
    bool Ok() const {
        bool ok = false;
        cose_status_t status = cose_validation_result_is_success(result_, &ok);
        if (status != COSE_OK) {
            throw cose_error(status);
        }
        return ok;
    }
    
    /**
     * @brief Get failure message if validation failed
     * @return Failure message string, or empty string if validation succeeded
     */
    std::string FailureMessage() const {
        char* msg = cose_validation_result_failure_message_utf8(result_);
        if (msg) {
            std::string result(msg);
            cose_string_free(msg);
            return result;
        }
        return std::string();
    }
    
private:
    cose_validation_result_t* result_;
};

/**
 * @brief RAII wrapper for validator
 */
class Validator {
public:
    explicit Validator(cose_validator_t* validator) : validator_(validator) {
        if (!validator_) {
            throw cose_error("Null validator");
        }
    }
    
    ~Validator() {
        if (validator_) {
            cose_validator_free(validator_);
        }
    }
    
    // Non-copyable
    Validator(const Validator&) = delete;
    Validator& operator=(const Validator&) = delete;
    
    // Movable
    Validator(Validator&& other) noexcept : validator_(other.validator_) {
        other.validator_ = nullptr;
    }
    
    Validator& operator=(Validator&& other) noexcept {
        if (this != &other) {
            if (validator_) {
                cose_validator_free(validator_);
            }
            validator_ = other.validator_;
            other.validator_ = nullptr;
        }
        return *this;
    }
    
    /**
     * @brief Validate COSE Sign1 message bytes
     * 
     * @param cose_bytes COSE Sign1 message bytes
     * @param detached_payload Optional detached payload bytes (empty for embedded payload)
     * @return ValidationResult object
     */
    ValidationResult Validate(
        const std::vector<uint8_t>& cose_bytes,
        const std::vector<uint8_t>& detached_payload = {}
    ) const {
        cose_validation_result_t* result = nullptr;
        
        const uint8_t* detached_ptr = detached_payload.empty() ? nullptr : detached_payload.data();
        size_t detached_len = detached_payload.size();
        
        cose_status_t status = cose_validator_validate_bytes(
            validator_,
            cose_bytes.data(),
            cose_bytes.size(),
            detached_ptr,
            detached_len,
            &result
        );
        
        if (status != COSE_OK) {
            throw cose_error(status);
        }
        
        return ValidationResult(result);
    }
    
private:
    cose_validator_t* validator_;
    
    friend class ValidatorBuilder;
};

/**
 * @brief Fluent builder for Validator
 * 
 * Example usage:
 * @code
 * auto validator = ValidatorBuilder()
 *     .WithCertificates()
 *     .WithMst()
 *     .Build();
 * auto result = validator.Validate(cose_bytes);
 * if (result.Ok()) {
 *     // Validation successful
 * }
 * @endcode
 */
class ValidatorBuilder {
public:
    ValidatorBuilder() {
        cose_status_t status = cose_validator_builder_new(&builder_);
        if (status != COSE_OK || !builder_) {
            throw cose_error(status);
        }
    }
    
    ~ValidatorBuilder() {
        if (builder_) {
            cose_validator_builder_free(builder_);
        }
    }
    
    // Non-copyable
    ValidatorBuilder(const ValidatorBuilder&) = delete;
    ValidatorBuilder& operator=(const ValidatorBuilder&) = delete;
    
    // Movable
    ValidatorBuilder(ValidatorBuilder&& other) noexcept : builder_(other.builder_) {
        other.builder_ = nullptr;
    }
    
    ValidatorBuilder& operator=(ValidatorBuilder&& other) noexcept {
        if (this != &other) {
            if (builder_) {
                cose_validator_builder_free(builder_);
            }
            builder_ = other.builder_;
            other.builder_ = nullptr;
        }
        return *this;
    }
    
    /**
     * @brief Build the validator
     * @return Validator object
     * @throws cose_error if build fails
     */
    Validator Build() {
        if (!builder_) {
            throw cose_error("Builder already consumed");
        }
        
        cose_validator_t* validator = nullptr;
        cose_status_t status = cose_validator_builder_build(builder_, &validator);
        
        // Builder is consumed, prevent double-free
        builder_ = nullptr;
        
        if (status != COSE_OK || !validator) {
            throw cose_error(status);
        }
        
        return Validator(validator);
    }

    /**
     * @brief Expose the underlying C builder handle for advanced / optional pack projections.
     */
    cose_validator_builder_t* native_handle() const {
        return builder_;
    }
    
protected:
    cose_validator_builder_t* builder_;
    
    // Helper for pack methods to check builder validity
    void CheckBuilder() const {
        if (!builder_) {
            throw cose_error("Builder already consumed or invalid");
        }
    }
};

} // namespace cose

#endif // COSE_VALIDATOR_HPP
