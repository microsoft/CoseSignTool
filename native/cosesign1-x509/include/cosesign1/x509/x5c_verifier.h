// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

/**
 * @file x5c_verifier.h
 * @brief X.509 (x5c) certificate chain based validation for COSE_Sign1 messages.
 */

#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include <cosesign1/common/cbor.h>

#include "cosesign1/validation/cose_sign1_verifier.h"
#include "cosesign1/validation/cose_sign1_validation_builder.h"
#include "cosesign1/validation/validation_result.h"

namespace cosesign1::x509 {

/**
 * @brief How the x5c verifier should decide trust for the signing certificate chain.
 */
enum class X509TrustMode {
    /**
     * @brief Chain must be trusted by the host OS trust store.
     */
    kSystem = 0,

    /**
     * @brief Chain must build to one of the caller-provided roots.
     */
    kCustomRoots = 1,
};

/**
 * @brief Revocation checking mode used when validating the certificate chain.
 */
enum class X509RevocationMode {
    kNoCheck = 0,
    kOnline = 1,
    kOffline = 2,
};

/**
 * @brief Options controlling X.509 chain validation for x5c.
 */
struct X509ChainVerifyOptions {
    X509TrustMode trust_mode = X509TrustMode::kSystem;
    X509RevocationMode revocation_mode = X509RevocationMode::kOnline;

    /**
     * @brief Caller-provided trust anchors (DER-encoded certificates).
     *
     * Used only when trust_mode == kCustomRoots. The chain must build to one of these
     * exact roots to be considered trusted.
     */
    std::vector<std::vector<std::uint8_t>> trusted_roots_der;

    /**
     * @brief Diagnostic mode: do not fail validation on chain trust errors.
     *
     * When true, signature verification must still succeed, but chain validation errors
     * will be returned in the ValidationResult.failures list to aid diagnostics.
     */
    bool allow_untrusted_roots = false;
};

/**
 * @brief Verifies a COSE_Sign1 using the leaf certificate in an embedded x5c header (label 33).
 *
 * This is intentionally separated from the base signature verifier to keep the base package small and explicit
 * about key material.
 */
validation::ValidationResult VerifyCoseSign1WithX5c(
    std::string_view validator_name,
    const std::vector<std::uint8_t>& cose_sign1,
    const validation::VerifyOptions& options);

/**
 * @brief Verifies a COSE_Sign1 using x5c-derived key material, and validates the X.509 chain.
 */
validation::ValidationResult VerifyCoseSign1WithX5c(
    std::string_view validator_name,
    const std::vector<std::uint8_t>& cose_sign1,
    const validation::VerifyOptions& options,
    const X509ChainVerifyOptions& chain_options);

/**
 * @brief Same as VerifyCoseSign1WithX5c, but for an already-parsed COSE_Sign1.
 */
validation::ValidationResult VerifyParsedCoseSign1WithX5c(
        std::string_view validator_name,
        const cosesign1::common::cbor::ParsedCoseSign1& parsed,
        std::optional<std::span<const std::uint8_t>> external_payload,
        const validation::VerifyOptions& options);

/**
 * @brief Same as VerifyCoseSign1WithX5c(…, chain_options) but for an already-parsed COSE_Sign1.
 */
validation::ValidationResult VerifyParsedCoseSign1WithX5c(
    std::string_view validator_name,
    const cosesign1::common::cbor::ParsedCoseSign1& parsed,
    std::optional<std::span<const std::uint8_t>> external_payload,
    const validation::VerifyOptions& options,
    const X509ChainVerifyOptions& chain_options);

/**
 * @brief Adapter validator so x509 verification can be plugged into CoseSign1ValidationBuilder.
 */
class X5cCoseSign1Validator final : public validation::ICoseSign1Validator {
 public:
    /**
     * @brief Constructs the adapter validator.
     */
    X5cCoseSign1Validator(std::string validator_name, validation::VerifyOptions options)
            : validator_name_(std::move(validator_name)), options_(std::move(options)) {}

    /**
     * @brief Validates a COSE_Sign1 using x5c-derived key material.
     */
    validation::ValidationResult Validate(const cosesign1::common::cbor::ParsedCoseSign1& input,
                                                                                const validation::CoseSign1ValidationContext& context) const override {
        std::optional<std::span<const std::uint8_t>> ext = context.external_payload;
        if (!ext && options_.external_payload) {
            ext = std::span<const std::uint8_t>(options_.external_payload->data(), options_.external_payload->size());
        }
        return VerifyParsedCoseSign1WithX5c(validator_name_, input, ext, options_);
    }

 private:
    std::string validator_name_;
    validation::VerifyOptions options_;
};

} // namespace cosesign1::x509
