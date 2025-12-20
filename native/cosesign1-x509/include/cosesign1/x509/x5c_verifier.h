#pragma once

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

// Verifies a COSE_Sign1 using the leaf certificate in an embedded x5c header (label 33).
//
// This is intentionally separated from the base signature verifier to keep the base package small and explicit
// about key material.
validation::ValidationResult VerifyCoseSign1WithX5c(
    std::string_view validator_name,
    const std::vector<std::uint8_t>& cose_sign1,
    const validation::VerifyOptions& options);

// Same as VerifyCoseSign1WithX5c, but for already-parsed COSE_Sign1.
validation::ValidationResult VerifyParsedCoseSign1WithX5c(
        std::string_view validator_name,
        const cosesign1::common::cbor::ParsedCoseSign1& parsed,
        std::optional<std::span<const std::uint8_t>> external_payload,
        const validation::VerifyOptions& options);

// Adapter validator so x509 can be plugged into cosesign1::validation::CoseSign1ValidationBuilder.
class X5cCoseSign1Validator final : public validation::ICoseSign1Validator {
 public:
    X5cCoseSign1Validator(std::string validator_name, validation::VerifyOptions options)
            : validator_name_(std::move(validator_name)), options_(std::move(options)) {}

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
