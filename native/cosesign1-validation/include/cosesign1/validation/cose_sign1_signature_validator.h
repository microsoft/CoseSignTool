// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "cosesign1/validation/cose_sign1_verifier.h"
#include "cosesign1/validation/i_cose_sign1_validator.h"

namespace cosesign1::validation {

/**
 * @file cose_sign1_signature_validator.h
 * @brief Adapter validator that delegates to the built-in COSE_Sign1 signature verifier.
 */

/**
 * @brief ICoseSign1Validator that verifies the COSE_Sign1 signature.
 *
 * This adapter primarily exists to:
 * - Integrate VerifyParsedCoseSign1 into the builder/composite pipeline.
 * - Centralize the external payload selection/materialization logic.
 */
class CoseSign1SignatureValidator final : public ICoseSign1Validator {
 public:
  /**
   * @brief Creates a signature validator.
   * @param validator_name Name reported in ValidationResult.
   * @param options Verification options (including optional external payload settings).
   */
  CoseSign1SignatureValidator(std::string validator_name, VerifyOptions options);

  ValidationResult Validate(const ParsedCoseSign1& input, const CoseSign1ValidationContext& context) const override;

 private:
  std::string validator_name_;
  VerifyOptions options_;

  // Mutable cache for provider materialization.
  // This is safe because Validate is logically const but may need to own bytes.
  mutable std::vector<std::uint8_t> owned_external_payload_;
};

} // namespace cosesign1::validation
