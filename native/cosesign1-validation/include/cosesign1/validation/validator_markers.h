// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

/**
 * @file validator_markers.h
 * @brief Marker interfaces used to express validator ordering requirements.
 */

namespace cosesign1::validation {

namespace internal {
void LastCoseSign1ValidatorDtorAnchor() noexcept;
} // namespace internal

// Marker interface for validators that must execute after all other validators.
class ILastCoseSign1Validator {
 public:
  virtual ~ILastCoseSign1Validator() { internal::LastCoseSign1ValidatorDtorAnchor(); }
};

} // namespace cosesign1::validation
