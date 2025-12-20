#pragma once

#include "cosesign1/validation/validation_result.h"

namespace cosesign1::validation {

namespace internal {
void ValidatorDtorAnchor() noexcept;
} // namespace internal

template <typename T>
class IValidator {
 public:
  virtual ~IValidator() { internal::ValidatorDtorAnchor(); }

  virtual ValidationResult Validate(const T& input) const = 0;
};

} // namespace cosesign1::validation
