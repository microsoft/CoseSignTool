#pragma once

#include <optional>
#include <string>

namespace cosesign1::validation {

struct ValidationFailure {
  std::string message;
  std::optional<std::string> error_code;
  std::optional<std::string> property_name;
  std::optional<std::string> attempted_value;
  std::optional<std::string> exception_message;
};

} // namespace cosesign1::validation
