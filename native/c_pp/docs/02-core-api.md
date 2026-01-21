# Core API (C++)

The core C++ surface is in `<cose/validator.hpp>`.

## Types

- `cose::ValidatorBuilder`: constructs a validator; owns a `cose_validator_builder_t*`
- `cose::Validator`: validates COSE_Sign1 bytes
- `cose::ValidationResult`: reports success/failure + provides a failure message
- `cose::cose_error`: thrown when a C API call returns a non-`COSE_OK` status

## Minimal example

```cpp
#include <cose/validator.hpp>
#include <vector>

bool validate(const std::vector<uint8_t>& msg)
{
    auto validator = cose::ValidatorBuilder().Build();
    auto result = validator.Validate(msg);

    if (!result.Ok()) {
        // result.FailureMessage() contains a human-readable reason
        return false;
    }

    return true;
}
```

## Detached payload

Use the second parameter of `Validator::Validate`:

```cpp
auto result = validator.Validate(cose_bytes, detached_payload);
```
