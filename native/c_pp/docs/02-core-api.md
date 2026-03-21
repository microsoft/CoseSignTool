# Core API (C++)

The core C++ surface is in `<cose/sign1/validation.hpp>`.

## Types

- `cose::ValidatorBuilder`: constructs a validator; owns a `cose_sign1_validator_builder_t*`
- `cose::Validator`: validates COSE_Sign1 bytes
- `cose::ValidationResult`: reports success/failure + provides a failure message
- `cose::cose_error`: thrown when a C API call returns a non-`COSE_OK` status

> **Namespace note:** All types live in `cose::sign1`. The umbrella header `<cose/cose.hpp>`
> imports them into `cose::` so you can write `cose::ValidatorBuilder` instead of
> `cose::sign1::ValidatorBuilder`.

## Minimal example

```cpp
#include <cose/cose.hpp>
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

## Trust plans

For trust plan and policy authoring, see [05-trust-plans.md](05-trust-plans.md).

## Extension packs

For registering certificate, MST, or AKV packs, see [04-packs.md](04-packs.md).
