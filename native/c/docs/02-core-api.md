# Core API (C)

The base validation API is in `<cose/cose_sign1.h>`.

## Basic flow

1) Create a builder
2) Optionally enable packs on the builder
3) Build a validator
4) Validate bytes
5) Inspect the result

## Minimal example

```c
#include <cose/cose_sign1.h>
#include <stdlib.h>

int validate(const unsigned char* msg, size_t msg_len) {
    cose_validator_builder_t* builder = NULL;
    cose_validator_t* validator = NULL;
    cose_validation_result_t* result = NULL;

    if (cose_validator_builder_new(&builder) != COSE_OK) return 1;

    if (cose_validator_builder_build(builder, &validator) != COSE_OK) {
        cose_validator_builder_free(builder);
        return 1;
    }

    // Builder can be freed after build.
    cose_validator_builder_free(builder);

    if (cose_validator_validate_bytes(validator, msg, msg_len, NULL, 0, &result) != COSE_OK) {
        cose_validator_free(validator);
        return 1;
    }

    bool ok = false;
    (void)cose_validation_result_is_success(result, &ok);

    cose_validation_result_free(result);
    cose_validator_free(validator);

    return ok ? 0 : 2;
}
```

## Detached payload

`cose_validator_validate_bytes` accepts an optional detached payload buffer. Pass `NULL, 0` for embedded payload.
