<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# Examples

This page contains copy/paste-friendly snippets to consume the **native** surface.

## C++: verify from bytes (in-memory)

```cpp
#include <cosesign1/cosesign1.hpp>

#include <cstdint>
#include <vector>

bool verify(const std::vector<std::uint8_t>& cose,
            const std::vector<std::uint8_t>& public_key_der)
{
    auto msg = cosesign1::CoseSign1::from_bytes(cose);
    const auto res = msg.verify_signature(nullptr, &public_key_der);
    return res.ok();
}
```

## C: verify from bytes (in-memory)

```c
#include <stdbool.h>
#include <stdint.h>

#include "cosesign1/cosesign1.h"

bool verify(const uint8_t* cose, size_t cose_len,
            const uint8_t* pubkey, size_t pubkey_len)
{
    cosesign1_validation_result* res = cosesign1_validation_verify_signature(
        cose, cose_len,
        /*payload*/ NULL, 0,
        pubkey, pubkey_len);

    const bool ok = cosesign1_validation_result_is_valid(res);
    cosesign1_validation_result_free(res);
    return ok;
}
```

## Minimal CLI pattern

For working examples, see:

- C++ consumer app: `native/docs/hello-world/cpp`
- C consumer app: `native/docs/hello-world/c`
