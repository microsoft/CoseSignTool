# C++ projection

For the full C++ developer guide (including vcpkg consumption), see [native/c_pp/docs/README.md](../c_pp/docs/README.md).

## Audience

You want an ergonomic C++ wrapper over the C ABI with RAII and modern types.

## API surface

- Headers live in [native/c_pp/include/](../c_pp/include/).
- The library wraps the C projection and stays ABI-stable by delegating to the C ABI.

Consume via vcpkg:

```cmake
find_package(cose_sign1_validation CONFIG REQUIRED)

target_link_libraries(your_target PRIVATE cosesign1_validation_native::cose_sign1_cpp)
```

## Notes on exceptions / error model

The C++ API typically reports failures via return objects (and may throw only for programmer errors, depending on the wrapper). Follow the header docs for each type.

## Testing and examples

- Examples: [native/c_pp/examples/](../c_pp/examples/)
- Tests: [native/c_pp/tests/](../c_pp/tests/)

See [testing + ASAN + coverage](06-testing-coverage-asan.md).
