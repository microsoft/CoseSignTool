# Errors (C++)

The C++ wrapper throws `cose::cose_error` when a C API call fails.

Under the hood it reads the thread-local last error message from the C API:

- `cose_last_error_message_utf8()`
- `cose_string_free()`

Validation failures are not thrown; they are represented by `cose::ValidationResult`:

- `result.Ok()` returns `false`
- `result.FailureMessage()` returns a message string
