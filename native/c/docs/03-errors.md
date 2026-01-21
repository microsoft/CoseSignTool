# Errors (C)

## Status codes

Most APIs return `cose_status_t`:

- `COSE_OK`: success
- `COSE_ERR`: failure; call `cose_last_error_message_utf8()` to get details
- `COSE_PANIC`: Rust panic crossed the FFI boundary
- `COSE_INVALID_ARG`: null pointer / invalid argument

## Getting the last error

`cose_last_error_message_utf8()` returns a newly allocated UTF-8 string for the current thread.

```c
char* msg = cose_last_error_message_utf8();
if (msg) {
    // log msg
    cose_string_free(msg);
}
```

You can clear it with `cose_last_error_clear()`.

## Validation failures vs call failures

- A call failure (e.g., invalid input buffer) returns a non-`COSE_OK` status.
- A validation failure still returns `COSE_OK`, but `cose_validation_result_is_success(..., &ok)` will set `ok=false`.

To get a human-readable validation failure reason:

```c
char* failure = cose_validation_result_failure_message_utf8(result);
if (failure) {
    // log failure
    cose_string_free(failure);
}
```
