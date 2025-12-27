#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cosesign1_failure_view {
    const char* message;
    const char* error_code; /* nullable */
} cosesign1_failure_view;

typedef struct cosesign1_kv_view {
    const char* key;
    const char* value;
} cosesign1_kv_view;

typedef struct cosesign1_byte_view {
    const uint8_t* data;
    size_t len;
} cosesign1_byte_view;

typedef struct cosesign1_string_view {
    const char* data;
} cosesign1_string_view;

typedef struct cosesign1_abstractions_result cosesign1_abstractions_result;

typedef struct cosesign1_abstractions_info {
    bool is_detached;
    cosesign1_byte_view payload;
} cosesign1_abstractions_info;

void cosesign1_abstractions_result_free(cosesign1_abstractions_result* res);
bool cosesign1_abstractions_result_is_valid(const cosesign1_abstractions_result* res);
const char* cosesign1_abstractions_result_validator_name(const cosesign1_abstractions_result* res);
size_t cosesign1_abstractions_result_failure_count(const cosesign1_abstractions_result* res);
cosesign1_failure_view cosesign1_abstractions_result_failure_at(const cosesign1_abstractions_result* res, size_t index);
size_t cosesign1_abstractions_result_metadata_count(const cosesign1_abstractions_result* res);
cosesign1_kv_view cosesign1_abstractions_result_metadata_at(const cosesign1_abstractions_result* res, size_t index);

cosesign1_abstractions_result* cosesign1_abstractions_inspect(
    const uint8_t* cose,
    size_t cose_len,
    cosesign1_abstractions_info* out_info);

#ifdef __cplusplus
} /* extern "C" */
#endif
