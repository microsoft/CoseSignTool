#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "abstractions.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cosesign1_validation_result cosesign1_validation_result;

typedef struct cosesign1_reader {
    void* ctx;
    /* return 0 on success, nonzero on failure */
    int32_t (*read)(void* ctx, uint8_t* out, size_t out_len, size_t* bytes_read);
    /* origin: 0=SET, 1=CUR, 2=END; return 0 on success */
    int32_t (*seek)(void* ctx, int64_t offset, int32_t origin, uint64_t* new_pos);
} cosesign1_reader;

void cosesign1_validation_result_free(cosesign1_validation_result* res);
bool cosesign1_validation_result_is_valid(const cosesign1_validation_result* res);
const char* cosesign1_validation_result_validator_name(const cosesign1_validation_result* res);
size_t cosesign1_validation_result_failure_count(const cosesign1_validation_result* res);
cosesign1_failure_view cosesign1_validation_result_failure_at(const cosesign1_validation_result* res, size_t index);
size_t cosesign1_validation_result_metadata_count(const cosesign1_validation_result* res);
cosesign1_kv_view cosesign1_validation_result_metadata_at(const cosesign1_validation_result* res, size_t index);

cosesign1_validation_result* cosesign1_validation_verify_signature(
    const uint8_t* cose,
    size_t cose_len,
    const uint8_t* payload, /* nullable */
    size_t payload_len,
    const uint8_t* public_key, /* nullable */
    size_t public_key_len);

cosesign1_validation_result* cosesign1_validation_verify_signature_with_payload_reader(
    const uint8_t* cose,
    size_t cose_len,
    cosesign1_reader reader,
    const uint8_t* public_key, /* nullable */
    size_t public_key_len);

#ifdef __cplusplus
} /* extern "C" */
#endif
