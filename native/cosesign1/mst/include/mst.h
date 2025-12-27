#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "abstractions.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cosesign1_mst_result cosesign1_mst_result;
typedef struct cosesign1_mst_keystore cosesign1_mst_keystore;

typedef struct cosesign1_mst_verification_options {
    int32_t authorized_receipt_behavior;   /* 0=VerifyAnyMatching, 1=VerifyAllMatching, 2=RequireAll */
    int32_t unauthorized_receipt_behavior; /* 0=VerifyAll, 1=IgnoreAll, 2=FailIfPresent */
} cosesign1_mst_verification_options;

void cosesign1_mst_result_free(cosesign1_mst_result* res);
bool cosesign1_mst_result_is_valid(const cosesign1_mst_result* res);
const char* cosesign1_mst_result_validator_name(const cosesign1_mst_result* res);
size_t cosesign1_mst_result_failure_count(const cosesign1_mst_result* res);
cosesign1_failure_view cosesign1_mst_result_failure_at(const cosesign1_mst_result* res, size_t index);
size_t cosesign1_mst_result_metadata_count(const cosesign1_mst_result* res);
cosesign1_kv_view cosesign1_mst_result_metadata_at(const cosesign1_mst_result* res, size_t index);

cosesign1_mst_keystore* cosesign1_mst_keystore_new(void);
void cosesign1_mst_keystore_free(cosesign1_mst_keystore* store);

cosesign1_mst_result* cosesign1_mst_keystore_add_issuer_jwks(
    cosesign1_mst_keystore* store,
    const char* issuer_host,
    const uint8_t* jwks_json,
    size_t jwks_len);

cosesign1_mst_result* cosesign1_mst_verify_transparent_statement(
    const cosesign1_mst_keystore* store,
    const uint8_t* transparent_statement_cose_sign1,
    size_t transparent_statement_len,
    const cosesign1_string_view* authorized_domains,
    size_t authorized_domain_count,
    cosesign1_mst_verification_options options);

#ifdef __cplusplus
} /* extern "C" */
#endif
