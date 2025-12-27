#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "abstractions.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cosesign1_x509_result cosesign1_x509_result;

typedef struct cosesign1_x509_chain_options {
    int32_t trust_mode;       /* 0=System, 1=CustomRoots */
    int32_t revocation_mode;  /* 0=NoCheck, 1=Online, 2=Offline */
    bool allow_untrusted_roots;
} cosesign1_x509_chain_options;

void cosesign1_x509_result_free(cosesign1_x509_result* res);
bool cosesign1_x509_result_is_valid(const cosesign1_x509_result* res);
const char* cosesign1_x509_result_validator_name(const cosesign1_x509_result* res);
size_t cosesign1_x509_result_failure_count(const cosesign1_x509_result* res);
cosesign1_failure_view cosesign1_x509_result_failure_at(const cosesign1_x509_result* res, size_t index);
size_t cosesign1_x509_result_metadata_count(const cosesign1_x509_result* res);
cosesign1_kv_view cosesign1_x509_result_metadata_at(const cosesign1_x509_result* res, size_t index);

cosesign1_x509_result* cosesign1_x509_validate_x5c_chain(
    const cosesign1_byte_view* certs,
    size_t cert_count,
    const cosesign1_byte_view* trusted_roots,
    size_t trusted_root_count,
    cosesign1_x509_chain_options options);

// Verify a COSE_Sign1 using an embedded `x5c` chain.
//
// Behavior:
// - Resolves the signing key from `x5c`.
// - Verifies the COSE signature.
// - Enforces X.509 chain trust as a message validator.
//
// `payload` is nullable for embedded-payload messages. For detached payloads, provide external payload bytes.
cosesign1_x509_result* cosesign1_x509_verify_cose_sign1_with_x5c_chain(
    const uint8_t* cose,
    size_t cose_len,
    const uint8_t* payload, /* nullable */
    size_t payload_len,
    const cosesign1_byte_view* trusted_roots,
    size_t trusted_root_count,
    cosesign1_x509_chain_options options);

#ifdef __cplusplus
} /* extern "C" */
#endif
