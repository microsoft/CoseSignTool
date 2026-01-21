// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COSE_TRUST_H
#define COSE_TRUST_H

/**
 * @file cose_trust.h
 * @brief C API for trust-plan authoring (bundled compiled trust plans)
 */

#include <cose/cose_sign1.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque handle for building a trust plan.
typedef struct cose_trust_plan_builder_t cose_trust_plan_builder_t;

// Opaque handle for building a custom trust policy (minimal fluent surface).
typedef struct cose_trust_policy_builder_t cose_trust_policy_builder_t;

// Opaque handle for a bundled compiled trust plan.
typedef struct cose_compiled_trust_plan_t cose_compiled_trust_plan_t;

/**
 * @brief Create a trust policy builder bound to the packs currently configured on a validator builder.
 *
 * This builder starts empty and lets callers express a minimal set of message-scope requirements.
 */
cose_status_t cose_trust_policy_builder_new_from_validator_builder(
    const cose_validator_builder_t* builder,
    cose_trust_policy_builder_t** out_policy_builder
);

/**
 * @brief Free a trust policy builder.
 */
void cose_trust_policy_builder_free(cose_trust_policy_builder_t* policy_builder);

/**
 * @brief Set the next composition operator to AND.
 */
cose_status_t cose_trust_policy_builder_and(cose_trust_policy_builder_t* policy_builder);

/**
 * @brief Set the next composition operator to OR.
 */
cose_status_t cose_trust_policy_builder_or(cose_trust_policy_builder_t* policy_builder);

/**
 * @brief Require Content-Type to be present and non-empty.
 */
cose_status_t cose_trust_policy_builder_require_content_type_non_empty(
    cose_trust_policy_builder_t* policy_builder
);

/**
 * @brief Require Content-Type to equal the provided value.
 */
cose_status_t cose_trust_policy_builder_require_content_type_eq(
    cose_trust_policy_builder_t* policy_builder,
    const char* content_type_utf8
);

/**
 * @brief Require a detached payload to be present.
 */
cose_status_t cose_trust_policy_builder_require_detached_payload_present(
    cose_trust_policy_builder_t* policy_builder
);

/**
 * @brief Require a detached payload to be absent.
 */
cose_status_t cose_trust_policy_builder_require_detached_payload_absent(
    cose_trust_policy_builder_t* policy_builder
);

/**
 * @brief If a counter-signature verifier produced envelope-integrity evidence, require that it
 * indicates the COSE_Sign1 Sig_structure is intact.
 *
 * If the evidence is missing, this requirement is treated as trusted.
 */
cose_status_t cose_trust_policy_builder_require_counter_signature_envelope_sig_structure_intact_or_missing(
    cose_trust_policy_builder_t* policy_builder
);

/**
 * @brief Require CWT claims (header parameter label 15) to be present.
 */
cose_status_t cose_trust_policy_builder_require_cwt_claims_present(
    cose_trust_policy_builder_t* policy_builder
);

/**
 * @brief Require CWT claims (header parameter label 15) to be absent.
 */
cose_status_t cose_trust_policy_builder_require_cwt_claims_absent(
    cose_trust_policy_builder_t* policy_builder
);

/**
 * @brief Require that CWT `iss` (issuer) equals the provided value.
 */
cose_status_t cose_trust_policy_builder_require_cwt_iss_eq(
    cose_trust_policy_builder_t* policy_builder,
    const char* iss_utf8
);

/**
 * @brief Require that CWT `sub` (subject) equals the provided value.
 */
cose_status_t cose_trust_policy_builder_require_cwt_sub_eq(
    cose_trust_policy_builder_t* policy_builder,
    const char* sub_utf8
);

/**
 * @brief Require that CWT `aud` (audience) equals the provided value.
 */
cose_status_t cose_trust_policy_builder_require_cwt_aud_eq(
    cose_trust_policy_builder_t* policy_builder,
    const char* aud_utf8
);

/**
 * @brief Require that a numeric-label CWT claim is present.
 */
cose_status_t cose_trust_policy_builder_require_cwt_claim_label_present(
    cose_trust_policy_builder_t* policy_builder,
    int64_t label
);

/**
 * @brief Require that a text-key CWT claim is present.
 */
cose_status_t cose_trust_policy_builder_require_cwt_claim_text_present(
    cose_trust_policy_builder_t* policy_builder,
    const char* key_utf8
);

/**
 * @brief Require that a numeric-label CWT claim decodes to an int64 and equals the provided value.
 */
cose_status_t cose_trust_policy_builder_require_cwt_claim_label_i64_eq(
    cose_trust_policy_builder_t* policy_builder,
    int64_t label,
    int64_t value
);

/**
 * @brief Require that a numeric-label CWT claim decodes to a bool and equals the provided value.
 */
cose_status_t cose_trust_policy_builder_require_cwt_claim_label_bool_eq(
    cose_trust_policy_builder_t* policy_builder,
    int64_t label,
    bool value
);

/**
 * @brief Require that a numeric-label CWT claim decodes to an int64 and is >= the provided value.
 */
cose_status_t cose_trust_policy_builder_require_cwt_claim_label_i64_ge(
    cose_trust_policy_builder_t* policy_builder,
    int64_t label,
    int64_t min
);

/**
 * @brief Require that a numeric-label CWT claim decodes to an int64 and is <= the provided value.
 */
cose_status_t cose_trust_policy_builder_require_cwt_claim_label_i64_le(
    cose_trust_policy_builder_t* policy_builder,
    int64_t label,
    int64_t max
);

/**
 * @brief Require that a text-key CWT claim decodes to a string and equals the provided value.
 */
cose_status_t cose_trust_policy_builder_require_cwt_claim_text_str_eq(
    cose_trust_policy_builder_t* policy_builder,
    const char* key_utf8,
    const char* value_utf8
);

/**
 * @brief Require that a numeric-label CWT claim decodes to a string and equals the provided value.
 */
cose_status_t cose_trust_policy_builder_require_cwt_claim_label_str_eq(
    cose_trust_policy_builder_t* policy_builder,
    int64_t label,
    const char* value_utf8
);

/**
 * @brief Require that a numeric-label CWT claim decodes to a string and starts with the prefix.
 */
cose_status_t cose_trust_policy_builder_require_cwt_claim_label_str_starts_with(
    cose_trust_policy_builder_t* policy_builder,
    int64_t label,
    const char* prefix_utf8
);

/**
 * @brief Require that a text-key CWT claim decodes to a string and starts with the prefix.
 */
cose_status_t cose_trust_policy_builder_require_cwt_claim_text_str_starts_with(
    cose_trust_policy_builder_t* policy_builder,
    const char* key_utf8,
    const char* prefix_utf8
);

/**
 * @brief Require that a numeric-label CWT claim decodes to a string and contains the needle.
 */
cose_status_t cose_trust_policy_builder_require_cwt_claim_label_str_contains(
    cose_trust_policy_builder_t* policy_builder,
    int64_t label,
    const char* needle_utf8
);

/**
 * @brief Require that a text-key CWT claim decodes to a string and contains the needle.
 */
cose_status_t cose_trust_policy_builder_require_cwt_claim_text_str_contains(
    cose_trust_policy_builder_t* policy_builder,
    const char* key_utf8,
    const char* needle_utf8
);

/**
 * @brief Require that a text-key CWT claim decodes to a bool and equals the provided value.
 */
cose_status_t cose_trust_policy_builder_require_cwt_claim_text_bool_eq(
    cose_trust_policy_builder_t* policy_builder,
    const char* key_utf8,
    bool value
);

/**
 * @brief Require that a text-key CWT claim decodes to an int64 and is >= the provided value.
 */
cose_status_t cose_trust_policy_builder_require_cwt_claim_text_i64_ge(
    cose_trust_policy_builder_t* policy_builder,
    const char* key_utf8,
    int64_t min
);

/**
 * @brief Require that a text-key CWT claim decodes to an int64 and is <= the provided value.
 */
cose_status_t cose_trust_policy_builder_require_cwt_claim_text_i64_le(
    cose_trust_policy_builder_t* policy_builder,
    const char* key_utf8,
    int64_t max
);

/**
 * @brief Require that a text-key CWT claim decodes to an int64 and equals the provided value.
 */
cose_status_t cose_trust_policy_builder_require_cwt_claim_text_i64_eq(
    cose_trust_policy_builder_t* policy_builder,
    const char* key_utf8,
    int64_t value
);

/**
 * @brief Require that CWT `exp` (expiration time) is >= the provided value.
 */
cose_status_t cose_trust_policy_builder_require_cwt_exp_ge(
    cose_trust_policy_builder_t* policy_builder,
    int64_t min
);

/**
 * @brief Require that CWT `exp` (expiration time) is <= the provided value.
 */
cose_status_t cose_trust_policy_builder_require_cwt_exp_le(
    cose_trust_policy_builder_t* policy_builder,
    int64_t max
);

/**
 * @brief Require that CWT `nbf` (not before) is >= the provided value.
 */
cose_status_t cose_trust_policy_builder_require_cwt_nbf_ge(
    cose_trust_policy_builder_t* policy_builder,
    int64_t min
);

/**
 * @brief Require that CWT `nbf` (not before) is <= the provided value.
 */
cose_status_t cose_trust_policy_builder_require_cwt_nbf_le(
    cose_trust_policy_builder_t* policy_builder,
    int64_t max
);

/**
 * @brief Require that CWT `iat` (issued at) is >= the provided value.
 */
cose_status_t cose_trust_policy_builder_require_cwt_iat_ge(
    cose_trust_policy_builder_t* policy_builder,
    int64_t min
);

/**
 * @brief Require that CWT `iat` (issued at) is <= the provided value.
 */
cose_status_t cose_trust_policy_builder_require_cwt_iat_le(
    cose_trust_policy_builder_t* policy_builder,
    int64_t max
);

/**
 * @brief Compile this policy into a bundled compiled trust plan.
 */
cose_status_t cose_trust_policy_builder_compile(
    cose_trust_policy_builder_t* policy_builder,
    cose_compiled_trust_plan_t** out_plan
);

/**
 * @brief Create a trust plan builder bound to the packs currently configured on a validator builder.
 *
 * The pack list is used to (a) discover pack default trust plans and (b) validate that a compiled
 * plan can be satisfied by the configured packs.
 */
cose_status_t cose_trust_plan_builder_new_from_validator_builder(
    const cose_validator_builder_t* builder,
    cose_trust_plan_builder_t** out_plan_builder
);

/**
 * @brief Free a trust plan builder.
 */
void cose_trust_plan_builder_free(cose_trust_plan_builder_t* plan_builder);

/**
 * @brief Select all configured packs' default trust plans.
 *
 * Packs that do not provide a default plan are ignored.
 */
cose_status_t cose_trust_plan_builder_add_all_pack_default_plans(
    cose_trust_plan_builder_t* plan_builder
);

/**
 * @brief Select a specific pack's default trust plan by pack name.
 *
 * @param pack_name_utf8 Pack name (must match CoseSign1TrustPack::name())
 */
cose_status_t cose_trust_plan_builder_add_pack_default_plan_by_name(
    cose_trust_plan_builder_t* plan_builder,
    const char* pack_name_utf8
);

/**
 * @brief Get the number of configured packs captured on this plan builder.
 */
cose_status_t cose_trust_plan_builder_pack_count(
    const cose_trust_plan_builder_t* plan_builder,
    size_t* out_count
);

/**
 * @brief Get the pack name at `index`.
 *
 * Ownership: caller must free via `cose_string_free`.
 */
char* cose_trust_plan_builder_pack_name_utf8(
    const cose_trust_plan_builder_t* plan_builder,
    size_t index
);

/**
 * @brief Returns whether the pack at `index` provides a default trust plan.
 */
cose_status_t cose_trust_plan_builder_pack_has_default_plan(
    const cose_trust_plan_builder_t* plan_builder,
    size_t index,
    bool* out_has_default
);

/**
 * @brief Clear any selected plans on this builder.
 */
cose_status_t cose_trust_plan_builder_clear_selected_plans(
    cose_trust_plan_builder_t* plan_builder
);

/**
 * @brief Compile the selected plans as an OR-composed bundled plan.
 */
cose_status_t cose_trust_plan_builder_compile_or(
    cose_trust_plan_builder_t* plan_builder,
    cose_compiled_trust_plan_t** out_plan
);

/**
 * @brief Compile the selected plans as an AND-composed bundled plan.
 */
cose_status_t cose_trust_plan_builder_compile_and(
    cose_trust_plan_builder_t* plan_builder,
    cose_compiled_trust_plan_t** out_plan
);

/**
 * @brief Compile an allow-all bundled plan.
 */
cose_status_t cose_trust_plan_builder_compile_allow_all(
    cose_trust_plan_builder_t* plan_builder,
    cose_compiled_trust_plan_t** out_plan
);

/**
 * @brief Compile a deny-all bundled plan.
 */
cose_status_t cose_trust_plan_builder_compile_deny_all(
    cose_trust_plan_builder_t* plan_builder,
    cose_compiled_trust_plan_t** out_plan
);

/**
 * @brief Free a bundled compiled trust plan.
 */
void cose_compiled_trust_plan_free(cose_compiled_trust_plan_t* plan);

/**
 * @brief Attach a bundled compiled trust plan to a validator builder.
 *
 * Once set, the eventual validator uses the bundled plan rather than OR-composing pack default plans.
 */
cose_status_t cose_validator_builder_with_compiled_trust_plan(
    cose_validator_builder_t* builder,
    const cose_compiled_trust_plan_t* plan
);

#ifdef __cplusplus
}
#endif

#endif // COSE_TRUST_H
