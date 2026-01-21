// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file trust.hpp
 * @brief C++ RAII wrappers for trust-plan authoring (Trust pack)
 */

#ifndef COSE_TRUST_HPP
#define COSE_TRUST_HPP

#include <cose/cose_trust.h>
#include <cose/validator.hpp>

#include <cstdint>
#include <string>
#include <vector>
#include <utility>

namespace cose {

class CompiledTrustPlan {
public:
    explicit CompiledTrustPlan(cose_compiled_trust_plan_t* plan) : plan_(plan) {
        if (!plan_) {
            throw cose_error("Null compiled trust plan");
        }
    }

    ~CompiledTrustPlan() {
        if (plan_) {
            cose_compiled_trust_plan_free(plan_);
        }
    }

    CompiledTrustPlan(const CompiledTrustPlan&) = delete;
    CompiledTrustPlan& operator=(const CompiledTrustPlan&) = delete;

    CompiledTrustPlan(CompiledTrustPlan&& other) noexcept : plan_(other.plan_) {
        other.plan_ = nullptr;
    }

    CompiledTrustPlan& operator=(CompiledTrustPlan&& other) noexcept {
        if (this != &other) {
            if (plan_) {
                cose_compiled_trust_plan_free(plan_);
            }
            plan_ = other.plan_;
            other.plan_ = nullptr;
        }
        return *this;
    }

    const cose_compiled_trust_plan_t* native_handle() const {
        return plan_;
    }

private:
    cose_compiled_trust_plan_t* plan_;

    friend class TrustPlanBuilder;
};

class TrustPlanBuilder {
public:
    explicit TrustPlanBuilder(const ValidatorBuilder& validator_builder) {
        cose_status_t status = cose_trust_plan_builder_new_from_validator_builder(
            validator_builder.native_handle(),
            &builder_
        );
        if (status != COSE_OK || !builder_) {
            throw cose_error(status);
        }
    }

    ~TrustPlanBuilder() {
        if (builder_) {
            cose_trust_plan_builder_free(builder_);
        }
    }

    TrustPlanBuilder(const TrustPlanBuilder&) = delete;
    TrustPlanBuilder& operator=(const TrustPlanBuilder&) = delete;

    TrustPlanBuilder(TrustPlanBuilder&& other) noexcept : builder_(other.builder_) {
        other.builder_ = nullptr;
    }

    TrustPlanBuilder& operator=(TrustPlanBuilder&& other) noexcept {
        if (this != &other) {
            if (builder_) {
                cose_trust_plan_builder_free(builder_);
            }
            builder_ = other.builder_;
            other.builder_ = nullptr;
        }
        return *this;
    }

    TrustPlanBuilder& AddAllPackDefaultPlans() {
        CheckBuilder();
        cose_status_t status = cose_trust_plan_builder_add_all_pack_default_plans(builder_);
        if (status != COSE_OK) {
            throw cose_error(status);
        }
        return *this;
    }

    TrustPlanBuilder& AddPackDefaultPlanByName(const std::string& pack_name) {
        CheckBuilder();
        cose_status_t status = cose_trust_plan_builder_add_pack_default_plan_by_name(
            builder_,
            pack_name.c_str()
        );
        if (status != COSE_OK) {
            throw cose_error(status);
        }
        return *this;
    }

    size_t PackCount() const {
        CheckBuilder();
        size_t count = 0;
        cose_status_t status = cose_trust_plan_builder_pack_count(builder_, &count);
        if (status != COSE_OK) {
            throw cose_error(status);
        }
        return count;
    }

    std::string PackName(size_t index) const {
        CheckBuilder();
        char* s = cose_trust_plan_builder_pack_name_utf8(builder_, index);
        if (!s) {
            throw cose_error(COSE_ERR);
        }
        std::string out(s);
        cose_string_free(s);
        return out;
    }

    bool PackHasDefaultPlan(size_t index) const {
        CheckBuilder();
        bool has_default = false;
        cose_status_t status = cose_trust_plan_builder_pack_has_default_plan(builder_, index, &has_default);
        if (status != COSE_OK) {
            throw cose_error(status);
        }
        return has_default;
    }

    TrustPlanBuilder& ClearSelectedPlans() {
        CheckBuilder();
        cose_status_t status = cose_trust_plan_builder_clear_selected_plans(builder_);
        if (status != COSE_OK) {
            throw cose_error(status);
        }
        return *this;
    }

    CompiledTrustPlan CompileOr() {
        CheckBuilder();
        cose_compiled_trust_plan_t* out = nullptr;
        cose_status_t status = cose_trust_plan_builder_compile_or(builder_, &out);
        if (status != COSE_OK || !out) {
            throw cose_error(status);
        }
        return CompiledTrustPlan(out);
    }

    CompiledTrustPlan CompileAnd() {
        CheckBuilder();
        cose_compiled_trust_plan_t* out = nullptr;
        cose_status_t status = cose_trust_plan_builder_compile_and(builder_, &out);
        if (status != COSE_OK || !out) {
            throw cose_error(status);
        }
        return CompiledTrustPlan(out);
    }

    CompiledTrustPlan CompileAllowAll() {
        CheckBuilder();
        cose_compiled_trust_plan_t* out = nullptr;
        cose_status_t status = cose_trust_plan_builder_compile_allow_all(builder_, &out);
        if (status != COSE_OK || !out) {
            throw cose_error(status);
        }
        return CompiledTrustPlan(out);
    }

    CompiledTrustPlan CompileDenyAll() {
        CheckBuilder();
        cose_compiled_trust_plan_t* out = nullptr;
        cose_status_t status = cose_trust_plan_builder_compile_deny_all(builder_, &out);
        if (status != COSE_OK || !out) {
            throw cose_error(status);
        }
        return CompiledTrustPlan(out);
    }

private:
    cose_trust_plan_builder_t* builder_ = nullptr;

    void CheckBuilder() const {
        if (!builder_) {
            throw cose_error("TrustPlanBuilder already consumed or invalid");
        }
    }
};

class TrustPolicyBuilder {
public:
    explicit TrustPolicyBuilder(const ValidatorBuilder& validator_builder) {
        cose_status_t status = cose_trust_policy_builder_new_from_validator_builder(
            validator_builder.native_handle(),
            &builder_
        );
        if (status != COSE_OK || !builder_) {
            throw cose_error(status);
        }
    }

    ~TrustPolicyBuilder() {
        if (builder_) {
            cose_trust_policy_builder_free(builder_);
        }
    }

    TrustPolicyBuilder(const TrustPolicyBuilder&) = delete;
    TrustPolicyBuilder& operator=(const TrustPolicyBuilder&) = delete;

    TrustPolicyBuilder(TrustPolicyBuilder&& other) noexcept : builder_(other.builder_) {
        other.builder_ = nullptr;
    }

    TrustPolicyBuilder& operator=(TrustPolicyBuilder&& other) noexcept {
        if (this != &other) {
            if (builder_) {
                cose_trust_policy_builder_free(builder_);
            }
            builder_ = other.builder_;
            other.builder_ = nullptr;
        }
        return *this;
    }

    /**
     * @brief Expose the underlying C policy-builder handle for optional pack projections.
     */
    cose_trust_policy_builder_t* native_handle() const {
        return builder_;
    }

    TrustPolicyBuilder& And() {
        CheckBuilder();
        cose_status_t status = cose_trust_policy_builder_and(builder_);
        if (status != COSE_OK) {
            throw cose_error(status);
        }
        return *this;
    }

    TrustPolicyBuilder& Or() {
        CheckBuilder();
        cose_status_t status = cose_trust_policy_builder_or(builder_);
        if (status != COSE_OK) {
            throw cose_error(status);
        }
        return *this;
    }

    TrustPolicyBuilder& RequireContentTypeNonEmpty() {
        CheckBuilder();
        cose_status_t status = cose_trust_policy_builder_require_content_type_non_empty(builder_);
        if (status != COSE_OK) {
            throw cose_error(status);
        }
        return *this;
    }

    TrustPolicyBuilder& RequireContentTypeEq(const std::string& content_type) {
        CheckBuilder();
        cose_status_t status = cose_trust_policy_builder_require_content_type_eq(
            builder_,
            content_type.c_str()
        );
        if (status != COSE_OK) {
            throw cose_error(status);
        }
        return *this;
    }

    TrustPolicyBuilder& RequireDetachedPayloadPresent() {
        CheckBuilder();
        cose_status_t status = cose_trust_policy_builder_require_detached_payload_present(builder_);
        if (status != COSE_OK) {
            throw cose_error(status);
        }
        return *this;
    }

    TrustPolicyBuilder& RequireDetachedPayloadAbsent() {
        CheckBuilder();
        cose_status_t status = cose_trust_policy_builder_require_detached_payload_absent(builder_);
        if (status != COSE_OK) {
            throw cose_error(status);
        }
        return *this;
    }

    TrustPolicyBuilder& RequireCounterSignatureEnvelopeSigStructureIntactOrMissing() {
        CheckBuilder();
        cose_status_t status =
            cose_trust_policy_builder_require_counter_signature_envelope_sig_structure_intact_or_missing(
                builder_
            );
        if (status != COSE_OK) {
            throw cose_error(status);
        }
        return *this;
    }

    TrustPolicyBuilder& RequireCwtClaimsPresent() {
        CheckBuilder();
        cose_status_t status = cose_trust_policy_builder_require_cwt_claims_present(builder_);
        if (status != COSE_OK) {
            throw cose_error(status);
        }
        return *this;
    }

    TrustPolicyBuilder& RequireCwtClaimsAbsent() {
        CheckBuilder();
        cose_status_t status = cose_trust_policy_builder_require_cwt_claims_absent(builder_);
        if (status != COSE_OK) {
            throw cose_error(status);
        }
        return *this;
    }

    TrustPolicyBuilder& RequireCwtIssEq(const std::string& iss) {
        CheckBuilder();
        cose_status_t status = cose_trust_policy_builder_require_cwt_iss_eq(
            builder_,
            iss.c_str()
        );
        if (status != COSE_OK) {
            throw cose_error(status);
        }
        return *this;
    }

    TrustPolicyBuilder& RequireCwtSubEq(const std::string& sub) {
        CheckBuilder();
        cose_status_t status = cose_trust_policy_builder_require_cwt_sub_eq(
            builder_,
            sub.c_str()
        );
        if (status != COSE_OK) {
            throw cose_error(status);
        }
        return *this;
    }

    TrustPolicyBuilder& RequireCwtAudEq(const std::string& aud) {
        CheckBuilder();
        cose_status_t status = cose_trust_policy_builder_require_cwt_aud_eq(
            builder_,
            aud.c_str()
        );
        if (status != COSE_OK) {
            throw cose_error(status);
        }
        return *this;
    }

    TrustPolicyBuilder& RequireCwtClaimLabelPresent(int64_t label) {
        CheckBuilder();
        cose_status_t status = cose_trust_policy_builder_require_cwt_claim_label_present(
            builder_,
            label
        );
        if (status != COSE_OK) {
            throw cose_error(status);
        }
        return *this;
    }

    TrustPolicyBuilder& RequireCwtClaimTextPresent(const std::string& key) {
        CheckBuilder();
        cose_status_t status = cose_trust_policy_builder_require_cwt_claim_text_present(
            builder_,
            key.c_str()
        );
        if (status != COSE_OK) {
            throw cose_error(status);
        }
        return *this;
    }

    TrustPolicyBuilder& RequireCwtClaimLabelI64Eq(int64_t label, int64_t value) {
        CheckBuilder();
        cose_status_t status = cose_trust_policy_builder_require_cwt_claim_label_i64_eq(
            builder_,
            label,
            value
        );
        if (status != COSE_OK) {
            throw cose_error(status);
        }
        return *this;
    }

    TrustPolicyBuilder& RequireCwtClaimLabelBoolEq(int64_t label, bool value) {
        CheckBuilder();
        cose_status_t status = cose_trust_policy_builder_require_cwt_claim_label_bool_eq(
            builder_,
            label,
            value
        );
        if (status != COSE_OK) {
            throw cose_error(status);
        }
        return *this;
    }

    TrustPolicyBuilder& RequireCwtClaimLabelI64Ge(int64_t label, int64_t min) {
        CheckBuilder();
        cose_status_t status = cose_trust_policy_builder_require_cwt_claim_label_i64_ge(
            builder_,
            label,
            min
        );
        if (status != COSE_OK) {
            throw cose_error(status);
        }
        return *this;
    }

    TrustPolicyBuilder& RequireCwtClaimLabelI64Le(int64_t label, int64_t max) {
        CheckBuilder();
        cose_status_t status = cose_trust_policy_builder_require_cwt_claim_label_i64_le(
            builder_,
            label,
            max
        );
        if (status != COSE_OK) {
            throw cose_error(status);
        }
        return *this;
    }

    TrustPolicyBuilder& RequireCwtClaimTextStrEq(const std::string& key, const std::string& value) {
        CheckBuilder();
        cose_status_t status = cose_trust_policy_builder_require_cwt_claim_text_str_eq(
            builder_,
            key.c_str(),
            value.c_str()
        );
        if (status != COSE_OK) {
            throw cose_error(status);
        }
        return *this;
    }

    TrustPolicyBuilder& RequireCwtClaimLabelStrEq(int64_t label, const std::string& value) {
        CheckBuilder();
        cose_status_t status = cose_trust_policy_builder_require_cwt_claim_label_str_eq(
            builder_,
            label,
            value.c_str()
        );
        if (status != COSE_OK) {
            throw cose_error(status);
        }
        return *this;
    }

    TrustPolicyBuilder& RequireCwtClaimLabelStrStartsWith(int64_t label, const std::string& prefix) {
        CheckBuilder();
        cose_status_t status = cose_trust_policy_builder_require_cwt_claim_label_str_starts_with(
            builder_,
            label,
            prefix.c_str()
        );
        if (status != COSE_OK) {
            throw cose_error(status);
        }
        return *this;
    }

    TrustPolicyBuilder& RequireCwtClaimTextStrStartsWith(
        const std::string& key,
        const std::string& prefix
    ) {
        CheckBuilder();
        cose_status_t status = cose_trust_policy_builder_require_cwt_claim_text_str_starts_with(
            builder_,
            key.c_str(),
            prefix.c_str()
        );
        if (status != COSE_OK) {
            throw cose_error(status);
        }
        return *this;
    }

    TrustPolicyBuilder& RequireCwtClaimLabelStrContains(int64_t label, const std::string& needle) {
        CheckBuilder();
        cose_status_t status = cose_trust_policy_builder_require_cwt_claim_label_str_contains(
            builder_,
            label,
            needle.c_str()
        );
        if (status != COSE_OK) {
            throw cose_error(status);
        }
        return *this;
    }

    TrustPolicyBuilder& RequireCwtClaimTextStrContains(
        const std::string& key,
        const std::string& needle
    ) {
        CheckBuilder();
        cose_status_t status = cose_trust_policy_builder_require_cwt_claim_text_str_contains(
            builder_,
            key.c_str(),
            needle.c_str()
        );
        if (status != COSE_OK) {
            throw cose_error(status);
        }
        return *this;
    }

    TrustPolicyBuilder& RequireCwtClaimTextBoolEq(const std::string& key, bool value) {
        CheckBuilder();
        cose_status_t status = cose_trust_policy_builder_require_cwt_claim_text_bool_eq(
            builder_,
            key.c_str(),
            value
        );
        if (status != COSE_OK) {
            throw cose_error(status);
        }
        return *this;
    }

    TrustPolicyBuilder& RequireCwtClaimTextI64Eq(const std::string& key, int64_t value) {
        CheckBuilder();
        cose_status_t status = cose_trust_policy_builder_require_cwt_claim_text_i64_eq(
            builder_,
            key.c_str(),
            value
        );
        if (status != COSE_OK) {
            throw cose_error(status);
        }
        return *this;
    }

    TrustPolicyBuilder& RequireCwtClaimTextI64Ge(const std::string& key, int64_t min) {
        CheckBuilder();
        cose_status_t status = cose_trust_policy_builder_require_cwt_claim_text_i64_ge(
            builder_,
            key.c_str(),
            min
        );
        if (status != COSE_OK) {
            throw cose_error(status);
        }
        return *this;
    }

    TrustPolicyBuilder& RequireCwtClaimTextI64Le(const std::string& key, int64_t max) {
        CheckBuilder();
        cose_status_t status = cose_trust_policy_builder_require_cwt_claim_text_i64_le(
            builder_,
            key.c_str(),
            max
        );
        if (status != COSE_OK) {
            throw cose_error(status);
        }
        return *this;
    }

    TrustPolicyBuilder& RequireCwtExpGe(int64_t min) {
        CheckBuilder();
        cose_status_t status = cose_trust_policy_builder_require_cwt_exp_ge(builder_, min);
        if (status != COSE_OK) {
            throw cose_error(status);
        }
        return *this;
    }

    TrustPolicyBuilder& RequireCwtExpLe(int64_t max) {
        CheckBuilder();
        cose_status_t status = cose_trust_policy_builder_require_cwt_exp_le(builder_, max);
        if (status != COSE_OK) {
            throw cose_error(status);
        }
        return *this;
    }

    TrustPolicyBuilder& RequireCwtNbfGe(int64_t min) {
        CheckBuilder();
        cose_status_t status = cose_trust_policy_builder_require_cwt_nbf_ge(builder_, min);
        if (status != COSE_OK) {
            throw cose_error(status);
        }
        return *this;
    }

    TrustPolicyBuilder& RequireCwtNbfLe(int64_t max) {
        CheckBuilder();
        cose_status_t status = cose_trust_policy_builder_require_cwt_nbf_le(builder_, max);
        if (status != COSE_OK) {
            throw cose_error(status);
        }
        return *this;
    }

    TrustPolicyBuilder& RequireCwtIatGe(int64_t min) {
        CheckBuilder();
        cose_status_t status = cose_trust_policy_builder_require_cwt_iat_ge(builder_, min);
        if (status != COSE_OK) {
            throw cose_error(status);
        }
        return *this;
    }

    TrustPolicyBuilder& RequireCwtIatLe(int64_t max) {
        CheckBuilder();
        cose_status_t status = cose_trust_policy_builder_require_cwt_iat_le(builder_, max);
        if (status != COSE_OK) {
            throw cose_error(status);
        }
        return *this;
    }

    CompiledTrustPlan Compile() {
        CheckBuilder();
        cose_compiled_trust_plan_t* out = nullptr;
        cose_status_t status = cose_trust_policy_builder_compile(builder_, &out);
        if (status != COSE_OK || !out) {
            throw cose_error(status);
        }
        return CompiledTrustPlan(out);
    }

private:
    cose_trust_policy_builder_t* builder_ = nullptr;

    void CheckBuilder() const {
        if (!builder_) {
            throw cose_error("TrustPolicyBuilder already consumed or invalid");
        }
    }
};

inline ValidatorBuilder& WithCompiledTrustPlan(
    ValidatorBuilder& builder,
    const CompiledTrustPlan& plan
) {
    cose_status_t status = cose_validator_builder_with_compiled_trust_plan(
        builder.native_handle(),
        plan.native_handle()
    );
    if (status != COSE_OK) {
        throw cose_error(status);
    }
    return builder;
}

} // namespace cose

#endif // COSE_TRUST_HPP
