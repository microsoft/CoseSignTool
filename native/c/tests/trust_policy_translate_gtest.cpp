// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Trust-policy translation smoke test (C++ consumer / GoogleTest).
//
// Mirrors trust_policy_translate_test.c but exercises the C ABI through C++
// translation units to assert the header is `extern "C"`-compatible.

#include <gtest/gtest.h>

extern "C" {
#include <cose/sign1/trust_policy.h>
#include <cose/sign1/validation.h>
}

#include <cstring>
#include <string>
#include <vector>

namespace {

class TrustPolicyResult {
public:
    explicit TrustPolicyResult(cose_sign1_trust_policy_translation_result_t* h)
        : handle_(h) {}
    ~TrustPolicyResult() {
        if (handle_) cose_sign1_trust_policy_result_free(handle_);
    }
    TrustPolicyResult(const TrustPolicyResult&) = delete;
    TrustPolicyResult& operator=(const TrustPolicyResult&) = delete;
    cose_sign1_trust_policy_translation_result_t* get() const { return handle_; }

private:
    cose_sign1_trust_policy_translation_result_t* handle_;
};

class TrustPolicySpec {
public:
    explicit TrustPolicySpec(cose_sign1_trust_policy_spec_t* h) : handle_(h) {}
    ~TrustPolicySpec() {
        if (handle_) cose_sign1_trust_policy_spec_free(handle_);
    }
    TrustPolicySpec(const TrustPolicySpec&) = delete;
    TrustPolicySpec& operator=(const TrustPolicySpec&) = delete;
    cose_sign1_trust_policy_spec_t* get() const { return handle_; }

private:
    cose_sign1_trust_policy_spec_t* handle_;
};

class CompiledPlan {
public:
    explicit CompiledPlan(cose_sign1_trust_policy_compiled_plan_t* h) : handle_(h) {}
    ~CompiledPlan() {
        if (handle_) cose_sign1_trust_policy_compiled_plan_free(handle_);
    }
    CompiledPlan(const CompiledPlan&) = delete;
    CompiledPlan& operator=(const CompiledPlan&) = delete;
    cose_sign1_trust_policy_compiled_plan_t* get() const { return handle_; }

private:
    cose_sign1_trust_policy_compiled_plan_t* handle_;
};

cose_sign1_trust_policy_translation_result_t* translate(const std::string& doc) {
    cose_sign1_trust_policy_translation_result_t* result = nullptr;
    cose_status_t st = cose_sign1_trust_policy_translate_json(
        reinterpret_cast<const uint8_t*>(doc.data()), doc.size(), &result);
    EXPECT_EQ(st, COSE_OK);
    EXPECT_NE(result, nullptr);
    return result;
}

std::string read_diag_code(const cose_sign1_trust_policy_diagnostic_t* diag) {
    const uint8_t* code_ptr = nullptr;
    size_t code_len = 0;
    cose_sign1_trust_policy_diagnostic_read(
        diag, nullptr, &code_ptr, &code_len, nullptr, nullptr, nullptr, nullptr);
    if (code_ptr == nullptr) return {};
    return std::string(reinterpret_cast<const char*>(code_ptr), code_len);
}

}  // namespace

TEST(TrustPolicyCpp, FrontendIdIsCanonical) {
    const char* id = cose_sign1_trust_policy_frontend_id();
    ASSERT_NE(id, nullptr);
    EXPECT_STREQ(id, "cose-tp-json/v1");
}

TEST(TrustPolicyCpp, TranslateMinimalDocumentSucceeds) {
    TrustPolicyResult result(translate(R"({
        "frontend": "cose-tp-json/v1",
        "message": { "allow_all": true }
    })"));
    EXPECT_EQ(cose_sign1_trust_policy_result_is_success(result.get()), 1);
    EXPECT_EQ(cose_sign1_trust_policy_result_diagnostic_count(result.get()), 0u);

    TrustPolicySpec spec(cose_sign1_trust_policy_result_spec(result.get()));
    ASSERT_NE(spec.get(), nullptr);
    EXPECT_EQ(cose_sign1_trust_policy_spec_has_parameters(spec.get()), 0);
}

TEST(TrustPolicyCpp, ParseErrorSurfacesViaDiagnostic) {
    TrustPolicyResult result(translate("definitely { not } json"));
    EXPECT_EQ(cose_sign1_trust_policy_result_is_success(result.get()), 0);

    const auto count = cose_sign1_trust_policy_result_diagnostic_count(result.get());
    ASSERT_GE(count, 1u);

    const auto* diag = cose_sign1_trust_policy_result_diagnostic_at(result.get(), 0);
    ASSERT_NE(diag, nullptr);

    uint8_t severity = 99;
    const uint8_t* code_ptr = nullptr;
    size_t code_len = 0;
    const uint8_t* msg_ptr = nullptr;
    size_t msg_len = 0;
    uint32_t line = 0;
    uint32_t column = 0;
    cose_sign1_trust_policy_diagnostic_read(
        diag, &severity, &code_ptr, &code_len, &msg_ptr, &msg_len, &line, &column);
    EXPECT_EQ(severity, COSE_TP_SEVERITY_ERROR);
    ASSERT_NE(code_ptr, nullptr);
    ASSERT_EQ(code_len, 6u);
    EXPECT_EQ(std::string(reinterpret_cast<const char*>(code_ptr), 6), "TPX001");
    EXPECT_GT(msg_len, 0u);
    EXPECT_GE(line, 1u);
    EXPECT_GE(column, 1u);
}

TEST(TrustPolicyCpp, OutOfBoundsDiagnosticAtReturnsNull) {
    TrustPolicyResult result(translate(R"({ "frontend": "cose-tp-json/v1", "message": {"allow_all": true} })"));
    EXPECT_EQ(cose_sign1_trust_policy_result_diagnostic_at(result.get(), 1000), nullptr);
}

TEST(TrustPolicyCpp, BindCompileLifecycle) {
    TrustPolicyResult result(translate(R"({
        "frontend": "cose-tp-json/v1",
        "primary_signing_key": {
            "fact": "x509-cert-identity/v1",
            "predicate": { "thumbprint": { "$param": "tp", "default": "abc" } }
        }
    })"));
    EXPECT_EQ(cose_sign1_trust_policy_result_is_success(result.get()), 1);
    TrustPolicySpec spec(cose_sign1_trust_policy_result_spec(result.get()));
    ASSERT_NE(spec.get(), nullptr);
    EXPECT_EQ(cose_sign1_trust_policy_spec_has_parameters(spec.get()), 1);

    const std::string params = R"({"tp": "my-thumbprint"})";
    cose_sign1_trust_policy_translation_result_t* bind_raw = nullptr;
    EXPECT_EQ(
        cose_sign1_trust_policy_spec_bind(
            spec.get(),
            reinterpret_cast<const uint8_t*>(params.data()), params.size(),
            &bind_raw),
        COSE_OK);
    TrustPolicyResult bind_result(bind_raw);
    EXPECT_EQ(cose_sign1_trust_policy_result_is_success(bind_result.get()), 1);

    TrustPolicySpec bound_spec(cose_sign1_trust_policy_result_spec(bind_result.get()));
    ASSERT_NE(bound_spec.get(), nullptr);
    EXPECT_EQ(cose_sign1_trust_policy_spec_has_parameters(bound_spec.get()), 0);

    cose_sign1_trust_policy_compiled_plan_t* plan_raw = nullptr;
    EXPECT_EQ(cose_sign1_trust_policy_spec_compile(bound_spec.get(), &plan_raw), COSE_OK);
    CompiledPlan plan(plan_raw);
    ASSERT_NE(plan.get(), nullptr);
}

TEST(TrustPolicyCpp, BindMissingParameterSurfacesTpx400) {
    TrustPolicyResult result(translate(R"({
        "frontend": "cose-tp-json/v1",
        "primary_signing_key": {
            "fact": "x509-cert-identity/v1",
            "predicate": { "thumbprint": { "$param": "tp" } }
        }
    })"));
    TrustPolicySpec spec(cose_sign1_trust_policy_result_spec(result.get()));
    ASSERT_NE(spec.get(), nullptr);

    const std::string params = "{}";
    cose_sign1_trust_policy_translation_result_t* bind_raw = nullptr;
    EXPECT_EQ(
        cose_sign1_trust_policy_spec_bind(
            spec.get(),
            reinterpret_cast<const uint8_t*>(params.data()), params.size(),
            &bind_raw),
        COSE_OK);
    TrustPolicyResult bind_result(bind_raw);
    EXPECT_EQ(cose_sign1_trust_policy_result_is_success(bind_result.get()), 0);
    ASSERT_GE(cose_sign1_trust_policy_result_diagnostic_count(bind_result.get()), 1u);
    EXPECT_EQ(
        read_diag_code(cose_sign1_trust_policy_result_diagnostic_at(bind_result.get(), 0)),
        "TPX400");
}

TEST(TrustPolicyCpp, NullToleranceOnEveryAccessor) {
    EXPECT_EQ(cose_sign1_trust_policy_result_diagnostic_count(nullptr), 0u);
    EXPECT_EQ(cose_sign1_trust_policy_result_diagnostic_at(nullptr, 0), nullptr);
    EXPECT_EQ(cose_sign1_trust_policy_result_is_success(nullptr), 0);
    EXPECT_EQ(cose_sign1_trust_policy_result_spec(nullptr), nullptr);
    EXPECT_EQ(cose_sign1_trust_policy_spec_has_parameters(nullptr), 0);

    cose_sign1_trust_policy_diagnostic_read(
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

    cose_sign1_trust_policy_result_free(nullptr);
    cose_sign1_trust_policy_spec_free(nullptr);
    cose_sign1_trust_policy_compiled_plan_free(nullptr);
}

TEST(TrustPolicyCpp, NullOutResultIsAnError) {
    const std::string doc = "{}";
    EXPECT_NE(
        cose_sign1_trust_policy_translate_json(
            reinterpret_cast<const uint8_t*>(doc.data()), doc.size(), nullptr),
        COSE_OK);
}
