// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <gtest/gtest.h>

extern "C" {
#include <cose/sign1/validation.h>
#include <cose/sign1/extension_packs/certificates.h>
#include <cose/sign1/extension_packs/mst.h>
#include <cose/sign1/extension_packs/azure_key_vault.h>
#include <cose/sign1/trust.h>
}

#include <string>

static std::string take_last_error() {
    char* err = cose_last_error_message_utf8();
    std::string out = err ? err : "(no error message)";
    if (err) cose_string_free(err);
    return out;
}

static void assert_ok(cose_status_t st, const char* call) {
    ASSERT_EQ(st, COSE_OK) << call << ": " << take_last_error();
}

TEST(SmokeC, TakeLastErrorReturnsString) {
    // Ensure the helper itself is covered even when assertions pass.
    const auto s = take_last_error();
    EXPECT_FALSE(s.empty());
}

TEST(SmokeC, AbiVersionAvailable) {
    EXPECT_GT(cose_sign1_validation_abi_version(), 0u);
}

TEST(SmokeC, BuilderCreatesAndBuilds) {
    cose_sign1_validator_builder_t* builder = nullptr;
    cose_sign1_validator_t* validator = nullptr;

    assert_ok(cose_sign1_validator_builder_new(&builder), "cose_sign1_validator_builder_new");

#ifdef COSE_HAS_CERTIFICATES_PACK
    assert_ok(cose_sign1_validator_builder_with_certificates_pack(builder), "cose_sign1_validator_builder_with_certificates_pack");
#endif

#ifdef COSE_HAS_MST_PACK
    assert_ok(cose_sign1_validator_builder_with_mst_pack(builder), "cose_sign1_validator_builder_with_mst_pack");
#endif

#ifdef COSE_HAS_AKV_PACK
    assert_ok(cose_sign1_validator_builder_with_akv_pack(builder), "cose_sign1_validator_builder_with_akv_pack");
#endif

#if defined(COSE_HAS_TRUST_PACK) && (defined(COSE_HAS_CERTIFICATES_PACK) || defined(COSE_HAS_MST_PACK) || defined(COSE_HAS_AKV_PACK))
    // Attach a bundled plan from pack defaults.
    // Requires at least one extension pack to contribute default plans.
    {
        cose_sign1_trust_plan_builder_t* plan_builder = nullptr;
        cose_sign1_compiled_trust_plan_t* plan = nullptr;

        assert_ok(
            cose_sign1_trust_plan_builder_new_from_validator_builder(builder, &plan_builder),
            "cose_sign1_trust_plan_builder_new_from_validator_builder");

        assert_ok(
            cose_sign1_trust_plan_builder_add_all_pack_default_plans(plan_builder),
            "cose_sign1_trust_plan_builder_add_all_pack_default_plans");

        assert_ok(cose_sign1_trust_plan_builder_compile_or(plan_builder, &plan), "cose_sign1_trust_plan_builder_compile_or");
        assert_ok(
            cose_sign1_validator_builder_with_compiled_trust_plan(builder, plan),
            "cose_sign1_validator_builder_with_compiled_trust_plan");

        cose_sign1_compiled_trust_plan_free(plan);
        cose_sign1_trust_plan_builder_free(plan_builder);
    }
#endif

    assert_ok(cose_sign1_validator_builder_build(builder, &validator), "cose_sign1_validator_builder_build");

    cose_sign1_validator_free(validator);
    cose_sign1_validator_builder_free(builder);
}
