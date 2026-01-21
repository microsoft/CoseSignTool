// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <gtest/gtest.h>

extern "C" {
#include <cose/cose_sign1.h>
#include <cose/cose_certificates.h>
#include <cose/cose_mst.h>
#include <cose/cose_azure_key_vault.h>
#include <cose/cose_trust.h>
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

TEST(SmokeC, AbiVersionAvailable) {
    EXPECT_GT(cose_ffi_abi_version(), 0u);
}

TEST(SmokeC, BuilderCreatesAndBuilds) {
    cose_validator_builder_t* builder = nullptr;
    cose_validator_t* validator = nullptr;

    assert_ok(cose_validator_builder_new(&builder), "cose_validator_builder_new");

#ifdef COSE_HAS_CERTIFICATES_PACK
    assert_ok(cose_validator_builder_with_certificates_pack(builder), "cose_validator_builder_with_certificates_pack");
#endif

#ifdef COSE_HAS_MST_PACK
    assert_ok(cose_validator_builder_with_mst_pack(builder), "cose_validator_builder_with_mst_pack");
#endif

#ifdef COSE_HAS_AKV_PACK
    assert_ok(cose_validator_builder_with_akv_pack(builder), "cose_validator_builder_with_akv_pack");
#endif

#ifdef COSE_HAS_TRUST_PACK
    // Attach a bundled plan from pack defaults.
    {
        cose_trust_plan_builder_t* plan_builder = nullptr;
        cose_compiled_trust_plan_t* plan = nullptr;

        assert_ok(
            cose_trust_plan_builder_new_from_validator_builder(builder, &plan_builder),
            "cose_trust_plan_builder_new_from_validator_builder");

        assert_ok(
            cose_trust_plan_builder_add_all_pack_default_plans(plan_builder),
            "cose_trust_plan_builder_add_all_pack_default_plans");

        assert_ok(cose_trust_plan_builder_compile_or(plan_builder, &plan), "cose_trust_plan_builder_compile_or");
        assert_ok(
            cose_validator_builder_with_compiled_trust_plan(builder, plan),
            "cose_validator_builder_with_compiled_trust_plan");

        cose_compiled_trust_plan_free(plan);
        cose_trust_plan_builder_free(plan_builder);
    }
#endif

    assert_ok(cose_validator_builder_build(builder, &validator), "cose_validator_builder_build");

    cose_validator_free(validator);
    cose_validator_builder_free(builder);
}
