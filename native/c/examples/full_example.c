// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file full_example.c
 * @brief Comprehensive COSE Sign1 C API demonstration.
 *
 * This example demonstrates the complete workflow across all available packs:
 *
 *   1. Validation with Trust Policy   (always available)
 *   2. Trust Plan Builder             (always available)
 *   3. CWT Claims                     (if COSE_HAS_CWT_HEADERS)
 *   4. Message Parsing                (if COSE_HAS_PRIMITIVES)
 *   5. Low-level Signing via Builder  (if COSE_HAS_SIGNING)
 *   6. Factory Signing                (if COSE_HAS_SIGNING && COSE_HAS_CRYPTO_OPENSSL)
 *
 * Each section is self-contained with its own cleanup.
 */

/* --- Validation & trust (always available) --- */
#include <cose/sign1/validation.h>
#include <cose/sign1/trust.h>

#ifdef COSE_HAS_CERTIFICATES_PACK
#include <cose/sign1/extension_packs/certificates.h>
#endif

#ifdef COSE_HAS_MST_PACK
#include <cose/sign1/extension_packs/mst.h>
#endif

#ifdef COSE_HAS_AKV_PACK
#include <cose/sign1/extension_packs/azure_key_vault.h>
#endif

#ifdef COSE_HAS_CWT_HEADERS
#include <cose/sign1/cwt.h>
#endif

#ifdef COSE_HAS_PRIMITIVES
#include <cose/sign1.h>
#endif

#ifdef COSE_HAS_SIGNING
#include <cose/sign1/signing.h>
#endif

#ifdef COSE_HAS_CRYPTO_OPENSSL
#include <cose/crypto/openssl.h>
#endif

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ========================================================================== */
/* Helper macros                                                              */
/* ========================================================================== */

static void print_last_error_and_free(void)
{
    char* err = cose_last_error_message_utf8();
    fprintf(stderr, "  Error: %s\n", err ? err : "(no error message)");
    if (err)
    {
        cose_string_free(err);
    }
}

/* Validation / trust / extension-pack layer (cose_status_t, COSE_OK). */
#define COSE_CHECK(call) \
    do { \
        cose_status_t _st = (call); \
        if (_st != COSE_OK) { \
            fprintf(stderr, "FAILED: %s\n", #call); \
            print_last_error_and_free(); \
            goto cleanup; \
        } \
    } while (0)

/* Signing layer (int, COSE_SIGN1_SIGNING_OK). */
#ifdef COSE_HAS_SIGNING
#define SIGNING_CHECK(call) \
    do { \
        int _st = (call); \
        if (_st != COSE_SIGN1_SIGNING_OK) { \
            fprintf(stderr, "FAILED: %s (status=%d)\n", #call, _st); \
            goto cleanup; \
        } \
    } while (0)
#endif

/* Primitives layer (int32_t, COSE_SIGN1_OK). */
#ifdef COSE_HAS_PRIMITIVES
#define PRIM_CHECK(call) \
    do { \
        int32_t _st = (call); \
        if (_st != COSE_SIGN1_OK) { \
            fprintf(stderr, "FAILED: %s (status=%d)\n", #call, _st); \
            goto cleanup; \
        } \
    } while (0)
#endif

/* CWT layer (int32_t, COSE_CWT_OK). */
#ifdef COSE_HAS_CWT_HEADERS
#define CWT_CHECK(call) \
    do { \
        int32_t _st = (call); \
        if (_st != COSE_CWT_OK) { \
            fprintf(stderr, "FAILED: %s (status=%d)\n", #call, _st); \
            goto cleanup; \
        } \
    } while (0)
#endif

/* ========================================================================== */
/* Part 1: Validation with Trust Policy (always available)                    */
/* ========================================================================== */

static int demo_validation_with_trust_policy(void)
{
    printf("\n=== Part 1: Validation with Trust Policy ===\n");

    cose_sign1_validator_builder_t* builder = NULL;
    cose_sign1_trust_policy_builder_t* policy = NULL;
    cose_sign1_compiled_trust_plan_t* plan = NULL;
    cose_sign1_validator_t* validator = NULL;
    cose_sign1_validation_result_t* result = NULL;
    int exit_code = -1;

    /* Dummy COSE_Sign1 bytes — validation will fail, but it demonstrates the
     * full API flow from builder through trust policy to validation. */
    const uint8_t dummy_cose[] = { 0xD2, 0x84, 0x40, 0xA0, 0xF6, 0x40 };

    printf("Creating validator builder...\n");
    COSE_CHECK(cose_sign1_validator_builder_new(&builder));

#ifdef COSE_HAS_CERTIFICATES_PACK
    printf("Registering certificates pack...\n");
    COSE_CHECK(cose_sign1_validator_builder_with_certificates_pack(builder));
#endif

#ifdef COSE_HAS_MST_PACK
    printf("Registering MST pack...\n");
    COSE_CHECK(cose_sign1_validator_builder_with_mst_pack(builder));
#endif

#ifdef COSE_HAS_AKV_PACK
    printf("Registering AKV pack...\n");
    COSE_CHECK(cose_sign1_validator_builder_with_akv_pack(builder));
#endif

    /* Build a custom trust policy from the configured packs. */
    printf("Building custom trust policy...\n");
    COSE_CHECK(cose_sign1_trust_policy_builder_new_from_validator_builder(builder, &policy));

    /* Message-scope requirements (available on every build). */
    COSE_CHECK(cose_sign1_trust_policy_builder_require_content_type_non_empty(policy));
    COSE_CHECK(cose_sign1_trust_policy_builder_require_detached_payload_absent(policy));

#ifdef COSE_HAS_CERTIFICATES_PACK
    /* Certificate-pack requirements. */
    COSE_CHECK(cose_sign1_trust_policy_builder_and(policy));
    COSE_CHECK(cose_sign1_certificates_trust_policy_builder_require_x509_chain_trusted(policy));
    COSE_CHECK(cose_sign1_certificates_trust_policy_builder_require_signing_certificate_present(policy));
    COSE_CHECK(cose_sign1_certificates_trust_policy_builder_require_signing_certificate_thumbprint_present(policy));
#endif

#ifdef COSE_HAS_MST_PACK
    /* MST-pack requirements. */
    COSE_CHECK(cose_sign1_trust_policy_builder_and(policy));
    COSE_CHECK(cose_sign1_mst_trust_policy_builder_require_receipt_present(policy));
    COSE_CHECK(cose_sign1_mst_trust_policy_builder_require_receipt_trusted(policy));
#endif

    /* Compile and attach. */
    printf("Compiling trust policy...\n");
    COSE_CHECK(cose_sign1_trust_policy_builder_compile(policy, &plan));
    COSE_CHECK(cose_sign1_validator_builder_with_compiled_trust_plan(builder, plan));

    /* Build the validator. */
    printf("Building validator...\n");
    COSE_CHECK(cose_sign1_validator_builder_build(builder, &validator));

    /* Validate dummy bytes (will fail — that's expected). */
    printf("Validating dummy COSE_Sign1 bytes...\n");
    COSE_CHECK(cose_sign1_validator_validate_bytes(
        validator, dummy_cose, sizeof(dummy_cose), NULL, 0, &result));

    {
        bool ok = false;
        COSE_CHECK(cose_sign1_validation_result_is_success(result, &ok));
        if (ok)
        {
            printf("  Validation PASSED (unexpected for dummy data)\n");
        }
        else
        {
            char* msg = cose_sign1_validation_result_failure_message_utf8(result);
            printf("  Validation FAILED (expected): %s\n", msg ? msg : "(no message)");
            if (msg)
            {
                cose_string_free(msg);
            }
        }
    }

    exit_code = 0;

cleanup:
    if (result) cose_sign1_validation_result_free(result);
    if (validator) cose_sign1_validator_free(validator);
    if (plan) cose_sign1_compiled_trust_plan_free(plan);
    if (policy) cose_sign1_trust_policy_builder_free(policy);
    if (builder) cose_sign1_validator_builder_free(builder);
    return exit_code;
}

/* ========================================================================== */
/* Part 2: Trust Plan Builder (always available)                              */
/* ========================================================================== */

static int demo_trust_plan_builder(void)
{
    printf("\n=== Part 2: Trust Plan Builder ===\n");

    cose_sign1_validator_builder_t* builder = NULL;
    cose_sign1_trust_plan_builder_t* plan_builder = NULL;
    cose_sign1_compiled_trust_plan_t* plan_or = NULL;
    cose_sign1_compiled_trust_plan_t* plan_and = NULL;
    int exit_code = -1;

    COSE_CHECK(cose_sign1_validator_builder_new(&builder));

#ifdef COSE_HAS_CERTIFICATES_PACK
    COSE_CHECK(cose_sign1_validator_builder_with_certificates_pack(builder));
#endif
#ifdef COSE_HAS_MST_PACK
    COSE_CHECK(cose_sign1_validator_builder_with_mst_pack(builder));
#endif

    /* Create a trust-plan builder that knows about the registered packs. */
    printf("Creating trust plan builder...\n");
    COSE_CHECK(cose_sign1_trust_plan_builder_new_from_validator_builder(builder, &plan_builder));

    /* Inspect the packs. */
    size_t pack_count = 0;
    COSE_CHECK(cose_sign1_trust_plan_builder_pack_count(plan_builder, &pack_count));
    printf("  Registered packs: %zu\n", pack_count);

    for (size_t i = 0; i < pack_count; i++)
    {
        char* name = cose_sign1_trust_plan_builder_pack_name_utf8(plan_builder, i);
        bool has_default = false;
        COSE_CHECK(cose_sign1_trust_plan_builder_pack_has_default_plan(plan_builder, i, &has_default));
        printf("    [%zu] %s (default plan: %s)\n",
               i, name ? name : "(null)", has_default ? "yes" : "no");
        if (name)
        {
            cose_string_free(name);
        }
    }

    /* Select all default plans and compile as OR (any pack may pass). */
    printf("Adding all pack default plans...\n");
    COSE_CHECK(cose_sign1_trust_plan_builder_add_all_pack_default_plans(plan_builder));

    printf("Compiling as OR (any pack may pass)...\n");
    COSE_CHECK(cose_sign1_trust_plan_builder_compile_or(plan_builder, &plan_or));
    printf("  OR plan compiled successfully\n");

    /* Re-select and compile as AND (all packs must pass). */
    COSE_CHECK(cose_sign1_trust_plan_builder_clear_selected_plans(plan_builder));
    COSE_CHECK(cose_sign1_trust_plan_builder_add_all_pack_default_plans(plan_builder));

    printf("Compiling as AND (all packs must pass)...\n");
    COSE_CHECK(cose_sign1_trust_plan_builder_compile_and(plan_builder, &plan_and));
    printf("  AND plan compiled successfully\n");

    exit_code = 0;

cleanup:
    if (plan_and) cose_sign1_compiled_trust_plan_free(plan_and);
    if (plan_or) cose_sign1_compiled_trust_plan_free(plan_or);
    if (plan_builder) cose_sign1_trust_plan_builder_free(plan_builder);
    if (builder) cose_sign1_validator_builder_free(builder);
    return exit_code;
}

/* ========================================================================== */
/* Part 3: CWT Claims (if COSE_HAS_CWT_HEADERS)                              */
/* ========================================================================== */

#ifdef COSE_HAS_CWT_HEADERS
static int demo_cwt_claims(void)
{
    printf("\n=== Part 3: CWT Claims ===\n");

    CoseCwtClaimsHandle* claims = NULL;
    CoseCwtErrorHandle* cwt_err = NULL;
    uint8_t* cbor_bytes = NULL;
    uint32_t cbor_len = 0;
    int exit_code = -1;

    printf("Creating CWT claims set...\n");
    CWT_CHECK(cose_cwt_claims_create(&claims, &cwt_err));

    printf("Setting issuer, subject, audience...\n");
    CWT_CHECK(cose_cwt_claims_set_issuer(claims, "did:x509:sha256:abc::eku:1.3.6.1", &cwt_err));
    CWT_CHECK(cose_cwt_claims_set_subject(claims, "contoso-supply-chain", &cwt_err));
    CWT_CHECK(cose_cwt_claims_set_audience(claims, "https://transparency.example.com", &cwt_err));

    /* Set time-based claims (Unix timestamps). */
    CWT_CHECK(cose_cwt_claims_set_issued_at(claims, 1700000000, &cwt_err));
    CWT_CHECK(cose_cwt_claims_set_not_before(claims, 1700000000, &cwt_err));
    CWT_CHECK(cose_cwt_claims_set_expiration(claims, 1700086400, &cwt_err));

    /* Serialize to CBOR. */
    printf("Serializing to CBOR...\n");
    CWT_CHECK(cose_cwt_claims_to_cbor(claims, &cbor_bytes, &cbor_len, &cwt_err));
    printf("  CBOR bytes: %u\n", cbor_len);

    /* Round-trip: deserialize back to verify. */
    CoseCwtClaimsHandle* claims2 = NULL;
    CWT_CHECK(cose_cwt_claims_from_cbor(cbor_bytes, cbor_len, &claims2, &cwt_err));

    const char* roundtrip_iss = NULL;
    CWT_CHECK(cose_cwt_claims_get_issuer(claims2, &roundtrip_iss, &cwt_err));
    printf("  Round-trip issuer: %s\n", roundtrip_iss ? roundtrip_iss : "(null)");

    const char* roundtrip_sub = NULL;
    CWT_CHECK(cose_cwt_claims_get_subject(claims2, &roundtrip_sub, &cwt_err));
    printf("  Round-trip subject: %s\n", roundtrip_sub ? roundtrip_sub : "(null)");

    cose_cwt_claims_free(claims2);
    printf("  CWT claims round-trip successful\n");

    exit_code = 0;

cleanup:
    if (cbor_bytes) cose_cwt_bytes_free(cbor_bytes, cbor_len);
    if (cwt_err)
    {
        char* msg = cose_cwt_error_message(cwt_err);
        if (msg)
        {
            fprintf(stderr, "  CWT error: %s\n", msg);
            cose_cwt_string_free(msg);
        }
        cose_cwt_error_free(cwt_err);
    }
    if (claims) cose_cwt_claims_free(claims);
    return exit_code;
}
#endif /* COSE_HAS_CWT_HEADERS */

/* ========================================================================== */
/* Part 4: Message Parsing (if COSE_HAS_PRIMITIVES)                           */
/* ========================================================================== */

#ifdef COSE_HAS_PRIMITIVES
static int demo_message_parsing(const uint8_t* cose_bytes, size_t cose_len)
{
    printf("\n=== Part 4: Message Parsing ===\n");

    CoseSign1MessageHandle* msg = NULL;
    CoseSign1ErrorHandle* err = NULL;
    CoseHeaderMapHandle* prot = NULL;
    int exit_code = -1;

    printf("Parsing COSE_Sign1 message (%zu bytes)...\n", cose_len);
    PRIM_CHECK(cose_sign1_message_parse(cose_bytes, cose_len, &msg, &err));

    /* Algorithm. */
    int64_t alg = 0;
    PRIM_CHECK(cose_sign1_message_alg(msg, &alg));
    printf("  Algorithm: %lld", (long long)alg);
    switch (alg)
    {
        case COSE_ALG_ES256:  printf(" (ES256)");  break;
        case COSE_ALG_ES384:  printf(" (ES384)");  break;
        case COSE_ALG_ES512:  printf(" (ES512)");  break;
        case COSE_ALG_EDDSA:  printf(" (EdDSA)");  break;
        case COSE_ALG_PS256:  printf(" (PS256)");  break;
        default:              printf(" (other)");   break;
    }
    printf("\n");

    /* Detached vs embedded payload. */
    bool detached = cose_sign1_message_is_detached(msg);
    printf("  Detached payload: %s\n", detached ? "yes" : "no");

    if (!detached)
    {
        const uint8_t* payload = NULL;
        size_t payload_len = 0;
        PRIM_CHECK(cose_sign1_message_payload(msg, &payload, &payload_len));
        printf("  Payload length: %zu bytes\n", payload_len);
    }

    /* Protected headers. */
    PRIM_CHECK(cose_sign1_message_protected_headers(msg, &prot));
    printf("  Protected header entries: %zu\n", cose_headermap_len(prot));

    if (cose_headermap_contains(prot, COSE_HEADER_CONTENT_TYPE))
    {
        char* ct = cose_headermap_get_text(prot, COSE_HEADER_CONTENT_TYPE);
        printf("  Content-Type: %s\n", ct ? ct : "(binary)");
        if (ct)
        {
            cose_sign1_string_free(ct);
        }
    }

    /* Signature. */
    const uint8_t* sig = NULL;
    size_t sig_len = 0;
    PRIM_CHECK(cose_sign1_message_signature(msg, &sig, &sig_len));
    printf("  Signature length: %zu bytes\n", sig_len);

    exit_code = 0;

cleanup:
    if (err)
    {
        char* m = cose_sign1_error_message(err);
        if (m)
        {
            fprintf(stderr, "  Parse error: %s\n", m);
            cose_sign1_string_free(m);
        }
        cose_sign1_error_free(err);
    }
    if (prot) cose_headermap_free(prot);
    if (msg) cose_sign1_message_free(msg);
    return exit_code;
}
#endif /* COSE_HAS_PRIMITIVES */

/* ========================================================================== */
/* Part 5: Low-level Signing via Builder (if COSE_HAS_SIGNING)                */
/* ========================================================================== */

#ifdef COSE_HAS_SIGNING

/* Dummy signing callback — produces a fixed-length fake signature.
 * In production you would call a real crypto library here. */
static int dummy_sign_callback(
    const uint8_t* protected_bytes, size_t protected_len,
    const uint8_t* payload,         size_t payload_len,
    const uint8_t* external_aad,    size_t external_aad_len,
    uint8_t** out_sig,              size_t* out_sig_len,
    void* user_data)
{
    (void)protected_bytes; (void)protected_len;
    (void)payload;         (void)payload_len;
    (void)external_aad;    (void)external_aad_len;
    (void)user_data;

    /* 64-byte fake signature (ES256-sized). */
    *out_sig_len = 64;
    *out_sig = (uint8_t*)malloc(64);
    if (!*out_sig)
    {
        return -1;
    }
    memset(*out_sig, 0xAB, 64);
    return 0;
}

static int demo_low_level_signing(uint8_t** out_bytes, size_t* out_len)
{
    printf("\n=== Part 5: Low-level Signing via Builder ===\n");

    cose_sign1_builder_t* builder = NULL;
    cose_headermap_t* headers = NULL;
    cose_key_t* key = NULL;
    cose_sign1_signing_error_t* sign_err = NULL;
    uint8_t* cose_bytes = NULL;
    size_t cose_len = 0;
    int exit_code = -1;

    const char* payload_text = "Hello from the low-level builder!";
    const uint8_t* payload = (const uint8_t*)payload_text;
    size_t payload_len = strlen(payload_text);

    /* Build protected headers. */
    printf("Creating protected headers...\n");
    SIGNING_CHECK(cose_headermap_new(&headers));
    SIGNING_CHECK(cose_headermap_set_int(headers, COSE_HEADER_ALG, COSE_ALG_ES256));
    SIGNING_CHECK(cose_headermap_set_text(headers, COSE_HEADER_CONTENT_TYPE, "text/plain"));

    /* Create a callback-based key. */
    printf("Creating callback-based signing key...\n");
    SIGNING_CHECK(cose_key_from_callback(
        COSE_ALG_ES256, "EC2", dummy_sign_callback, NULL, &key));

    /* Create builder and configure it. */
    printf("Configuring builder...\n");
    SIGNING_CHECK(cose_sign1_builder_new(&builder));
    SIGNING_CHECK(cose_sign1_builder_set_tagged(builder, true));
    SIGNING_CHECK(cose_sign1_builder_set_detached(builder, false));
    SIGNING_CHECK(cose_sign1_builder_set_protected(builder, headers));

    /* Sign — this consumes the builder. */
    printf("Signing payload (%zu bytes)...\n", payload_len);
    SIGNING_CHECK(cose_sign1_builder_sign(
        builder, key, payload, payload_len, &cose_bytes, &cose_len, &sign_err));
    builder = NULL; /* consumed */

    printf("  COSE_Sign1 message: %zu bytes\n", cose_len);

    *out_bytes = cose_bytes;
    *out_len = cose_len;
    cose_bytes = NULL; /* ownership transferred to caller */
    exit_code = 0;

cleanup:
    if (sign_err)
    {
        char* m = cose_sign1_signing_error_message(sign_err);
        if (m)
        {
            fprintf(stderr, "  Signing error: %s\n", m);
            cose_sign1_string_free(m);
        }
        cose_sign1_signing_error_free(sign_err);
    }
    if (cose_bytes) cose_sign1_bytes_free(cose_bytes, cose_len);
    if (key) cose_key_free(key);
    if (headers) cose_headermap_free(headers);
    if (builder) cose_sign1_builder_free(builder);
    return exit_code;
}
#endif /* COSE_HAS_SIGNING */

/* ========================================================================== */
/* Part 6: Factory Signing (if COSE_HAS_SIGNING && COSE_HAS_CRYPTO_OPENSSL)  */
/* ========================================================================== */

#if defined(COSE_HAS_SIGNING) && defined(COSE_HAS_CRYPTO_OPENSSL)
static int demo_factory_signing(const uint8_t* private_key_der, size_t key_len)
{
    printf("\n=== Part 6: Factory Signing with Crypto Signer ===\n");

    cose_crypto_provider_t* provider = NULL;
    cose_crypto_signer_t* signer = NULL;
    cose_sign1_factory_t* factory = NULL;
    cose_sign1_signing_error_t* sign_err = NULL;
    uint8_t* cose_bytes = NULL;
    uint32_t cose_len = 0;
    int exit_code = -1;

    const char* payload_text = "Hello from the factory!";
    const uint8_t* payload = (const uint8_t*)payload_text;
    uint32_t payload_len = (uint32_t)strlen(payload_text);

    /* Create OpenSSL provider + signer. */
    printf("Creating OpenSSL crypto provider...\n");
    if (cose_crypto_openssl_provider_new(&provider) != COSE_OK)
    {
        fprintf(stderr, "Failed to create crypto provider\n");
        print_last_error_and_free();
        goto cleanup;
    }

    printf("Creating signer from DER key (%zu bytes)...\n", key_len);
    if (cose_crypto_openssl_signer_from_der(provider, private_key_der, key_len, &signer) != COSE_OK)
    {
        fprintf(stderr, "Failed to create signer\n");
        print_last_error_and_free();
        goto cleanup;
    }

    int64_t alg = cose_crypto_signer_algorithm(signer);
    printf("  Signer algorithm: %lld\n", (long long)alg);

    /* Create factory from signer — signer ownership is transferred. */
    printf("Creating factory from crypto signer...\n");
    SIGNING_CHECK(cose_sign1_factory_from_crypto_signer(
        (void*)signer, &factory, &sign_err));
    signer = NULL; /* consumed */

    /* Direct (embedded) signature. */
    printf("Signing with direct (embedded) signature...\n");
    SIGNING_CHECK(cose_sign1_factory_sign_direct(
        factory, payload, payload_len, "text/plain",
        &cose_bytes, &cose_len, &sign_err));
    printf("  COSE_Sign1 message: %u bytes\n", cose_len);

    exit_code = 0;

cleanup:
    if (sign_err)
    {
        char* m = cose_sign1_signing_error_message(sign_err);
        if (m)
        {
            fprintf(stderr, "  Signing error: %s\n", m);
            cose_sign1_string_free(m);
        }
        cose_sign1_signing_error_free(sign_err);
    }
    if (cose_bytes) cose_sign1_cose_bytes_free(cose_bytes, cose_len);
    if (factory) cose_sign1_factory_free(factory);
    if (signer) cose_crypto_signer_free(signer);
    if (provider) cose_crypto_openssl_provider_free(provider);
    return exit_code;
}
#endif /* COSE_HAS_SIGNING && COSE_HAS_CRYPTO_OPENSSL */

/* ========================================================================== */
/* Main                                                                       */
/* ========================================================================== */

int main(void)
{
    printf("========================================\n");
    printf(" COSE Sign1 Full C API Demonstration\n");
    printf("========================================\n");

    /* ---- Part 1: Validation with Trust Policy ---- */
    demo_validation_with_trust_policy();

    /* ---- Part 2: Trust Plan Builder ---- */
    demo_trust_plan_builder();

    /* ---- Part 3: CWT Claims ---- */
#ifdef COSE_HAS_CWT_HEADERS
    demo_cwt_claims();
#else
    printf("\n=== Part 3: CWT Claims ===\n");
    printf("  SKIPPED (COSE_HAS_CWT_HEADERS not defined)\n");
#endif

    /* ---- Part 4 & 5: Signing + Parsing ---- */
#ifdef COSE_HAS_SIGNING
    {
        uint8_t* signed_bytes = NULL;
        size_t signed_len = 0;

        /* Part 5: Low-level signing produces bytes we can parse in Part 4. */
        if (demo_low_level_signing(&signed_bytes, &signed_len) == 0)
        {
#ifdef COSE_HAS_PRIMITIVES
            /* Part 4: Parse the message we just signed. */
            demo_message_parsing(signed_bytes, signed_len);
#else
            printf("\n=== Part 4: Message Parsing ===\n");
            printf("  SKIPPED (COSE_HAS_PRIMITIVES not defined)\n");
#endif
            cose_sign1_bytes_free(signed_bytes, signed_len);
        }
    }
#else
    printf("\n=== Part 5: Low-level Signing ===\n");
    printf("  SKIPPED (COSE_HAS_SIGNING not defined)\n");
    printf("\n=== Part 4: Message Parsing ===\n");
    printf("  SKIPPED (COSE_HAS_SIGNING not defined — no bytes to parse)\n");
#endif

    /* ---- Part 6: Factory Signing ---- */
#if defined(COSE_HAS_SIGNING) && defined(COSE_HAS_CRYPTO_OPENSSL)
    printf("\n  NOTE: Part 6 (Factory Signing) requires a real DER private key.\n");
    printf("        Skipping in this demo — see trust_policy_example.c for\n");
    printf("        a standalone validation-only walkthrough.\n");
    /* To run Part 6 for real, call:
     *   demo_factory_signing(private_key_der, key_len);
     * with a DER-encoded private key loaded from disk. */
#else
    printf("\n=== Part 6: Factory Signing ===\n");
    printf("  SKIPPED (COSE_HAS_SIGNING + COSE_HAS_CRYPTO_OPENSSL required)\n");
#endif

    printf("\n========================================\n");
    printf(" All demonstrations completed.\n");
    printf("========================================\n");
    return 0;
}
