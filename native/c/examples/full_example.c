// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file full_example.c
 * @brief Comprehensive COSE Sign1 C API demonstration
 *
 * This example demonstrates the complete workflow:
 * 1. Signing with ephemeral P-256 certificate (local crypto)
 * 2. Signing with 3-tier certificate chain
 * 3. PQC signing with ML-DSA-65 (if available)
 * 4. Message Inspection - Parse and inspect message headers
 * 5. Validation with Trust Policy - Build custom trust policy and validate
 * 6. DID:x509 Generation - Generate and validate DID from certificate chain
 */

#include <cose/signing/cosesign1_signing.h>
#include <cose/signing/headers.h>
#include <cose/validation/cose_sign1.h>
#include <cose/validation/cose_trust.h>

#ifdef COSE_HAS_CERTIFICATES_LOCAL
#include <cose/extension_packs/certificates/cose_certificates_local.h>
#endif

#ifdef COSE_HAS_CRYPTO_OPENSSL
#include <cose/crypto/cose_crypto.h>
#endif

#ifdef COSE_HAS_PRIMITIVES
#include <cose/primitives/cosesign1.h>
#endif

#ifdef COSE_HAS_CERTIFICATES_PACK
#include <cose/extension_packs/certificates/cose_certificates.h>
#endif

#ifdef COSE_HAS_DID_X509
#include <cose/did/did_x509.h>
#endif

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ============================================================================
// Helper macros
// ============================================================================

#define CHECK_IMPL(call, label) \
    do { \
        int _st = (call); \
        if (_st != COSESIGN1_IMPL_OK) { \
            fprintf(stderr, "SIGNING FAILED: %s (status=%d)\n", #call, _st); \
            goto label; \
        } \
    } while (0)

#define COSE_CHECK(call) \
    do { \
        cose_status_t _st = (call); \
        if (_st != COSE_OK) { \
            fprintf(stderr, "VALIDATION FAILED: %s (status=%d)\n", #call, _st); \
            print_cose_last_error(); \
            goto cleanup; \
        } \
    } while (0)

#ifdef COSE_HAS_PRIMITIVES
#define CHECK_PRIM(call, label) \
    do { \
        int32_t _st = (call); \
        if (_st != COSESIGN1_OK) { \
            fprintf(stderr, "PRIMITIVES FAILED: %s (status=%d)\n", #call, _st); \
            goto label; \
        } \
    } while (0)
#endif

#ifdef COSE_HAS_DID_X509
#define CHECK_DID(call, label) \
    do { \
        int _st = (call); \
        if (_st != DID_X509_OK) { \
            fprintf(stderr, "DID_X509 FAILED: %s (status=%d)\n", #call, _st); \
            goto label; \
        } \
    } while (0)
#endif

#ifdef COSE_HAS_CRYPTO_OPENSSL
// Crypto signing callback is no longer needed when using cosesign1_impl_factory_from_crypto_signer
#endif /* COSE_HAS_CRYPTO_OPENSSL */

// ============================================================================
// Error printing helpers
// ============================================================================

static void print_cose_last_error(void) {
    char* err = cose_last_error_message_utf8();
    fprintf(stderr, "  Error: %s\n", err ? err : "(no error message)");
    if (err) cose_string_free(err);
}

#ifdef COSE_HAS_PRIMITIVES
static void print_primitives_error(CoseSign1ErrorHandle* error) {
    if (error) {
        char* msg = cosesign1_error_message(error);
        fprintf(stderr, "  Error: %s\n", msg ? msg : "(no error message)");
        if (msg) cosesign1_string_free(msg);
    }
}
#endif

#ifdef COSE_HAS_DID_X509
static void print_did_error(DidX509ErrorHandle* error) {
    if (error) {
        char* msg = did_x509_error_message(error);
        fprintf(stderr, "  Error: %s\n", msg ? msg : "(no error message)");
        if (msg) did_x509_string_free(msg);
    }
}
#endif

// ============================================================================
// Part 1: Signing with Ephemeral P-256 Certificate
// ============================================================================

#if defined(COSE_HAS_CERTIFICATES_LOCAL) && defined(COSE_HAS_CRYPTO_OPENSSL) && defined(COSE_HAS_FACTORIES)
static int demo_signing_local_p256(uint8_t** out_cose_bytes, size_t* out_cose_len)
{
    printf("\n=== Part 1: Signing with Ephemeral P-256 Certificate ===\n");

    cose_cert_local_factory_t* factory = NULL;
    uint8_t* cert_der = NULL;
    size_t cert_len = 0;
    uint8_t* key_der = NULL;
    size_t key_len = 0;
    cose_crypto_provider_t* crypto_provider = NULL;
    cose_crypto_signer_t* crypto_signer = NULL;
    cosesign1_impl_factory_t* sign_factory = NULL;
    cosesign1_impl_error_t* error = NULL;
    uint8_t* direct_bytes = NULL;
    uint32_t direct_len = 0;
    int result = -1;

    /* Sample payload */
    const char* payload_text = "Hello from P-256!";
    const uint8_t* payload = (const uint8_t*)payload_text;
    uint32_t payload_len = (uint32_t)strlen(payload_text);

    printf("Creating ephemeral P-256 certificate factory...\n");
    if (cose_cert_local_factory_new(&factory) != COSE_OK) {
        fprintf(stderr, "Failed to create certificate factory\n");
        goto cleanup_part1;
    }

    printf("Generating self-signed P-256 certificate...\n");
    if (cose_cert_local_factory_create_self_signed(factory, &cert_der, &cert_len, &key_der, &key_len) != COSE_OK) {
        fprintf(stderr, "Failed to create self-signed certificate\n");
        char* err = cose_cert_local_last_error_message_utf8();
        if (err) {
            fprintf(stderr, "  Error: %s\n", err);
            cose_cert_local_string_free(err);
        }
        goto cleanup_part1;
    }
    printf("✓ Certificate created: %zu bytes, private key: %zu bytes\n", cert_len, key_len);

    printf("Creating OpenSSL crypto provider...\n");
    if (cose_crypto_openssl_provider_new(&crypto_provider) != COSE_OK) {
        fprintf(stderr, "Failed to create crypto provider\n");
        goto cleanup_part1;
    }

    printf("Creating crypto signer from private key...\n");
    if (cose_crypto_openssl_signer_from_der(crypto_provider, key_der, key_len, &crypto_signer) != COSE_OK) {
        fprintf(stderr, "Failed to create crypto signer\n");
        char* err = cose_last_error_message_utf8();
        if (err) {
            fprintf(stderr, "  Error: %s\n", err);
            cose_string_free(err);
        }
        goto cleanup_part1;
    }

    int64_t alg = cose_crypto_signer_algorithm(crypto_signer);
    printf("✓ Crypto signer created with algorithm: %lld\n", (long long)alg);

    /* Create factory DIRECTLY from signer (no callback bridge!) */
    printf("Creating factory directly from crypto signer...\n");
    CHECK_IMPL(cosesign1_impl_factory_from_crypto_signer(crypto_signer, &sign_factory, &error), cleanup_part1);
    /* Ownership of crypto_signer was transferred - prevent double free */
    crypto_signer = NULL;

    printf("Signing with direct signature (embedded payload)...\n");
    CHECK_IMPL(cosesign1_impl_factory_sign_direct(
        sign_factory,
        payload,
        payload_len,
        "text/plain",
        &direct_bytes,
        &direct_len,
        &error
    ), cleanup_part1);
    printf("✓ Direct signature created with real cryptography: %u bytes\n", direct_len);

    /* Return the direct signature for validation in later parts */
    *out_cose_bytes = direct_bytes;
    *out_cose_len = direct_len;
    result = 0;

cleanup_part1:
    if (result != 0 && error) {
        char* err_msg = cosesign1_impl_error_message(error);
        fprintf(stderr, "  Signing error: %s\n", err_msg ? err_msg : "(no message)");
        if (err_msg) cosesign1_impl_string_free(err_msg);
    }
    if (result != 0 && direct_bytes) {
        cosesign1_impl_cose_bytes_free(direct_bytes, direct_len);
    }
    if (error) cosesign1_impl_error_free(error);
    if (sign_factory) cosesign1_impl_factory_free(sign_factory);
    if (crypto_signer) cose_crypto_signer_free(crypto_signer); /* Only if not transferred */
    if (crypto_provider) cose_crypto_openssl_provider_free(crypto_provider);
    if (key_der) cose_cert_local_bytes_free(key_der, key_len);
    if (cert_der) cose_cert_local_bytes_free(cert_der, cert_len);
    if (factory) cose_cert_local_factory_free(factory);

    return result;
}
#else
static int demo_signing_local_p256(uint8_t** out_cose_bytes, size_t* out_cose_len)
{
    printf("\n=== Part 1: Signing with Ephemeral P-256 Certificate ===\n");
    printf("SKIPPED: COSE_HAS_CERTIFICATES_LOCAL, COSE_HAS_CRYPTO_OPENSSL, and COSE_HAS_FACTORIES required\n");
    (void)out_cose_bytes;
    (void)out_cose_len;
    return -1;
}
#endif

// ============================================================================
// Part 2: Signing with 3-Tier Certificate Chain
// ============================================================================

#if defined(COSE_HAS_CERTIFICATES_LOCAL) && defined(COSE_HAS_CRYPTO_OPENSSL) && defined(COSE_HAS_FACTORIES)
static int demo_signing_3tier_chain(void)
{
    printf("\n=== Part 2: Signing with 3-Tier Certificate Chain ===\n");

    cose_cert_local_chain_t* chain_factory = NULL;
    uint8_t** certs_data = NULL;
    size_t* certs_lengths = NULL;
    size_t certs_count = 0;
    uint8_t** keys_data = NULL;
    size_t* keys_lengths = NULL;
    size_t keys_count = 0;
    cose_crypto_provider_t* crypto_provider = NULL;
    cose_crypto_signer_t* crypto_signer = NULL;
    cosesign1_impl_factory_t* sign_factory = NULL;
    cosesign1_impl_error_t* error = NULL;
    uint8_t* direct_bytes = NULL;
    uint32_t direct_len = 0;
    int result = -1;

    const char* payload_text = "Hello from 3-tier chain!";
    const uint8_t* payload = (const uint8_t*)payload_text;
    uint32_t payload_len = (uint32_t)strlen(payload_text);

    printf("Creating certificate chain factory...\n");
    if (cose_cert_local_chain_new(&chain_factory) != COSE_OK) {
        fprintf(stderr, "Failed to create chain factory\n");
        goto cleanup_part2;
    }

    printf("Generating 3-tier chain (root->intermediate->leaf) with ECDSA...\n");
    if (cose_cert_local_chain_create(
        chain_factory,
        COSE_KEY_ALG_ECDSA,  /* ECDSA algorithm */
        true,                 /* include intermediate */
        &certs_data,
        &certs_lengths,
        &certs_count,
        &keys_data,
        &keys_lengths,
        &keys_count
    ) != COSE_OK) {
        fprintf(stderr, "Failed to create certificate chain\n");
        char* err = cose_cert_local_last_error_message_utf8();
        if (err) {
            fprintf(stderr, "  Error: %s\n", err);
            cose_cert_local_string_free(err);
        }
        goto cleanup_part2;
    }
    printf("✓ Chain created: %zu certificates, %zu private keys\n", certs_count, keys_count);

    /* Print chain info */
    for (size_t i = 0; i < certs_count; i++) {
        const char* label = (i == 0) ? "Root" : (i == 1) ? "Intermediate" : "Leaf";
        printf("  %s certificate: %zu bytes\n", label, certs_lengths[i]);
    }

    /* Sign with leaf certificate's private key (last key in the chain) */
    if (keys_count == 0) {
        fprintf(stderr, "No private keys in chain\n");
        goto cleanup_part2;
    }

    size_t leaf_key_idx = keys_count - 1;
    printf("Using leaf certificate's private key for signing (%zu bytes)...\n", keys_lengths[leaf_key_idx]);

    printf("Creating OpenSSL crypto provider...\n");
    if (cose_crypto_openssl_provider_new(&crypto_provider) != COSE_OK) {
        fprintf(stderr, "Failed to create crypto provider\n");
        goto cleanup_part2;
    }

    printf("Creating crypto signer from leaf private key...\n");
    if (cose_crypto_openssl_signer_from_der(
        crypto_provider,
        keys_data[leaf_key_idx],
        keys_lengths[leaf_key_idx],
        &crypto_signer
    ) != COSE_OK) {
        fprintf(stderr, "Failed to create crypto signer\n");
        char* err = cose_last_error_message_utf8();
        if (err) {
            fprintf(stderr, "  Error: %s\n", err);
            cose_string_free(err);
        }
        goto cleanup_part2;
    }

    int64_t alg = cose_crypto_signer_algorithm(crypto_signer);
    printf("✓ Crypto signer created with algorithm: %lld\n", (long long)alg);

    /* Create factory DIRECTLY from signer (no callback!) */
    printf("Creating factory directly from crypto signer...\n");
    CHECK_IMPL(cosesign1_impl_factory_from_crypto_signer(crypto_signer, &sign_factory, &error), cleanup_part2);
    /* Ownership of crypto_signer was transferred */
    crypto_signer = NULL;

    printf("Signing with leaf certificate...\n");
    CHECK_IMPL(cosesign1_impl_factory_sign_direct(
        sign_factory,
        payload,
        payload_len,
        "text/plain",
        &direct_bytes,
        &direct_len,
        &error
    ), cleanup_part2);
    printf("✓ Message signed with 3-tier chain: %u bytes\n", direct_len);

    result = 0;

cleanup_part2:
    if (result != 0 && error) {
        char* err_msg = cosesign1_impl_error_message(error);
        fprintf(stderr, "  Error: %s\n", err_msg ? err_msg : "(no message)");
        if (err_msg) cosesign1_impl_string_free(err_msg);
    }
    if (direct_bytes) cosesign1_impl_cose_bytes_free(direct_bytes, direct_len);
    if (error) cosesign1_impl_error_free(error);
    if (sign_factory) cosesign1_impl_factory_free(sign_factory);
    if (crypto_signer) cose_crypto_signer_free(crypto_signer); /* Only if not transferred */
    if (crypto_provider) cose_crypto_openssl_provider_free(crypto_provider);
    
    /* Free chain arrays */
    if (keys_data) {
        for (size_t i = 0; i < keys_count; i++) {
            if (keys_data[i]) cose_cert_local_bytes_free(keys_data[i], keys_lengths[i]);
        }
        cose_cert_local_array_free(keys_data, keys_count);
    }
    if (keys_lengths) cose_cert_local_lengths_array_free(keys_lengths, keys_count);
    if (certs_data) {
        for (size_t i = 0; i < certs_count; i++) {
            if (certs_data[i]) cose_cert_local_bytes_free(certs_data[i], certs_lengths[i]);
        }
        cose_cert_local_array_free(certs_data, certs_count);
    }
    if (certs_lengths) cose_cert_local_lengths_array_free(certs_lengths, certs_count);
    if (chain_factory) cose_cert_local_chain_free(chain_factory);

    return result;
}
#else
static int demo_signing_3tier_chain(void)
{
    printf("\n=== Part 2: Signing with 3-Tier Certificate Chain ===\n");
    printf("SKIPPED: COSE_HAS_CERTIFICATES_LOCAL, COSE_HAS_CRYPTO_OPENSSL, and COSE_HAS_FACTORIES required\n");
    return 0;
}
#endif

// ============================================================================
// Part 3: PQC Signing with ML-DSA-65 (Post-Quantum)
// ============================================================================

#if defined(COSE_HAS_CERTIFICATES_LOCAL) && defined(COSE_HAS_CRYPTO_OPENSSL) && defined(COSE_HAS_FACTORIES) && defined(COSE_HAS_PQC)
static int demo_signing_pqc_mldsa65(void)
{
    printf("\n=== Part 3: PQC Signing with ML-DSA-65 ===\n");

    cose_cert_local_factory_t* factory = NULL;
    uint8_t* cert_der = NULL;
    size_t cert_len = 0;
    uint8_t* key_der = NULL;
    size_t key_len = 0;
    cose_crypto_provider_t* crypto_provider = NULL;
    cose_crypto_signer_t* crypto_signer = NULL;
    cosesign1_impl_factory_t* sign_factory = NULL;
    cosesign1_impl_error_t* error = NULL;
    uint8_t* direct_bytes = NULL;
    uint32_t direct_len = 0;
    int result = -1;

    const char* payload_text = "Hello from post-quantum future!";
    const uint8_t* payload = (const uint8_t*)payload_text;
    uint32_t payload_len = (uint32_t)strlen(payload_text);

    printf("Creating certificate factory...\n");
    if (cose_cert_local_factory_new(&factory) != COSE_OK) {
        fprintf(stderr, "Failed to create certificate factory\n");
        goto cleanup_part3;
    }

    printf("Generating ML-DSA-65 (post-quantum) certificate...\n");
    if (cose_cert_local_factory_create_cert(
        factory,
        "CN=PQC Test Certificate",
        COSE_KEY_ALG_MLDSA,  /* ML-DSA algorithm */
        65,                   /* ML-DSA-65 parameter */
        86400,                /* 1 day validity */
        &cert_der,
        &cert_len,
        &key_der,
        &key_len
    ) != COSE_OK) {
        fprintf(stderr, "Failed to create ML-DSA-65 certificate\n");
        char* err = cose_cert_local_last_error_message_utf8();
        if (err) {
            fprintf(stderr, "  Error: %s\n", err);
            cose_cert_local_string_free(err);
        }
        goto cleanup_part3;
    }
    printf("✓ PQC certificate created: %zu bytes, private key: %zu bytes\n", cert_len, key_len);

    printf("Creating OpenSSL crypto provider...\n");
    if (cose_crypto_openssl_provider_new(&crypto_provider) != COSE_OK) {
        fprintf(stderr, "Failed to create crypto provider\n");
        goto cleanup_part3;
    }

    printf("Creating crypto signer from ML-DSA-65 private key...\n");
    if (cose_crypto_openssl_signer_from_der(crypto_provider, key_der, key_len, &crypto_signer) != COSE_OK) {
        fprintf(stderr, "Failed to create crypto signer\n");
        char* err = cose_last_error_message_utf8();
        if (err) {
            fprintf(stderr, "  Error: %s\n", err);
            cose_string_free(err);
        }
        goto cleanup_part3;
    }

    int64_t alg = cose_crypto_signer_algorithm(crypto_signer);
    printf("✓ PQC crypto signer created with algorithm: %lld (ML-DSA-65)\n", (long long)alg);

    /* Create factory DIRECTLY from signer (no callback!) */
    printf("Creating factory directly from crypto signer...\n");
    CHECK_IMPL(cosesign1_impl_factory_from_crypto_signer(crypto_signer, &sign_factory, &error), cleanup_part3);
    /* Ownership of crypto_signer was transferred */
    crypto_signer = NULL;

    printf("Signing with post-quantum ML-DSA-65...\n");
    CHECK_IMPL(cosesign1_impl_factory_sign_direct(
        sign_factory,
        payload,
        payload_len,
        "text/plain",
        &direct_bytes,
        &direct_len,
        &error
    ), cleanup_part3);
    printf("✓ Message signed with post-quantum cryptography: %u bytes\n", direct_len);
    printf("  (Future-proof against quantum computer attacks!)\n");

    result = 0;

cleanup_part3:
    if (result != 0 && error) {
        char* err_msg = cosesign1_impl_error_message(error);
        fprintf(stderr, "  Error: %s\n", err_msg ? err_msg : "(no message)");
        if (err_msg) cosesign1_impl_string_free(err_msg);
    }
    if (direct_bytes) cosesign1_impl_cose_bytes_free(direct_bytes, direct_len);
    if (error) cosesign1_impl_error_free(error);
    if (sign_factory) cosesign1_impl_factory_free(sign_factory);
    if (crypto_signer) cose_crypto_signer_free(crypto_signer); /* Only if not transferred */
    if (crypto_provider) cose_crypto_openssl_provider_free(crypto_provider);
    if (key_der) cose_cert_local_bytes_free(key_der, key_len);
    if (cert_der) cose_cert_local_bytes_free(cert_der, cert_len);
    if (factory) cose_cert_local_factory_free(factory);

    return result;
}
#else
static int demo_signing_pqc_mldsa65(void)
{
    printf("\n=== Part 3: PQC Signing with ML-DSA-65 ===\n");
    printf("SKIPPED: COSE_HAS_CERTIFICATES_LOCAL, COSE_HAS_CRYPTO_OPENSSL, COSE_HAS_FACTORIES, and COSE_HAS_PQC required\n");
    return 0;
}
#endif

// ============================================================================
// Part 4: Streaming Signing (large payload support)
// ============================================================================

#if defined(COSE_HAS_FACTORIES) && defined(COSE_HAS_CRYPTO_OPENSSL) && defined(COSE_HAS_CERTIFICATES_LOCAL)

/* Callback context for streaming */
typedef struct {
    const uint8_t* data;
    size_t data_len;
    size_t offset;
} streaming_context_t;

/* Read callback for streaming API */
static int64_t streaming_read_callback(uint8_t* buffer, size_t buffer_len, void* user_data)
{
    streaming_context_t* ctx = (streaming_context_t*)user_data;
    
    if (ctx->offset >= ctx->data_len) {
        return 0; /* EOF */
    }
    
    size_t remaining = ctx->data_len - ctx->offset;
    size_t to_read = (buffer_len < remaining) ? buffer_len : remaining;
    
    memcpy(buffer, ctx->data + ctx->offset, to_read);
    ctx->offset += to_read;
    
    return (int64_t)to_read;
}

static int demo_streaming_signing(void)
{
    printf("\n=== Part 4: Streaming Signing ===\n");
    
    cose_cert_local_factory_t* factory = NULL;
    uint8_t* cert_der = NULL;
    size_t cert_len = 0;
    uint8_t* key_der = NULL;
    size_t key_len = 0;
    cose_crypto_provider_t* crypto_provider = NULL;
    cose_crypto_signer_t* crypto_signer = NULL;
    cosesign1_impl_factory_t* sign_factory = NULL;
    cosesign1_impl_error_t* error = NULL;
    uint8_t* file_sig = NULL;
    uint32_t file_sig_len = 0;
    uint8_t* stream_sig = NULL;
    uint32_t stream_sig_len = 0;
    int result = -1;
    
    const char* test_file = "test_payload.bin";
    FILE* f = NULL;
    
    /* Create test file (1MB) */
    printf("Creating test file: %s (1MB)...\n", test_file);
    f = fopen(test_file, "wb");
    if (!f) {
        fprintf(stderr, "Failed to create test file\n");
        goto cleanup_streaming;
    }
    
    /* Write 1MB of test data */
    uint8_t chunk[65536]; /* 64KB chunks */
    memset(chunk, 0x42, sizeof(chunk));
    for (int i = 0; i < 16; i++) {
        if (fwrite(chunk, 1, sizeof(chunk), f) != sizeof(chunk)) {
            fprintf(stderr, "Failed to write test file\n");
            fclose(f);
            goto cleanup_streaming;
        }
    }
    fclose(f);
    f = NULL;
    printf("✓ Created test file (1MB)\n");
    
    /* Generate ephemeral certificate */
    printf("Generating ephemeral certificate...\n");
    if (cose_cert_local_factory_new(&factory) != COSE_OK) {
        fprintf(stderr, "Failed to create factory\n");
        goto cleanup_streaming;
    }
    
    if (cose_cert_local_factory_create_self_signed(
        factory,
        &cert_der, &cert_len,
        &key_der, &key_len
    ) != COSE_OK) {
        fprintf(stderr, "Failed to create certificate\n");
        goto cleanup_streaming;
    }
    
    /* Create crypto signer */
    printf("Creating crypto signer...\n");
    if (cose_crypto_openssl_provider_new(&crypto_provider) != COSE_OK) {
        fprintf(stderr, "Failed to create crypto provider\n");
        goto cleanup_streaming;
    }
    
    if (cose_crypto_openssl_signer_from_der(
        crypto_provider,
        key_der, key_len,
        &crypto_signer
    ) != COSE_OK) {
        fprintf(stderr, "Failed to create crypto signer\n");
        goto cleanup_streaming;
    }
    
    /* Create signature factory */
    printf("Creating signature factory...\n");
    CHECK_IMPL(cosesign1_impl_factory_from_crypto_signer(
        crypto_signer,
        &sign_factory,
        &error
    ), cleanup_streaming);
    crypto_signer = NULL; /* Ownership transferred */
    
    /* File-based streaming sign */
    printf("Signing file with streaming (file never fully loaded into memory)...\n");
    CHECK_IMPL(cosesign1_impl_factory_sign_direct_file(
        sign_factory,
        test_file,
        "application/octet-stream",
        &file_sig,
        &file_sig_len,
        &error
    ), cleanup_streaming);
    printf("✓ Streamed 1MB file -> detached signature: %u bytes\n", file_sig_len);
    printf("  (File was never fully loaded into memory)\n");
    
    /* Callback-based streaming */
    printf("Signing with callback streaming...\n");
    
    /* Create 1MB in-memory buffer for demonstration */
    uint8_t* in_memory_data = (uint8_t*)malloc(1024 * 1024);
    if (!in_memory_data) {
        fprintf(stderr, "Failed to allocate memory\n");
        goto cleanup_streaming;
    }
    memset(in_memory_data, 0xAB, 1024 * 1024);
    
    streaming_context_t ctx = {
        .data = in_memory_data,
        .data_len = 1024 * 1024,
        .offset = 0
    };
    
    CHECK_IMPL(cosesign1_impl_factory_sign_direct_streaming(
        sign_factory,
        streaming_read_callback,
        1024 * 1024,
        &ctx,
        "application/octet-stream",
        &stream_sig,
        &stream_sig_len,
        &error
    ), cleanup_streaming);
    
    free(in_memory_data);
    printf("✓ Callback-streamed 1MB -> detached signature: %u bytes\n", stream_sig_len);
    
    /* Cleanup test file */
    remove(test_file);
    printf("✓ Cleaned up test file\n");
    
    result = 0;
    
cleanup_streaming:
    if (result != 0 && error) {
        char* err_msg = cosesign1_impl_error_message(error);
        if (err_msg) {
            fprintf(stderr, "  Error: %s\n", err_msg);
            cosesign1_impl_string_free(err_msg);
        }
    }
    if (stream_sig) cosesign1_impl_cose_bytes_free(stream_sig, stream_sig_len);
    if (file_sig) cosesign1_impl_cose_bytes_free(file_sig, file_sig_len);
    if (error) cosesign1_impl_error_free(error);
    if (sign_factory) cosesign1_impl_factory_free(sign_factory);
    if (crypto_signer) cose_crypto_signer_free(crypto_signer);
    if (crypto_provider) cose_crypto_openssl_provider_free(crypto_provider);
    if (key_der) cose_cert_local_bytes_free(key_der, key_len);
    if (cert_der) cose_cert_local_bytes_free(cert_der, cert_len);
    if (factory) cose_cert_local_factory_free(factory);
    if (f) fclose(f);
    
    return result;
}
#else
static int demo_streaming_signing(void)
{
    printf("\n=== Part 4: Streaming Signing ===\n");
    printf("SKIPPED: Requires COSE_HAS_FACTORIES, COSE_HAS_CRYPTO_OPENSSL, COSE_HAS_CERTIFICATES_LOCAL\n");
    return 0;
}
#endif

// ============================================================================
// Part 5: Message Inspection (if COSE_HAS_PRIMITIVES)
// ============================================================================

#ifdef COSE_HAS_PRIMITIVES
static int demo_inspection(const uint8_t* cose_bytes, size_t cose_len)
{
    printf("\n=== Part 5: Message Inspection ===\n");

    CoseSign1MessageHandle* message = NULL;
    CoseSign1ErrorHandle* error = NULL;
    CoseHeaderMapHandle* protected_headers = NULL;
    int result = -1;

    printf("Parsing COSE_Sign1 message...\n");
    CHECK_PRIM(cosesign1_message_parse(
        cose_bytes,
        cose_len,
        &message,
        &error
    ), cleanup_inspect);
    printf("✓ Message parsed successfully\n");

    /* Check if payload is detached */
    bool is_detached = cosesign1_message_is_detached(message);
    printf("Payload type: %s\n", is_detached ? "detached" : "embedded");

    /* Extract algorithm from protected headers */
    int64_t algorithm = 0;
    CHECK_PRIM(cosesign1_message_alg(message, &algorithm), cleanup_inspect);
    printf("Algorithm: %lld (", (long long)algorithm);
    switch (algorithm) {
        case COSE_ALG_ES256: printf("ES256"); break;
        case COSE_ALG_ES384: printf("ES384"); break;
        case COSE_ALG_ES512: printf("ES512"); break;
        case COSE_ALG_EDDSA: printf("EdDSA"); break;
        default: printf("unknown"); break;
    }
    printf(")\n");

    /* Extract content type if present */
    CHECK_PRIM(cosesign1_message_protected_headers(message, &protected_headers), cleanup_inspect);
    char* content_type = cosesign1_headermap_get_text(protected_headers, COSE_HEADER_CONTENT_TYPE);
    if (content_type) {
        printf("Content-Type: %s\n", content_type);
        cosesign1_string_free(content_type);
    } else {
        printf("Content-Type: (not present)\n");
    }

    /* Get payload if embedded */
    if (!is_detached) {
        const uint8_t* payload_ptr = NULL;
        size_t payload_len = 0;
        CHECK_PRIM(cosesign1_message_payload(message, &payload_ptr, &payload_len), cleanup_inspect);
        printf("Payload (%zu bytes): ", payload_len);
        /* Print as text if printable */
        bool printable = true;
        for (size_t i = 0; i < payload_len && i < 50; i++) {
            if (payload_ptr[i] < 32 || payload_ptr[i] > 126) {
                printable = false;
                break;
            }
        }
        if (printable && payload_len > 0) {
            printf("\"%.*s\"\n", (int)(payload_len < 50 ? payload_len : 50), payload_ptr);
        } else {
            printf("(binary data)\n");
        }
    }

    /* Get signature bytes */
    const uint8_t* signature_ptr = NULL;
    size_t signature_len = 0;
    CHECK_PRIM(cosesign1_message_signature(message, &signature_ptr, &signature_len), cleanup_inspect);
    printf("Signature: %zu bytes\n", signature_len);

    printf("✓ Message inspection complete\n");
    result = 0;

cleanup_inspect:
    if (result != 0 && error) {
        print_primitives_error(error);
    }
    if (protected_headers) cosesign1_headermap_free(protected_headers);
    if (error) cosesign1_error_free(error);
    if (message) cosesign1_message_free(message);

    return result;
}
#endif /* COSE_HAS_PRIMITIVES */

// ============================================================================
// Part 6: Validation with Trust Policy (if COSE_HAS_CERTIFICATES_PACK)
// ============================================================================

#ifdef COSE_HAS_CERTIFICATES_PACK
static int demo_validation(const uint8_t* cose_bytes, size_t cose_len)
{
    printf("\n=== Part 6: Validation with Trust Policy ===\n");

    cose_validator_builder_t* builder = NULL;
    cose_trust_policy_builder_t* policy = NULL;
    cose_compiled_trust_plan_t* plan = NULL;
    cose_validator_t* validator = NULL;
    cose_validation_result_t* validation_result = NULL;

    printf("Creating validator builder...\n");
    COSE_CHECK(cose_validator_builder_new(&builder));

    printf("Adding certificates validation pack...\n");
    COSE_CHECK(cose_validator_builder_with_certificates_pack(builder));

    printf("Building custom trust policy...\n");
    COSE_CHECK(cose_trust_policy_builder_new_from_validator_builder(builder, &policy));

    /* Require embedded payload */
    printf("  - Requiring embedded payload\n");
    COSE_CHECK(cose_trust_policy_builder_require_detached_payload_absent(policy));

    /* Require content type header */
    printf("  - Requiring content-type header present\n");
    COSE_CHECK(cose_trust_policy_builder_require_content_type_non_empty(policy));

    /* Note: X.509 chain requirements would require actual certificate data in the message */
    /* For this demo, we use local certificates but don't embed them in protected headers */

    printf("Compiling trust policy...\n");
    COSE_CHECK(cose_trust_policy_builder_compile(policy, &plan));

    printf("Attaching compiled trust plan to validator builder...\n");
    COSE_CHECK(cose_validator_builder_with_compiled_trust_plan(builder, plan));

    printf("Building validator...\n");
    COSE_CHECK(cose_validator_builder_build(builder, &validator));

    printf("Validating COSE_Sign1 message...\n");
    COSE_CHECK(cose_validator_validate_bytes(
        validator,
        cose_bytes,
        cose_len,
        NULL,  /* no detached payload */
        0,
        &validation_result
    ));

    /* Check validation result */
    bool is_valid = false;
    COSE_CHECK(cose_validation_result_is_success(validation_result, &is_valid));

    if (is_valid) {
        printf("✓ Validation SUCCESSFUL\n");
    } else {
        printf("✗ Validation FAILED\n");
        char* failure_msg = cose_validation_result_failure_message_utf8(validation_result);
        if (failure_msg) {
            printf("  Reason: %s\n", failure_msg);
            cose_string_free(failure_msg);
        }
    }

cleanup:
    if (validation_result) cose_validation_result_free(validation_result);
    if (validator) cose_validator_free(validator);
    if (plan) cose_compiled_trust_plan_free(plan);
    if (policy) cose_trust_policy_builder_free(policy);
    if (builder) cose_validator_builder_free(builder);

    return 0;
}
#endif /* COSE_HAS_CERTIFICATES_PACK */

// ============================================================================
// Part 7: DID:x509 Generation (if COSE_HAS_DID_X509)
// ============================================================================

#ifdef COSE_HAS_DID_X509
static int demo_did_x509(void)
{
    printf("\n=== Part 7: DID:x509 Generation ===\n");

    /* Mock certificate data (would be real DER-encoded cert in production) */
    /* This is a simplified example; real certificates would be much larger */
    uint8_t mock_ca_cert[] = {
        0x30, 0x82, 0x01, 0x00,  /* SEQUENCE header */
        /* ... certificate data would go here ... */
        /* For demo, we'll use dummy data */
    };
    uint32_t mock_ca_cert_len = sizeof(mock_ca_cert);

    char* did_string = NULL;
    DidX509ErrorHandle* error = NULL;
    DidX509ParsedHandle* parsed = NULL;
    int result = -1;

    printf("Note: DID:x509 generation requires valid X.509 certificate data.\n");
    printf("This demo uses mock certificate data and will likely fail.\n");
    printf("In production, use real DER-encoded X.509 certificates.\n\n");

    /* Example EKU OIDs (Extended Key Usage) */
    const char* eku_oids[] = {
        "1.3.6.1.5.5.7.3.1",  /* id-kp-serverAuth */
        "1.3.6.1.5.5.7.3.2"   /* id-kp-clientAuth */
    };

    printf("Attempting to build DID:x509 from certificate...\n");
    int build_result = did_x509_build_with_eku(
        mock_ca_cert,
        mock_ca_cert_len,
        eku_oids,
        2,
        &did_string,
        &error
    );

    if (build_result == DID_X509_OK && did_string) {
        printf("✓ Generated DID: %s\n", did_string);

        /* Parse the DID to extract components */
        printf("Parsing generated DID...\n");
        CHECK_DID(did_x509_parse(did_string, &parsed, &error), cleanup_did);

        const char* fingerprint = NULL;
        CHECK_DID(did_x509_parsed_get_fingerprint(parsed, &fingerprint, &error), cleanup_did);
        printf("  CA Fingerprint: %s\n", fingerprint ? fingerprint : "(none)");

        const char* hash_alg = NULL;
        CHECK_DID(did_x509_parsed_get_hash_algorithm(parsed, &hash_alg, &error), cleanup_did);
        printf("  Hash Algorithm: %s\n", hash_alg ? hash_alg : "(none)");

        uint32_t policy_count = 0;
        CHECK_DID(did_x509_parsed_get_policy_count(parsed, &policy_count), cleanup_did);
        printf("  Policy Count: %u\n", policy_count);

        printf("✓ DID:x509 processing complete\n");
        result = 0;
    } else {
        printf("✗ DID:x509 generation failed (expected with mock data)\n");
        if (error) {
            print_did_error(error);
        }
        /* Not an error for demo purposes since we're using mock data */
        result = 0;
    }

cleanup_did:
    if (parsed) did_x509_parsed_free(parsed);
    if (error) did_x509_error_free(error);
    if (did_string) did_x509_string_free(did_string);

    return result;
}
#endif /* COSE_HAS_DID_X509 */

// ============================================================================
// Main
// ============================================================================

int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    printf("========================================\n");
    printf(" COSE Sign1 Full API Demonstration\n");
    printf("========================================\n");
    printf("\nThis example demonstrates:\n");
    printf("  1. Signing with ephemeral P-256 certificate (real crypto)\n");
    printf("  2. Signing with 3-tier certificate chain\n");
    printf("  3. PQC signing with ML-DSA-65 (if available)\n");
#ifdef COSE_HAS_PRIMITIVES
    printf("  4. Message inspection with primitives API\n");
#endif
#ifdef COSE_HAS_CERTIFICATES_PACK
    printf("  5. Validation with custom trust policies\n");
#endif
#ifdef COSE_HAS_DID_X509
    printf("  6. DID:x509 generation and parsing\n");
#endif
    printf("\n");

    uint8_t* cose_bytes = NULL;
    size_t cose_len = 0;

    /* Part 1: Signing with ephemeral P-256 */
    if (demo_signing_local_p256(&cose_bytes, &cose_len) != 0) {
        fprintf(stderr, "Part 1 failed (may be skipped if dependencies unavailable)\n");
        /* Continue with other parts */
    }

    /* Part 2: 3-tier chain signing */
    if (demo_signing_3tier_chain() != 0) {
        fprintf(stderr, "Part 2 failed (may be skipped)\n");
    }

    /* Part 3: PQC signing */
    if (demo_signing_pqc_mldsa65() != 0) {
        fprintf(stderr, "Part 3 failed (may be skipped)\n");
    }

    /* Part 4: Streaming signing */
    if (demo_streaming_signing() != 0) {
        fprintf(stderr, "Part 4 failed (may be skipped)\n");
    }

#ifdef COSE_HAS_PRIMITIVES
    /* Part 5: Message Inspection (only if Part 1 succeeded) */
    if (cose_bytes != NULL) {
        if (demo_inspection(cose_bytes, cose_len) != 0) {
            fprintf(stderr, "Inspection demonstration failed\n");
            cosesign1_impl_cose_bytes_free(cose_bytes, (uint32_t)cose_len);
            return 1;
        }
    }
#endif

#ifdef COSE_HAS_CERTIFICATES_PACK
    /* Part 6: Validation with Trust Policy (only if Part 1 succeeded) */
    if (cose_bytes != NULL) {
        if (demo_validation(cose_bytes, cose_len) != 0) {
            fprintf(stderr, "Validation demonstration failed\n");
            cosesign1_impl_cose_bytes_free(cose_bytes, (uint32_t)cose_len);
            return 1;
        }
    }
#endif

    /* Clean up signed message */
    if (cose_bytes) {
        cosesign1_impl_cose_bytes_free(cose_bytes, (uint32_t)cose_len);
    }

#ifdef COSE_HAS_DID_X509
    /* Part 7: DID:x509 Generation */
    if (demo_did_x509() != 0) {
        fprintf(stderr, "DID:x509 demonstration failed\n");
        return 1;
    }
#endif

    printf("\n========================================\n");
    printf(" All demonstrations completed!\n");
    printf("========================================\n");

    return 0;
}
