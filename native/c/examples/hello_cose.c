// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file hello_cose.c
 * @brief Minimal COSE_Sign1 message parse + inspect example (~30 lines of logic).
 *
 * Demonstrates:
 *   1. Parse a COSE_Sign1 message from bytes
 *   2. Read the algorithm from protected headers
 *   3. Read the embedded payload
 *   4. Proper error handling and cleanup
 *
 * Build: link against cose_sign1 (requires COSE_HAS_PRIMITIVES).
 */

#include <stdio.h>
#include <string.h>

#ifdef COSE_HAS_PRIMITIVES
#include <cose/sign1.h>
#endif

int main(void) {
#ifndef COSE_HAS_PRIMITIVES
    fprintf(stderr,
        "This example requires the primitives FFI library.\n"
        "Build Rust first: cd native/rust && cargo build --release --workspace\n"
        "Then re-run CMake with -DBUILD_TESTING=ON.\n");
    return 1;
#else
    /*
     * A minimal COSE_Sign1 message (tagged, ES256, payload = "Hello, COSE!").
     *
     * Structure (CBOR diagnostic):
     *   18(                              -- COSE_Sign1 tag (18)
     *     [
     *       h'a10126',                   -- protected: {1: -7} (alg: ES256)
     *       {},                          -- unprotected: empty
     *       h'48656c6c6f2c20434f534521', -- payload: "Hello, COSE!"
     *       h'...'                       -- signature (64 bytes, not verifiable
     *                                    --   without the matching public key)
     *     ]
     *   )
     *
     * This is a structurally valid COSE_Sign1 message. The signature is a
     * placeholder — it will parse correctly but won't verify without the
     * original signing key.
     */
    static const uint8_t cose_msg[] = {
        0xd2, 0x84,                                     /* tag(18), array(4) */
        0x43, 0xa1, 0x01, 0x26,                         /* protected: {1:-7} */
        0xa0,                                           /* unprotected: {}   */
        0x4c, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20,
        0x43, 0x4f, 0x53, 0x45, 0x21,                  /* payload: "Hello, COSE!" */
        0x58, 0x40,                                     /* signature: 64 bytes */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f
    };

    /* 1. Parse the message */
    CoseSign1MessageHandle* msg = NULL;
    CoseSign1ErrorHandle* error = NULL;

    int32_t status = cose_sign1_message_parse(cose_msg, sizeof(cose_msg), &msg, &error);
    if (status != COSE_SIGN1_OK) {
        char* err_msg = error ? cose_sign1_error_message(error) : NULL;
        fprintf(stderr, "Parse failed (code %d): %s\n",
            status, err_msg ? err_msg : "unknown error");
        cose_sign1_string_free(err_msg);
        cose_sign1_error_free(error);
        return 1;
    }

    /* 2. Read algorithm from protected headers */
    int64_t alg = 0;
    status = cose_sign1_message_alg(msg, &alg);
    if (status == COSE_SIGN1_OK) {
        printf("Algorithm: %lld (ES256 = -7)\n", (long long)alg);
    } else {
        printf("Algorithm: not found in protected headers\n");
    }

    /* 3. Read embedded payload */
    const uint8_t* payload = NULL;
    size_t payload_len = 0;
    status = cose_sign1_message_payload(msg, &payload, &payload_len);
    if (status == COSE_SIGN1_OK && payload) {
        printf("Payload (%zu bytes): %.*s\n",
            payload_len, (int)payload_len, (const char*)payload);
    } else if (status == COSE_SIGN1_ERR_PAYLOAD_MISSING) {
        printf("Payload: detached (not embedded)\n");
    }

    /* 4. Clean up */
    cose_sign1_message_free(msg);

    printf("Success!\n");
    return 0;
#endif /* COSE_HAS_PRIMITIVES */
}
