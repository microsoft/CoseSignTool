// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file hello_cose.cpp
 * @brief Minimal COSE_Sign1 message parse + inspect example using C++ RAII wrappers.
 *
 * Demonstrates:
 *   1. Parse a COSE_Sign1 message from bytes
 *   2. Read the algorithm from protected headers
 *   3. Read the embedded payload (zero-copy ByteView)
 *   4. Automatic cleanup via RAII
 *
 * Build: link against cose_sign1_cpp (requires COSE_HAS_PRIMITIVES).
 */

#include <iostream>
#include <string_view>

#ifdef COSE_HAS_PRIMITIVES
#include <cose/sign1.hpp>
#endif

int main() {
#ifndef COSE_HAS_PRIMITIVES
    std::cerr
        << "This example requires the primitives FFI library.\n"
        << "Build Rust first: cd native/rust && cargo build --release --workspace\n"
        << "Then re-run CMake with -DBUILD_TESTING=ON.\n";
    return 1;
#else
    /*
     * A minimal COSE_Sign1 message (tagged, ES256, payload = "Hello, COSE!").
     *
     * The signature is a placeholder — it will parse correctly but won't
     * verify without the original signing key.
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

    try {
        /* 1. Parse — RAII handles cleanup automatically */
        auto msg = cose::sign1::CoseSign1Message::Parse(cose_msg, sizeof(cose_msg));

        /* 2. Read algorithm (returns std::optional) */
        auto alg = msg.Algorithm();
        if (alg) {
            std::cout << "Algorithm: " << *alg << " (ES256 = -7)" << std::endl;
        } else {
            std::cout << "Algorithm: not found in protected headers" << std::endl;
        }

        /* 3. Read payload — zero-copy ByteView borrowed from the message */
        auto payload = msg.Payload();
        if (payload && !payload->empty()) {
            std::string_view text(
                reinterpret_cast<const char*>(payload->data), payload->size);
            std::cout << "Payload (" << payload->size << " bytes): "
                      << text << std::endl;
        } else {
            std::cout << "Payload: detached (not embedded)" << std::endl;
        }

        /* msg is freed automatically when it goes out of scope */
        std::cout << "Success!" << std::endl;
        return 0;

    } catch (const cose::sign1::primitives_error& e) {
        std::cerr << "COSE error: " << e.what() << std::endl;
        return 1;
    }
#endif /* COSE_HAS_PRIMITIVES */
}
