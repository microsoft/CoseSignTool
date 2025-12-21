// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file oqs_utils.h
 * @brief Internal liboqs helper declarations.
 */

#pragma once

#include <cstdint>
#include <span>

namespace cosesign1::internal {

// Verifies ML-DSA signatures via liboqs.
// `cose_alg` must be one of: -48 (ML-DSA-44), -49 (ML-DSA-65), -50 (ML-DSA-87).
bool VerifyMlDsa(std::int64_t cose_alg,
                std::span<const std::uint8_t> to_be_signed,
                std::span<const std::uint8_t> signature,
                std::span<const std::uint8_t> public_key_bytes);

} // namespace cosesign1::internal
