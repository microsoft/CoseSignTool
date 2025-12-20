// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <cstdint>
#include <optional>
#include <span>

#include "cosesign1/validation/cose_sign1_verifier.h"

namespace cosesign1::validation {

/**
 * @file cose_sign1_validation_context.h
 * @brief Per-validation inputs that are not part of the COSE_Sign1 structure itself.
 */
struct CoseSign1ValidationContext {
  /**
   * @brief External payload bytes used when the COSE_Sign1 payload is detached.
   *
   * If the COSE_Sign1 payload is detached (i.e. the payload is `null`), validators may
   * use this span as the payload bytes.
   */
  std::optional<std::span<const std::uint8_t>> external_payload;

  /**
   * @brief Optional callback used to materialize external payload bytes on demand.
   *
   * This is intended for stream-backed payloads. The provider may be invoked by multiple
   * validators; it should return the full payload bytes.
   */
  VerifyOptions::BytesProvider external_payload_provider;
};

} // namespace cosesign1::validation
