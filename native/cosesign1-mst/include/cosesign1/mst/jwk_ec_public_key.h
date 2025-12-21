// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <string>

namespace cosesign1::mst {

/**
 * @file jwk_ec_public_key.h
 * @brief Data model for an EC JWK public key (RFC 7517 / RFC 7518).
 */

/**
 * @brief Represents an EC public key in JWK form.
 *
 * The coordinates are stored as base64url strings as they appear in the JWKS payload.
 */
struct JwkEcPublicKey {
  /** @brief Key identifier used to select the key. */
  std::string kid;

  /** @brief Curve name (e.g. "P-256"). */
  std::string crv;

  /** @brief Key type (must be "EC" for EC keys). */
  std::string kty;

  /** @brief X coordinate, base64url encoded. */
  std::string x_b64url;

  /** @brief Y coordinate, base64url encoded. */
  std::string y_b64url;
};

} // namespace cosesign1::mst
