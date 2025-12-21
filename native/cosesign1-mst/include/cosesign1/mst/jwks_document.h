// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <vector>

#include "cosesign1/mst/jwk_ec_public_key.h"

namespace cosesign1::mst {

/**
 * @file jwks_document.h
 * @brief Data model for a JWKS (JSON Web Key Set) document.
 */

/**
 * @brief Represents a JWKS document containing one or more keys.
 */
struct JwksDocument {
  std::vector<JwkEcPublicKey> keys;
};

} // namespace cosesign1::mst
