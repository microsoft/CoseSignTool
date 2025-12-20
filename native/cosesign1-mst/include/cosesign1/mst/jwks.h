// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "cosesign1/mst/jwk_ec_public_key.h"
#include "cosesign1/mst/jwks_document.h"
#include "cosesign1/validation/cose_sign1_verifier.h"

namespace cosesign1::mst {

/**
 * @file jwks.h
 * @brief JWKS parsing and EC JWK key conversion utilities.
 */

/**
 * @brief Parses a JWKS JSON document (RFC 7517).
 *
 * Supported key form:
 * - EC JWKs with (kty=EC, crv, x, y).
 */
std::optional<JwksDocument> ParseJwks(std::string_view jwks_json);

/**
 * @brief Converts an EC JWK public key into a PEM-encoded SubjectPublicKeyInfo.
 */
std::optional<std::string> EcJwkToPublicKeyPem(const JwkEcPublicKey& jwk);

/**
 * @brief Converts an EC JWK public key into a DER-encoded SubjectPublicKeyInfo.
 */
std::optional<std::vector<std::uint8_t>> EcJwkToPublicKeyDer(const JwkEcPublicKey& jwk);

/**
 * @brief Determines the expected COSE algorithm from an EC curve name.
 */
std::optional<cosesign1::validation::CoseAlgorithm> ExpectedAlgFromCrv(std::string_view crv);

} // namespace cosesign1::mst
