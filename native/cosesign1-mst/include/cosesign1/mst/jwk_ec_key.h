// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

/**
 * @file jwk_ec_key.h
 * @brief Backward-compatible umbrella header for JWKS/JWK types and helpers.
 *
 * This header intentionally contains no type definitions. Concrete types are split
 * into dedicated headers to keep one public type per header.
 */

#include "cosesign1/mst/jwk_ec_public_key.h"
#include "cosesign1/mst/jwks_document.h"
#include "cosesign1/mst/jwks.h"
#include "cosesign1/mst/offline_ec_key_store.h"
