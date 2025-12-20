// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

/**
 * @file cbor.h
 * @brief CBOR parsing helpers used by the COSE_Sign1 model.
 */

// Umbrella header for cosesign1-common CBOR/COSE helpers.
//
// Keep this as a lightweight include that exposes the public surface area without
// duplicating definitions across headers.

#include <cosesign1/common/cbor_primitives.h>
#include <cosesign1/common/cose_header_map.h>
#include <cosesign1/common/cose_sign1.h>
