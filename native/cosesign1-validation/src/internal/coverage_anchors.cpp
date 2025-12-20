// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file coverage_anchors.cpp
 * @brief Small anchor functions used to make key destructors coverable.
 */

#include "cosesign1/validation/validator.h"
#include "cosesign1/validation/validator_markers.h"

namespace cosesign1::validation::internal {

void ValidatorDtorAnchor() noexcept {}

void LastCoseSign1ValidatorDtorAnchor() noexcept {}

} // namespace cosesign1::validation::internal