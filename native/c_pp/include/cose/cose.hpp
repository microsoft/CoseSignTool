// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file cose.hpp
 * @brief Convenience header that includes all COSE C++ wrappers
 * 
 * This header includes all available pack extensions. If you want to use only
 * specific packs, include the individual headers instead.
 */

#ifndef COSE_HPP
#define COSE_HPP

#include <cose/validator.hpp>

// Optional pack headers - include only if the corresponding FFI library is available
#ifdef COSE_HAS_CERTIFICATES_PACK
#include <cose/certificates.hpp>
#endif

#ifdef COSE_HAS_MST_PACK
#include <cose/mst.hpp>
#endif

#ifdef COSE_HAS_AKV_PACK
#include <cose/azure_key_vault.hpp>
#endif

#endif // COSE_HPP
