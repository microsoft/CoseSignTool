// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file azure_artifact_signing.hpp
 * @brief C++ wrappers for Azure Artifact Signing trust pack
 */

#ifndef COSE_SIGN1_ATS_HPP
#define COSE_SIGN1_ATS_HPP

#include <cose/sign1/validation.hpp>
#include <cose/sign1/trust.hpp>
#include <cose/sign1/extension_packs/azure_artifact_signing.h>
#include <string>

namespace cose::sign1 {

/**
 * @brief Options for Azure Artifact Signing
 */
struct AzureArtifactSigningOptions {
    std::string endpoint;
    std::string account_name;
    std::string certificate_profile_name;
};

/**
 * @brief Add Azure Artifact Signing pack with default options.
 */
inline void WithAzureArtifactSigning(ValidatorBuilder& builder) {
    cose::detail::ThrowIfNotOk(
        cose_sign1_validator_builder_with_ats_pack(builder.native_handle()));
}

/**
 * @brief Add Azure Artifact Signing pack with custom options.
 */
inline void WithAzureArtifactSigning(ValidatorBuilder& builder,
                                     const AzureArtifactSigningOptions& opts) {
    cose_ats_trust_options_t c_opts{};
    c_opts.endpoint = opts.endpoint.c_str();
    c_opts.account_name = opts.account_name.c_str();
    c_opts.certificate_profile_name = opts.certificate_profile_name.c_str();
    cose::detail::ThrowIfNotOk(
        cose_sign1_validator_builder_with_ats_pack_ex(builder.native_handle(), &c_opts));
}

} // namespace cose::sign1

#endif // COSE_SIGN1_ATS_HPP