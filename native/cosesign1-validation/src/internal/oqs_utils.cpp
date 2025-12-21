// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file oqs_utils.cpp
 * @brief liboqs helpers for PQC signature verification.
 */

#include "oqs_utils.h"

#include <oqs/oqs.h>

#include <memory>

namespace cosesign1::internal {

namespace {

const char* OqsAlgFromCoseAlg(std::int64_t cose_alg) {
  switch (cose_alg) {
    case -48:
#if defined(OQS_SIG_alg_ml_dsa_44)
      return OQS_SIG_alg_ml_dsa_44;
#else
      return OQS_SIG_alg_dilithium_2;
#endif
    case -49:
#if defined(OQS_SIG_alg_ml_dsa_65)
      return OQS_SIG_alg_ml_dsa_65;
#else
      return OQS_SIG_alg_dilithium_3;
#endif
    case -50:
#if defined(OQS_SIG_alg_ml_dsa_87)
      return OQS_SIG_alg_ml_dsa_87;
#else
      return OQS_SIG_alg_dilithium_5;
#endif
    default:
      return nullptr;
  }
}

struct OqsSigDeleter {
  void operator()(OQS_SIG* s) const { OQS_SIG_free(s); }
};

} // namespace

bool VerifyMlDsa(std::int64_t cose_alg,
                std::span<const std::uint8_t> to_be_signed,
                std::span<const std::uint8_t> signature,
                std::span<const std::uint8_t> public_key_bytes) {
  const char* alg = OqsAlgFromCoseAlg(cose_alg);
  if (!alg) {
    return false;
  }

  std::unique_ptr<OQS_SIG, OqsSigDeleter> sig(OQS_SIG_new(alg));
  if (!sig) {
    return false;
  }

  if (public_key_bytes.size() != sig->length_public_key) {
    return false;
  }

  if (signature.size() != sig->length_signature) {
    return false;
  }

  const auto rc = OQS_SIG_verify(sig.get(),
                                to_be_signed.data(),
                                to_be_signed.size(),
                                signature.data(),
                                signature.size(),
                                public_key_bytes.data());
  return rc == OQS_SUCCESS;
}

} // namespace cosesign1::internal
