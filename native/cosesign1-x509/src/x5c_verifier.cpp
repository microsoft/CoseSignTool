// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file x5c_verifier.cpp
 * @brief X.509 (x5c) certificate-chain based COSE_Sign1 verification.
 */

#include "cosesign1/x509/x5c_verifier.h"

#include <cstddef>
#include <string>
#include <stdexcept>

#include <openssl/evp.h>
#include <openssl/pem.h>

#include <tinycbor/cbor.h>

#include <cosesign1/common/cbor.h>

namespace cosesign1::x509 {

namespace {

validation::ValidationResult Fail(std::string_view validator_name, std::string message, std::string code) {
  validation::ValidationFailure f;
  f.message = std::move(message);
  f.error_code = std::move(code);
  return validation::ValidationResult::Failure(std::string(validator_name), std::vector<validation::ValidationFailure>{std::move(f)});
}

bool TryExtractLeafDerFromHeaders(const cosesign1::common::cbor::ParsedCoseSign1& parsed, std::vector<std::uint8_t>& leaf_der) {

  auto try_extract_leaf_from_x5c_value = [&](const std::vector<std::uint8_t>& x5c_value_cbor) -> bool {
    // x5c is an array of bstr; leaf is first element.
    CborParser p;
    CborValue it;
    if (cbor_parser_init(x5c_value_cbor.data(), x5c_value_cbor.size(), 0, &p, &it) != CborNoError) return false;
    if (!cbor_value_is_array(&it)) return false;

    CborValue certs;
    if (cbor_value_enter_container(&it, &certs) != CborNoError) return false;
    if (cbor_value_at_end(&certs)) return false;

    if (!cosesign1::common::cbor::ReadByteString(&certs, leaf_der)) return false;

    // Consume remaining elements (if any) so leave_container succeeds.
    // We only care about the first element (the leaf certificate).
    while (!cbor_value_at_end(&certs)) {
      if (cbor_value_advance(&certs) != CborNoError) return false;
    }

    return cbor_value_leave_container(&it, &certs) == CborNoError;
  };

  // COSE rules: unprotected header parameters apply too, but protected is authoritative.
  // For x5c specifically, accept either (and prefer protected if both present).
  if (parsed.protected_headers.TryGetFirstByteStringFromArray(33, leaf_der)) {
    return true;
  }
  if (parsed.unprotected_headers.TryGetFirstByteStringFromArray(33, leaf_der)) {
    return true;
  }

  // Fallback: if x5c exists but wasn't decoded as array-of-bstr, parse raw CBOR value bytes.
  // Prefer protected if present.
  std::vector<std::uint8_t> raw;
  if (parsed.protected_headers.TryGetRawValueCbor(33, raw)) {
    return try_extract_leaf_from_x5c_value(raw);
  }
  if (parsed.unprotected_headers.TryGetRawValueCbor(33, raw)) {
    return try_extract_leaf_from_x5c_value(raw);
  }

  return false;
}

std::string PemCertificateFromDer(const std::vector<std::uint8_t>& der) {
  if (der.empty()) {
    throw std::runtime_error("empty certificate DER");
  }

  // Base64 encode DER with PEM line wrapping.
  std::string b64;
  b64.resize(((der.size() + 2) / 3) * 4);
  const int len = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(b64.data()),
                                  reinterpret_cast<const unsigned char*>(der.data()),
                                  static_cast<int>(der.size()));
  if (len <= 0) {
    throw std::runtime_error("EVP_EncodeBlock failed");
  }
  b64.resize(static_cast<std::size_t>(len));

  std::string pem;
  pem.reserve(b64.size() + 128);
  pem.append("-----BEGIN CERTIFICATE-----\n");
  for (std::size_t i = 0; i < b64.size(); i += 64) {
    pem.append(b64.substr(i, std::min<std::size_t>(64, b64.size() - i)));
    pem.push_back('\n');
  }
  pem.append("-----END CERTIFICATE-----\n");
  return pem;
}

} // namespace

validation::ValidationResult VerifyCoseSign1WithX5c(std::string_view validator_name,
                                                    const std::vector<std::uint8_t>& cose_sign1,
                                                    const validation::VerifyOptions& options) {
  cosesign1::common::cbor::ParsedCoseSign1 parsed;
  std::string parse_error;
  if (!cosesign1::common::cbor::ParseCoseSign1(cose_sign1, parsed, &parse_error)) {
    // Preserve legacy behavior: parse failures are treated as "missing/invalid x5c".
    return Fail(validator_name, "x5c header (label 33) not found or invalid", "MISSING_X5C");
  }

  std::optional<std::span<const std::uint8_t>> external_payload;
  if (options.external_payload) {
    external_payload = std::span<const std::uint8_t>(options.external_payload->data(), options.external_payload->size());
  }

  return VerifyParsedCoseSign1WithX5c(validator_name, parsed, external_payload, options);
}

validation::ValidationResult VerifyParsedCoseSign1WithX5c(std::string_view validator_name,
                                                          const cosesign1::common::cbor::ParsedCoseSign1& parsed,
                                                          std::optional<std::span<const std::uint8_t>> external_payload,
                                                          const validation::VerifyOptions& options) {
  std::vector<std::uint8_t> leaf_der;
  if (!TryExtractLeafDerFromHeaders(parsed, leaf_der)) {
    return Fail(validator_name, "x5c header (label 33) not found or invalid", "MISSING_X5C");
  }

  if (leaf_der.empty()) {
    return Fail(validator_name, "x5c leaf certificate was empty", "INVALID_X5C");
  }

  validation::VerifyOptions opt = options;
  // Pass the certificate DER bytes to the signature verifier.
  // For classic algorithms OpenSSL can extract the public key.
  // For PQC algorithms the signature verifier may extract algorithm-specific key bytes.
  opt.public_key_bytes = leaf_der;

  return validation::VerifyParsedCoseSign1(validator_name, parsed, external_payload, opt);
}

} // namespace cosesign1::x509
