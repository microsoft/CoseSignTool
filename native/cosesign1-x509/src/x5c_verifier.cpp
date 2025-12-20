// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file x5c_verifier.cpp
 * @brief X.509 (x5c) certificate-chain based COSE_Sign1 verification.
 */

#include "cosesign1/x509/x5c_verifier.h"

#include <cstddef>
#include <cstring>
#include <memory>
#include <string>
#include <stdexcept>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

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

validation::ValidationResult Fail(std::string_view validator_name, std::vector<validation::ValidationFailure> failures) {
  return validation::ValidationResult::Failure(std::string(validator_name), std::move(failures));
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

bool TryExtractX5cCertsDerFromHeaders(const cosesign1::common::cbor::ParsedCoseSign1& parsed,
                                      std::vector<std::vector<std::uint8_t>>& certs_der) {
  auto try_extract_all_from_x5c_value = [&](const std::vector<std::uint8_t>& x5c_value_cbor) -> bool {
    CborParser p;
    CborValue it;
    if (cbor_parser_init(x5c_value_cbor.data(), x5c_value_cbor.size(), 0, &p, &it) != CborNoError) return false;
    if (!cbor_value_is_array(&it)) return false;

    CborValue certs;
    if (cbor_value_enter_container(&it, &certs) != CborNoError) return false;

    certs_der.clear();
    while (!cbor_value_at_end(&certs)) {
      // Best-effort: accept bstr elements, ignore non-bstr elements.
      if (cbor_value_is_byte_string(&certs)) {
        std::vector<std::uint8_t> der;
        if (!cosesign1::common::cbor::ReadByteString(&certs, der)) return false;
        if (!der.empty()) {
          certs_der.push_back(std::move(der));
          continue;
        }
      }

      if (cbor_value_advance(&certs) != CborNoError) return false;
    }

    if (cbor_value_leave_container(&it, &certs) != CborNoError) return false;
    return !certs_der.empty();
  };

  // Prefer protected headers.
  if (parsed.protected_headers.TryGetByteStringArray(33, certs_der) && !certs_der.empty()) {
    return true;
  }
  if (parsed.unprotected_headers.TryGetByteStringArray(33, certs_der) && !certs_der.empty()) {
    return true;
  }

  std::vector<std::uint8_t> raw;
  if (parsed.protected_headers.TryGetRawValueCbor(33, raw)) {
    return try_extract_all_from_x5c_value(raw);
  }
  if (parsed.unprotected_headers.TryGetRawValueCbor(33, raw)) {
    return try_extract_all_from_x5c_value(raw);
  }

  return false;
}

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>

namespace {

struct CertContextDeleter {
  void operator()(PCCERT_CONTEXT p) const noexcept {
    if (p) {
      CertFreeCertificateContext(p);
    }
  }
};

struct CertChainContextDeleter {
  void operator()(PCCERT_CHAIN_CONTEXT p) const noexcept {
    if (p) {
      CertFreeCertificateChain(p);
    }
  }
};

struct CertStoreDeleter {
  void operator()(HCERTSTORE h) const noexcept {
    if (h) {
      CertCloseStore(h, 0);
    }
  }
};

struct CertChainEngineDeleter {
  void operator()(HCERTCHAINENGINE h) const noexcept {
    if (h) {
      CertFreeCertificateChainEngine(h);
    }
  }
};

using UniqueCertContext = std::unique_ptr<const CERT_CONTEXT, CertContextDeleter>;
using UniqueCertChainContext = std::unique_ptr<const CERT_CHAIN_CONTEXT, CertChainContextDeleter>;
using UniqueCertStore = std::unique_ptr<void, CertStoreDeleter>;
using UniqueChainEngine = std::unique_ptr<void, CertChainEngineDeleter>;

UniqueCertContext MakeCertContextFromDer(const std::vector<std::uint8_t>& der) {
  if (der.empty()) return {};
  PCCERT_CONTEXT ctx = CertCreateCertificateContext(
      X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
      reinterpret_cast<const BYTE*>(der.data()),
      static_cast<DWORD>(der.size()));
  return UniqueCertContext(ctx);
}

UniqueCertStore MakeMemoryStore() {
  return UniqueCertStore(CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, nullptr));
}

bool AddDerCertToStore(HCERTSTORE store, const std::vector<std::uint8_t>& der) {
  if (!store || der.empty()) return false;
  // CertAddEncodedCertificateToStore copies the encoded bytes.
  return CertAddEncodedCertificateToStore(
      store,
      X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
      reinterpret_cast<const BYTE*>(der.data()),
      static_cast<DWORD>(der.size()),
      CERT_STORE_ADD_ALWAYS,
      nullptr) == TRUE;
}

std::vector<validation::ValidationFailure> FailuresFromWinChainErrorStatus(DWORD errorStatus) {
  if (errorStatus == CERT_TRUST_NO_ERROR) {
    return {};
  }

  const char* code = "CERT_CHAIN_INVALID";
  const char* message = "Certificate chain validation failed.";

  if ((errorStatus & CERT_TRUST_IS_UNTRUSTED_ROOT) != 0) {
    code = "CERT_CHAIN_UNTRUSTED_ROOT";
    message = "Certificate chain ends in an untrusted root.";
  }

  validation::ValidationFailure f;
  f.message = message;
  f.error_code = std::string(code);
  return {std::move(f)};
}

DWORD GetWinChainFlagsForRevocation(X509RevocationMode mode) {
  if (mode == X509RevocationMode::kOnline) {
    return CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT;
  }
  if (mode == X509RevocationMode::kOffline) {
    return CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY;
  }
  return 0;
}

validation::ValidationResult ValidateChainWithWindowsCrypto(
    std::string_view validator_name,
    const std::vector<std::vector<std::uint8_t>>& x5c_certs_der,
    const X509ChainVerifyOptions& chain_options) {
  // leaf is first.
  UniqueCertContext leaf = MakeCertContextFromDer(x5c_certs_der.front());
  UniqueCertStore extraStore = MakeMemoryStore();

  for (size_t i = 1; i < x5c_certs_der.size(); ++i) {
    // Best-effort: skip empty/interpretable.
    if (x5c_certs_der[i].empty()) continue;
    (void)AddDerCertToStore(reinterpret_cast<HCERTSTORE>(extraStore.get()), x5c_certs_der[i]);
  }

  DWORD flags = GetWinChainFlagsForRevocation(chain_options.revocation_mode);

  CERT_CHAIN_PARA chainPara;
  std::memset(&chainPara, 0, sizeof(chainPara));
  chainPara.cbSize = sizeof(chainPara);

  // In custom-roots mode, treat caller-provided roots as trust anchors.
  // We add them to the extra store so the chain builder can locate them.
  if (chain_options.trust_mode == X509TrustMode::kCustomRoots) {
    if (chain_options.trusted_roots_der.empty()) {
      return Fail(validator_name, "custom root trust mode requires at least one trusted root", "CERT_CHAIN_NO_TRUST_ANCHORS");
    }

    for (const auto& rootDer : chain_options.trusted_roots_der) {
      if (!AddDerCertToStore(reinterpret_cast<HCERTSTORE>(extraStore.get()), rootDer)) {
        return Fail(validator_name, "failed to add a trusted root certificate", "CERT_CHAIN_TRUST_ANCHOR_ERROR");
      }
    }
  }

  PCCERT_CHAIN_CONTEXT chainCtxRaw = nullptr;
  if (!CertGetCertificateChain(
      nullptr,
          leaf.get(),
          nullptr,
          reinterpret_cast<HCERTSTORE>(extraStore.get()),
          &chainPara,
          flags,
          nullptr,
          &chainCtxRaw) || !chainCtxRaw) {
    return Fail(validator_name, "failed to build certificate chain", "CERT_CHAIN_BUILD_ERROR");
  }

  UniqueCertChainContext chainCtx(chainCtxRaw);
  DWORD errorStatus = chainCtx->TrustStatus.dwErrorStatus;

  // In custom-roots mode, ensure the chain terminates at an *exact* caller-provided root (DER match).
  if (chain_options.trust_mode == X509TrustMode::kCustomRoots && chainCtx->cChain > 0) {
    const CERT_SIMPLE_CHAIN* simple = chainCtx->rgpChain[0];
    if (simple && simple->cElement > 0) {
      const CERT_CHAIN_ELEMENT* last = simple->rgpElement[simple->cElement - 1];
      const CERT_CONTEXT* rootCtx = last ? last->pCertContext : nullptr;

      bool exactMatch = false;
      if (rootCtx && rootCtx->pbCertEncoded && rootCtx->cbCertEncoded > 0) {
        for (const auto& rootDer : chain_options.trusted_roots_der) {
          if (rootDer.size() == rootCtx->cbCertEncoded &&
              std::memcmp(rootDer.data(), rootCtx->pbCertEncoded, rootCtx->cbCertEncoded) == 0) {
            exactMatch = true;
            break;
          }
        }
      }

      if (!exactMatch) {
        validation::ValidationFailure f;
        f.message = "Certificate chain did not build to one of the caller-provided trusted roots.";
        f.error_code = std::string("CERT_CHAIN_NOT_AN_EXACT_TRUST_ANCHOR");
        return Fail(validator_name, std::vector<validation::ValidationFailure>{std::move(f)});
      }

      // If we matched an exact caller-provided root, treat that root as trusted.
      errorStatus &= ~CERT_TRUST_IS_UNTRUSTED_ROOT;
    }
  }

  std::vector<validation::ValidationFailure> failures = FailuresFromWinChainErrorStatus(errorStatus);
  if (failures.empty()) {
    return validation::ValidationResult::Success(std::string(validator_name), {
      {"x5c.chain_valid", "true"},
    });
  }

  // Chain invalid (always report as invalid; caller can choose to allow it).
  validation::ValidationResult r = Fail(validator_name, std::move(failures));
  r.metadata.insert({
      {"x5c.chain_valid", "false"},
  });
  return r;
}

} // namespace

#endif // _WIN32

validation::ValidationResult ValidateX5cChain(
    std::string_view validator_name,
    const std::vector<std::vector<std::uint8_t>>& x5c_certs_der,
    const X509ChainVerifyOptions& chain_options) {
#ifdef _WIN32
  return ValidateChainWithWindowsCrypto(validator_name, x5c_certs_der, chain_options);
#else
  // OpenSSL fallback (best-effort). Revocation checking is not implemented unless the caller
  // provides CRLs/OCSP configuration externally.
  if (chain_options.revocation_mode != X509RevocationMode::kNoCheck) {
    return Fail(validator_name, "revocation checking is not supported on this platform in the native verifier", "CERT_CHAIN_REVOCATION_NOT_SUPPORTED");
  }

  if (x5c_certs_der.empty() || x5c_certs_der.front().empty()) {
    return Fail(validator_name, "x5c header (label 33) not found or invalid", "MISSING_X5C");
  }

  auto parse_x509 = [](const std::vector<std::uint8_t>& der) -> X509* {
    const unsigned char* p = der.data();
    return d2i_X509(nullptr, &p, static_cast<long>(der.size()));
  };

  std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)> store(X509_STORE_new(), X509_STORE_free);
  if (!store) {
    return Fail(validator_name, "failed to create X509 store", "CERT_CHAIN_STORE_ERROR");
  }

  if (chain_options.trust_mode == X509TrustMode::kSystem) {
    X509_STORE_set_default_paths(store.get());
  } else {
    if (chain_options.trusted_roots_der.empty()) {
      return Fail(validator_name, "custom root trust mode requires at least one trusted root", "CERT_CHAIN_NO_TRUST_ANCHORS");
    }
    for (const auto& rootDer : chain_options.trusted_roots_der) {
      std::unique_ptr<X509, decltype(&X509_free)> root(parse_x509(rootDer), X509_free);
      if (!root) {
        return Fail(validator_name, "failed to parse a trusted root certificate", "CERT_CHAIN_TRUST_ANCHOR_ERROR");
      }
      if (X509_STORE_add_cert(store.get(), root.get()) != 1) {
        // Ignore duplicates.
      }
    }
  }

  std::unique_ptr<X509, decltype(&X509_free)> leaf(parse_x509(x5c_certs_der.front()), X509_free);
  if (!leaf) {
    return Fail(validator_name, "x5c leaf certificate was invalid DER", "INVALID_X5C");
  }

  std::unique_ptr<STACK_OF(X509), decltype(&sk_X509_free)> untrusted(sk_X509_new_null(), sk_X509_free);
  if (!untrusted) {
    return Fail(validator_name, "failed to allocate intermediate chain", "CERT_CHAIN_BUILD_ERROR");
  }

  for (size_t i = 1; i < x5c_certs_der.size(); ++i) {
    if (x5c_certs_der[i].empty()) continue;
    X509* cert = parse_x509(x5c_certs_der[i]);
    if (!cert) continue;
    sk_X509_push(untrusted.get(), cert); // stack owns cert
  }

  std::unique_ptr<X509_STORE_CTX, decltype(&X509_STORE_CTX_free)> ctx(X509_STORE_CTX_new(), X509_STORE_CTX_free);
  if (!ctx) {
    return Fail(validator_name, "failed to create store context", "CERT_CHAIN_BUILD_ERROR");
  }

  if (X509_STORE_CTX_init(ctx.get(), store.get(), leaf.get(), untrusted.get()) != 1) {
    return Fail(validator_name, "failed to initialize store context", "CERT_CHAIN_BUILD_ERROR");
  }

  const int ok = X509_verify_cert(ctx.get());
  if (ok == 1) {
    if (chain_options.trust_mode == X509TrustMode::kCustomRoots) {
      // Enforce the same semantics as Windows custom-roots mode: the verified chain must
      // terminate at one of the caller-provided roots, matched by exact DER bytes.
      STACK_OF(X509)* chain = X509_STORE_CTX_get0_chain(ctx.get());
      const int chainLen = chain ? sk_X509_num(chain) : 0;
      if (chainLen <= 0) {
        return Fail(validator_name, "failed to read verified certificate chain", "CERT_CHAIN_BUILD_ERROR");
      }

      X509* root = sk_X509_value(chain, chainLen - 1);
      if (!root) {
        return Fail(validator_name, "failed to read verified certificate chain root", "CERT_CHAIN_BUILD_ERROR");
      }

      const int derLen = i2d_X509(root, nullptr);
      if (derLen <= 0) {
        return Fail(validator_name, "failed to serialize chain root certificate", "CERT_CHAIN_BUILD_ERROR");
      }

      std::vector<std::uint8_t> rootDer(static_cast<size_t>(derLen));
      unsigned char* p = rootDer.data();
      if (i2d_X509(root, &p) != derLen) {
        return Fail(validator_name, "failed to serialize chain root certificate", "CERT_CHAIN_BUILD_ERROR");
      }

      bool exactMatch = false;
      for (const auto& trustedRootDer : chain_options.trusted_roots_der) {
        if (trustedRootDer == rootDer) {
          exactMatch = true;
          break;
        }
      }

      if (!exactMatch) {
        return Fail(validator_name,
                    "certificate chain did not terminate at an exact trusted root",
                    "CERT_CHAIN_NOT_AN_EXACT_TRUST_ANCHOR");
      }
    }

    return validation::ValidationResult::Success(std::string(validator_name), {
      {"x5c.chain_valid", "true"},
    });
  }

  const int err = X509_STORE_CTX_get_error(ctx.get());
  const char* errStr = X509_verify_cert_error_string(err);

  validation::ValidationFailure f;
  f.message = errStr ? std::string("Certificate chain validation failed: ") + errStr : "Certificate chain validation failed.";
  f.error_code = std::string("CERT_CHAIN_INVALID");

  validation::ValidationResult r = Fail(validator_name, std::vector<validation::ValidationFailure>{std::move(f)});
  r.metadata.insert({
      {"x5c.chain_valid", "false"},
  });
  return r;
#endif
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

validation::ValidationResult VerifyCoseSign1WithX5c(std::string_view validator_name,
                                                    const std::vector<std::uint8_t>& cose_sign1,
                                                    const validation::VerifyOptions& options,
                                                    const X509ChainVerifyOptions& chain_options) {
  cosesign1::common::cbor::ParsedCoseSign1 parsed;
  std::string parse_error;
  if (!cosesign1::common::cbor::ParseCoseSign1(cose_sign1, parsed, &parse_error)) {
    return Fail(validator_name, "x5c header (label 33) not found or invalid", "MISSING_X5C");
  }

  std::optional<std::span<const std::uint8_t>> external_payload;
  if (options.external_payload) {
    external_payload = std::span<const std::uint8_t>(options.external_payload->data(), options.external_payload->size());
  }

  return VerifyParsedCoseSign1WithX5c(validator_name, parsed, external_payload, options, chain_options);
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

validation::ValidationResult VerifyParsedCoseSign1WithX5c(std::string_view validator_name,
                                                          const cosesign1::common::cbor::ParsedCoseSign1& parsed,
                                                          std::optional<std::span<const std::uint8_t>> external_payload,
                                                          const validation::VerifyOptions& options,
                                                          const X509ChainVerifyOptions& chain_options) {
  std::vector<std::vector<std::uint8_t>> x5c_certs_der;
  if (!TryExtractX5cCertsDerFromHeaders(parsed, x5c_certs_der)) {
    return Fail(validator_name, "x5c header (label 33) not found or invalid", "MISSING_X5C");
  }

  if (x5c_certs_der.front().empty()) {
    return Fail(validator_name, "x5c leaf certificate was empty", "INVALID_X5C");
  }

  validation::VerifyOptions opt = options;
  opt.public_key_bytes = x5c_certs_der.front();

  // 1) Verify COSE signature using leaf public key.
  validation::ValidationResult sig = validation::VerifyParsedCoseSign1(validator_name, parsed, external_payload, opt);
  if (!sig.is_valid) {
    return sig;
  }

  // 2) Validate the certificate chain according to the requested policy.
  validation::ValidationResult chain = ValidateX5cChain(validator_name, x5c_certs_der, chain_options);
  if (chain.is_valid) {
    // Chain OK => preserve signature success.
    sig.metadata.insert(chain.metadata.begin(), chain.metadata.end());
    return sig;
  }

  // Chain invalid.
  if (chain_options.allow_untrusted_roots) {
    // Diagnostic mode: keep signature success, but return the chain errors.
    sig.metadata.insert(chain.metadata.begin(), chain.metadata.end());
    sig.failures = std::move(chain.failures);
    return sig;
  }

  return chain;
}

} // namespace cosesign1::x509
