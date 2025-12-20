#include <cosesign1/common/cose_sign1.h>

#include <cosesign1/mst/jwks.h>
#include <cosesign1/mst/mst_verifier.h>
#include <cosesign1/mst/offline_ec_key_store.h>
#include <cosesign1/mst/verification_options.h>

#include <cosesign1/validation/cose_sign1_verifier.h>
#include <cosesign1/validation/validation_result.h>

#include <cosesign1/x509/x5c_verifier.h>

#include <cstdint>
#include <fstream>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

std::vector<std::uint8_t> ReadAllBytes(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  if (!f) {
    throw std::runtime_error("failed to open file: " + path);
  }

  f.seekg(0, std::ios::end);
  std::streamoff size = f.tellg();
  if (size < 0) {
    throw std::runtime_error("failed to get file size: " + path);
  }
  f.seekg(0, std::ios::beg);

  std::vector<std::uint8_t> out(static_cast<std::size_t>(size));
  if (!out.empty()) {
    f.read(reinterpret_cast<char*>(out.data()), size);
  }
  if (!f) {
    throw std::runtime_error("failed to read file: " + path);
  }

  return out;
}

std::string ReadAllText(const std::string& path) {
  std::ifstream f(path);
  if (!f) {
    throw std::runtime_error("failed to open file: " + path);
  }

  std::string out;
  f.seekg(0, std::ios::end);
  const std::streamoff size = f.tellg();
  if (size < 0) {
    throw std::runtime_error("failed to get file size: " + path);
  }
  out.resize(static_cast<std::size_t>(size));
  f.seekg(0, std::ios::beg);
  if (!out.empty()) {
    f.read(out.data(), size);
  }
  if (!f) {
    throw std::runtime_error("failed to read file: " + path);
  }

  return out;
}

void PrintResult(const cosesign1::validation::ValidationResult& r) {
  std::cout << "is_valid: " << (r.is_valid ? "true" : "false") << "\n";
  std::cout << "validator: " << r.validator_name << "\n";

  if (!r.metadata.empty()) {
    std::cout << "metadata:\n";
    for (const auto& kv : r.metadata) {
      std::cout << "  " << kv.first << ": " << kv.second << "\n";
    }
  }

  if (!r.failures.empty()) {
    std::cout << "failures:\n";
    for (const auto& f : r.failures) {
      std::cout << "- " << f.message;
      if (f.error_code) {
        std::cout << " (" << *f.error_code << ")";
      }
      std::cout << "\n";

      if (f.property_name) {
        std::cout << "  property: " << *f.property_name << "\n";
      }
      if (f.attempted_value) {
        std::cout << "  value: " << *f.attempted_value << "\n";
      }
      if (f.exception_message) {
        std::cout << "  exception: " << *f.exception_message << "\n";
      }
    }
  }
}

std::optional<cosesign1::validation::CoseAlgorithm> ParseAlg(std::string_view s) {
  using cosesign1::validation::CoseAlgorithm;

  if (s.empty()) {
    return std::nullopt;
  }

  if (s == "ES256") return CoseAlgorithm::ES256;
  if (s == "ES384") return CoseAlgorithm::ES384;
  if (s == "ES512") return CoseAlgorithm::ES512;
  if (s == "PS256") return CoseAlgorithm::PS256;
  if (s == "RS256") return CoseAlgorithm::RS256;
  if (s == "MLDsa44") return CoseAlgorithm::MLDsa44;
  if (s == "MLDsa65") return CoseAlgorithm::MLDsa65;
  if (s == "MLDsa87") return CoseAlgorithm::MLDsa87;

  return std::nullopt;
}

std::string GetArgValue(int argc, char** argv, const std::string& name) {
  for (int i = 0; i < argc; ++i) {
    if (argv[i] == name) {
      if (i + 1 >= argc) {
        throw std::runtime_error("missing value for " + name);
      }
      return argv[i + 1];
    }
  }
  return {};
}

bool HasFlag(int argc, char** argv, const std::string& name) {
  for (int i = 0; i < argc; ++i) {
    if (argv[i] == name) {
      return true;
    }
  }
  return false;
}

[[noreturn]] void PrintUsageAndExit(const char* exe) {
  std::cerr
      << "Usage:\n"
      << "  " << exe << " key --cose <file> --public-key <der> [--payload <file>] [--expected-alg <ES256|PS256|...>]\n"
      << "  " << exe << " x5c --cose <file> [--payload <file>] [--expected-alg <ES256|...>]\n"
      << "        --trust <system|custom> [--root <der>] [--revocation <online|offline|none>] [--allow-untrusted] \n"
      << "  " << exe << " mst --statement <file> --issuer-host <host> --jwks <file>\n";
  std::exit(2);
}

} // namespace

int main(int argc, char** argv) {
  try {
    if (argc < 2) {
      PrintUsageAndExit(argv[0]);
    }

    const std::string mode = argv[1];

    if (mode == "key") {
      const std::string cosePath = GetArgValue(argc, argv, "--cose");
      const std::string keyPath = GetArgValue(argc, argv, "--public-key");
      const std::string payloadPath = GetArgValue(argc, argv, "--payload");
      const std::string algStr = GetArgValue(argc, argv, "--expected-alg");

      if (cosePath.empty() || keyPath.empty()) {
        PrintUsageAndExit(argv[0]);
      }

      const auto cose = ReadAllBytes(cosePath);
      const auto keyBytes = ReadAllBytes(keyPath);

      cosesign1::common::cbor::ParsedCoseSign1 parsed;
      std::string parseErr;
      if (!cosesign1::common::cbor::ParseCoseSign1(cose, parsed, &parseErr)) {
        std::cerr << "COSE parse failed: " << parseErr << "\n";
        return 1;
      }

      cosesign1::validation::VerifyOptions opt;
      opt.public_key_bytes = keyBytes;
      opt.expected_alg = ParseAlg(algStr);

      if (!parsed.payload.has_value()) {
        if (payloadPath.empty()) {
          std::cerr << "COSE payload is detached (null); provide --payload <file>\n";
          return 1;
        }
        opt.external_payload = ReadAllBytes(payloadPath);
      }

      const auto r = cosesign1::validation::VerifyCoseSign1("Signature", cose, opt);
      PrintResult(r);
      return r.is_valid ? 0 : 3;
    }

    if (mode == "x5c") {
      const std::string cosePath = GetArgValue(argc, argv, "--cose");
      const std::string payloadPath = GetArgValue(argc, argv, "--payload");
      const std::string algStr = GetArgValue(argc, argv, "--expected-alg");

      const std::string trust = GetArgValue(argc, argv, "--trust");
      const std::string rootPath = GetArgValue(argc, argv, "--root");
      const std::string revocation = GetArgValue(argc, argv, "--revocation");
      const bool allowUntrusted = HasFlag(argc, argv, "--allow-untrusted");

      if (cosePath.empty()) {
        PrintUsageAndExit(argv[0]);
      }

      const auto cose = ReadAllBytes(cosePath);

      cosesign1::common::cbor::ParsedCoseSign1 parsed;
      std::string parseErr;
      if (!cosesign1::common::cbor::ParseCoseSign1(cose, parsed, &parseErr)) {
        std::cerr << "COSE parse failed: " << parseErr << "\n";
        return 1;
      }

      cosesign1::validation::VerifyOptions opt;
      opt.expected_alg = ParseAlg(algStr);

      if (!parsed.payload.has_value()) {
        if (payloadPath.empty()) {
          std::cerr << "COSE payload is detached (null); provide --payload <file>\n";
          return 1;
        }
        opt.external_payload = ReadAllBytes(payloadPath);
      }

      cosesign1::x509::X509ChainVerifyOptions chain;
      chain.allow_untrusted_roots = allowUntrusted;

      // Keep the sample safe/offline by default.
      chain.revocation_mode = cosesign1::x509::X509RevocationMode::kNoCheck;
      if (revocation == "online") {
        chain.revocation_mode = cosesign1::x509::X509RevocationMode::kOnline;
      } else if (revocation == "offline") {
        chain.revocation_mode = cosesign1::x509::X509RevocationMode::kOffline;
      } else if (revocation.empty() || revocation == "none") {
        chain.revocation_mode = cosesign1::x509::X509RevocationMode::kNoCheck;
      } else {
        std::cerr << "unknown --revocation value: " << revocation << "\n";
        return 2;
      }

      if (trust.empty() || trust == "system") {
        chain.trust_mode = cosesign1::x509::X509TrustMode::kSystem;
      } else if (trust == "custom") {
        chain.trust_mode = cosesign1::x509::X509TrustMode::kCustomRoots;
        if (rootPath.empty()) {
          std::cerr << "custom trust requires --root <der>\n";
          return 2;
        }
        chain.trusted_roots_der = {ReadAllBytes(rootPath)};
      } else {
        std::cerr << "unknown --trust value: " << trust << "\n";
        return 2;
      }

      const auto r = cosesign1::x509::VerifyCoseSign1WithX5c("X5cVerifier", cose, opt, chain);
      PrintResult(r);
      return r.is_valid ? 0 : 3;
    }

    if (mode == "mst") {
      const std::string statementPath = GetArgValue(argc, argv, "--statement");
      const std::string issuerHost = GetArgValue(argc, argv, "--issuer-host");
      const std::string jwksPath = GetArgValue(argc, argv, "--jwks");

      if (statementPath.empty() || issuerHost.empty() || jwksPath.empty()) {
        PrintUsageAndExit(argv[0]);
      }

      const auto statement = ReadAllBytes(statementPath);
      const std::string jwksJson = ReadAllText(jwksPath);

      auto jwks = cosesign1::mst::ParseJwks(jwksJson);
      if (!jwks) {
        std::cerr << "failed to parse JWKS JSON" << "\n";
        return 1;
      }

      cosesign1::mst::OfflineEcKeyStore store;
      store.AddIssuerKeys(issuerHost, std::move(*jwks));

      cosesign1::mst::VerificationOptions options;
      options.authorized_domains = {issuerHost};

      const auto r = cosesign1::mst::VerifyTransparentStatement("MST", statement, store, options);
      PrintResult(r);
      return r.is_valid ? 0 : 3;
    }

    PrintUsageAndExit(argv[0]);
  } catch (const std::exception& ex) {
    std::cerr << "fatal: " << ex.what() << "\n";
    return 1;
  }
}
