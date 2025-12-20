#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/x509.h>

namespace cosesign1::internal {

using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;

EvpPkeyPtr LoadPublicKeyOrCertFromPem(const std::string& pem);

// Loads a public key from DER-encoded SubjectPublicKeyInfo, or from DER-encoded X.509 certificate.
EvpPkeyPtr LoadPublicKeyOrCertFromDer(std::span<const std::uint8_t> der);

// Extracts the raw SubjectPublicKey BIT STRING bytes from a PEM-encoded X.509 certificate.
// This is useful for algorithms not supported by OpenSSL EVP, but where we can still parse the certificate.
std::optional<std::vector<std::uint8_t>> ExtractSubjectPublicKeyBytesFromCertificatePem(const std::string& pem);

// COSE encodes ECDSA signatures as raw r||s.
std::optional<std::vector<std::uint8_t>> CoseEcdsaRawToDer(std::span<const std::uint8_t> cose_raw_sig);
std::optional<std::vector<std::uint8_t>> EcdsaDerToCoseRaw(std::span<const std::uint8_t> der_sig, std::size_t component_size);

bool VerifyEs256(EVP_PKEY* key, std::span<const std::uint8_t> to_be_signed, std::span<const std::uint8_t> cose_raw_sig);
bool VerifyEs384(EVP_PKEY* key, std::span<const std::uint8_t> to_be_signed, std::span<const std::uint8_t> cose_raw_sig);
bool VerifyEs512(EVP_PKEY* key, std::span<const std::uint8_t> to_be_signed, std::span<const std::uint8_t> cose_raw_sig);
bool VerifyPs256(EVP_PKEY* key, std::span<const std::uint8_t> to_be_signed, std::span<const std::uint8_t> signature);
bool VerifyRs256(EVP_PKEY* key, std::span<const std::uint8_t> to_be_signed, std::span<const std::uint8_t> signature);

} // namespace cosesign1::internal
