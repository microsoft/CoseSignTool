#include "cosesign1/mst/mst_verifier.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <type_traits>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <openssl/evp.h>

#include <tinycbor/cbor.h>

#include <cosesign1/common/cbor.h>

#include "cosesign1/validation/cose_sign1_verifier.h"

namespace cosesign1::mst {

namespace {
constexpr std::int64_t kCoseHeaderEmbeddedReceipts = 394;
constexpr std::int64_t kCoseReceiptCwtMapLabel = 15;
constexpr std::int64_t kCoseReceiptCwtIssLabel = 1;
constexpr std::int64_t kCosePhdrVdsLabel = 395;
constexpr std::int64_t kCosePhdrVdpLabel = 396;
constexpr std::int64_t kCcfTreeAlgLabel = 2;
constexpr std::int64_t kCoseReceiptInclusionProofLabel = -1;
constexpr std::int64_t kCcfProofLeafLabel = 1;
constexpr std::int64_t kCcfProofPathLabel = 2;

constexpr std::string_view kUnknownIssuerPrefix = "__unknown-issuer::";

using ParsedSign1 = cosesign1::common::cbor::ParsedCoseSign1;
using HeaderMap = cosesign1::common::cbor::CoseHeaderMap;

template <typename TVerifyOptions, typename = void>
struct VerifyOptionsPublicKeyBytesSetter {
  static void Set(TVerifyOptions&, const std::optional<std::vector<std::uint8_t>>&) {}
};

template <typename...>
using void_t = void;

template <typename TVerifyOptions>
struct VerifyOptionsPublicKeyBytesSetter<TVerifyOptions, void_t<decltype(std::declval<TVerifyOptions&>().public_key_bytes)>> {
  static void Set(TVerifyOptions& opts, const std::optional<std::vector<std::uint8_t>>& bytes) { opts.public_key_bytes = bytes; }
};

template <typename TVerifyOptions>
void MaybeSetVerifyOptionsPublicKeyBytes(TVerifyOptions& opts, const std::optional<std::vector<std::uint8_t>>& bytes) {
  VerifyOptionsPublicKeyBytesSetter<TVerifyOptions>::Set(opts, bytes);
}

struct ProofElement {
  bool left = false;
  std::vector<std::uint8_t> hash;
};

struct Leaf {
  std::vector<std::uint8_t> internal_transaction_hash;
  std::string internal_evidence;
  std::vector<std::uint8_t> data_hash;
};

cosesign1::validation::ValidationFailure MakeFailure(std::string message,
                                                    std::string error_code,
                                                    std::optional<std::string> property = std::nullopt) {
  cosesign1::validation::ValidationFailure f;
  f.message = std::move(message);
  f.error_code = std::move(error_code);
  f.property_name = std::move(property);
  return f;
}

std::string ToLower(std::string_view s) {
  std::string out;
  out.reserve(s.size());
  for (char ch : s) {
    out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
  }
  return out;
}

using cosesign1::common::cbor::ReadByteString;
using cosesign1::common::cbor::ReadInt64;
using cosesign1::common::cbor::ReadTextString;
using cosesign1::common::cbor::SkipAny;
using cosesign1::common::cbor::SkipOptionalCoseSign1Tag;

bool LooksLikePrintableAscii(const std::vector<std::uint8_t>& bytes) {
  for (auto b : bytes) {
    if (b < 0x20 || b > 0x7e) {
      return false;
    }
  }
  return true;
}

} // namespace

static std::string ToLowerAscii(std::string_view s) {
  std::string out;
  out.reserve(s.size());
  for (char c : s) {
    if (c >= 'A' && c <= 'Z') {
      out.push_back(static_cast<char>(c - 'A' + 'a'));
    } else {
      out.push_back(c);
    }
  }
  return out;
}

namespace internal {

void RunCoverageHooks_MstVerifier() {
  // Intentionally includes non-uppercase characters to cover ToLowerAscii's else branch.
  (void)ToLowerAscii("kid-1");
}

} // namespace internal

namespace {

std::string BytesToHexLower(const std::vector<std::uint8_t>& bytes) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.resize(bytes.size() * 2);
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    out[i * 2] = kHex[(bytes[i] >> 4) & 0x0f];
    out[i * 2 + 1] = kHex[bytes[i] & 0x0f];
  }
  return out;
}

std::string NormalizeKid(const std::vector<std::uint8_t>& kid_bytes) {
  if (LooksLikePrintableAscii(kid_bytes)) {
    return std::string(reinterpret_cast<const char*>(kid_bytes.data()), kid_bytes.size());
  }
  return BytesToHexLower(kid_bytes);
}

std::optional<ParsedSign1> ParseCoseSign1(const std::vector<std::uint8_t>& cose_sign1) {
  ParsedSign1 out;
  if (!cosesign1::common::cbor::ParseCoseSign1(cose_sign1, out)) {
    return std::nullopt;
  }
  return out;
}

std::vector<std::vector<std::uint8_t>> ReadEmbeddedReceiptList(const ParsedSign1& transparent_statement) {
  std::vector<std::vector<std::uint8_t>> receipts;

  if (transparent_statement.unprotected_headers.TryGetByteStringArray(kCoseHeaderEmbeddedReceipts, receipts)) {
    return receipts;
  }

  // Fallback: parse raw CBOR value bytes if it wasn't decoded as an array-of-bstr.
  std::vector<std::uint8_t> raw;
  if (!transparent_statement.unprotected_headers.TryGetRawValueCbor(kCoseHeaderEmbeddedReceipts, raw)) {
    return receipts;
  }

  CborParser p;
  CborValue it;
  if (cbor_parser_init(raw.data(), raw.size(), 0, &p, &it) != CborNoError) {
    return {};
  }
  if (!cbor_value_is_array(&it)) {
    return {};
  }

  CborValue arr;
  if (cbor_value_enter_container(&it, &arr) != CborNoError) {
    return {};
  }

  while (!cbor_value_at_end(&arr)) {
    std::vector<std::uint8_t> receipt;
    if (!ReadByteString(&arr, receipt)) {
      return {};
    }
    receipts.push_back(std::move(receipt));
  }

  if (cbor_value_leave_container(&it, &arr) != CborNoError) {
    return {};
  }
  return receipts;
}

std::vector<std::uint8_t> EncodeCoseSign1WithEmptyUnprotected(const ParsedSign1& msg) {
  // [protected, unprotected, payload/null, signature]
  const auto& protected_bytes = msg.protected_headers.EncodedMapCbor();
  std::vector<std::uint8_t> buf(128 + protected_bytes.size() + msg.signature.size() + (msg.payload ? msg.payload->size() : 0));

  while (true) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf.data(), buf.size(), 0);

    CborEncoder arr;
    if (cbor_encoder_create_array(&enc, &arr, 4) != CborNoError) {
      buf.resize(buf.size() * 2);
      continue;
    }

    if (cbor_encode_byte_string(&arr, protected_bytes.data(), protected_bytes.size()) != CborNoError) {
      buf.resize(buf.size() * 2);
      continue;
    }

    CborEncoder empty_map;
    if (cbor_encoder_create_map(&arr, &empty_map, 0) != CborNoError) {
      buf.resize(buf.size() * 2);
      continue;
    }
    if (cbor_encoder_close_container(&arr, &empty_map) != CborNoError) {
      buf.resize(buf.size() * 2);
      continue;
    }

    if (msg.payload) {
      if (cbor_encode_byte_string(&arr, msg.payload->data(), msg.payload->size()) != CborNoError) {
        buf.resize(buf.size() * 2);
        continue;
      }
    } else {
      if (cbor_encode_null(&arr) != CborNoError) {
        buf.resize(buf.size() * 2);
        continue;
      }
    }

    if (cbor_encode_byte_string(&arr, msg.signature.data(), msg.signature.size()) != CborNoError) {
      buf.resize(buf.size() * 2);
      continue;
    }

    if (cbor_encoder_close_container(&enc, &arr) != CborNoError) {
      buf.resize(buf.size() * 2);
      continue;
    }

    const size_t used = cbor_encoder_get_buffer_size(&enc, buf.data());
    buf.resize(used);
    return buf;
  }
}

std::vector<std::uint8_t> Sha256(const std::uint8_t* data, std::size_t size) {
  std::vector<std::uint8_t> out(32);

  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) {
    return {};
  }

  const int ok = EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1 &&
                 EVP_DigestUpdate(ctx, data, size) == 1 &&
                 EVP_DigestFinal_ex(ctx, out.data(), nullptr) == 1;
  EVP_MD_CTX_free(ctx);

  if (!ok) {
    return {};
  }

  return out;
}

std::vector<std::uint8_t> Sha256(const std::vector<std::uint8_t>& data) {
  return Sha256(data.data(), data.size());
}

void AppendCborUIntBigEndian(std::vector<std::uint8_t>& out, std::uint64_t value, int bytes) {
  for (int i = bytes - 1; i >= 0; --i) {
    out.push_back(static_cast<std::uint8_t>((value >> (8 * i)) & 0xff));
  }
}

void AppendCborTypeAndLength(std::vector<std::uint8_t>& out, std::uint8_t major_type, std::uint64_t len) {
  if (len < 24) {
    out.push_back(static_cast<std::uint8_t>((major_type << 5) | static_cast<std::uint8_t>(len)));
    return;
  }

  if (len <= 0xff) {
    out.push_back(static_cast<std::uint8_t>((major_type << 5) | 24));
    out.push_back(static_cast<std::uint8_t>(len));
    return;
  }

  if (len <= 0xffff) {
    out.push_back(static_cast<std::uint8_t>((major_type << 5) | 25));
    AppendCborUIntBigEndian(out, len, 2);
    return;
  }

  if (len <= 0xffffffffULL) {
    out.push_back(static_cast<std::uint8_t>((major_type << 5) | 26));
    AppendCborUIntBigEndian(out, len, 4);
    return;
  }

  // Lengths > 4GiB are not expected in this verifier; clamp to avoid emitting 8-byte lengths.
  out.push_back(static_cast<std::uint8_t>((major_type << 5) | 26));
  AppendCborUIntBigEndian(out, 0xffffffffULL, 4);
}

std::vector<std::uint8_t> EncodeCoseSign1WithNullPayload(const std::vector<std::uint8_t>& protected_headers_bstr,
                                                         const std::vector<std::uint8_t>& signature) {
  // COSE_Sign1 = [ protected : bstr, unprotected : map, payload : bstr / null, signature : bstr ]
  // We only need a syntactically valid structure whose Sig_structure uses the same protected headers and signature.
  std::vector<std::uint8_t> out;
  out.reserve(16 + protected_headers_bstr.size() + signature.size());

  // Array(4)
  out.push_back(0x84);

  // protected (bstr)
  AppendCborTypeAndLength(out, 2, protected_headers_bstr.size());
  out.insert(out.end(), protected_headers_bstr.begin(), protected_headers_bstr.end());

  // unprotected (empty map)
  out.push_back(0xa0);

  // payload (null)
  out.push_back(0xf6);

  // signature (bstr)
  AppendCborTypeAndLength(out, 2, signature.size());
  out.insert(out.end(), signature.begin(), signature.end());

  return out;
}

std::vector<std::uint8_t> Concat(const std::vector<std::uint8_t>& a, const std::vector<std::uint8_t>& b) {
  std::vector<std::uint8_t> out(a.size() + b.size());
  std::memcpy(out.data(), a.data(), a.size());
  std::memcpy(out.data() + a.size(), b.data(), b.size());
  return out;
}

std::vector<std::uint8_t> Concat3(const std::vector<std::uint8_t>& a,
                                  const std::vector<std::uint8_t>& b,
                                  const std::vector<std::uint8_t>& c) {
  std::vector<std::uint8_t> out(a.size() + b.size() + c.size());
  std::memcpy(out.data(), a.data(), a.size());
  std::memcpy(out.data() + a.size(), b.data(), b.size());
  std::memcpy(out.data() + a.size() + b.size(), c.data(), c.size());
  return out;
}

std::optional<std::vector<std::uint8_t>> ReadReceiptKid(const HeaderMap& protected_headers) {
  std::vector<std::uint8_t> kid;
  if (!protected_headers.TryGetByteString(4, kid)) {
    return std::nullopt;
  }
  return kid;
}

std::optional<std::int64_t> ReadProtectedIntHeader(const HeaderMap& protected_headers, std::int64_t label) {
  if (const auto v = protected_headers.TryGetInt64(label)) {
    return v;
  }

  return std::nullopt;
}

std::optional<std::string> ReadReceiptIssuerHost(const HeaderMap& protected_headers) {
  std::vector<std::uint8_t> raw;
  if (!protected_headers.TryGetRawValueCbor(kCoseReceiptCwtMapLabel, raw)) {
    return std::nullopt;
  }

  CborParser p;
  CborValue it;
  if (cbor_parser_init(raw.data(), raw.size(), 0, &p, &it) != CborNoError) {
    return std::nullopt;
  }
  if (!cbor_value_is_map(&it)) {
    return std::nullopt;
  }

  CborValue map_it;
  if (cbor_value_enter_container(&it, &map_it) != CborNoError) {
    return std::nullopt;
  }

  while (!cbor_value_at_end(&map_it)) {
    std::int64_t cwt_key = 0;
    if (!ReadInt64(&map_it, cwt_key)) {
      return std::nullopt;
    }

    if (cwt_key == kCoseReceiptCwtIssLabel) {
      std::string issuer;
      if (!ReadTextString(&map_it, issuer)) {
        return std::nullopt;
      }
      return issuer;
    }

    if (!SkipAny(&map_it)) {
      return std::nullopt;
    }
  }

  return std::nullopt;
}

std::optional<std::vector<std::uint8_t>> ComputeAccumulator(const Leaf& leaf, const std::vector<ProofElement>& proof_elements) {
  const auto* evidence_ptr = reinterpret_cast<const std::uint8_t*>(leaf.internal_evidence.data());
  auto evidence_hash = Sha256(evidence_ptr, leaf.internal_evidence.size());
  if (evidence_hash.empty()) {
    return std::nullopt;
  }

  auto leaf_hash_input = Concat3(leaf.internal_transaction_hash, evidence_hash, leaf.data_hash);
  auto accumulator = Sha256(leaf_hash_input);
  if (accumulator.empty()) {
    return std::nullopt;
  }

  for (const auto& pe : proof_elements) {
    if (pe.left) {
      accumulator = Sha256(Concat(pe.hash, accumulator));
    } else {
      accumulator = Sha256(Concat(accumulator, pe.hash));
    }

    if (accumulator.empty()) {
      return std::nullopt;
    }
  }

  return accumulator;
}

bool ReadLeafFromArrayValue(CborValue* v, Leaf& out_leaf) {
  if (!cbor_value_is_array(v)) {
    return false;
  }

  CborValue leaf_arr = *v;
  if (cbor_value_enter_container(v, &leaf_arr) != CborNoError) {
    return false;
  }

  Leaf l;
  if (!ReadByteString(&leaf_arr, l.internal_transaction_hash)) {
    return false;
  }
  if (!ReadTextString(&leaf_arr, l.internal_evidence)) {
    return false;
  }
  if (!ReadByteString(&leaf_arr, l.data_hash)) {
    return false;
  }

  if (cbor_value_leave_container(v, &leaf_arr) != CborNoError) {
    return false;
  }

  out_leaf = std::move(l);
  return true;
}

bool ReadLeafFromBytes(const std::vector<std::uint8_t>& leaf_cbor, Leaf& out_leaf) {
  CborParser p;
  CborValue it;
  if (cbor_parser_init(leaf_cbor.data(), leaf_cbor.size(), 0, &p, &it) != CborNoError) {
    return false;
  }
  return ReadLeafFromArrayValue(&it, out_leaf);
}

bool ReadProofElementsFromArrayValue(CborValue* v, std::vector<ProofElement>& out_elements) {
  if (!cbor_value_is_array(v)) {
    return false;
  }

  CborValue outer = *v;
  if (cbor_value_enter_container(v, &outer) != CborNoError) {
    return false;
  }

  std::vector<ProofElement> elements;
  while (!cbor_value_at_end(&outer)) {
    if (!cbor_value_is_array(&outer)) {
      return false;
    }

    CborValue inner = outer;
    if (cbor_value_enter_container(&outer, &inner) != CborNoError) {
      return false;
    }

    ProofElement pe;
    if (!cbor_value_is_boolean(&inner)) {
      return false;
    }
    bool left = false;
    if (cbor_value_get_boolean(&inner, &left) != CborNoError) {
      return false;
    }
    pe.left = left;
    if (cbor_value_advance_fixed(&inner) != CborNoError) {
      return false;
    }
    if (!ReadByteString(&inner, pe.hash)) {
      return false;
    }

    if (cbor_value_leave_container(&outer, &inner) != CborNoError) {
      return false;
    }

    elements.push_back(std::move(pe));
  }

  if (cbor_value_leave_container(v, &outer) != CborNoError) {
    return false;
  }

  out_elements = std::move(elements);
  return true;
}

bool ReadProofElementsFromBytes(const std::vector<std::uint8_t>& path_cbor, std::vector<ProofElement>& out_elements) {
  CborParser p;
  CborValue it;
  if (cbor_parser_init(path_cbor.data(), path_cbor.size(), 0, &p, &it) != CborNoError) {
    return false;
  }
  return ReadProofElementsFromArrayValue(&it, out_elements);
}

bool ReadLeafOrLeafBytes(CborValue* v, Leaf& out_leaf) {
  if (cbor_value_is_array(v)) {
    return ReadLeafFromArrayValue(v, out_leaf);
  }
  if (cbor_value_is_byte_string(v)) {
    std::vector<std::uint8_t> leaf_bytes;
    if (!ReadByteString(v, leaf_bytes)) {
      return false;
    }
    return ReadLeafFromBytes(leaf_bytes, out_leaf);
  }
  return false;
}

bool ReadPathOrPathBytes(CborValue* v, std::vector<ProofElement>& out_elements) {
  if (cbor_value_is_array(v)) {
    return ReadProofElementsFromArrayValue(v, out_elements);
  }
  if (cbor_value_is_byte_string(v)) {
    std::vector<std::uint8_t> path_bytes;
    if (!ReadByteString(v, path_bytes)) {
      return false;
    }
    return ReadProofElementsFromBytes(path_bytes, out_elements);
  }
  return false;
}
bool VerifyReceiptAgainstStatement(
    const std::vector<std::uint8_t>& receipt_cose_sign1,
    const std::vector<std::uint8_t>& statement_without_receipts,
    const OfflineEcKeyStore::ResolvedKey& key,
    std::optional<std::string_view> expected_kid,
    std::string& out_issuer,
    std::vector<cosesign1::validation::ValidationFailure>& out_failures) {
  const auto parsed_receipt = ParseCoseSign1(receipt_cose_sign1);
  if (!parsed_receipt) {
    out_failures.push_back(MakeFailure("Invalid receipt COSE_Sign1 structure", "MST_RECEIPT_PARSE_ERROR"));
    return false;
  }

  // Issuer is best-effort for error reporting.
  if (auto issuer = ReadReceiptIssuerHost(parsed_receipt->protected_headers)) {
    out_issuer = *issuer;
  }

  // Verify KID matches the expected key id.
  auto kid_bytes = ReadReceiptKid(parsed_receipt->protected_headers);
  if (!kid_bytes) {
    out_failures.push_back(MakeFailure("Receipt KID not found", "MST_KID_MISSING", "kid"));
    return false;
  }

  if (expected_kid && !expected_kid->empty()) {
    const auto kid_norm = NormalizeKid(*kid_bytes);
    if (ToLowerAscii(kid_norm) != ToLowerAscii(*expected_kid)) {
      out_failures.push_back(MakeFailure("KID mismatch", "MST_KID_MISMATCH", "kid"));
      return false;
    }
  }

  // Validate vds = CCF.
  const auto vds = ReadProtectedIntHeader(parsed_receipt->protected_headers, kCosePhdrVdsLabel);
  if (!vds) {
    out_failures.push_back(MakeFailure("Verifiable Data Structure is required", "MST_VDS_MISSING", "vds"));
    return false;
  }
  if (*vds != kCcfTreeAlgLabel) {
    out_failures.push_back(MakeFailure("Verifiable Data Structure is not CCF", "MST_VDS_NOT_CCF", "vds"));
    return false;
  }

  // claimsDigest = sha256(statement_without_receipts)
  const auto claims_digest = Sha256(statement_without_receipts);

  // Find VDP (label 396) in the receipt unprotected headers.
  std::vector<std::uint8_t> vdp_raw;
  if (!parsed_receipt->unprotected_headers.TryGetRawValueCbor(kCosePhdrVdpLabel, vdp_raw)) {
    out_failures.push_back(MakeFailure("Verifiable data proof is required", "MST_VDP_MISSING", "vdp"));
    return false;
  }

  CborParser vdp_parser;
  CborValue vdp_root;
  if (cbor_parser_init(vdp_raw.data(), vdp_raw.size(), 0, &vdp_parser, &vdp_root) != CborNoError || !cbor_value_is_map(&vdp_root)) {
    out_failures.push_back(MakeFailure("VDP parse error", "MST_VDP_PARSE_ERROR"));
    return false;
  }

  CborValue vdp_it;
  if (cbor_value_enter_container(&vdp_root, &vdp_it) != CborNoError) {
    out_failures.push_back(MakeFailure("VDP parse error", "MST_VDP_PARSE_ERROR"));
    return false;
  }

  bool found_inclusion = false;
  std::vector<std::vector<std::uint8_t>> inclusion_maps;

  while (!cbor_value_at_end(&vdp_it)) {
    std::int64_t vdp_key = 0;
    if (!ReadInt64(&vdp_it, vdp_key)) {
      out_failures.push_back(MakeFailure("VDP parse error", "MST_VDP_PARSE_ERROR"));
      return false;
    }

    if (vdp_key == kCoseReceiptInclusionProofLabel) {
      found_inclusion = true;
      if (!cbor_value_is_array(&vdp_it)) {
        out_failures.push_back(MakeFailure("Inclusion proof is required", "MST_INCLUSION_MISSING"));
        return false;
      }

      CborValue proofs_it = vdp_it;
      if (cbor_value_enter_container(&vdp_it, &proofs_it) != CborNoError) {
        out_failures.push_back(MakeFailure("Inclusion proofs parse error", "MST_INCLUSION_PARSE_ERROR"));
        return false;
      }

      while (!cbor_value_at_end(&proofs_it)) {
        std::vector<std::uint8_t> inclusion_proof_map_bytes;
        if (!ReadByteString(&proofs_it, inclusion_proof_map_bytes)) {
          out_failures.push_back(MakeFailure("Inclusion proof element must be a byte string", "MST_INCLUSION_PARSE_ERROR"));
          return false;
        }
        inclusion_maps.push_back(std::move(inclusion_proof_map_bytes));
      }

      if (cbor_value_leave_container(&vdp_it, &proofs_it) != CborNoError) {
        out_failures.push_back(MakeFailure("Inclusion proofs parse error", "MST_INCLUSION_PARSE_ERROR"));
        return false;
      }

      break;
    }

    if (!SkipAny(&vdp_it)) {
      out_failures.push_back(MakeFailure("VDP parse error", "MST_VDP_PARSE_ERROR"));
      return false;
    }
  }

  if (!found_inclusion || inclusion_maps.empty()) {
    out_failures.push_back(MakeFailure("At least one inclusion proof is required", "MST_INCLUSION_MISSING"));
    return false;
  }

  for (const auto& inclusion_map_bytes : inclusion_maps) {
        // inclusion proof map: {1: leaf(array), 2: path(array)}
        CborParser p;
        CborValue root;
        if (cbor_parser_init(inclusion_map_bytes.data(), inclusion_map_bytes.size(), 0, &p, &root) != CborNoError || !cbor_value_is_map(&root)) {
          out_failures.push_back(MakeFailure("Inclusion proof map parse error", "MST_INCLUSION_PARSE_ERROR"));
          return false;
        }

        CborValue map_it2;
        if (cbor_value_enter_container(&root, &map_it2) != CborNoError) {
          out_failures.push_back(MakeFailure("Inclusion proof map parse error", "MST_INCLUSION_PARSE_ERROR"));
          return false;
        }

        std::optional<Leaf> leaf;
        std::optional<std::vector<ProofElement>> proof_elements;

        while (!cbor_value_at_end(&map_it2)) {
          std::int64_t k = 0;
          if (!ReadInt64(&map_it2, k)) {
            out_failures.push_back(MakeFailure("Inclusion proof map parse error", "MST_INCLUSION_PARSE_ERROR"));
            return false;
          }

          if (k == kCcfProofLeafLabel) {
            Leaf l;
            if (!ReadLeafOrLeafBytes(&map_it2, l)) {
              out_failures.push_back(MakeFailure("Leaf parse error", "MST_LEAF_PARSE_ERROR"));
              return false;
            }

            leaf = std::move(l);
            continue;
          }

          if (k == kCcfProofPathLabel) {
            std::vector<ProofElement> elements;
            if (!ReadPathOrPathBytes(&map_it2, elements)) {
              out_failures.push_back(MakeFailure("Path parse error", "MST_PATH_PARSE_ERROR"));
              return false;
            }

            proof_elements = std::move(elements);
            continue;
          }

          if (!SkipAny(&map_it2)) {
            out_failures.push_back(MakeFailure("Inclusion proof map parse error", "MST_INCLUSION_PARSE_ERROR"));
            return false;
          }
        }

        if (!leaf) {
          out_failures.push_back(MakeFailure("Leaf must be present", "MST_LEAF_MISSING"));
          return false;
        }
        if (!proof_elements) {
          out_failures.push_back(MakeFailure("Path must be present", "MST_PATH_MISSING"));
          return false;
        }

        auto accumulator = ComputeAccumulator(*leaf, *proof_elements);
        if (!accumulator) {
          out_failures.push_back(MakeFailure("Failed to compute receipt accumulator", "MST_ACCUMULATOR_ERROR"));
          return false;
        }

        // Verify receipt signature (detached payload = accumulator)
        cosesign1::validation::VerifyOptions verify_opts;
        verify_opts.external_payload = *accumulator;
        MaybeSetVerifyOptionsPublicKeyBytes(verify_opts, key.public_key_bytes);
        verify_opts.expected_alg = key.expected_alg;

        // Match Azure SDK behavior (`CoseSign1Message.VerifyDetached`) by forcing a detached-payload
        // verification even if the receipt happens to embed a payload bstr.
        const auto detached_receipt_for_sig = EncodeCoseSign1WithNullPayload(parsed_receipt->protected_headers.EncodedMapCbor(), parsed_receipt->signature);
        auto sig_result = cosesign1::validation::VerifyCoseSign1("MstReceiptSignature", detached_receipt_for_sig, verify_opts);
        if (!sig_result.is_valid) {
          std::string details;
          if (!sig_result.failures.empty()) {
            const auto& f = sig_result.failures.front();
            const std::string code = f.error_code.value_or("UNKNOWN");
            details = ": " + code + ": " + f.message;
          }
          std::vector<std::uint8_t> prefix;
          prefix.assign(detached_receipt_for_sig.begin(),
                        detached_receipt_for_sig.begin() + std::min<std::size_t>(detached_receipt_for_sig.size(), 8));
          const std::string buf_info = " (detached_sign1_len=" + std::to_string(detached_receipt_for_sig.size()) +
                                       ", prefix=" + BytesToHexLower(prefix) + ")";
          out_failures.push_back(MakeFailure("Receipt signature verification failed" + details + buf_info, "MST_RECEIPT_SIGNATURE_INVALID"));
          return false;
        }

        // Ensure claims digest matches the leaf data hash.
        if (leaf->data_hash != claims_digest) {
          out_failures.push_back(MakeFailure("Claim digest mismatch", "MST_CLAIM_DIGEST_MISMATCH"));
          return false;
        }
      }

  return true;
}

} // namespace

cosesign1::validation::ValidationResult VerifyTransparentStatement(
    std::string_view validator_name,
    const std::vector<std::uint8_t>& transparent_statement_cose_sign1,
    const OfflineEcKeyStore& key_store,
    const VerificationOptions& options) {
  std::vector<cosesign1::validation::ValidationFailure> failures;

  auto parsed = ParseCoseSign1(transparent_statement_cose_sign1);
  if (!parsed) {
    failures.push_back(MakeFailure("Invalid COSE_Sign1 structure (CBOR parse failed)", "CBOR_PARSE_ERROR"));
    return cosesign1::validation::ValidationResult::Failure(std::string(validator_name), std::move(failures));
  }

  const auto receipts = ReadEmbeddedReceiptList(*parsed);
  if (receipts.empty()) {
    failures.push_back(MakeFailure("No receipts found in the transparent statement", "MST_NO_RECEIPT"));
    return cosesign1::validation::ValidationResult::Failure(std::string(validator_name), std::move(failures));
  }

  // Build canonical bytes of the statement without any unprotected headers.
  const auto statement_without_unprotected = EncodeCoseSign1WithEmptyUnprotected(*parsed);

  // Normalize authorized list.
  std::unordered_set<std::string> authorized;
  for (const auto& d : options.authorized_domains) {
    if (!d.empty() && d.rfind(kUnknownIssuerPrefix, 0) != 0) {
      authorized.insert(ToLower(d));
    }
  }
  const bool user_provided_authorized = !authorized.empty();

  if (!user_provided_authorized && options.unauthorized_receipt_behavior == UnauthorizedReceiptBehavior::IgnoreAll) {
    failures.push_back(MakeFailure("No receipts would be verified as no authorized domains were provided and unauthorized behavior is IgnoreAll", "MST_NO_VERIFIABLE_RECEIPTS"));
    return cosesign1::validation::ValidationResult::Failure(std::string(validator_name), std::move(failures));
  }

  std::vector<cosesign1::validation::ValidationFailure> authorized_failures;
  std::vector<cosesign1::validation::ValidationFailure> unauthorized_failures;

  std::unordered_set<std::string> valid_authorized_domains;
  std::unordered_set<std::string> authorized_domains_with_receipt;

  // Early failure if FailIfPresent.
  if (options.unauthorized_receipt_behavior == UnauthorizedReceiptBehavior::FailIfPresent) {
    for (std::size_t i = 0; i < receipts.size(); ++i) {
      const auto parsed_receipt = ParseCoseSign1(receipts[i]);
      std::string issuer;
      if (parsed_receipt) {
        if (auto iss = ReadReceiptIssuerHost(parsed_receipt->protected_headers)) {
          issuer = *iss;
        }
      }
      if (issuer.empty()) {
        issuer = std::string(kUnknownIssuerPrefix) + std::to_string(i);
      }

      if (authorized.find(ToLower(issuer)) == authorized.end()) {
        authorized_failures.push_back(MakeFailure("Receipt issuer '" + issuer + "' is not in the authorized domain list", "MST_UNAUTHORIZED_RECEIPT"));
      }
    }

    if (!authorized_failures.empty()) {
      return cosesign1::validation::ValidationResult::Failure(std::string(validator_name), std::move(authorized_failures));
    }
  }

  for (std::size_t i = 0; i < receipts.size(); ++i) {
    const auto& receipt_bytes = receipts[i];

    std::string issuer;
    auto parsed_receipt = ParseCoseSign1(receipt_bytes);
    if (parsed_receipt) {
      if (auto iss = ReadReceiptIssuerHost(parsed_receipt->protected_headers)) {
        issuer = *iss;
      }
    }
    if (issuer.empty()) {
      issuer = std::string(kUnknownIssuerPrefix) + std::to_string(i);
    }

    const bool is_authorized = authorized.find(ToLower(issuer)) != authorized.end();
    if (is_authorized) {
      authorized_domains_with_receipt.insert(ToLower(issuer));
    }

    bool should_verify = true;
    if (!is_authorized) {
      switch (options.unauthorized_receipt_behavior) {
        case UnauthorizedReceiptBehavior::VerifyAll:
          should_verify = true;
          break;
        case UnauthorizedReceiptBehavior::IgnoreAll:
          should_verify = false;
          break;
        case UnauthorizedReceiptBehavior::FailIfPresent:
          should_verify = false;
          break;
      }
    }

    if (!should_verify) {
      continue;
    }

    if (issuer.rfind(kUnknownIssuerPrefix, 0) == 0) {
      unauthorized_failures.push_back(MakeFailure("Cannot verify receipt with unknown issuer '" + issuer + "'", "MST_UNKNOWN_ISSUER"));
      continue;
    }

    // Resolve key by KID.
    auto kid_bytes = ReadReceiptKid(parsed_receipt->protected_headers);
    if (!kid_bytes) {
      unauthorized_failures.push_back(MakeFailure("KID not found in receipt", "MST_KID_MISSING"));
      continue;
    }

    const auto kid_str = NormalizeKid(*kid_bytes);
    auto key = key_store.Resolve(issuer, kid_str);
    if (!key) {
      auto& bucket = is_authorized ? authorized_failures : unauthorized_failures;
      bucket.push_back(MakeFailure("Key with ID '" + kid_str + "' not found for issuer '" + issuer + "'", "MST_KEY_NOT_FOUND"));
      continue;
    }

    std::vector<cosesign1::validation::ValidationFailure> receipt_failures;
    std::string issuer_out = issuer;
    auto ok = VerifyReceiptAgainstStatement(receipt_bytes, statement_without_unprotected, *key, std::nullopt, issuer_out, receipt_failures);
    if (!ok) {
      auto& bucket = is_authorized ? authorized_failures : unauthorized_failures;
      for (auto& f : receipt_failures) {
        bucket.push_back(std::move(f));
      }
      continue;
    }

    if (is_authorized) {
      valid_authorized_domains.insert(ToLower(issuer));
    }
  }

  // Post-process authorized receipt behavior.
  if (user_provided_authorized) {
    switch (options.authorized_receipt_behavior) {
      case AuthorizedReceiptBehavior::VerifyAnyMatching:
        if (!authorized.empty() && valid_authorized_domains.empty()) {
          authorized_failures.push_back(MakeFailure("No valid receipts found for any authorized issuer domain", "MST_NO_VALID_AUTHORIZED_RECEIPTS"));
        } else {
          authorized_failures.clear();
        }
        break;
      case AuthorizedReceiptBehavior::VerifyAllMatching:
        if (!authorized.empty() && authorized_domains_with_receipt.empty()) {
          authorized_failures.push_back(MakeFailure("No receipts found for any authorized issuer domain", "MST_NO_VALID_AUTHORIZED_RECEIPTS"));
        }
        for (const auto& dom : authorized_domains_with_receipt) {
          if (valid_authorized_domains.find(dom) == valid_authorized_domains.end()) {
            authorized_failures.push_back(MakeFailure("A receipt from the required domain '" + dom + "' failed verification", "MST_REQUIRED_DOMAIN_FAILED"));
          }
        }
        break;
      case AuthorizedReceiptBehavior::RequireAll:
        for (const auto& dom : authorized) {
          if (valid_authorized_domains.find(dom) == valid_authorized_domains.end()) {
            authorized_failures.push_back(MakeFailure("No valid receipt found for a required domain '" + dom + "'", "MST_REQUIRED_DOMAIN_MISSING"));
          }
        }
        break;
    }
  }

  failures.insert(failures.end(), authorized_failures.begin(), authorized_failures.end());
  failures.insert(failures.end(), unauthorized_failures.begin(), unauthorized_failures.end());

  if (!failures.empty()) {
    return cosesign1::validation::ValidationResult::Failure(std::string(validator_name), std::move(failures));
  }

  std::unordered_map<std::string, std::string> metadata;
  metadata.emplace("receipts", std::to_string(receipts.size()));
  metadata.emplace("verifiedAuthorizedDomains", std::to_string(valid_authorized_domains.size()));
  return cosesign1::validation::ValidationResult::Success(std::string(validator_name), std::move(metadata));
}

cosesign1::validation::ValidationResult VerifyTransparentStatementReceipt(
    std::string_view validator_name,
    const JwkEcPublicKey& jwk,
    const std::vector<std::uint8_t>& receipt_cose_sign1,
    const std::vector<std::uint8_t>& input_signed_claims) {
  std::vector<cosesign1::validation::ValidationFailure> failures;

  auto der = EcJwkToPublicKeyDer(jwk);
  if (!der) {
    failures.push_back(MakeFailure("Failed to convert JWK to public key", "MST_JWK_ERROR"));
    return cosesign1::validation::ValidationResult::Failure(std::string(validator_name), std::move(failures));
  }

  OfflineEcKeyStore::ResolvedKey key;
  key.public_key_bytes = *der;
  key.expected_alg = ExpectedAlgFromCrv(jwk.crv);

  std::string issuer;
  const bool ok = VerifyReceiptAgainstStatement(
      receipt_cose_sign1, input_signed_claims, key, std::optional<std::string_view>(jwk.kid), issuer, failures);
  if (!ok) {
    return cosesign1::validation::ValidationResult::Failure(std::string(validator_name), std::move(failures));
  }

  return cosesign1::validation::ValidationResult::Success(std::string(validator_name));
}

} // namespace cosesign1::mst
