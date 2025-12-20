#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <tinycbor/cbor.h>

#include <cosesign1/common/cbor.h>

namespace {

struct DecodedSigStructure {
  std::string context;
  std::vector<std::uint8_t> body_protected;
  std::vector<std::uint8_t> external_aad;
  std::vector<std::uint8_t> payload;
};

bool DecodeSigStructure(const std::vector<std::uint8_t>& encoded, DecodedSigStructure& out) {
  out = {};

  CborParser parser;
  CborValue it;
  if (cbor_parser_init(encoded.data(), encoded.size(), 0, &parser, &it) != CborNoError) {
    return false;
  }
  if (!cbor_value_is_array(&it)) {
    return false;
  }

  size_t length = 0;
  if (cbor_value_get_array_length(&it, &length) != CborNoError || length != 4) {
    return false;
  }

  CborValue arr;
  if (cbor_value_enter_container(&it, &arr) != CborNoError) {
    return false;
  }

  if (!cosesign1::common::cbor::ReadTextString(&arr, out.context)) {
    return false;
  }
  if (!cosesign1::common::cbor::ReadByteString(&arr, out.body_protected)) {
    return false;
  }
  if (!cosesign1::common::cbor::ReadByteString(&arr, out.external_aad)) {
    return false;
  }
  if (!cosesign1::common::cbor::ReadByteString(&arr, out.payload)) {
    return false;
  }

  if (!cbor_value_at_end(&arr)) {
    return false;
  }
  if (cbor_value_leave_container(&it, &arr) != CborNoError) {
    return false;
  }

  return true;
}

bool ParseHeaderMapBytes(const std::vector<std::uint8_t>& map_cbor,
                         cosesign1::common::cbor::CoseHeaderMap& out,
                         std::string& out_error) {
  out_error.clear();
  CborParser parser;
  CborValue it;
  if (cbor_parser_init(map_cbor.data(), map_cbor.size(), 0, &parser, &it) != CborNoError) {
    out_error = "cbor_parser_init failed";
    return false;
  }
  return cosesign1::common::cbor::ParseCoseHeaderMap(it, out, &out_error);
}

std::vector<std::uint8_t> EncodeCoseSign1(
    const std::vector<std::uint8_t>& protected_map_cbor,
    const std::vector<std::pair<std::int64_t, std::vector<std::uint8_t>>>& unprotected_bstr_values,
    const std::optional<std::vector<std::uint8_t>>& payload,
    const std::vector<std::uint8_t>& signature,
    bool with_tag_18) {
  std::vector<std::uint8_t> out(4096);

  CborEncoder root;
  cbor_encoder_init(&root, out.data(), out.size(), 0);

  CborEncoder top = root;
  if (with_tag_18) {
    REQUIRE(cbor_encode_tag(&top, cosesign1::common::cbor::kCoseSign1Tag) == CborNoError);
  }

  CborEncoder arr;
  REQUIRE(cbor_encoder_create_array(&top, &arr, 4) == CborNoError);

  // 0: protected (bstr)
  REQUIRE(cbor_encode_byte_string(&arr, protected_map_cbor.data(), protected_map_cbor.size()) == CborNoError);

  // 1: unprotected (map)
  CborEncoder map;
  REQUIRE(cbor_encoder_create_map(&arr, &map, CborIndefiniteLength) == CborNoError);
  for (const auto& kv : unprotected_bstr_values) {
    REQUIRE(cbor_encode_int(&map, kv.first) == CborNoError);
    REQUIRE(cbor_encode_byte_string(&map, kv.second.data(), kv.second.size()) == CborNoError);
  }
  REQUIRE(cbor_encoder_close_container(&arr, &map) == CborNoError);

  // 2: payload (bstr or null)
  if (!payload) {
    REQUIRE(cbor_encode_null(&arr) == CborNoError);
  } else {
    REQUIRE(cbor_encode_byte_string(&arr, payload->data(), payload->size()) == CborNoError);
  }

  // 3: signature (bstr)
  REQUIRE(cbor_encode_byte_string(&arr, signature.data(), signature.size()) == CborNoError);

  REQUIRE(cbor_encoder_close_container(&top, &arr) == CborNoError);

  const auto written = cbor_encoder_get_buffer_size(&top, out.data());
  out.resize(written);
  return out;
}

std::vector<std::uint8_t> EncodeProtectedMapWithAlg(std::int64_t alg) {
  std::vector<std::uint8_t> buf(256);

  CborEncoder root;
  cbor_encoder_init(&root, buf.data(), buf.size(), 0);

  CborEncoder map;
  REQUIRE(cbor_encoder_create_map(&root, &map, 1) == CborNoError);
  REQUIRE(cbor_encode_int(&map, 1) == CborNoError);
  REQUIRE(cbor_encode_int(&map, alg) == CborNoError);
  REQUIRE(cbor_encoder_close_container(&root, &map) == CborNoError);

  const auto written = cbor_encoder_get_buffer_size(&root, buf.data());
  buf.resize(written);
  return buf;
}

std::vector<std::uint8_t> EncodeProtectedMapWithX5c(const std::vector<std::vector<std::uint8_t>>& certs) {
  std::vector<std::uint8_t> buf(2048);

  CborEncoder root;
  cbor_encoder_init(&root, buf.data(), buf.size(), 0);

  CborEncoder map;
  REQUIRE(cbor_encoder_create_map(&root, &map, 1) == CborNoError);
  REQUIRE(cbor_encode_int(&map, 33) == CborNoError);

  CborEncoder arr;
  REQUIRE(cbor_encoder_create_array(&map, &arr, certs.size()) == CborNoError);
  for (const auto& c : certs) {
    REQUIRE(cbor_encode_byte_string(&arr, c.data(), c.size()) == CborNoError);
  }
  REQUIRE(cbor_encoder_close_container(&map, &arr) == CborNoError);

  REQUIRE(cbor_encoder_close_container(&root, &map) == CborNoError);

  const auto written = cbor_encoder_get_buffer_size(&root, buf.data());
  buf.resize(written);
  return buf;
}

} // namespace

TEST_CASE("SigStructureView references protected headers and payload") {
  const auto protected_map = EncodeProtectedMapWithAlg(-7);
  const std::vector<std::uint8_t> payload{0x01, 0x02, 0x03, 0x04};

  const auto cose = EncodeCoseSign1(
      protected_map,
      /*unprotected_bstr_values=*/{},
      /*payload=*/payload,
      /*signature=*/std::vector<std::uint8_t>{0xAA},
      /*with_tag_18=*/true);

  cosesign1::common::cbor::ParsedCoseSign1 parsed;
  REQUIRE(cosesign1::common::cbor::ParseCoseSign1(cose, parsed));

  const auto sig = parsed.Signature1SigStructure();
  REQUIRE(sig.context == cosesign1::common::cbor::kSigStructureContextSignature1);
  REQUIRE(std::vector<std::uint8_t>(sig.body_protected.begin(), sig.body_protected.end()) == protected_map);
  REQUIRE(sig.external_aad.empty());
  REQUIRE(sig.payload.has_value());
  REQUIRE(std::vector<std::uint8_t>(sig.payload->begin(), sig.payload->end()) == payload);
}

TEST_CASE("SigStructureView marks detached payload") {
  const auto protected_map = EncodeProtectedMapWithAlg(-7);

  const auto cose = EncodeCoseSign1(
      protected_map,
      /*unprotected_bstr_values=*/{},
      /*payload=*/std::nullopt,
      /*signature=*/std::vector<std::uint8_t>{0xAA},
      /*with_tag_18=*/false);

  cosesign1::common::cbor::ParsedCoseSign1 parsed;
  REQUIRE(cosesign1::common::cbor::ParseCoseSign1(cose, parsed));

  const auto sig = parsed.Signature1SigStructure();
  REQUIRE(sig.context == cosesign1::common::cbor::kSigStructureContextSignature1);
  REQUIRE(std::vector<std::uint8_t>(sig.body_protected.begin(), sig.body_protected.end()) == protected_map);
  REQUIRE(sig.external_aad.empty());
  REQUIRE_FALSE(sig.payload.has_value());
}

TEST_CASE("EncodeSignature1SigStructure encodes RFC Sig_structure (attached payload)") {
  const auto protected_map = EncodeProtectedMapWithAlg(-7);
  const std::vector<std::uint8_t> payload{0x10, 0x11, 0x12};

  const auto cose = EncodeCoseSign1(
      protected_map,
      /*unprotected_bstr_values=*/{},
      /*payload=*/payload,
      /*signature=*/std::vector<std::uint8_t>{0xAA},
      /*with_tag_18=*/true);

  cosesign1::common::cbor::ParsedCoseSign1 parsed;
  REQUIRE(cosesign1::common::cbor::ParseCoseSign1(cose, parsed));

  std::vector<std::uint8_t> encoded;
  std::string error;
  REQUIRE(cosesign1::common::cbor::EncodeSignature1SigStructure(parsed, /*external_payload=*/std::nullopt, encoded, &error));
  REQUIRE(error.empty());

  DecodedSigStructure decoded;
  REQUIRE(DecodeSigStructure(encoded, decoded));
  REQUIRE(decoded.context == "Signature1");
  REQUIRE(decoded.body_protected == protected_map);
  REQUIRE(decoded.external_aad.empty());
  REQUIRE(decoded.payload == payload);
}

TEST_CASE("EncodeSignature1SigStructure encodes RFC Sig_structure (detached payload)") {
  const auto protected_map = EncodeProtectedMapWithAlg(-7);
  const std::vector<std::uint8_t> detached_payload{0x99, 0x98, 0x97, 0x96};

  const auto cose = EncodeCoseSign1(
      protected_map,
      /*unprotected_bstr_values=*/{},
      /*payload=*/std::nullopt,
      /*signature=*/std::vector<std::uint8_t>{0xAA},
      /*with_tag_18=*/false);

  cosesign1::common::cbor::ParsedCoseSign1 parsed;
  REQUIRE(cosesign1::common::cbor::ParseCoseSign1(cose, parsed));

  std::vector<std::uint8_t> encoded;
  std::string error;
  REQUIRE(cosesign1::common::cbor::EncodeSignature1SigStructure(
      parsed,
      std::span<const std::uint8_t>(detached_payload.data(), detached_payload.size()),
      encoded,
      &error));
  REQUIRE(error.empty());

  DecodedSigStructure decoded;
  REQUIRE(DecodeSigStructure(encoded, decoded));
  REQUIRE(decoded.context == "Signature1");
  REQUIRE(decoded.body_protected == protected_map);
  REQUIRE(decoded.external_aad.empty());
  REQUIRE(decoded.payload == detached_payload);
}

TEST_CASE("ParseCoseSign1 parses tagged COSE_Sign1 and exposes typed alg") {
  const auto protected_map = EncodeProtectedMapWithAlg(-7);

  const auto cose = EncodeCoseSign1(
      protected_map,
      /*unprotected_bstr_values=*/{},
      /*payload=*/std::vector<std::uint8_t>{0x01, 0x02, 0x03},
      /*signature=*/std::vector<std::uint8_t>{0xAA, 0xBB},
      /*with_tag_18=*/true);

  cosesign1::common::cbor::ParsedCoseSign1 parsed;
  std::string error;
  REQUIRE(cosesign1::common::cbor::ParseCoseSign1(cose, parsed, &error));
  REQUIRE(error.empty());

  REQUIRE(parsed.payload.has_value());
  REQUIRE(parsed.payload->size() == 3);

  const auto alg = parsed.protected_headers.TryGetInt64(1);
  REQUIRE(alg.has_value());
  REQUIRE(*alg == -7);

  // COSE precedence: protected wins.
  REQUIRE_FALSE(parsed.unprotected_headers.TryGetInt64(1).has_value());
}

TEST_CASE("ParseCoseSign1 supports detached payload") {
  const auto protected_map = EncodeProtectedMapWithAlg(-7);

  const auto cose = EncodeCoseSign1(
      protected_map,
      /*unprotected_bstr_values=*/{},
      /*payload=*/std::nullopt,
      /*signature=*/std::vector<std::uint8_t>{0xAA},
      /*with_tag_18=*/false);

  cosesign1::common::cbor::ParsedCoseSign1 parsed;
  std::string error;
  REQUIRE(cosesign1::common::cbor::ParseCoseSign1(cose, parsed, &error));
  REQUIRE(error.empty());
  REQUIRE_FALSE(parsed.payload.has_value());
}

TEST_CASE("ParseCoseSign1 parses x5c as array of bstr") {
  const std::vector<std::uint8_t> leaf{0x30, 0x82, 0x01, 0x02};
  const std::vector<std::uint8_t> intermediate{0x30, 0x82, 0x09, 0x09};

  const auto protected_map = EncodeProtectedMapWithX5c({leaf, intermediate});

  const auto cose = EncodeCoseSign1(
      protected_map,
      /*unprotected_bstr_values=*/{},
      /*payload=*/std::vector<std::uint8_t>{0x11},
      /*signature=*/std::vector<std::uint8_t>{0x22},
      /*with_tag_18=*/true);

  cosesign1::common::cbor::ParsedCoseSign1 parsed;
  std::string error;
  REQUIRE(cosesign1::common::cbor::ParseCoseSign1(cose, parsed, &error));
  REQUIRE(error.empty());

  std::vector<std::uint8_t> first;
  REQUIRE(parsed.protected_headers.TryGetFirstByteStringFromArray(33, first));
  REQUIRE(first == leaf);

  std::vector<std::vector<std::uint8_t>> chain;
  REQUIRE(parsed.protected_headers.TryGetByteStringArray(33, chain));
  REQUIRE(chain.size() == 2);
  REQUIRE(chain[0] == leaf);
  REQUIRE(chain[1] == intermediate);
}

TEST_CASE("ParseCoseSign1 rejects wrong top-level structure") {
  // Encode a CBOR map instead of array.
  std::vector<std::uint8_t> buf(64);
  CborEncoder root;
  cbor_encoder_init(&root, buf.data(), buf.size(), 0);
  CborEncoder map;
  REQUIRE(cbor_encoder_create_map(&root, &map, 0) == CborNoError);
  REQUIRE(cbor_encoder_close_container(&root, &map) == CborNoError);
  buf.resize(cbor_encoder_get_buffer_size(&root, buf.data()));

  cosesign1::common::cbor::ParsedCoseSign1 parsed;
  std::string error;
  REQUIRE_FALSE(cosesign1::common::cbor::ParseCoseSign1(buf, parsed, &error));
  REQUIRE_FALSE(error.empty());
}

TEST_CASE("CoseHeaderMap captures raw CBOR value bytes for all labels") {
  // Build protected headers with two entries:
  // - 1: alg (int)
  // - 99: an array containing a map (unknown shape for our decoder) but should still be present and have raw bytes
  std::vector<std::uint8_t> protected_buf(512);
  CborEncoder root;
  cbor_encoder_init(&root, protected_buf.data(), protected_buf.size(), 0);

  CborEncoder map;
  REQUIRE(cbor_encoder_create_map(&root, &map, 2) == CborNoError);
  REQUIRE(cbor_encode_int(&map, 1) == CborNoError);
  REQUIRE(cbor_encode_int(&map, -7) == CborNoError);

  REQUIRE(cbor_encode_int(&map, 99) == CborNoError);
  CborEncoder arr;
  REQUIRE(cbor_encoder_create_array(&map, &arr, 1) == CborNoError);
  CborEncoder inner_map;
  REQUIRE(cbor_encoder_create_map(&arr, &inner_map, 0) == CborNoError);
  REQUIRE(cbor_encoder_close_container(&arr, &inner_map) == CborNoError);
  REQUIRE(cbor_encoder_close_container(&map, &arr) == CborNoError);

  REQUIRE(cbor_encoder_close_container(&root, &map) == CborNoError);
  protected_buf.resize(cbor_encoder_get_buffer_size(&root, protected_buf.data()));

  const auto cose = EncodeCoseSign1(
      protected_buf,
      /*unprotected_bstr_values=*/{},
      /*payload=*/std::vector<std::uint8_t>{0x01},
      /*signature=*/std::vector<std::uint8_t>{0x02},
      /*with_tag_18=*/false);

  cosesign1::common::cbor::ParsedCoseSign1 parsed;
  std::string error;
  REQUIRE(cosesign1::common::cbor::ParseCoseSign1(cose, parsed, &error));
  REQUIRE(error.empty());

  // alg entry exists and has raw bytes.
  REQUIRE(parsed.protected_headers.TryGetInt64(1).has_value());
  std::vector<std::uint8_t> raw_alg;
  REQUIRE(parsed.protected_headers.TryGetRawValueCbor(1, raw_alg));
  REQUIRE_FALSE(raw_alg.empty());

  // unknown-shape entry should still be captured.
  REQUIRE(parsed.protected_headers.Contains(99));
  std::vector<std::uint8_t> raw_99;
  REQUIRE(parsed.protected_headers.TryGetRawValueCbor(99, raw_99));
  REQUIRE_FALSE(raw_99.empty());
}

TEST_CASE("CoseHeaderMap supports tstr labels") {
  // Protected headers: { "kid": h'010203' }
  std::vector<std::uint8_t> protected_buf(256);
  CborEncoder root;
  cbor_encoder_init(&root, protected_buf.data(), protected_buf.size(), 0);

  CborEncoder map;
  REQUIRE(cbor_encoder_create_map(&root, &map, 1) == CborNoError);
  REQUIRE(cbor_encode_text_stringz(&map, "kid") == CborNoError);
  const std::uint8_t kid_bytes[] = {0x01, 0x02, 0x03};
  REQUIRE(cbor_encode_byte_string(&map, kid_bytes, sizeof(kid_bytes)) == CborNoError);
  REQUIRE(cbor_encoder_close_container(&root, &map) == CborNoError);

  protected_buf.resize(cbor_encoder_get_buffer_size(&root, protected_buf.data()));

  const auto cose = EncodeCoseSign1(
      protected_buf,
      /*unprotected_bstr_values=*/{},
      /*payload=*/std::vector<std::uint8_t>{0x01},
      /*signature=*/std::vector<std::uint8_t>{0x02},
      /*with_tag_18=*/false);

  cosesign1::common::cbor::ParsedCoseSign1 parsed;
  std::string error;
  REQUIRE(cosesign1::common::cbor::ParseCoseSign1(cose, parsed, &error));
  REQUIRE(error.empty());

  REQUIRE(parsed.protected_headers.Contains("kid"));

  std::vector<std::uint8_t> kid_out;
  REQUIRE(parsed.protected_headers.TryGetByteString("kid", kid_out));
  REQUIRE(kid_out == std::vector<std::uint8_t>({0x01, 0x02, 0x03}));

  std::vector<std::uint8_t> raw;
  REQUIRE(parsed.protected_headers.TryGetRawValueCbor("kid", raw));
  REQUIRE_FALSE(raw.empty());

}


TEST_CASE("CoseHeaderMap GetOrParseParsed caches per-label parsed object") {
  // Protected headers: { "kid": h'010203' }
  std::vector<std::uint8_t> protected_buf(256);
  CborEncoder root;
  cbor_encoder_init(&root, protected_buf.data(), protected_buf.size(), 0);

  CborEncoder map;
  REQUIRE(cbor_encoder_create_map(&root, &map, 1) == CborNoError);
  REQUIRE(cbor_encode_text_stringz(&map, "kid") == CborNoError);
  const std::uint8_t kid_bytes[] = {0x01, 0x02, 0x03};
  REQUIRE(cbor_encode_byte_string(&map, kid_bytes, sizeof(kid_bytes)) == CborNoError);
  REQUIRE(cbor_encoder_close_container(&root, &map) == CborNoError);
  protected_buf.resize(cbor_encoder_get_buffer_size(&root, protected_buf.data()));

  const auto cose = EncodeCoseSign1(
      protected_buf,
      /*unprotected_bstr_values=*/{},
      /*payload=*/std::vector<std::uint8_t>{0x01},
      /*signature=*/std::vector<std::uint8_t>{0x02},
      /*with_tag_18=*/false);

  cosesign1::common::cbor::ParsedCoseSign1 parsed;
  std::string error;
  REQUIRE(cosesign1::common::cbor::ParseCoseSign1(cose, parsed, &error));
  REQUIRE(error.empty());

  int parse_calls = 0;

  struct ParsedKid {
    std::size_t length = 0;
  };

  auto* p1 = parsed.protected_headers.GetOrParseParsed<ParsedKid>("kid", [&](const std::vector<std::uint8_t>& raw, const cosesign1::common::cbor::CoseHeaderMap::Value&) -> std::optional<ParsedKid> {
    parse_calls++;
    // raw is CBOR for a bstr; just ensure it looks sane.
    if (raw.empty()) return std::nullopt;
    return ParsedKid{raw.size()};
  });

  REQUIRE(p1 != nullptr);
  REQUIRE(parse_calls == 1);

  auto* p2 = parsed.protected_headers.GetOrParseParsed<ParsedKid>("kid", [&](const std::vector<std::uint8_t>&, const cosesign1::common::cbor::CoseHeaderMap::Value&) -> std::optional<ParsedKid> {
    parse_calls++;
    return ParsedKid{123};
  });

  REQUIRE(p2 != nullptr);
  REQUIRE(parse_calls == 1);
  REQUIRE(p2->length == p1->length);
}

TEST_CASE("ParseCoseHeaderMap skips unsupported key types and unknown value shapes") {
  // Protected headers: { h'00': 1, 98: {}, 1: -7 }
  // - h'00' key is unsupported and should be skipped along with its value
  // - 98 has a map value (unknown shape) and should be present but decoded as monostate
  std::vector<std::uint8_t> protected_buf(512);
  CborEncoder root;
  cbor_encoder_init(&root, protected_buf.data(), protected_buf.size(), 0);

  CborEncoder map;
  REQUIRE(cbor_encoder_create_map(&root, &map, 3) == CborNoError);

  const std::uint8_t unsupported_key[] = {0x00};
  REQUIRE(cbor_encode_byte_string(&map, unsupported_key, sizeof(unsupported_key)) == CborNoError);
  REQUIRE(cbor_encode_int(&map, 1) == CborNoError);

  REQUIRE(cbor_encode_int(&map, 98) == CborNoError);
  CborEncoder inner_map;
  REQUIRE(cbor_encoder_create_map(&map, &inner_map, 0) == CborNoError);
  REQUIRE(cbor_encoder_close_container(&map, &inner_map) == CborNoError);

  REQUIRE(cbor_encode_int(&map, 1) == CborNoError);
  REQUIRE(cbor_encode_int(&map, -7) == CborNoError);

  REQUIRE(cbor_encoder_close_container(&root, &map) == CborNoError);
  protected_buf.resize(cbor_encoder_get_buffer_size(&root, protected_buf.data()));

  const auto cose = EncodeCoseSign1(
      protected_buf,
      /*unprotected_bstr_values=*/{},
      /*payload=*/std::vector<std::uint8_t>{0x01},
      /*signature=*/std::vector<std::uint8_t>{0x02},
      /*with_tag_18=*/false);

  cosesign1::common::cbor::ParsedCoseSign1 parsed;
  std::string error;
  REQUIRE(cosesign1::common::cbor::ParseCoseSign1(cose, parsed, &error));
  REQUIRE(error.empty());

  REQUIRE(parsed.protected_headers.TryGetInt64(1).has_value());
  REQUIRE(*parsed.protected_headers.TryGetInt64(1) == -7);

  // Unsupported key should not create an entry.
  REQUIRE_FALSE(parsed.protected_headers.Contains(""));

  // Unknown map-shaped value should still be present for label 98.
  REQUIRE(parsed.protected_headers.Contains(98));
  std::vector<std::uint8_t> raw_98;
  REQUIRE(parsed.protected_headers.TryGetRawValueCbor(98, raw_98));
  REQUIRE_FALSE(raw_98.empty());
}

TEST_CASE("CoseHeaderMap parsed-object APIs and type getters") {
  const auto protected_map = EncodeProtectedMapWithAlg(-7);
  const auto cose = EncodeCoseSign1(
      protected_map,
      /*unprotected_bstr_values=*/{},
      /*payload=*/std::vector<std::uint8_t>{0x01},
      /*signature=*/std::vector<std::uint8_t>{0x02},
      /*with_tag_18=*/false);

  cosesign1::common::cbor::ParsedCoseSign1 parsed;
  std::string error;
  REQUIRE(cosesign1::common::cbor::ParseCoseSign1(cose, parsed, &error));
  REQUIRE(error.empty());

  // Mismatched type queries should fail.
  std::vector<std::uint8_t> bytes;
  REQUIRE_FALSE(parsed.protected_headers.TryGetByteString(1, bytes));
  std::string text;
  REQUIRE_FALSE(parsed.protected_headers.TryGetTextString(1, text));

  // Parsed-object cache via SetParsed / TryGetParsed (int label).
  struct CustomParsed {
    int v;
  };

  parsed.protected_headers.SetParsed(1, CustomParsed{123});
  auto* p = parsed.protected_headers.TryGetParsed<CustomParsed>(1);
  REQUIRE(p != nullptr);
  REQUIRE(p->v == 123);

  const auto& cparsed = parsed;
  const auto* cp = cparsed.protected_headers.TryGetParsed<CustomParsed>(1);
  REQUIRE(cp != nullptr);
  REQUIRE(cp->v == 123);
}

TEST_CASE("ParseCoseHeaderMap rejects non-map input") {
  // CBOR int(1)
  const std::vector<std::uint8_t> buf{0x01};
  CborParser parser;
  CborValue it;
  REQUIRE(cbor_parser_init(buf.data(), buf.size(), 0, &parser, &it) == CborNoError);

  cosesign1::common::cbor::CoseHeaderMap headers;
  std::string error;
  REQUIRE_FALSE(cosesign1::common::cbor::ParseCoseHeaderMap(it, headers, &error));
  REQUIRE_FALSE(error.empty());
}

TEST_CASE("ParseCoseHeaderMap detects map ended after label") {
  // Indefinite map with a single key (1) and an early break -> invalid (missing value).
  const std::vector<std::uint8_t> buf{0xBF, 0x01, 0xFF};
  CborParser parser;
  CborValue it;
  REQUIRE(cbor_parser_init(buf.data(), buf.size(), 0, &parser, &it) == CborNoError);
  REQUIRE(cbor_value_is_map(&it));

  cosesign1::common::cbor::CoseHeaderMap headers;
  std::string error;
  REQUIRE_FALSE(cosesign1::common::cbor::ParseCoseHeaderMap(it, headers, &error));
  REQUIRE_FALSE(error.empty());
}

TEST_CASE("ParseCoseHeaderMap detects map ended after unsupported key") {
  // Indefinite map with a single unsupported key (bstr(0)) and an early break -> invalid.
  const std::vector<std::uint8_t> buf{0xBF, 0x40, 0xFF};
  CborParser parser;
  CborValue it;
  REQUIRE(cbor_parser_init(buf.data(), buf.size(), 0, &parser, &it) == CborNoError);
  REQUIRE(cbor_value_is_map(&it));

  cosesign1::common::cbor::CoseHeaderMap headers;
  std::string error;
  REQUIRE_FALSE(cosesign1::common::cbor::ParseCoseHeaderMap(it, headers, &error));
  REQUIRE_FALSE(error.empty());
}

TEST_CASE("ParseProtectedHeaderBytes rejects invalid CBOR") {
  // Truncated major type that cannot be parsed.
  const std::vector<std::uint8_t> invalid{0x1A};
  cosesign1::common::cbor::CoseHeaderMap headers;
  std::string error;
  REQUIRE_FALSE(cosesign1::common::cbor::ParseProtectedHeaderBytes(invalid, headers, &error));
  REQUIRE(error.find("failed to parse protected headers bytes") != std::string::npos);
}

TEST_CASE("ParseCoseSign1 rejects indefinite-length arrays") {
  // COSE_Sign1 encoded as an indefinite-length array.
  // [ h'', {}, null, h'00' ] but with indefinite array header.
  const std::vector<std::uint8_t> buf{
      0x9F,        // start indefinite array
      0x40,        // protected: empty bstr
      0xA0,        // unprotected: empty map
      0xF6,        // payload: null
      0x41, 0x00,  // signature: bstr(1) = 0x00
      0xFF         // break
  };

  cosesign1::common::cbor::ParsedCoseSign1 parsed;
  std::string error;
  REQUIRE_FALSE(cosesign1::common::cbor::ParseCoseSign1(buf, parsed, &error));
  REQUIRE_FALSE(error.empty());
}

TEST_CASE("ParseCoseSign1 rejects wrong types for envelope fields") {
  // Build a COSE_Sign1-ish array with wrong field types.
  std::vector<std::uint8_t> buf(256);
  CborEncoder root;
  cbor_encoder_init(&root, buf.data(), buf.size(), 0);
  CborEncoder arr;
  REQUIRE(cbor_encoder_create_array(&root, &arr, 4) == CborNoError);

  // 0: protected headers should be bstr, but use int.
  REQUIRE(cbor_encode_int(&arr, 1) == CborNoError);
  // 1: unprotected headers should be map, but use int.
  REQUIRE(cbor_encode_int(&arr, 2) == CborNoError);
  // 2: payload should be bstr or null, but use int.
  REQUIRE(cbor_encode_int(&arr, 3) == CborNoError);
  // 3: signature should be bstr, but use int.
  REQUIRE(cbor_encode_int(&arr, 4) == CborNoError);

  REQUIRE(cbor_encoder_close_container(&root, &arr) == CborNoError);
  buf.resize(cbor_encoder_get_buffer_size(&root, buf.data()));

  cosesign1::common::cbor::ParsedCoseSign1 parsed;
  std::string error;
  REQUIRE_FALSE(cosesign1::common::cbor::ParseCoseSign1(buf, parsed, &error));
  REQUIRE_FALSE(error.empty());
}

TEST_CASE("EncodeSignature1SigStructure requires external payload for detached messages") {
  const auto protected_map = EncodeProtectedMapWithAlg(-7);
  const auto cose = EncodeCoseSign1(
      protected_map,
      /*unprotected_bstr_values=*/{},
      /*payload=*/std::nullopt,
      /*signature=*/std::vector<std::uint8_t>{0xAA},
      /*with_tag_18=*/false);

  cosesign1::common::cbor::ParsedCoseSign1 parsed;
  std::string parse_error;
  REQUIRE(cosesign1::common::cbor::ParseCoseSign1(cose, parsed, &parse_error));
  REQUIRE(parse_error.empty());
  REQUIRE_FALSE(parsed.payload.has_value());

  std::vector<std::uint8_t> encoded;
  std::string error;
  REQUIRE_FALSE(cosesign1::common::cbor::EncodeSignature1SigStructure(parsed, std::nullopt, encoded, &error));
  REQUIRE(error.find("detached payload") != std::string::npos);
}

TEST_CASE("Fail helper sets error message") {
  std::string error;
  REQUIRE_FALSE(cosesign1::common::cbor::Fail(&error, "nope"));
  REQUIRE(error == "nope");
}

TEST_CASE("ParseCoseHeaderMap fails to enter map on truncated map") {
  // Map(1) with no key/value bytes.
  const std::vector<std::uint8_t> buf{0xA1};
  cosesign1::common::cbor::CoseHeaderMap headers;
  std::string error;
  REQUIRE_FALSE(ParseHeaderMapBytes(buf, headers, error));
  REQUIRE_FALSE(error.empty());
}

TEST_CASE("ParseCoseHeaderMap reports unsupported key advance failure") {
  // { h'00' : ??? } but key encoding is truncated (bstr(1) with no data)
  const std::vector<std::uint8_t> buf{0xA1, 0x41};
  cosesign1::common::cbor::CoseHeaderMap headers;
  std::string error;
  REQUIRE_FALSE(ParseHeaderMapBytes(buf, headers, error));
  REQUIRE_FALSE(error.empty());
}

TEST_CASE("ParseCoseHeaderMap reports unsupported value advance failure") {
  // { h'' : h'??' } where value encoding is truncated.
  const std::vector<std::uint8_t> buf{0xA1, 0x40, 0x41};
  cosesign1::common::cbor::CoseHeaderMap headers;
  std::string error;
  REQUIRE_FALSE(ParseHeaderMapBytes(buf, headers, error));
  REQUIRE_FALSE(error.empty());
}

TEST_CASE("ParseCoseHeaderMap reports bstr-value read failure on truncated bstr") {
  // { 1 : h'??' } where value encoding is truncated.
  const std::vector<std::uint8_t> buf{0xA1, 0x01, 0x41};
  cosesign1::common::cbor::CoseHeaderMap headers;
  std::string error;
  REQUIRE_FALSE(ParseHeaderMapBytes(buf, headers, error));
  REQUIRE(error.find("bstr header value") != std::string::npos);
}

TEST_CASE("ParseCoseHeaderMap reports unknown-length array values") {
  // { 1 : [ _ ] } with an indefinite-length array of bstr.
  const std::vector<std::uint8_t> buf{0xA1, 0x01, 0x9F, 0x40, 0xFF};
  cosesign1::common::cbor::CoseHeaderMap headers;
  std::string error;
  REQUIRE_FALSE(ParseHeaderMapBytes(buf, headers, error));
  REQUIRE(error.find("array length") != std::string::npos);
}

TEST_CASE("ParseCoseHeaderMap reports probe failure for malformed bstr in array") {
  // { 1 : [ h'??' ] } where the bstr element is truncated.
  const std::vector<std::uint8_t> buf{0xA1, 0x01, 0x81, 0x41};
  cosesign1::common::cbor::CoseHeaderMap headers;
  std::string error;
  REQUIRE_FALSE(ParseHeaderMapBytes(buf, headers, error));
  REQUIRE(error.find("probe array header value") != std::string::npos);
}

TEST_CASE("ParseCoseHeaderMap reports text-label read failure on truncated tstr") {
  // Map(1) with a truncated tstr key: { "?" : ... } but the key bytes are missing.
  const std::vector<std::uint8_t> buf{0xA1, 0x61};
  cosesign1::common::cbor::CoseHeaderMap headers;
  std::string error;
  REQUIRE_FALSE(ParseHeaderMapBytes(buf, headers, error));
  REQUIRE(error.find("text header label") != std::string::npos);
}

TEST_CASE("ParseCoseHeaderMap rejects malformed indefinite bstr header value") {
  // { 1 : (_bstr) } but with an invalid chunk type (tstr chunk inside bstr).
  const std::vector<std::uint8_t> buf{0xA1, 0x01, 0x5F, 0x61, 0x61, 0xFF};
  cosesign1::common::cbor::CoseHeaderMap headers;
  std::string error;
  REQUIRE_FALSE(ParseHeaderMapBytes(buf, headers, error));
  REQUIRE_FALSE(error.empty());
}

TEST_CASE("ParseCoseHeaderMap reports tstr-value read failure on truncated tstr") {
  // { 1 : "?" } where the tstr value encoding is truncated (tstr(1) with no byte).
  const std::vector<std::uint8_t> buf{0xA1, 0x01, 0x61};
  cosesign1::common::cbor::CoseHeaderMap headers;
  std::string error;
  REQUIRE_FALSE(ParseHeaderMapBytes(buf, headers, error));
  REQUIRE(error.find("tstr header value") != std::string::npos);
}

TEST_CASE("ParseCoseHeaderMap reports integer-label advance failure on malformed map") {
  // { 1 : uint64 } where the uint64 value encoding is truncated.
  // 0x1B indicates an 8-byte unsigned integer, but we provide only one byte.
  const std::vector<std::uint8_t> buf{0xA1, 0x01, 0x1B, 0x00};
  cosesign1::common::cbor::CoseHeaderMap headers;
  std::string error;
  REQUIRE_FALSE(ParseHeaderMapBytes(buf, headers, error));
  INFO(error);
  REQUIRE(error.find("advance past integer header label") != std::string::npos);
}

TEST_CASE("ParseCoseHeaderMap reports array-enter failure on malformed array value") {
  // { 1 : [ 0x1B ... ] } where the array contains a non-bstr element with truncated encoding.
  const std::vector<std::uint8_t> buf{0xA1, 0x01, 0x81, 0x1B, 0x00};
  cosesign1::common::cbor::CoseHeaderMap headers;
  std::string error;
  REQUIRE_FALSE(ParseHeaderMapBytes(buf, headers, error));
  INFO(error);
  REQUIRE(error.find("enter array header value") != std::string::npos);
}

TEST_CASE("ParseCoseHeaderMap rejects array element with malformed indefinite bstr") {
  // { 1 : [ (_bstr) ] } but the bstr element has an invalid chunk type.
  const std::vector<std::uint8_t> buf{0xA1, 0x01, 0x81, 0x5F, 0x61, 0x61, 0xFF};
  cosesign1::common::cbor::CoseHeaderMap headers;
  std::string error;
  REQUIRE_FALSE(ParseHeaderMapBytes(buf, headers, error));
  REQUIRE_FALSE(error.empty());
}

TEST_CASE("ParseCoseSign1 rejects unprotected headers not being a map") {
  // [ h'', 1, null, h'00' ]
  const std::vector<std::uint8_t> buf{0x84, 0x40, 0x01, 0xF6, 0x41, 0x00};
  cosesign1::common::cbor::ParsedCoseSign1 parsed;
  std::string error;
  REQUIRE_FALSE(cosesign1::common::cbor::ParseCoseSign1(buf, parsed, &error));
  REQUIRE(error.find("unprotected headers") != std::string::npos);
}

TEST_CASE("ParseCoseSign1 rejects payload wrong type") {
  // [ h'', {}, 1, h'00' ]
  const std::vector<std::uint8_t> buf{0x84, 0x40, 0xA0, 0x01, 0x41, 0x00};
  cosesign1::common::cbor::ParsedCoseSign1 parsed;
  std::string error;
  REQUIRE_FALSE(cosesign1::common::cbor::ParseCoseSign1(buf, parsed, &error));
  REQUIRE(error.find("payload") != std::string::npos);
}

TEST_CASE("ParseCoseSign1 rejects signature wrong type") {
  // [ h'', {}, null, 1 ]
  const std::vector<std::uint8_t> buf{0x84, 0x40, 0xA0, 0xF6, 0x01};
  cosesign1::common::cbor::ParsedCoseSign1 parsed;
  std::string error;
  REQUIRE_FALSE(cosesign1::common::cbor::ParseCoseSign1(buf, parsed, &error));
  REQUIRE(error.find("signature") != std::string::npos);
}

TEST_CASE("ParseCoseSign1 reports protected header parse error details") {
  // [ h'FF', {}, null, h'00' ] where protected headers bstr contains invalid CBOR bytes.
  const std::vector<std::uint8_t> buf{0x84, 0x41, 0xFF, 0xA0, 0xF6, 0x41, 0x00};
  cosesign1::common::cbor::ParsedCoseSign1 parsed;
  std::string error;
  REQUIRE_FALSE(cosesign1::common::cbor::ParseCoseSign1(buf, parsed, &error));
  REQUIRE(error.find("protected") != std::string::npos);
}

TEST_CASE("ParseCoseSign1 reports unprotected header parse error details") {
  // [ h'', { 1 : [ _ ] }, null, h'00' ] where unprotected headers contain an indefinite-length array.
  const std::vector<std::uint8_t> buf{0x84, 0x40, 0xA1, 0x01, 0x9F, 0x40, 0xFF, 0xF6, 0x41, 0x00};
  cosesign1::common::cbor::ParsedCoseSign1 parsed;
  std::string error;
  REQUIRE_FALSE(cosesign1::common::cbor::ParseCoseSign1(buf, parsed, &error));
  REQUIRE(error.find("array length") != std::string::npos);
}

TEST_CASE("ParseCoseSign1 rejects wrong array length") {
  std::vector<std::uint8_t> buf(128);
  CborEncoder root;
  cbor_encoder_init(&root, buf.data(), buf.size(), 0);
  CborEncoder arr;
  REQUIRE(cbor_encoder_create_array(&root, &arr, 3) == CborNoError);
  REQUIRE(cbor_encode_int(&arr, 0) == CborNoError);
  REQUIRE(cbor_encode_int(&arr, 0) == CborNoError);
  REQUIRE(cbor_encode_int(&arr, 0) == CborNoError);
  REQUIRE(cbor_encoder_close_container(&root, &arr) == CborNoError);
  buf.resize(cbor_encoder_get_buffer_size(&root, buf.data()));

  cosesign1::common::cbor::ParsedCoseSign1 parsed;
  std::string error;
  REQUIRE_FALSE(cosesign1::common::cbor::ParseCoseSign1(buf, parsed, &error));
  REQUIRE_FALSE(error.empty());
}

TEST_CASE("ParseCoseSign1 rejects unexpected tag") {
  std::vector<std::uint8_t> buf(256);
  CborEncoder root;
  cbor_encoder_init(&root, buf.data(), buf.size(), 0);

  // Tag 19 instead of 18.
  REQUIRE(cbor_encode_tag(&root, cosesign1::common::cbor::kCoseSign1Tag + 1) == CborNoError);

  CborEncoder arr;
  REQUIRE(cbor_encoder_create_array(&root, &arr, 4) == CborNoError);
  REQUIRE(cbor_encode_byte_string(&arr, nullptr, 0) == CborNoError);
  CborEncoder map;
  REQUIRE(cbor_encoder_create_map(&arr, &map, 0) == CborNoError);
  REQUIRE(cbor_encoder_close_container(&arr, &map) == CborNoError);
  REQUIRE(cbor_encode_null(&arr) == CborNoError);
  const std::uint8_t sig[] = {0x00};
  REQUIRE(cbor_encode_byte_string(&arr, sig, sizeof(sig)) == CborNoError);
  REQUIRE(cbor_encoder_close_container(&root, &arr) == CborNoError);

  buf.resize(cbor_encoder_get_buffer_size(&root, buf.data()));

  cosesign1::common::cbor::ParsedCoseSign1 parsed;
  std::string error;
  REQUIRE_FALSE(cosesign1::common::cbor::ParseCoseSign1(buf, parsed, &error));
  REQUIRE_FALSE(error.empty());
}

TEST_CASE("ParseProtectedHeaderBytes rejects non-map protected bytes") {
  // protected headers bstr contains CBOR int 1 instead of a map.
  std::vector<std::uint8_t> protected_buf(16);
  CborEncoder root;
  cbor_encoder_init(&root, protected_buf.data(), protected_buf.size(), 0);
  REQUIRE(cbor_encode_int(&root, 1) == CborNoError);
  protected_buf.resize(cbor_encoder_get_buffer_size(&root, protected_buf.data()));

  const auto cose = EncodeCoseSign1(
      protected_buf,
      /*unprotected_bstr_values=*/{},
      /*payload=*/std::vector<std::uint8_t>{0x01},
      /*signature=*/std::vector<std::uint8_t>{0x02},
      /*with_tag_18=*/false);

  cosesign1::common::cbor::ParsedCoseSign1 parsed;
  std::string error;
  REQUIRE_FALSE(cosesign1::common::cbor::ParseCoseSign1(cose, parsed, &error));
  REQUIRE_FALSE(error.empty());
}

TEST_CASE("ParseCoseSign1 rejects empty input") {
  cosesign1::common::cbor::ParsedCoseSign1 parsed;
  std::string error;
  REQUIRE_FALSE(cosesign1::common::cbor::ParseCoseSign1({}, parsed, &error));
  REQUIRE_FALSE(error.empty());
}

TEST_CASE("ParseCoseSign1 reports array-enter failure on truncated array") {
  // Array(4) with no element bytes.
  const std::vector<std::uint8_t> buf{0x84};
  cosesign1::common::cbor::ParsedCoseSign1 parsed;
  std::string error;
  REQUIRE_FALSE(cosesign1::common::cbor::ParseCoseSign1(buf, parsed, &error));
  REQUIRE(error.find("enter array container") != std::string::npos);
}
