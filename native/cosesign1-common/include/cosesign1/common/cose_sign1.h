#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <tinycbor/cbor.h>

#include <cosesign1/common/cbor_primitives.h>
#include <cosesign1/common/cose_header_map.h>

namespace cosesign1::common::cbor {

inline constexpr std::string_view kSigStructureContextSignature1 = "Signature1";

// Sig_structure from RFC 9052:
// Sig_structure = [ context : tstr, body_protected : bstr, external_aad : bstr, payload : bstr ]
// For COSE_Sign1, context is "Signature1".
struct SigStructureView {
  std::string_view context;
  std::span<const std::uint8_t> body_protected;
  std::span<const std::uint8_t> external_aad;
  std::optional<std::span<const std::uint8_t>> payload;  // nullopt means detached
};

struct ParsedCoseSign1 {
  CoseHeaderMap protected_headers;
  CoseHeaderMap unprotected_headers;
  std::optional<std::vector<std::uint8_t>> payload;  // null => detached
  std::vector<std::uint8_t> signature;

  SigStructureView Signature1SigStructure() const {
    SigStructureView view;
    view.context = kSigStructureContextSignature1;
    view.body_protected = std::span<const std::uint8_t>(protected_headers.EncodedMapCbor().data(), protected_headers.EncodedMapCbor().size());
    view.external_aad = std::span<const std::uint8_t>{};
    if (payload) {
      view.payload = std::span<const std::uint8_t>(payload->data(), payload->size());
    } else {
      view.payload = std::nullopt;
    }
    return view;
  }
};

inline bool ParseCoseSign1(const std::vector<std::uint8_t>& cose_sign1, ParsedCoseSign1& out, std::string* out_error = nullptr) {
  if (out_error) out_error->clear();

  out.protected_headers.Clear();
  out.unprotected_headers.Clear();
  out.payload = std::nullopt;
  out.signature.clear();

  CborParser parser;
  CborValue it;
  if (cbor_parser_init(cose_sign1.data(), cose_sign1.size(), 0, &parser, &it) != CborNoError) {
    return Fail(out_error, "cbor_parser_init failed");
  }

  if (!SkipOptionalCoseSign1Tag(&it)) {
    return Fail(out_error, "unexpected CBOR tag (expected COSE_Sign1 tag 18 or no tag)");
  }

  if (!cbor_value_is_array(&it)) {
    return Fail(out_error, "top-level item is not an array");
  }

  size_t length = 0;
  if (cbor_value_get_array_length(&it, &length) != CborNoError) {
    return Fail(out_error, "failed to get array length");
  }
  if (length != 4) {
    return Fail(out_error, "array length was not 4");
  }

  CborValue arr;
  if (cbor_value_enter_container(&it, &arr) != CborNoError) {
    return Fail(out_error, "failed to enter array container");
  }

  std::vector<std::uint8_t> protected_headers_bstr;
  if (!ReadByteString(&arr, protected_headers_bstr)) {
    return Fail(out_error, "failed to read protected headers (bstr)");
  }

  {
    std::string hdr_error;
    if (!ParseProtectedHeaderBytes(protected_headers_bstr, out.protected_headers, &hdr_error)) {
      if (out_error) *out_error = hdr_error.empty() ? "failed to parse protected headers" : hdr_error;
      return false;
    }
  }

  if (!cbor_value_is_map(&arr)) {
    return Fail(out_error, "unprotected headers are not a map");
  }

  {
    std::string hdr_error;
    if (!ParseCoseHeaderMap(arr, out.unprotected_headers, &hdr_error)) {
      if (out_error) *out_error = hdr_error.empty() ? "failed to parse unprotected headers map" : hdr_error;
      return false;
    }
  }

  const bool advanced_past_unprotected = cbor_value_advance(&arr) == CborNoError;

  if (!ReadOptionalPayload(&arr, out.payload)) {
    return Fail(out_error, "failed to read payload (bstr or null)");
  }

  if (!ReadByteString(&arr, out.signature)) {
    return Fail(out_error, "failed to read signature (bstr)");
  }

  const bool at_end = cbor_value_at_end(&arr);
  const bool left = cbor_value_leave_container(&it, &arr) == CborNoError;
  return advanced_past_unprotected && at_end && left;
}

inline bool EncodeSignature1SigStructure(const ParsedCoseSign1& msg,
                                        std::optional<std::span<const std::uint8_t>> external_payload,
                                        std::vector<std::uint8_t>& out,
                                        std::string* out_error = nullptr) {
  if (out_error) out_error->clear();

  std::span<const std::uint8_t> payload_span;
  if (msg.payload) {
    payload_span = std::span<const std::uint8_t>(msg.payload->data(), msg.payload->size());
  } else {
    if (!external_payload.has_value()) {
      return Fail(out_error, "detached payload requires external payload bytes");
    }
    payload_span = *external_payload;
  }

  const auto& body_protected = msg.protected_headers.EncodedMapCbor();

  // Sig_structure = ["Signature1", body_protected, external_aad, payload]
  out.assign(256 + body_protected.size() + payload_span.size(), 0);

  while (true) {
    CborEncoder enc;
    cbor_encoder_init(&enc, out.data(), out.size(), 0);

    CborEncoder arr;
    if (cbor_encoder_create_array(&enc, &arr, 4) != CborNoError) {
      out.resize(out.size() * 2);
      continue;
    }

    if (cbor_encode_text_stringz(&arr, "Signature1") != CborNoError) {
      out.resize(out.size() * 2);
      continue;
    }

    if (cbor_encode_byte_string(&arr, body_protected.data(), body_protected.size()) != CborNoError) {
      out.resize(out.size() * 2);
      continue;
    }

    // external_aad = empty bstr
    if (cbor_encode_byte_string(&arr, nullptr, 0) != CborNoError) {
      out.resize(out.size() * 2);
      continue;
    }

    if (cbor_encode_byte_string(&arr, payload_span.data(), payload_span.size()) != CborNoError) {
      out.resize(out.size() * 2);
      continue;
    }

    if (cbor_encoder_close_container(&enc, &arr) != CborNoError) {
      out.resize(out.size() * 2);
      continue;
    }

    const size_t used = cbor_encoder_get_buffer_size(&enc, out.data());
    out.resize(used);
    return true;
  }
}

} // namespace cosesign1::common::cbor
