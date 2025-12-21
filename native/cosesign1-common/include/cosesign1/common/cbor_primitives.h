// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

/**
 * @file cbor_primitives.h
 * @brief Small CBOR decoding primitives shared across native modules.
 */

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <tinycbor/cbor.h>

namespace cosesign1::common::cbor {

// COSE_Sign1 tag is 18 (RFC 8152 / RFC 9052).
constexpr CborTag kCoseSign1Tag = 18;

inline bool ReadByteString(CborValue* v, std::vector<std::uint8_t>& out) {
  if (!cbor_value_is_byte_string(v)) {
    return false;
  }

  size_t len = 0;
  if (cbor_value_calculate_string_length(v, &len) != CborNoError) {
    return false;
  }

  out.resize(len);
  size_t copied = len;
  CborValue next = *v;
  if (cbor_value_copy_byte_string(v, out.data(), &copied, &next) != CborNoError) {
    return false;
  }
  *v = next;
  out.resize(copied);
  return true;
}

inline bool ReadTextString(CborValue* v, std::string& out) {
  if (!cbor_value_is_text_string(v)) {
    return false;
  }

  size_t len = 0;
  if (cbor_value_calculate_string_length(v, &len) != CborNoError) {
    return false;
  }

  out.resize(len);
  size_t copied = len;
  CborValue next = *v;
  if (cbor_value_copy_text_string(v, out.data(), &copied, &next) != CborNoError) {
    return false;
  }
  *v = next;
  out.resize(copied);
  return true;
}

inline bool ReadInt64(CborValue* v, std::int64_t& out) {
  if (!cbor_value_is_integer(v)) {
    return false;
  }
  return cbor_value_get_int64(v, &out) == CborNoError && cbor_value_advance_fixed(v) == CborNoError;
}

inline bool SkipAny(CborValue* v) {
  return cbor_value_advance(v) == CborNoError;
}

inline bool SkipOptionalTag(CborValue* v, CborTag expected) {
  if (!cbor_value_is_tag(v)) {
    return true;
  }

  CborTag tag = 0;
  if (cbor_value_get_tag(v, &tag) != CborNoError) {
    return false;
  }

  if (tag != expected) {
    return false;
  }

  return cbor_value_advance_fixed(v) == CborNoError;
}

inline bool SkipOptionalCoseSign1Tag(CborValue* v) {
  return SkipOptionalTag(v, kCoseSign1Tag);
}

inline bool ReadOptionalPayload(CborValue* v, std::optional<std::vector<std::uint8_t>>& payload) {
  if (cbor_value_is_null(v)) {
    payload = std::nullopt;
    return cbor_value_advance_fixed(v) == CborNoError;
  }

  std::vector<std::uint8_t> bytes;
  if (!ReadByteString(v, bytes)) {
    return false;
  }

  payload = std::move(bytes);
  return true;
}

inline bool EnterArrayOfLength(CborValue* v, std::size_t expected_length, CborValue& out_arr) {
  if (!cbor_value_is_array(v)) {
    return false;
  }

  size_t length = 0;
  if (cbor_value_get_array_length(v, &length) != CborNoError || length != expected_length) {
    return false;
  }

  return cbor_value_enter_container(v, &out_arr) == CborNoError;
}

// Scans a CBOR map for an integer key (label) with an integer value.
// - Only integer keys are considered.
// - Non-integer keys are skipped (key + value).
// - On malformed map encoding, returns false.
inline bool TryReadInt64FromMap(CborValue map_value, std::int64_t label, std::optional<std::int64_t>& out_value) {
  out_value = std::nullopt;

  if (!cbor_value_is_map(&map_value)) {
    return false;
  }

  CborValue it = map_value;
  if (cbor_value_enter_container(&map_value, &it) != CborNoError) {
    return false;
  }

  while (!cbor_value_at_end(&it)) {
    if (cbor_value_is_integer(&it)) {
      std::int64_t key = 0;
      if (cbor_value_get_int64(&it, &key) != CborNoError) {
        return false;
      }
      if (cbor_value_advance_fixed(&it) != CborNoError) {
        return false;
      }

      if (key == label) {
        if (!cbor_value_is_integer(&it)) {
          return false;
        }
        std::int64_t value = 0;
        if (cbor_value_get_int64(&it, &value) != CborNoError) {
          return false;
        }
        out_value = value;
        if (cbor_value_advance_fixed(&it) != CborNoError) {
          return false;
        }
        continue;
      }

      if (cbor_value_advance(&it) != CborNoError) {
        return false;
      }

      continue;
    }

    // Skip non-integer key
    if (cbor_value_advance(&it) != CborNoError) {
      return false;
    }
    if (cbor_value_at_end(&it)) {
      return false;
    }
    if (cbor_value_advance(&it) != CborNoError) {
      return false;
    }
  }

  return cbor_value_leave_container(&map_value, &it) == CborNoError;
}

inline bool CopyRawCborItemBytes(const CborValue& value, std::vector<std::uint8_t>& out) {
  out.clear();

  const uint8_t* start = cbor_value_get_next_byte(&value);
  if (!start) {
    return false;
  }

  CborValue tmp = value;
  if (cbor_value_advance(&tmp) != CborNoError) {
    return false;
  }

  const uint8_t* end = cbor_value_get_next_byte(&tmp);
  // If advancing succeeded, TinyCBOR should always be able to report the next byte.
  // Treat end as valid and monotonic with start.
  out.assign(start, end);
  return true;
}

// Keep this out-of-line under MSVC so coverage tools can attribute hits reliably.
#if defined(_MSC_VER)
__declspec(noinline)
#endif
inline bool Fail(std::string* out_error, const char* message) {
  return out_error ? ((*out_error = message), false) : false;
}

} // namespace cosesign1::common::cbor
