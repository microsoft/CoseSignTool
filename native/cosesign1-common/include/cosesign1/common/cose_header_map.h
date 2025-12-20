#pragma once

#include <any>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

#include <tinycbor/cbor.h>

#include <cosesign1/common/cbor_primitives.h>

namespace cosesign1::common::cbor {

// A small, typed representation of commonly-used COSE header values.
//
// COSE headers are a CBOR map with integer or tstr labels and CBOR values. Verifiers typically only
// need a few value shapes (int, bstr, tstr, array of bstr). This class standardizes decoding
// and makes label inspection consistent across validators.
class CoseHeaderMap {
public:
  using Label = std::variant<std::int64_t, std::string>;
  using Value = std::variant<std::monostate, std::int64_t, std::vector<std::uint8_t>, std::string, std::vector<std::vector<std::uint8_t>>>;

  struct Entry {
    // Raw CBOR bytes for the value (not including the label key).
    std::vector<std::uint8_t> raw_value_cbor;

    // Commonly-used decoded shapes.
    Value decoded;

    // Optional validator-specific decoded object.
    std::any parsed;
  };

  // Raw CBOR bytes that encoded this header map.
  // - For protected headers, this is the exact bytes contained in the COSE protected header bstr
  //   (which may be empty to represent an empty map).
  // - For unprotected headers, this is the raw CBOR map item bytes from the COSE_Sign1 envelope.
  const std::vector<std::uint8_t>& EncodedMapCbor() const { return encoded_map_cbor_; }

  void Clear() {
    encoded_map_cbor_.clear();
    values_.clear();
  }

  bool Contains(std::int64_t label) const { return values_.find(Label{label}) != values_.end(); }
  bool Contains(std::string_view label) const { return values_.find(Label{std::string(label)}) != values_.end(); }

  bool TryGetRawValueCbor(std::int64_t label, std::vector<std::uint8_t>& out) const {
    const auto it = values_.find(Label{label});
    if (it == values_.end()) return false;
    out = it->second.raw_value_cbor;
    return true;
  }

  bool TryGetRawValueCbor(std::string_view label, std::vector<std::uint8_t>& out) const {
    const auto it = values_.find(Label{std::string(label)});
    if (it == values_.end()) return false;
    out = it->second.raw_value_cbor;
    return true;
  }

  std::optional<std::int64_t> TryGetInt64(std::int64_t label) const {
    const auto it = values_.find(Label{label});
    if (it == values_.end()) return std::nullopt;
    if (const auto p = std::get_if<std::int64_t>(&it->second.decoded)) return *p;
    return std::nullopt;
  }

  std::optional<std::int64_t> TryGetInt64(std::string_view label) const {
    const auto it = values_.find(Label{std::string(label)});
    if (it == values_.end()) return std::nullopt;
    if (const auto p = std::get_if<std::int64_t>(&it->second.decoded)) return *p;
    return std::nullopt;
  }

  bool TryGetByteString(std::int64_t label, std::vector<std::uint8_t>& out) const {
    const auto it = values_.find(Label{label});
    if (it == values_.end()) return false;
    const auto p = std::get_if<std::vector<std::uint8_t>>(&it->second.decoded);
    if (!p) return false;
    out = *p;
    return true;
  }

  bool TryGetByteString(std::string_view label, std::vector<std::uint8_t>& out) const {
    const auto it = values_.find(Label{std::string(label)});
    if (it == values_.end()) return false;
    const auto p = std::get_if<std::vector<std::uint8_t>>(&it->second.decoded);
    if (!p) return false;
    out = *p;
    return true;
  }

  bool TryGetTextString(std::int64_t label, std::string& out) const {
    const auto it = values_.find(Label{label});
    if (it == values_.end()) return false;
    const auto p = std::get_if<std::string>(&it->second.decoded);
    if (!p) return false;
    out = *p;
    return true;
  }

  bool TryGetTextString(std::string_view label, std::string& out) const {
    const auto it = values_.find(Label{std::string(label)});
    if (it == values_.end()) return false;
    const auto p = std::get_if<std::string>(&it->second.decoded);
    if (!p) return false;
    out = *p;
    return true;
  }

  bool TryGetByteStringArray(std::int64_t label, std::vector<std::vector<std::uint8_t>>& out) const {
    const auto it = values_.find(Label{label});
    if (it == values_.end()) return false;
    const auto p = std::get_if<std::vector<std::vector<std::uint8_t>>>(&it->second.decoded);
    if (!p) return false;
    out = *p;
    return true;
  }

  bool TryGetByteStringArray(std::string_view label, std::vector<std::vector<std::uint8_t>>& out) const {
    const auto it = values_.find(Label{std::string(label)});
    if (it == values_.end()) return false;
    const auto p = std::get_if<std::vector<std::vector<std::uint8_t>>>(&it->second.decoded);
    if (!p) return false;
    out = *p;
    return true;
  }

  bool TryGetFirstByteStringFromArray(std::int64_t label, std::vector<std::uint8_t>& out) const {
    std::vector<std::vector<std::uint8_t>> arr;
    if (!TryGetByteStringArray(label, arr) || arr.empty()) return false;
    out = std::move(arr.front());
    return true;
  }

  bool TryGetFirstByteStringFromArray(std::string_view label, std::vector<std::uint8_t>& out) const {
    std::vector<std::vector<std::uint8_t>> arr;
    if (!TryGetByteStringArray(label, arr) || arr.empty()) return false;
    out = std::move(arr.front());
    return true;
  }

  template <typename T>
  void SetParsed(std::int64_t label, T value) {
    values_[Label{label}].parsed = std::move(value);
  }

  template <typename T>
  void SetParsed(std::string_view label, T value) {
    values_[Label{std::string(label)}].parsed = std::move(value);
  }

  template <typename T>
  T* TryGetParsed(std::int64_t label) {
    auto it = values_.find(Label{label});
    if (it == values_.end()) return nullptr;
    return std::any_cast<T>(&it->second.parsed);
  }

  template <typename T>
  T* TryGetParsed(std::string_view label) {
    auto it = values_.find(Label{std::string(label)});
    if (it == values_.end()) return nullptr;
    return std::any_cast<T>(&it->second.parsed);
  }

  template <typename T>
  const T* TryGetParsed(std::int64_t label) const {
    auto it = values_.find(Label{label});
    if (it == values_.end()) return nullptr;
    return std::any_cast<T>(&it->second.parsed);
  }

  template <typename T>
  const T* TryGetParsed(std::string_view label) const {
    auto it = values_.find(Label{std::string(label)});
    if (it == values_.end()) return nullptr;
    return std::any_cast<T>(&it->second.parsed);
  }

  // Attempts to return a validator-specific parsed object for a header entry.
  // If not present, calls the provided parser to create it from the raw CBOR value bytes
  // and caches the result in the header entry.
  //
  // The parser must return std::optional<T>. Returning std::nullopt leaves the cache empty.
  template <typename T, typename TParser>
  T* GetOrParseParsed(std::int64_t label, TParser&& parser) {
    Entry* entry = FindEntry(label);
    if (!entry) return nullptr;

    if (T* cached = std::any_cast<T>(&entry->parsed)) {
      return cached;
    }

    auto parsed = parser(entry->raw_value_cbor, entry->decoded);
    if (!parsed.has_value()) return nullptr;

    entry->parsed = std::move(*parsed);
    return std::any_cast<T>(&entry->parsed);
  }

  template <typename T, typename TParser>
  T* GetOrParseParsed(std::string_view label, TParser&& parser) {
    Entry* entry = FindEntry(label);
    if (!entry) return nullptr;

    if (T* cached = std::any_cast<T>(&entry->parsed)) {
      return cached;
    }

    auto parsed = parser(entry->raw_value_cbor, entry->decoded);
    if (!parsed.has_value()) return nullptr;

    entry->parsed = std::move(*parsed);
    return std::any_cast<T>(&entry->parsed);
  }

private:
  friend bool ParseCoseHeaderMap(CborValue map_value, CoseHeaderMap& out, std::string* out_error);
  friend bool ParseProtectedHeaderBytes(const std::vector<std::uint8_t>& protected_headers_bstr, CoseHeaderMap& out, std::string* out_error);

  Entry* FindEntry(std::int64_t label) {
    const auto it = values_.find(Label{label});
    if (it == values_.end()) return nullptr;
    return &it->second;
  }

  Entry* FindEntry(std::string_view label) {
    const auto it = values_.find(Label{std::string(label)});
    if (it == values_.end()) return nullptr;
    return &it->second;
  }

  struct LabelHash {
    std::size_t operator()(const Label& l) const noexcept {
      if (const auto p = std::get_if<std::int64_t>(&l)) {
        return std::hash<std::int64_t>{}(*p);
      }
      return std::hash<std::string>{}(std::get<std::string>(l));
    }
  };

  struct LabelEq {
    bool operator()(const Label& a, const Label& b) const noexcept {
      if (a.index() != b.index()) return false;
      if (const auto pa = std::get_if<std::int64_t>(&a)) {
        return *pa == std::get<std::int64_t>(b);
      }
      return std::get<std::string>(a) == std::get<std::string>(b);
    }
  };

  std::vector<std::uint8_t> encoded_map_cbor_;
  std::unordered_map<Label, Entry, LabelHash, LabelEq> values_;
};

inline bool ParseCoseHeaderMap(CborValue map_value, CoseHeaderMap& out, std::string* out_error = nullptr) {
  if (out_error) out_error->clear();
  out.Clear();

  if (!cbor_value_is_map(&map_value)) {
    return Fail(out_error, "headers are not a map");
  }

  // Keep a copy of the original map value so we can capture the exact raw CBOR bytes for
  // successfully-parsed maps. For malformed CBOR, capturing raw bytes may fail; in those cases
  // we prefer returning a more specific parse error from the loop below.
  const CborValue map_for_bytes = map_value;

  CborValue it;
  if (cbor_value_enter_container(&map_value, &it) != CborNoError) {
    return Fail(out_error, "failed to enter map");
  }

  while (!cbor_value_at_end(&it)) {
    // COSE labels can be integer or tstr. Skip other key types defensively.
    CoseHeaderMap::Label label;
    if (cbor_value_is_integer(&it)) {
      std::int64_t int_label = 0;
      if (cbor_value_get_int64(&it, &int_label) != CborNoError) {
        return Fail(out_error, "failed to read integer header label");
      }
      if (cbor_value_advance_fixed(&it) != CborNoError) {
        return Fail(out_error, "failed to advance past integer header label");
      }
      label = int_label;
    } else if (cbor_value_is_text_string(&it)) {
      std::string text_label;
      if (!ReadTextString(&it, text_label)) {
        return Fail(out_error, "failed to read text header label");
      }
      label = std::move(text_label);
    } else {
      if (!SkipAny(&it)) {
        return Fail(out_error, "failed to skip unsupported key type");
      }
      if (!SkipAny(&it)) {
        return Fail(out_error, "failed to skip value for unsupported key");
      }
      continue;
    }

    CoseHeaderMap::Entry entry;
    (void)CopyRawCborItemBytes(it, entry.raw_value_cbor);

    // Decode only common shapes; store unknown as monostate (but keep presence).
    if (cbor_value_is_integer(&it)) {
      std::int64_t v = 0;
      if (cbor_value_get_int64(&it, &v) != CborNoError) {
        return Fail(out_error, "failed to read integer header value");
      }
      if (cbor_value_advance_fixed(&it) != CborNoError) {
        return Fail(out_error, "failed to advance past integer header value");
      }
      entry.decoded = v;
      out.values_[std::move(label)] = std::move(entry);
      continue;
    }

    if (cbor_value_is_byte_string(&it)) {
      std::vector<std::uint8_t> bytes;
      if (!ReadByteString(&it, bytes)) {
        return Fail(out_error, "failed to read bstr header value");
      }
      entry.decoded = std::move(bytes);
      out.values_[std::move(label)] = std::move(entry);
      continue;
    }

    if (cbor_value_is_text_string(&it)) {
      std::string text;
      if (!ReadTextString(&it, text)) {
        return Fail(out_error, "failed to read tstr header value");
      }
      entry.decoded = std::move(text);
      out.values_[std::move(label)] = std::move(entry);
      continue;
    }

    if (cbor_value_is_array(&it)) {
      // Special-case array of bstr (e.g., x5c). If it isn't an array-of-bstr,
      // treat as unknown but still keep raw_value_cbor.

      // Probe without mutating the main iterator.
      bool all_bstr = true;
      {
        CborValue probe = it;
        CborValue probe_arr;
        if (cbor_value_enter_container(&probe, &probe_arr) != CborNoError) {
          return Fail(out_error, "failed to enter array header value");
        }

        while (!cbor_value_at_end(&probe_arr)) {
          if (!cbor_value_is_byte_string(&probe_arr)) {
            all_bstr = false;
            break;
          }
          if (cbor_value_advance(&probe_arr) != CborNoError) {
            return Fail(out_error, "failed to probe array header value");
          }
        }

        // Best-effort clean leave to avoid TinyCBOR assertions in debug builds.
        if (!cbor_value_at_end(&probe_arr)) {
          while (!cbor_value_at_end(&probe_arr)) {
            if (cbor_value_advance(&probe_arr) != CborNoError) {
              break;
            }
          }
        }
        (void)cbor_value_leave_container(&probe, &probe_arr);
      }

      if (!all_bstr) {
        if (!SkipAny(&it)) {
          return Fail(out_error, "failed to skip non-bstr array header value");
        }
        entry.decoded = std::monostate{};
        out.values_[std::move(label)] = std::move(entry);
        continue;
      }

      size_t array_len = 0;
      // TinyCBOR reports unknown length for indefinite arrays; those are valid CBOR but we
      // can't efficiently pre-size, and some callers prefer to re-parse the raw value bytes.
      // Treat such arrays as "unknown" while preserving raw_value_cbor so validators can fall
      // back to parsing the raw CBOR value bytes.
      if (cbor_value_get_array_length(&it, &array_len) != CborNoError) {
        if (!SkipAny(&it)) {
          return Fail(out_error, "failed to skip unknown-length array header value");
        }
        entry.decoded = std::monostate{};
        out.values_[std::move(label)] = std::move(entry);
        continue;
      }

      CborValue arr;
      if (cbor_value_enter_container(&it, &arr) != CborNoError) {
        return Fail(out_error, "failed to enter array header value");
      }

      std::vector<std::vector<std::uint8_t>> elements;
      elements.reserve(array_len);
      while (!cbor_value_at_end(&arr)) {
        std::vector<std::uint8_t> b;
        if (!ReadByteString(&arr, b)) {
          return Fail(out_error, "failed to read bstr array element");
        }
        elements.push_back(std::move(b));
      }

      if (cbor_value_leave_container(&it, &arr) != CborNoError) {
        return Fail(out_error, "failed to leave array header value");
      }

      entry.decoded = std::move(elements);
      out.values_[std::move(label)] = std::move(entry);
      continue;
    }

    // Unknown value shape; skip it.
    if (!SkipAny(&it)) {
      return Fail(out_error, "failed to skip unknown header value");
    }
    entry.decoded = std::monostate{};
    out.values_[std::move(label)] = std::move(entry);
  }

  const bool leave_ok = cbor_value_leave_container(&map_value, &it) == CborNoError;

  // Capture raw map bytes for callers that need to re-parse or preserve exact encoding.
  const bool bytes_ok = CopyRawCborItemBytes(map_for_bytes, out.encoded_map_cbor_);

  return leave_ok && bytes_ok;
}

inline bool ParseProtectedHeaderBytes(const std::vector<std::uint8_t>& protected_headers_bstr,
                                      CoseHeaderMap& out,
                                      std::string* out_error = nullptr) {
  if (out_error) out_error->clear();
  out.Clear();

  // Preserve exact bytes that were inside the protected bstr (may be empty).
  out.encoded_map_cbor_ = protected_headers_bstr;

  // COSE allows empty bstr to represent an empty protected header map.
  if (protected_headers_bstr.empty()) {
    return true;
  }

  CborParser parser;
  CborValue it;
  if (cbor_parser_init(protected_headers_bstr.data(), protected_headers_bstr.size(), 0, &parser, &it) != CborNoError) {
    return Fail(out_error, "failed to parse protected headers bytes as CBOR");
  }

  if (!cbor_value_is_map(&it)) {
    return Fail(out_error, "protected headers bytes are not a CBOR map");
  }

  return ParseCoseHeaderMap(it, out, out_error);
}

} // namespace cosesign1::common::cbor
