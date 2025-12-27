#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "abstractions.h"

namespace cosesign1 {

struct Failure {
    std::string message;
    std::string error_code;
};

using MetadataMap = std::unordered_map<std::string, std::string>;

inline std::string string_or_empty(const char* s) {
    return s ? std::string(s) : std::string();
}

template <typename Handle, void (*FreeFn)(Handle*)>
class UniqueHandle {
public:
    UniqueHandle() noexcept = default;
    explicit UniqueHandle(Handle* p) noexcept : p_(p) {}
    ~UniqueHandle() { reset(); }

    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;

    UniqueHandle(UniqueHandle&& other) noexcept : p_(other.p_) { other.p_ = nullptr; }
    UniqueHandle& operator=(UniqueHandle&& other) noexcept {
        if (this != &other) {
            reset();
            p_ = other.p_;
            other.p_ = nullptr;
        }
        return *this;
    }

    Handle* get() const noexcept { return p_; }
    explicit operator bool() const noexcept { return p_ != nullptr; }

    Handle* release() noexcept {
        Handle* tmp = p_;
        p_ = nullptr;
        return tmp;
    }

    void reset(Handle* p = nullptr) noexcept {
        if (p_) {
            FreeFn(p_);
        }
        p_ = p;
    }

private:
    Handle* p_ = nullptr;
};

template <
    typename Handle,
    void (*FreeFn)(Handle*),
    bool (*IsValidFn)(const Handle*),
    const char* (*ValidatorNameFn)(const Handle*),
    size_t (*FailureCountFn)(const Handle*),
    cosesign1_failure_view (*FailureAtFn)(const Handle*, size_t),
    size_t (*MetadataCountFn)(const Handle*),
    cosesign1_kv_view (*MetadataAtFn)(const Handle*, size_t)>
class Result : private UniqueHandle<Handle, FreeFn> {
public:
    using UniqueHandle<Handle, FreeFn>::UniqueHandle;
    using UniqueHandle<Handle, FreeFn>::get;
    using UniqueHandle<Handle, FreeFn>::operator bool;
    using UniqueHandle<Handle, FreeFn>::release;
    using UniqueHandle<Handle, FreeFn>::reset;

    bool ok() const noexcept {
        const auto* p = this->get();
        return p && IsValidFn(p);
    }

    std::string validator_name() const {
        const auto* p = this->get();
        return string_or_empty(p ? ValidatorNameFn(p) : nullptr);
    }

    std::vector<Failure> failures() const {
        std::vector<Failure> out;
        const auto* p = this->get();
        if (!p) return out;
        const size_t n = FailureCountFn(p);
        out.reserve(n);
        for (size_t i = 0; i < n; ++i) {
            const auto f = FailureAtFn(p, i);
            out.push_back(Failure{ string_or_empty(f.message), string_or_empty(f.error_code) });
        }
        return out;
    }

    MetadataMap metadata() const {
        MetadataMap out;
        const auto* p = this->get();
        if (!p) return out;
        const size_t n = MetadataCountFn(p);
        for (size_t i = 0; i < n; ++i) {
            const auto kv = MetadataAtFn(p, i);
            if (kv.key && kv.value) {
                out.emplace(std::string(kv.key), std::string(kv.value));
            }
        }
        return out;
    }
};

class AbstractionsResult : public Result<
                             cosesign1_abstractions_result,
                             cosesign1_abstractions_result_free,
                             cosesign1_abstractions_result_is_valid,
                             cosesign1_abstractions_result_validator_name,
                             cosesign1_abstractions_result_failure_count,
                             cosesign1_abstractions_result_failure_at,
                             cosesign1_abstractions_result_metadata_count,
                             cosesign1_abstractions_result_metadata_at> {
public:
    using Result::Result;
};

inline bool is_detached_payload(const std::vector<std::uint8_t>& cose) {
    cosesign1_abstractions_info info{};
    auto res = AbstractionsResult(cosesign1_abstractions_inspect(cose.data(), cose.size(), &info));
    if (!res.ok()) {
        // If inspection fails, treat as "unknown" and let verification return the parse error.
        return false;
    }
    return info.is_detached;
}

} // namespace cosesign1
