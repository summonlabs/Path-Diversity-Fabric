// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <ostream>
#include <stdexcept>
#include <string>
#include <string_view>

#include "path_diversity/export.hpp"

namespace path_diversity {

// Thrown when an identity, generation or enum encoding is malformed. Every
// identity is untrusted input on a decode path: persistence files, wire frames
// and caller supplied requests all arrive here.
class PATH_DIVERSITY_API IdentityError : public std::invalid_argument {
 public:
  explicit IdentityError(const std::string& what) : std::invalid_argument(what) {}
};

namespace detail {
PATH_DIVERSITY_API bool valid_identity_text(std::string_view text, std::size_t max_len) noexcept;
}  // namespace detail

// Strongly typed, bounded, self-validating text identity. Distinct Tag types
// are distinct C++ types and never convert into one another, so a PathId can
// never be passed where a FailureDomainId is expected.
template <class Tag, std::size_t MaxLen>
class StringId {
 public:
  using tag_type = Tag;
  static constexpr std::size_t max_length = MaxLen;

  constexpr StringId() noexcept = default;

  static std::optional<StringId> try_parse(std::string_view text) noexcept {
    if (!detail::valid_identity_text(text, MaxLen)) {
      return std::nullopt;
    }
    StringId id;
    id.length_ = static_cast<std::uint16_t>(text.size());
    for (std::size_t i = 0; i < text.size(); ++i) {
      id.buffer_[i] = text[i];
    }
    return id;
  }

  static StringId parse(std::string_view text) {
    auto parsed = try_parse(text);
    if (!parsed.has_value()) {
      throw IdentityError("malformed " + std::string(Tag::name()) + " encoding");
    }
    return *parsed;
  }

  // Decode helper used by persistence and the wire codec: a malformed encoding
  // is rejected rather than silently defaulted.
  static std::optional<StringId> from_wire(std::string_view text) noexcept { return try_parse(text); }

  bool valid() const noexcept { return length_ != 0; }
  explicit operator bool() const noexcept { return valid(); }

  std::string_view view() const noexcept { return std::string_view(buffer_.data(), length_); }
  std::string str() const { return std::string(view()); }

  static constexpr std::string_view type_name() noexcept { return Tag::name(); }

  friend bool operator==(const StringId& lhs, const StringId& rhs) noexcept {
    return lhs.view() == rhs.view();
  }
  friend std::strong_ordering operator<=>(const StringId& lhs, const StringId& rhs) noexcept {
    return lhs.view() <=> rhs.view();
  }

  std::size_t hash() const noexcept {
    std::size_t h = 1469598103934665603ULL;
    for (char c : view()) {
      h ^= static_cast<unsigned char>(c);
      h *= 1099511628211ULL;
    }
    return h;
  }

  friend std::ostream& operator<<(std::ostream& os, const StringId& id) { return os << id.view(); }

 private:
  std::array<char, MaxLen> buffer_{};
  std::uint16_t length_ = 0;
};

template <class Tag, std::size_t MaxLen>
struct StringIdHash {
  std::size_t operator()(const StringId<Tag, MaxLen>& id) const noexcept { return id.hash(); }
};

// Strongly typed monotonic generation counter. Value 0 means "unset" and is
// never a legal wire or persistence encoding for a required generation.
template <class Tag>
class Generation {
 public:
  using tag_type = Tag;
  using value_type = std::uint64_t;

  constexpr Generation() noexcept = default;
  static constexpr Generation from_value(std::uint64_t value) noexcept { return Generation(value); }

  static std::optional<Generation> from_wire(std::uint64_t value) noexcept {
    if (value == 0) {
      return std::nullopt;
    }
    return Generation(value);
  }

  constexpr std::uint64_t value() const noexcept { return value_; }
  constexpr bool is_set() const noexcept { return value_ != 0; }
  constexpr explicit operator bool() const noexcept { return is_set(); }

  // Callers must check can_advance() first; generation overflow is a defect and
  // is never allowed to wrap.
  constexpr Generation next() const noexcept { return Generation(value_ + 1); }
  static constexpr bool can_advance(std::uint64_t value) noexcept {
    return value != static_cast<std::uint64_t>(-1);
  }

  static constexpr std::string_view type_name() noexcept { return Tag::name(); }

  friend constexpr bool operator==(const Generation&, const Generation&) noexcept = default;
  friend constexpr std::strong_ordering operator<=>(const Generation& lhs,
                                                    const Generation& rhs) noexcept {
    return lhs.value_ <=> rhs.value_;
  }

  friend std::ostream& operator<<(std::ostream& os, const Generation& generation) {
    return os << generation.value_;
  }

 private:
  constexpr explicit Generation(std::uint64_t value) noexcept : value_(value) {}
  std::uint64_t value_ = 0;
};

template <class Tag>
struct GenerationHash {
  std::size_t operator()(const Generation<Tag>& generation) const noexcept {
    return std::hash<std::uint64_t>{}(generation.value());
  }
};

}  // namespace path_diversity
