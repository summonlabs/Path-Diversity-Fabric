// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <string>

#include "path_diversity/export.hpp"

namespace path_diversity {

// Deterministic 128-bit content digest (FNV-1a over the canonical byte stream).
//
// This is a *determinism* device, not a cryptographic primitive: it detects
// accidental corruption and makes identity independent of process, build,
// thread and arrival order. It provides no collision resistance against a
// motivated adversary and no authentication whatsoever. Wire and persistence
// integrity use the same scheme and carry the same honest limitation.
class PATH_DIVERSITY_API Digest {
 public:
  using bytes_type = std::array<std::uint8_t, 16>;

  constexpr Digest() noexcept = default;
  explicit constexpr Digest(bytes_type bytes) noexcept : bytes_(bytes) {}

  static Digest of(const void* data, std::size_t size) noexcept;

  const Digest& update(const void* data, std::size_t size) noexcept;
  const Digest& update_u8(std::uint8_t value) noexcept;
  const Digest& update_u16(std::uint16_t value) noexcept;
  const Digest& update_u32(std::uint32_t value) noexcept;
  const Digest& update_u64(std::uint64_t value) noexcept;
  const Digest& update_varint(std::uint64_t value) noexcept;
  // Length-prefixed byte string: distinct from the same bytes with a different
  // length and from the concatenation of two shorter strings.
  const Digest& update_bytes(const void* data, std::size_t size) noexcept;
  const Digest& update_text(std::string_view text) noexcept;

  const bytes_type& bytes() const noexcept { return bytes_; }
  std::string hex() const;
  std::uint64_t low64() const noexcept;

  friend bool operator==(const Digest&, const Digest&) noexcept = default;
  friend std::strong_ordering operator<=>(const Digest& lhs, const Digest& rhs) noexcept {
    return lhs.bytes_ <=> rhs.bytes_;
  }

 private:
  bytes_type bytes_{};
};

struct DigestHash {
  std::size_t operator()(const Digest& digest) const noexcept {
    std::uint64_t folded = 0;
    for (std::uint8_t byte : digest.bytes()) {
      folded = (folded << 8) ^ byte;
    }
    return static_cast<std::size_t>(folded ^ digest.low64());
  }
};

// A deterministic content-minting counter. Used for artifact identities derived
// from canonical content ("pset-<hex>", "proof-<hex>", "snap-<hex>").
PATH_DIVERSITY_API std::string mint_prefixed(const char* prefix, const Digest& digest);

}  // namespace path_diversity
