// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include "path_diversity/canonical.hpp"

#include <cstring>

#include "path_diversity/digest.hpp"
#include "path_diversity/strong_id.hpp"
#include "path_diversity/version.hpp"

namespace path_diversity {

namespace detail {

bool valid_identity_text(std::string_view text, std::size_t max_len) noexcept {
  if (text.empty() || text.size() > max_len) {
    return false;
  }
  for (std::size_t i = 0; i < text.size(); ++i) {
    const char c = text[i];
    const unsigned char raw = static_cast<unsigned char>(c);
    const bool alphanumeric = (raw >= 'a' && raw <= 'z') || (raw >= 'A' && raw <= 'Z') ||
                              (raw >= '0' && raw <= '9');
    const bool separator = c == '.' || c == '_' || c == '-' || c == ':' || c == '/' || c == '#' ||
                           c == '@' || c == '+';
    if (!alphanumeric && !separator) {
      return false;
    }
  }
  return true;
}

}  // namespace detail

// ---------------------------------------------------------------------------
// Version surface
// ---------------------------------------------------------------------------
std::string_view library_name() noexcept { return "Path Diversity Fabric"; }

std::string_view version_string() noexcept { return "1.0.0"; }

std::string version_report() {
  std::string report;
  report += library_name();
  report += " ";
  report += version_string();
  report += " (persistence ";
  report += std::to_string(kPersistenceFormatVersion);
  report += ", canonical ";
  report += std::to_string(kCanonicalEncodingVersion);
  report += ", digest ";
  report += std::to_string(kDigestSchemeVersion);
  report += ", wire ";
  report += std::to_string(kWireProtocolVersion);
  report += ", rule set ";
  report += std::to_string(kDiversityRuleSetVersion);
  report += ")";
  return report;
}

// ---------------------------------------------------------------------------
// Digest: FNV-1a over the canonical byte stream, 128-bit state.
//
// The multiplication is a schoolbook 4x32-bit accumulate that keeps the low 128
// bits, so the result is bit-identical on every compiler and architecture.
// ---------------------------------------------------------------------------
namespace {

constexpr std::uint32_t kOffsetBasis[4] = {0x6295c58dU, 0x62b82175U, 0x07bb0142U, 0x6c62272eU};
constexpr std::uint32_t kPrime[4] = {0x0000013bU, 0x00000000U, 0x00000001U, 0x00000000U};

inline void fnv_multiply(std::uint32_t state[4]) noexcept {
  std::uint32_t out[4] = {0U, 0U, 0U, 0U};
  for (int i = 0; i < 4; ++i) {
    std::uint64_t carry = 0;
    for (int j = 0; i + j < 4; ++j) {
      const std::uint64_t current = static_cast<std::uint64_t>(out[i + j]) +
                                    static_cast<std::uint64_t>(state[j]) *
                                        static_cast<std::uint64_t>(kPrime[i]) +
                                    carry;
      out[i + j] = static_cast<std::uint32_t>(current & 0xffffffffULL);
      carry = current >> 32;
    }
  }
  for (int i = 0; i < 4; ++i) {
    state[i] = out[i];
  }
}

inline void fnv_update(std::uint32_t state[4], const void* data, std::size_t size) noexcept {
  const unsigned char* bytes = static_cast<const unsigned char*>(data);
  for (std::size_t i = 0; i < size; ++i) {
    state[0] ^= static_cast<std::uint32_t>(bytes[i]);
    fnv_multiply(state);
  }
}

inline void fnv_finalize(std::uint32_t state[4], Digest::bytes_type& out) noexcept {
  for (int i = 0; i < 4; ++i) {
    out[static_cast<std::size_t>(i) * 4 + 0] = static_cast<std::uint8_t>(state[i] & 0xffU);
    out[static_cast<std::size_t>(i) * 4 + 1] = static_cast<std::uint8_t>((state[i] >> 8) & 0xffU);
    out[static_cast<std::size_t>(i) * 4 + 2] = static_cast<std::uint8_t>((state[i] >> 16) & 0xffU);
    out[static_cast<std::size_t>(i) * 4 + 3] = static_cast<std::uint8_t>((state[i] >> 24) & 0xffU);
  }
}

}  // namespace

Digest Digest::of(const void* data, std::size_t size) noexcept {
  std::uint32_t state[4] = {kOffsetBasis[0], kOffsetBasis[1], kOffsetBasis[2], kOffsetBasis[3]};
  fnv_update(state, data, size);
  Digest digest;
  fnv_finalize(state, digest.bytes_);
  return digest;
}

const Digest& Digest::update(const void* data, std::size_t size) noexcept {
  // The 128-bit state is rebuilt from the current value, mutated, and written
  // back, so Digest stays a small trivially-copyable value type with no hidden
  // allocation.
  std::uint32_t state[4] = {0U, 0U, 0U, 0U};
  state[0] = static_cast<std::uint32_t>(bytes_[0]) | (static_cast<std::uint32_t>(bytes_[1]) << 8) |
             (static_cast<std::uint32_t>(bytes_[2]) << 16) |
             (static_cast<std::uint32_t>(bytes_[3]) << 24);
  state[1] = static_cast<std::uint32_t>(bytes_[4]) | (static_cast<std::uint32_t>(bytes_[5]) << 8) |
             (static_cast<std::uint32_t>(bytes_[6]) << 16) |
             (static_cast<std::uint32_t>(bytes_[7]) << 24);
  state[2] = static_cast<std::uint32_t>(bytes_[8]) | (static_cast<std::uint32_t>(bytes_[9]) << 8) |
             (static_cast<std::uint32_t>(bytes_[10]) << 16) |
             (static_cast<std::uint32_t>(bytes_[11]) << 24);
  state[3] = static_cast<std::uint32_t>(bytes_[12]) |
             (static_cast<std::uint32_t>(bytes_[13]) << 8) |
             (static_cast<std::uint32_t>(bytes_[14]) << 16) |
             (static_cast<std::uint32_t>(bytes_[15]) << 24);
  fnv_update(state, data, size);
  fnv_finalize(state, bytes_);
  return *this;
}

const Digest& Digest::update_u8(std::uint8_t value) noexcept { return update(&value, 1); }

const Digest& Digest::update_u16(std::uint16_t value) noexcept {
  const std::uint8_t bytes[2] = {static_cast<std::uint8_t>(value & 0xffU),
                                 static_cast<std::uint8_t>((value >> 8) & 0xffU)};
  return update(bytes, 2);
}

const Digest& Digest::update_u32(std::uint32_t value) noexcept {
  std::uint8_t bytes[4];
  for (int i = 0; i < 4; ++i) {
    bytes[i] = static_cast<std::uint8_t>((value >> (8 * i)) & 0xffU);
  }
  return update(bytes, 4);
}

const Digest& Digest::update_u64(std::uint64_t value) noexcept {
  std::uint8_t bytes[8];
  for (int i = 0; i < 8; ++i) {
    bytes[i] = static_cast<std::uint8_t>((value >> (8 * i)) & 0xffU);
  }
  return update(bytes, 8);
}

const Digest& Digest::update_varint(std::uint64_t value) noexcept {
  std::uint8_t bytes[10];
  std::size_t count = 0;
  std::uint64_t remaining = value;
  do {
    std::uint8_t byte = static_cast<std::uint8_t>(remaining & 0x7fU);
    remaining >>= 7;
    if (remaining != 0) {
      byte = static_cast<std::uint8_t>(byte | 0x80U);
    }
    bytes[count] = byte;
    ++count;
  } while (remaining != 0);
  return update(bytes, count);
}

const Digest& Digest::update_bytes(const void* data, std::size_t size) noexcept {
  update_varint(static_cast<std::uint64_t>(size));
  if (size != 0) {
    update(data, size);
  }
  return *this;
}

const Digest& Digest::update_text(std::string_view text) noexcept {
  return update_bytes(text.data(), text.size());
}

std::string Digest::hex() const {
  static const char* kDigits = "0123456789abcdef";
  std::string out;
  out.reserve(32);
  for (std::uint8_t byte : bytes_) {
    out.push_back(kDigits[(byte >> 4) & 0x0fU]);
    out.push_back(kDigits[byte & 0x0fU]);
  }
  return out;
}

std::uint64_t Digest::low64() const noexcept {
  std::uint64_t value = 0;
  for (int i = 0; i < 8; ++i) {
    value |= static_cast<std::uint64_t>(bytes_[static_cast<std::size_t>(i)]) << (8 * i);
  }
  return value;
}

std::string mint_prefixed(const char* prefix, const Digest& digest) {
  std::string out(prefix);
  out += digest.hex();
  return out;
}

std::uint64_t fnv1a64(const void* data, std::size_t size) noexcept {
  const unsigned char* bytes = static_cast<const unsigned char*>(data);
  std::uint64_t hash = 14695981039346656037ULL;
  for (std::size_t i = 0; i < size; ++i) {
    hash ^= static_cast<std::uint64_t>(bytes[i]);
    hash *= 1099511628211ULL;
  }
  return hash;
}

}  // namespace path_diversity
