// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "path_diversity/digest.hpp"
#include "path_diversity/export.hpp"

namespace path_diversity {

// Versioned, self-delimiting canonical byte encoding.
//
// Rules, all of which are relied on by proof identity:
//   * little-endian fixed-width integers;
//   * LEB128 varints for counts and lengths;
//   * every length-prefixed byte string is bounded by the caller's limit;
//   * no padding, no alignment, no raw struct copy;
//   * a decoder that does not consume the whole input rejects "trailing bytes".
class PATH_DIVERSITY_API ByteWriter {
 public:
  void u8(std::uint8_t value);
  void u16(std::uint16_t value);
  void u32(std::uint32_t value);
  void u64(std::uint64_t value);
  void varint(std::uint64_t value);
  void bytes(const void* data, std::size_t size);
  void text(std::string_view text);
  void boolean(bool value);

  const std::vector<std::uint8_t>& data() const noexcept { return data_; }
  std::size_t size() const noexcept { return data_.size(); }
  void reserve(std::size_t bytes);
  std::vector<std::uint8_t> take();

 private:
  std::vector<std::uint8_t> data_;
};

// Failure modes are distinct: a caller must be able to tell "the input ended"
// from "the input lied about a length" from "there was extra data".
enum class DecodeStatus : std::uint8_t {
  OK = 0,
  TRUNCATED = 1,
  LENGTH_OVERRUN = 2,
  TRAILING_BYTES = 3,
  INVALID_ENCODING = 4,
  LIMIT_EXCEEDED = 5,
};

PATH_DIVERSITY_API std::string_view to_string(DecodeStatus status) noexcept;

class PATH_DIVERSITY_API ByteReader {
 public:
  ByteReader(const std::uint8_t* data, std::size_t size) noexcept : data_(data), size_(size) {}

  bool u8(std::uint8_t& out);
  bool u16(std::uint16_t& out);
  bool u32(std::uint32_t& out);
  bool u64(std::uint64_t& out);
  bool varint(std::uint64_t& out);
  // Length-prefixed byte string bounded by max_size.
  bool bytes(std::string& out, std::size_t max_size);
  bool text(std::string& out, std::size_t max_size);
  bool boolean(bool& out);

  bool at_end() const noexcept { return offset_ == size_; }
  std::size_t remaining() const noexcept { return size_ - offset_; }
  std::size_t offset() const noexcept { return offset_; }
  DecodeStatus status() const noexcept { return status_; }
  void fail(DecodeStatus status) noexcept;

 private:
  const std::uint8_t* data_ = nullptr;
  std::size_t size_ = 0;
  std::size_t offset_ = 0;
  DecodeStatus status_ = DecodeStatus::OK;
};

// Canonical ascending unique ordering of strongly typed identities. Inputs that
// arrive in a different order canonicalize to the same value; duplicates are
// rejected by the caller when duplicates are meaningful and removed when they
// are not.
template <class Id>
void canonical_sort_unique(std::vector<Id>& values) {
  for (std::size_t i = 0; i < values.size(); ++i) {
    for (std::size_t j = i + 1; j < values.size(); ++j) {
      if (values[j] < values[i]) {
        Id temporary = values[i];
        values[i] = values[j];
        values[j] = temporary;
      }
    }
  }
  std::size_t write = 0;
  for (std::size_t read = 0; read < values.size(); ++read) {
    if (write == 0 || !(values[read] == values[write - 1])) {
      values[write] = values[read];
      ++write;
    }
  }
  values.resize(write);
}

template <class Id>
bool has_duplicates(const std::vector<Id>& values) {
  for (std::size_t i = 0; i < values.size(); ++i) {
    for (std::size_t j = i + 1; j < values.size(); ++j) {
      if (values[i] == values[j]) {
        return true;
      }
    }
  }
  return false;
}

// Deterministic FNV-1a 64-bit over a byte range. Used for integrity trailers
// and frame digests where a full Digest is unnecessary.
PATH_DIVERSITY_API std::uint64_t fnv1a64(const void* data, std::size_t size) noexcept;

}  // namespace path_diversity
