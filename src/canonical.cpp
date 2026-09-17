// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include "path_diversity/canonical.hpp"

#include <cstring>
#include <limits>

namespace path_diversity {

void ByteWriter::reserve(std::size_t bytes) { data_.reserve(bytes); }

void ByteWriter::u8(std::uint8_t value) { data_.push_back(value); }

void ByteWriter::u16(std::uint16_t value) {
  data_.push_back(static_cast<std::uint8_t>(value & 0xffU));
  data_.push_back(static_cast<std::uint8_t>((value >> 8) & 0xffU));
}

void ByteWriter::u32(std::uint32_t value) {
  for (int i = 0; i < 4; ++i) {
    data_.push_back(static_cast<std::uint8_t>((value >> (8 * i)) & 0xffU));
  }
}

void ByteWriter::u64(std::uint64_t value) {
  for (int i = 0; i < 8; ++i) {
    data_.push_back(static_cast<std::uint8_t>((value >> (8 * i)) & 0xffU));
  }
}

void ByteWriter::varint(std::uint64_t value) {
  std::uint64_t remaining = value;
  do {
    std::uint8_t byte = static_cast<std::uint8_t>(remaining & 0x7fU);
    remaining >>= 7;
    if (remaining != 0) {
      byte = static_cast<std::uint8_t>(byte | 0x80U);
    }
    data_.push_back(byte);
  } while (remaining != 0);
}

void ByteWriter::bytes(const void* data, std::size_t size) {
  varint(static_cast<std::uint64_t>(size));
  if (size != 0) {
    const std::uint8_t* source = static_cast<const std::uint8_t*>(data);
    data_.insert(data_.end(), source, source + size);
  }
}

void ByteWriter::text(std::string_view text_value) {
  bytes(text_value.data(), text_value.size());
}

void ByteWriter::boolean(bool value) { u8(value ? 1U : 0U); }

std::vector<std::uint8_t> ByteWriter::take() { return std::move(data_); }

std::string_view to_string(DecodeStatus status) noexcept {
  switch (status) {
    case DecodeStatus::OK:
      return "OK";
    case DecodeStatus::TRUNCATED:
      return "TRUNCATED";
    case DecodeStatus::LENGTH_OVERRUN:
      return "LENGTH_OVERRUN";
    case DecodeStatus::TRAILING_BYTES:
      return "TRAILING_BYTES";
    case DecodeStatus::INVALID_ENCODING:
      return "INVALID_ENCODING";
    case DecodeStatus::LIMIT_EXCEEDED:
      return "LIMIT_EXCEEDED";
  }
  return "UNKNOWN";
}

void ByteReader::fail(DecodeStatus status) noexcept {
  if (status_ == DecodeStatus::OK) {
    status_ = status;
  }
}

bool ByteReader::u8(std::uint8_t& out) {
  if (status_ != DecodeStatus::OK) {
    return false;
  }
  if (remaining() < 1) {
    fail(DecodeStatus::TRUNCATED);
    return false;
  }
  out = data_[offset_];
  ++offset_;
  return true;
}

bool ByteReader::u16(std::uint16_t& out) {
  if (status_ != DecodeStatus::OK) {
    return false;
  }
  if (remaining() < 2) {
    fail(DecodeStatus::TRUNCATED);
    return false;
  }
  out = static_cast<std::uint16_t>(static_cast<std::uint16_t>(data_[offset_]) |
                                   static_cast<std::uint16_t>(
                                       static_cast<std::uint16_t>(data_[offset_ + 1]) << 8));
  offset_ += 2;
  return true;
}

bool ByteReader::u32(std::uint32_t& out) {
  if (status_ != DecodeStatus::OK) {
    return false;
  }
  if (remaining() < 4) {
    fail(DecodeStatus::TRUNCATED);
    return false;
  }
  std::uint32_t value = 0;
  for (int i = 0; i < 4; ++i) {
    value |= static_cast<std::uint32_t>(data_[offset_ + static_cast<std::size_t>(i)])
             << (8 * i);
  }
  offset_ += 4;
  out = value;
  return true;
}

bool ByteReader::u64(std::uint64_t& out) {
  if (status_ != DecodeStatus::OK) {
    return false;
  }
  if (remaining() < 8) {
    fail(DecodeStatus::TRUNCATED);
    return false;
  }
  std::uint64_t value = 0;
  for (int i = 0; i < 8; ++i) {
    value |= static_cast<std::uint64_t>(data_[offset_ + static_cast<std::size_t>(i)])
             << (8 * i);
  }
  offset_ += 8;
  out = value;
  return true;
}

bool ByteReader::varint(std::uint64_t& out) {
  if (status_ != DecodeStatus::OK) {
    return false;
  }
  std::uint64_t value = 0;
  int shift = 0;
  while (true) {
    if (remaining() < 1) {
      fail(DecodeStatus::TRUNCATED);
      return false;
    }
    const std::uint8_t byte = data_[offset_];
    ++offset_;
    if (shift > 63) {
      // Ten continuation bytes cannot encode a 64-bit value: the encoding is
      // malformed, not merely large.
      fail(DecodeStatus::INVALID_ENCODING);
      return false;
    }
    value |= static_cast<std::uint64_t>(byte & 0x7fU) << shift;
    if ((byte & 0x80U) == 0) {
      break;
    }
    shift += 7;
  }
  out = value;
  return true;
}

bool ByteReader::bytes(std::string& out, std::size_t max_size) {
  std::uint64_t length = 0;
  if (!varint(length)) {
    return false;
  }
  if (length > static_cast<std::uint64_t>(max_size)) {
    fail(DecodeStatus::LIMIT_EXCEEDED);
    return false;
  }
  if (static_cast<std::uint64_t>(remaining()) < length) {
    fail(DecodeStatus::LENGTH_OVERRUN);
    return false;
  }
  out.assign(reinterpret_cast<const char*>(data_ + offset_), static_cast<std::size_t>(length));
  offset_ += static_cast<std::size_t>(length);
  return true;
}

bool ByteReader::text(std::string& out, std::size_t max_size) { return bytes(out, max_size); }

bool ByteReader::boolean(bool& out) {
  std::uint8_t raw = 0;
  if (!u8(raw)) {
    return false;
  }
  if (raw > 1) {
    fail(DecodeStatus::INVALID_ENCODING);
    return false;
  }
  out = raw == 1;
  return true;
}

}  // namespace path_diversity
