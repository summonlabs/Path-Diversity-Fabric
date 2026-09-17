// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include "path_diversity/wire.hpp"

#include <algorithm>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#include "path_diversity/version.hpp"

namespace path_diversity {

std::string_view to_string(MessageId value) noexcept {
  switch (value) {
    case MessageId::HELLO:
      return "HELLO";
    case MessageId::HELLO_ACK:
      return "HELLO_ACK";
    case MessageId::PUBLISH_POLICY:
      return "PUBLISH_POLICY";
    case MessageId::PUBLISH_PROOF:
      return "PUBLISH_PROOF";
    case MessageId::REVALIDATE:
      return "REVALIDATE";
    case MessageId::QUERY:
      return "QUERY";
    case MessageId::QUERY_RESULT:
      return "QUERY_RESULT";
    case MessageId::SNAPSHOT:
      return "SNAPSHOT";
    case MessageId::DIFF:
      return "DIFF";
    case MessageId::EXPLAIN:
      return "EXPLAIN";
    case MessageId::FENCE:
      return "FENCE";
    case MessageId::CLOSE:
      return "CLOSE";
    case MessageId::ERROR_REPLY:
      return "ERROR";
    case MessageId::PING:
      return "PING";
    case MessageId::PONG:
      return "PONG";
  }
  return "UNKNOWN";
}

bool is_defined_message_id(std::uint16_t raw) noexcept {
  return raw >= static_cast<std::uint16_t>(MessageId::HELLO) &&
         raw <= static_cast<std::uint16_t>(MessageId::PONG);
}

// SNAPSHOT, DIFF and EXPLAIN are reserved identifiers. Reserve them means a peer
// must not send them in 1.0.0; the server answers ERROR rather than guessing.
bool is_reserved_message(std::uint16_t raw) noexcept {
  return raw == static_cast<std::uint16_t>(MessageId::SNAPSHOT) ||
         raw == static_cast<std::uint16_t>(MessageId::DIFF) ||
         raw == static_cast<std::uint16_t>(MessageId::EXPLAIN);
}

std::string_view to_string(WireStatus value) noexcept {
  switch (value) {
    case WireStatus::OK:
      return "OK";
    case WireStatus::INCOMPLETE:
      return "INCOMPLETE";
    case WireStatus::BAD_MAGIC:
      return "BAD_MAGIC";
    case WireStatus::UNSUPPORTED_VERSION:
      return "UNSUPPORTED_VERSION";
    case WireStatus::UNKNOWN_MESSAGE:
      return "UNKNOWN_MESSAGE";
    case WireStatus::FRAME_TOO_LARGE:
      return "FRAME_TOO_LARGE";
    case WireStatus::INTEGRITY_FAILURE:
      return "INTEGRITY_FAILURE";
    case WireStatus::MALFORMED_PAYLOAD:
      return "MALFORMED_PAYLOAD";
    case WireStatus::TRAILING_BYTES:
      return "TRAILING_BYTES";
    case WireStatus::ASSEMBLY_LIMIT_EXCEEDED:
      return "ASSEMBLY_LIMIT_EXCEEDED";
    case WireStatus::LIMIT_EXCEEDED:
      return "LIMIT_EXCEEDED";
  }
  return "UNKNOWN";
}

bool is_defined_wire_status(std::uint8_t raw) noexcept {
  return raw >= static_cast<std::uint8_t>(WireStatus::OK) &&
         raw <= static_cast<std::uint8_t>(WireStatus::LIMIT_EXCEEDED);
}

namespace {

void write_header(std::vector<std::uint8_t>& out, MessageId message, std::uint32_t payload_len) {
  const std::uint32_t magic = kWireFrameMagic;
  const std::uint16_t version = kWireProtocolVersion;
  const std::uint16_t id = static_cast<std::uint16_t>(message);
  for (int i = 0; i < 4; ++i) {
    out.push_back(static_cast<std::uint8_t>((magic >> (8 * i)) & 0xffU));
  }
  out.push_back(static_cast<std::uint8_t>(version & 0xffU));
  out.push_back(static_cast<std::uint8_t>((version >> 8) & 0xffU));
  out.push_back(static_cast<std::uint8_t>(id & 0xffU));
  out.push_back(static_cast<std::uint8_t>((id >> 8) & 0xffU));
  for (int i = 0; i < 4; ++i) {
    out.push_back(static_cast<std::uint8_t>((payload_len >> (8 * i)) & 0xffU));
  }
}

void write_u64(std::vector<std::uint8_t>& out, std::uint64_t value) {
  for (int i = 0; i < 8; ++i) {
    out.push_back(static_cast<std::uint8_t>((value >> (8 * i)) & 0xffU));
  }
}

std::uint64_t read_u64(const std::uint8_t* data) {
  std::uint64_t value = 0;
  for (int i = 0; i < 8; ++i) {
    value |= static_cast<std::uint64_t>(data[i]) << (8 * i);
  }
  return value;
}

}  // namespace

std::vector<std::uint8_t> encode_frame(MessageId message,
                                       const std::vector<std::uint8_t>& payload,
                                       const Limits& limits) {
  if (payload.size() > limits.max_frame_bytes) {
    return {};
  }
  std::vector<std::uint8_t> prefix;
  prefix.reserve(kWireHeaderBytes);
  write_header(prefix, message, static_cast<std::uint32_t>(payload.size()));
  // The integrity covers the semantic header bytes and the payload together, so
  // a retargeted header cannot be hidden behind a recomputed payload value. It
  // is carried inside the fixed header, between the length and the payload, so
  // an assembler can reject a bad header before the payload has arrived.
  std::vector<std::uint8_t> covered = prefix;
  covered.insert(covered.end(), payload.begin(), payload.end());
  const std::uint64_t integrity = fnv1a64(covered.data(), covered.size());

  std::vector<std::uint8_t> out;
  out.reserve(kWireHeaderBytes + payload.size());
  out.insert(out.end(), prefix.begin(), prefix.end());
  write_u64(out, integrity);
  out.insert(out.end(), payload.begin(), payload.end());
  return out;
}

WireStatus decode_frame_header(const std::uint8_t* data, std::size_t size, const Limits& limits,
                               MessageId& message, std::uint32_t& payload_len,
                               std::uint64_t& integrity) {
  if (size < kWireHeaderBytes) {
    return WireStatus::INCOMPLETE;
  }
  std::uint32_t magic = 0;
  for (int i = 0; i < 4; ++i) {
    magic |= static_cast<std::uint32_t>(data[i]) << (8 * i);
  }
  if (magic != kWireFrameMagic) {
    return WireStatus::BAD_MAGIC;
  }
  const std::uint16_t version =
      static_cast<std::uint16_t>(static_cast<std::uint16_t>(data[4]) |
                                 static_cast<std::uint16_t>(static_cast<std::uint16_t>(data[5])
                                                            << 8));
  if (version != kWireProtocolVersion) {
    return WireStatus::UNSUPPORTED_VERSION;
  }
  const std::uint16_t id = static_cast<std::uint16_t>(
      static_cast<std::uint16_t>(data[6]) |
      static_cast<std::uint16_t>(static_cast<std::uint16_t>(data[7]) << 8));
  if (!is_defined_message_id(id) || is_reserved_message(id)) {
    return WireStatus::UNKNOWN_MESSAGE;
  }
  std::uint32_t length = 0;
  for (int i = 0; i < 4; ++i) {
    length |= static_cast<std::uint32_t>(data[8 + i]) << (8 * i);
  }
  if (length > limits.max_frame_bytes) {
    return WireStatus::FRAME_TOO_LARGE;
  }
  message = static_cast<MessageId>(id);
  payload_len = length;
  integrity = read_u64(data + 12);
  return WireStatus::OK;
}

WireStatus decode_frame(const std::uint8_t* data, std::size_t size, const Limits& limits,
                        WireFrame& out) {
  MessageId message = MessageId::PING;
  std::uint32_t payload_len = 0;
  std::uint64_t integrity = 0;
  const WireStatus header = decode_frame_header(data, size, limits, message, payload_len, integrity);
  if (header != WireStatus::OK) {
    return header;
  }
  const std::size_t total = kWireHeaderBytes + payload_len;
  if (size < total) {
    return WireStatus::INCOMPLETE;
  }
  if (size > total) {
    return WireStatus::TRAILING_BYTES;
  }
  // The integrity field sits between the semantic header and the payload, so
  // the covered bytes are the first twelve header bytes followed by the payload.
  std::vector<std::uint8_t> covered;
  covered.reserve(12 + payload_len);
  covered.insert(covered.end(), data, data + 12);
  covered.insert(covered.end(), data + kWireHeaderBytes, data + total);
  const std::uint64_t computed = fnv1a64(covered.data(), covered.size());
  if (computed != integrity) {
    return WireStatus::INTEGRITY_FAILURE;
  }
  out.message = message;
  out.payload.assign(data + kWireHeaderBytes, data + total);
  return WireStatus::OK;
}

struct FrameAssembler::Impl {
  explicit Impl(const Limits& configured) : limits(configured) {}
  Limits limits;
  std::vector<std::uint8_t> buffer;
  std::size_t consumed = 0;
  WireStatus status = WireStatus::OK;
};

FrameAssembler::FrameAssembler(Limits limits) : impl_(new Impl(limits)) {}
FrameAssembler::~FrameAssembler() = default;

void FrameAssembler::append(const std::uint8_t* data, std::size_t size) {
  if (impl_->status != WireStatus::OK) {
    return;
  }
  if (impl_->consumed != 0) {
    impl_->buffer.erase(impl_->buffer.begin(),
                        impl_->buffer.begin() + static_cast<std::ptrdiff_t>(impl_->consumed));
    impl_->consumed = 0;
  }
  impl_->buffer.insert(impl_->buffer.end(), data, data + size);
  if (impl_->buffer.size() > impl_->limits.max_wire_assembly_bytes) {
    // A started partial frame is bounded by product-level assembly behaviour;
    // exceeding the bound is an explicit failure, never unbounded buffering.
    impl_->status = WireStatus::ASSEMBLY_LIMIT_EXCEEDED;
  }
}

WireStatus FrameAssembler::next(WireFrame& out) {
  if (impl_->status != WireStatus::OK) {
    return impl_->status;
  }
  const std::uint8_t* base = impl_->buffer.data() + impl_->consumed;
  const std::size_t available = impl_->buffer.size() - impl_->consumed;
  if (available == 0) {
    return WireStatus::INCOMPLETE;
  }
  MessageId message = MessageId::PING;
  std::uint32_t payload_len = 0;
  std::uint64_t integrity = 0;
  const WireStatus header =
      decode_frame_header(base, available, impl_->limits, message, payload_len, integrity);
  if (header != WireStatus::OK) {
    if (header == WireStatus::INCOMPLETE) {
      return WireStatus::INCOMPLETE;
    }
    impl_->status = header;
    return header;
  }
  const std::size_t total = kWireHeaderBytes + payload_len;
  if (available < total) {
    return WireStatus::INCOMPLETE;
  }
  const WireStatus frame_status = decode_frame(base, total, impl_->limits, out);
  if (frame_status != WireStatus::OK) {
    impl_->status = frame_status;
    return frame_status;
  }
  impl_->consumed += total;
  return WireStatus::OK;
}

std::size_t FrameAssembler::buffered() const noexcept {
  return impl_->buffer.size() - impl_->consumed;
}

void FrameAssembler::clear() noexcept {
  impl_->buffer.clear();
  impl_->consumed = 0;
  impl_->status = WireStatus::OK;
}

WireStatus FrameAssembler::status() const noexcept { return impl_->status; }

// ---------------------------------------------------------------------------
// Payload codecs. Every decoder enforces strict trailing-byte and enum
// validation and treats its input as untrusted.
// ---------------------------------------------------------------------------
namespace {

void write_id(ByteWriter& writer, std::string_view text) { writer.text(text); }

DecodeStatus read_id(ByteReader& reader, const Limits& limits, std::string& out) {
  return reader.text(out, limits.max_identity_length) ? DecodeStatus::OK : reader.status();
}

template <class Id>
DecodeStatus read_typed_id(ByteReader& reader, const Limits& limits, Id& out) {
  std::string text;
  const DecodeStatus status = read_id(reader, limits, text);
  if (status != DecodeStatus::OK) {
    return status;
  }
  const auto parsed = Id::from_wire(text);
  if (!parsed.has_value()) {
    reader.fail(DecodeStatus::INVALID_ENCODING);
    return DecodeStatus::INVALID_ENCODING;
  }
  out = *parsed;
  return DecodeStatus::OK;
}

}  // namespace

void encode_acting_authority(ByteWriter& writer, const ActingAuthority& value) {
  writer.text(value.epoch.value() == 0 ? std::string_view("epoch-unset") : std::string_view("epoch-set"));
  writer.u64(value.epoch.value());
  write_id(writer, value.publisher.view());
  write_id(writer, value.boot.view());
  write_id(writer, value.scope.view());
  write_id(writer, value.attempt.view());
  writer.u64(value.expected_policy_generation.value());
  writer.u64(value.expected_proof_generation.value());
}

DecodeStatus decode_acting_authority(ByteReader& reader, const Limits& limits,
                                     ActingAuthority& out) {
  std::string marker;
  if (read_id(reader, limits, marker) != DecodeStatus::OK) {
    return reader.status();
  }
  if (!(marker == "epoch-set" || marker == "epoch-unset")) {
    reader.fail(DecodeStatus::INVALID_ENCODING);
    return DecodeStatus::INVALID_ENCODING;
  }
  std::uint64_t epoch = 0;
  if (!reader.u64(epoch)) {
    return reader.status();
  }
  out.epoch = CoordinatorEpoch::from_value(epoch);
  DecodeStatus status = read_typed_id(reader, limits, out.publisher);
  if (status != DecodeStatus::OK) {
    return status;
  }
  status = read_typed_id(reader, limits, out.boot);
  if (status != DecodeStatus::OK) {
    return status;
  }
  status = read_typed_id(reader, limits, out.scope);
  if (status != DecodeStatus::OK) {
    return status;
  }
  status = read_typed_id(reader, limits, out.attempt);
  if (status != DecodeStatus::OK) {
    return status;
  }
  std::uint64_t policy_generation = 0;
  std::uint64_t proof_generation = 0;
  if (!reader.u64(policy_generation) || !reader.u64(proof_generation)) {
    return reader.status();
  }
  out.expected_policy_generation = DiversityPolicyGeneration::from_value(policy_generation);
  out.expected_proof_generation = DiversityProofGeneration::from_value(proof_generation);
  return DecodeStatus::OK;
}

void encode_hello(ByteWriter& writer, const HelloPayload& value) {
  write_id(writer, value.publisher.view());
  write_id(writer, value.boot.view());
  writer.u64(value.epoch.value());
  write_id(writer, value.scope.view());
}

DecodeStatus decode_hello(ByteReader& reader, const Limits& limits, HelloPayload& out) {
  DecodeStatus status = read_typed_id(reader, limits, out.publisher);
  if (status != DecodeStatus::OK) {
    return status;
  }
  status = read_typed_id(reader, limits, out.boot);
  if (status != DecodeStatus::OK) {
    return status;
  }
  std::uint64_t epoch = 0;
  if (!reader.u64(epoch)) {
    return reader.status();
  }
  out.epoch = CoordinatorEpoch::from_value(epoch);
  return read_typed_id(reader, limits, out.scope);
}

void encode_proof_request(ByteWriter& writer, const ProofRequest& value) {
  write_id(writer, value.policy.view());
  writer.u64(value.policy_generation.value());
  writer.varint(value.paths.size());
  for (const PathRef& reference : value.paths) {
    write_id(writer, reference.path.view());
    writer.u64(reference.authority_generation.value());
  }
}

DecodeStatus decode_proof_request(ByteReader& reader, const Limits& limits, ProofRequest& out) {
  DecodeStatus status = read_typed_id(reader, limits, out.policy);
  if (status != DecodeStatus::OK) {
    return status;
  }
  std::uint64_t policy_generation = 0;
  if (!reader.u64(policy_generation)) {
    return reader.status();
  }
  out.policy_generation = DiversityPolicyGeneration::from_value(policy_generation);
  std::uint64_t path_count = 0;
  if (!reader.varint(path_count)) {
    return reader.status();
  }
  if (path_count > limits.max_paths_per_proof) {
    reader.fail(DecodeStatus::LIMIT_EXCEEDED);
    return DecodeStatus::LIMIT_EXCEEDED;
  }
  out.paths.clear();
  for (std::uint64_t i = 0; i < path_count; ++i) {
    PathRef reference;
    status = read_typed_id(reader, limits, reference.path);
    if (status != DecodeStatus::OK) {
      return status;
    }
    std::uint64_t authority = 0;
    if (!reader.u64(authority)) {
      return reader.status();
    }
    reference.authority_generation = PathAuthorityGeneration::from_value(authority);
    out.paths.push_back(std::move(reference));
  }
  return DecodeStatus::OK;
}

void encode_publish_policy(ByteWriter& writer, const PublishPolicyPayload& value) {
  encode_acting_authority(writer, value.authority);
  encode_policy(writer, value.policy);
}

DecodeStatus decode_publish_policy(ByteReader& reader, const Limits& limits,
                                   PublishPolicyPayload& out) {
  DecodeStatus status = decode_acting_authority(reader, limits, out.authority);
  if (status != DecodeStatus::OK) {
    return status;
  }
  return decode_policy(reader, limits, out.policy);
}

void encode_publish_proof(ByteWriter& writer, const PublishProofPayload& value) {
  encode_acting_authority(writer, value.authority);
  encode_proof_request(writer, value.request);
}

DecodeStatus decode_publish_proof(ByteReader& reader, const Limits& limits,
                                  PublishProofPayload& out) {
  DecodeStatus status = decode_acting_authority(reader, limits, out.authority);
  if (status != DecodeStatus::OK) {
    return status;
  }
  return decode_proof_request(reader, limits, out.request);
}

void encode_revalidate(ByteWriter& writer, const RevalidatePayload& value) {
  encode_acting_authority(writer, value.authority);
  write_id(writer, value.proof.view());
}

DecodeStatus decode_revalidate(ByteReader& reader, const Limits& limits, RevalidatePayload& out) {
  DecodeStatus status = decode_acting_authority(reader, limits, out.authority);
  if (status != DecodeStatus::OK) {
    return status;
  }
  return read_typed_id(reader, limits, out.proof);
}

// A query names exactly one selector, so the identities it does not use are
// unset. Unset is a legal state and is encoded as an explicit presence flag: an
// empty identity is not a valid encoding of any identity.
void encode_query(ByteWriter& writer, const QueryPayload& value) {
  writer.u8(value.selector);
  writer.boolean(value.path.valid());
  if (value.path.valid()) {
    write_id(writer, value.path.view());
  }
  writer.boolean(value.domain.valid());
  if (value.domain.valid()) {
    write_id(writer, value.domain.view());
  }
  writer.boolean(value.policy.valid());
  if (value.policy.valid()) {
    write_id(writer, value.policy.view());
  }
  writer.u8(static_cast<std::uint8_t>(value.entity_kind));
  writer.text(value.entity_id);
}

DecodeStatus decode_query(ByteReader& reader, const Limits& limits, QueryPayload& out) {
  std::uint8_t selector = 0;
  if (!reader.u8(selector)) {
    return reader.status();
  }
  if (selector > 5) {
    reader.fail(DecodeStatus::INVALID_ENCODING);
    return DecodeStatus::INVALID_ENCODING;
  }
  out.selector = selector;
  bool present = false;
  if (!reader.boolean(present)) {
    return reader.status();
  }
  if (present) {
    const DecodeStatus status = read_typed_id(reader, limits, out.path);
    if (status != DecodeStatus::OK) {
      return status;
    }
  }
  if (!reader.boolean(present)) {
    return reader.status();
  }
  if (present) {
    const DecodeStatus status = read_typed_id(reader, limits, out.domain);
    if (status != DecodeStatus::OK) {
      return status;
    }
  }
  if (!reader.boolean(present)) {
    return reader.status();
  }
  if (present) {
    const DecodeStatus status = read_typed_id(reader, limits, out.policy);
    if (status != DecodeStatus::OK) {
      return status;
    }
  }
  std::uint8_t kind = 0;
  if (!reader.u8(kind)) {
    return reader.status();
  }
  if (!is_defined_entity_kind(kind)) {
    reader.fail(DecodeStatus::INVALID_ENCODING);
    return DecodeStatus::INVALID_ENCODING;
  }
  out.entity_kind = static_cast<EntityKind>(kind);
  if (!reader.text(out.entity_id, limits.max_identity_length)) {
    return reader.status();
  }
  return DecodeStatus::OK;
}

void encode_query_result(ByteWriter& writer, const QueryResultPayload& value) {
  writer.varint(value.proofs.size());
  for (const DiversityProofId& id : value.proofs) {
    write_id(writer, id.view());
  }
  writer.boolean(value.truncated);
  writer.u64(value.total);
}

DecodeStatus decode_query_result(ByteReader& reader, const Limits& limits,
                                 QueryResultPayload& out) {
  std::uint64_t count = 0;
  if (!reader.varint(count)) {
    return reader.status();
  }
  if (count > limits.max_query_results) {
    reader.fail(DecodeStatus::LIMIT_EXCEEDED);
    return DecodeStatus::LIMIT_EXCEEDED;
  }
  out.proofs.clear();
  for (std::uint64_t i = 0; i < count; ++i) {
    DiversityProofId id;
    const DecodeStatus status = read_typed_id(reader, limits, id);
    if (status != DecodeStatus::OK) {
      return status;
    }
    out.proofs.push_back(id);
  }
  if (!reader.boolean(out.truncated) || !reader.u64(out.total)) {
    return reader.status();
  }
  if (out.total < out.proofs.size()) {
    reader.fail(DecodeStatus::INVALID_ENCODING);
    return DecodeStatus::INVALID_ENCODING;
  }
  return DecodeStatus::OK;
}

void encode_mutation_result(ByteWriter& writer, const MutationResultPayload& value) {
  writer.u8(static_cast<std::uint8_t>(value.status));
  writer.text(value.detail);
  writer.boolean(value.has_proof);
  if (value.has_proof) {
    encode_proof(writer, value.proof);
  }
}

DecodeStatus decode_mutation_result(ByteReader& reader, const Limits& limits,
                                    MutationResultPayload& out) {
  std::uint8_t status = 0;
  if (!reader.u8(status)) {
    return reader.status();
  }
  if (!is_defined_mutation_status(status)) {
    reader.fail(DecodeStatus::INVALID_ENCODING);
    return DecodeStatus::INVALID_ENCODING;
  }
  out.status = static_cast<MutationStatus>(status);
  if (!reader.text(out.detail, limits.max_persistence_record_bytes / 4U)) {
    return reader.status();
  }
  if (!reader.boolean(out.has_proof)) {
    return reader.status();
  }
  if (out.has_proof) {
    return decode_proof(reader, limits, out.proof);
  }
  return DecodeStatus::OK;
}

void encode_error(ByteWriter& writer, const ErrorPayload& value) {
  writer.u8(static_cast<std::uint8_t>(value.status));
  writer.text(value.detail);
}

DecodeStatus decode_error(ByteReader& reader, const Limits& limits, ErrorPayload& out) {
  std::uint8_t status = 0;
  if (!reader.u8(status)) {
    return reader.status();
  }
  if (!is_defined_wire_status(status)) {
    reader.fail(DecodeStatus::INVALID_ENCODING);
    return DecodeStatus::INVALID_ENCODING;
  }
  out.status = static_cast<WireStatus>(status);
  if (!reader.text(out.detail, limits.max_persistence_record_bytes / 4U)) {
    return reader.status();
  }
  return DecodeStatus::OK;
}

}  // namespace path_diversity
