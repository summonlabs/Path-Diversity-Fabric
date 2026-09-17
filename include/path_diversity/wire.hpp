// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "path_diversity/authority.hpp"
#include "path_diversity/canonical.hpp"
#include "path_diversity/digest.hpp"
#include "path_diversity/domain.hpp"
#include "path_diversity/export.hpp"
#include "path_diversity/ids.hpp"
#include "path_diversity/limits.hpp"
#include "path_diversity/mutation.hpp"
#include "path_diversity/persistence.hpp"
#include "path_diversity/proof.hpp"

namespace path_diversity {

// Stable numeric message identifiers. They are part of the wire contract and
// never change meaning: a retired identifier is never reused.
enum class MessageId : std::uint16_t {
  HELLO = 1,
  HELLO_ACK = 2,
  PUBLISH_POLICY = 3,
  PUBLISH_PROOF = 4,
  REVALIDATE = 5,
  QUERY = 6,
  QUERY_RESULT = 7,
  SNAPSHOT = 8,
  DIFF = 9,
  EXPLAIN = 10,
  FENCE = 11,
  CLOSE = 12,
  // Named ERROR_REPLY rather than ERROR because ERROR is a Windows macro and
  // this identifier has to survive every platform header.
  ERROR_REPLY = 13,
  PING = 14,
  PONG = 15,
};

PATH_DIVERSITY_API std::string_view to_string(MessageId value) noexcept;
PATH_DIVERSITY_API bool is_defined_message_id(std::uint16_t raw) noexcept;

enum class WireStatus : std::uint8_t {
  OK = 1,
  INCOMPLETE = 2,
  BAD_MAGIC = 3,
  UNSUPPORTED_VERSION = 4,
  UNKNOWN_MESSAGE = 5,
  FRAME_TOO_LARGE = 6,
  INTEGRITY_FAILURE = 7,
  MALFORMED_PAYLOAD = 8,
  TRAILING_BYTES = 9,
  ASSEMBLY_LIMIT_EXCEEDED = 10,
  LIMIT_EXCEEDED = 11,
};

PATH_DIVERSITY_API std::string_view to_string(WireStatus value) noexcept;
PATH_DIVERSITY_API bool is_defined_wire_status(std::uint8_t raw) noexcept;

// Fixed frame layout, little-endian, twenty bytes:
//   u32 magic | u16 wire_version | u16 message_id | u32 payload_len | u64 integrity
// The integrity value is FNV-1a 64 over the first twelve header bytes followed
// by the payload, so it covers the semantic header and the payload together and
// a header cannot be retargeted without detection. As everywhere in this
// library the integrity value detects corruption; it is not a cryptographic
// authenticator and provides no defence against a motivated adversary.
inline constexpr std::uint32_t kWireFrameMagic = 0x31464450U;
inline constexpr std::size_t kWireHeaderBytes = 20;

struct PATH_DIVERSITY_API WireFrame {
  MessageId message = MessageId::PING;
  std::vector<std::uint8_t> payload;
  friend bool operator==(const WireFrame&, const WireFrame&) = default;
};

PATH_DIVERSITY_API std::vector<std::uint8_t> encode_frame(MessageId message,
                                                          const std::vector<std::uint8_t>& payload,
                                                          const Limits& limits);
PATH_DIVERSITY_API WireStatus decode_frame_header(const std::uint8_t* data, std::size_t size,
                                                  const Limits& limits, MessageId& message,
                                                  std::uint32_t& payload_len,
                                                  std::uint64_t& integrity);
PATH_DIVERSITY_API WireStatus decode_frame(const std::uint8_t* data, std::size_t size,
                                           const Limits& limits, WireFrame& out);

// Bounded incremental assembly. A partial frame never grows past
// limits.max_wire_assembly_bytes; exceeding the bound is an explicit failure
// rather than unbounded buffering.
class PATH_DIVERSITY_API FrameAssembler {
 public:
  explicit FrameAssembler(Limits limits);
  FrameAssembler(const FrameAssembler&) = delete;
  FrameAssembler& operator=(const FrameAssembler&) = delete;
  ~FrameAssembler();

  void append(const std::uint8_t* data, std::size_t size);
  // Pops one complete, fully validated frame. Returns INCOMPLETE when more
  // bytes are needed, and the sticky status for a fatal encoding failure.
  WireStatus next(WireFrame& out);
  std::size_t buffered() const noexcept;
  void clear() noexcept;
  WireStatus status() const noexcept;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

// --- Payload codecs -------------------------------------------------------
struct PATH_DIVERSITY_API HelloPayload {
  PublisherId publisher;
  WorkerBootId boot;
  CoordinatorEpoch epoch;
  ScopeId scope;
  friend bool operator==(const HelloPayload&, const HelloPayload&) = default;
};

struct PATH_DIVERSITY_API PublishPolicyPayload {
  ActingAuthority authority;
  DiversityPolicy policy;
  friend bool operator==(const PublishPolicyPayload&, const PublishPolicyPayload&) = default;
};

struct PATH_DIVERSITY_API PublishProofPayload {
  ActingAuthority authority;
  ProofRequest request;
  friend bool operator==(const PublishProofPayload&, const PublishProofPayload&) = default;
};

struct PATH_DIVERSITY_API RevalidatePayload {
  ActingAuthority authority;
  DiversityProofId proof;
  friend bool operator==(const RevalidatePayload&, const RevalidatePayload&) = default;
};

struct PATH_DIVERSITY_API QueryPayload {
  // 0 = all, 1 = by path, 2 = by domain, 3 = by policy, 4 = by entity,
  // 5 = current proofs only.
  std::uint8_t selector = 0;
  PathId path;
  FailureDomainId domain;
  DiversityPolicyId policy;
  EntityKind entity_kind = EntityKind::LINK;
  std::string entity_id;
  friend bool operator==(const QueryPayload&, const QueryPayload&) = default;
};

struct PATH_DIVERSITY_API QueryResultPayload {
  std::vector<DiversityProofId> proofs;
  bool truncated = false;
  std::uint64_t total = 0;
  friend bool operator==(const QueryResultPayload&, const QueryResultPayload&) = default;
};

struct PATH_DIVERSITY_API MutationResultPayload {
  MutationStatus status = MutationStatus::MALFORMED;
  std::string detail;
  bool has_proof = false;
  DiversityProof proof;
  friend bool operator==(const MutationResultPayload&, const MutationResultPayload&) = default;
};

struct PATH_DIVERSITY_API ErrorPayload {
  WireStatus status = WireStatus::MALFORMED_PAYLOAD;
  std::string detail;
  friend bool operator==(const ErrorPayload&, const ErrorPayload&) = default;
};

PATH_DIVERSITY_API void encode_acting_authority(ByteWriter& writer, const ActingAuthority& value);
PATH_DIVERSITY_API DecodeStatus decode_acting_authority(ByteReader& reader, const Limits& limits,
                                                        ActingAuthority& out);
PATH_DIVERSITY_API void encode_hello(ByteWriter& writer, const HelloPayload& value);
PATH_DIVERSITY_API DecodeStatus decode_hello(ByteReader& reader, const Limits& limits,
                                             HelloPayload& out);
PATH_DIVERSITY_API void encode_publish_policy(ByteWriter& writer, const PublishPolicyPayload& value);
PATH_DIVERSITY_API DecodeStatus decode_publish_policy(ByteReader& reader, const Limits& limits,
                                                      PublishPolicyPayload& out);
PATH_DIVERSITY_API void encode_publish_proof(ByteWriter& writer, const PublishProofPayload& value);
PATH_DIVERSITY_API DecodeStatus decode_publish_proof(ByteReader& reader, const Limits& limits,
                                                     PublishProofPayload& out);
PATH_DIVERSITY_API void encode_revalidate(ByteWriter& writer, const RevalidatePayload& value);
PATH_DIVERSITY_API DecodeStatus decode_revalidate(ByteReader& reader, const Limits& limits,
                                                  RevalidatePayload& out);
PATH_DIVERSITY_API void encode_query(ByteWriter& writer, const QueryPayload& value);
PATH_DIVERSITY_API DecodeStatus decode_query(ByteReader& reader, const Limits& limits,
                                             QueryPayload& out);
PATH_DIVERSITY_API void encode_query_result(ByteWriter& writer, const QueryResultPayload& value);
PATH_DIVERSITY_API DecodeStatus decode_query_result(ByteReader& reader, const Limits& limits,
                                                    QueryResultPayload& out);
PATH_DIVERSITY_API void encode_mutation_result(ByteWriter& writer,
                                               const MutationResultPayload& value);
PATH_DIVERSITY_API DecodeStatus decode_mutation_result(ByteReader& reader, const Limits& limits,
                                                       MutationResultPayload& out);
PATH_DIVERSITY_API void encode_error(ByteWriter& writer, const ErrorPayload& value);
PATH_DIVERSITY_API DecodeStatus decode_error(ByteReader& reader, const Limits& limits,
                                             ErrorPayload& out);
PATH_DIVERSITY_API void encode_proof_request(ByteWriter& writer, const ProofRequest& value);
PATH_DIVERSITY_API DecodeStatus decode_proof_request(ByteReader& reader, const Limits& limits,
                                                     ProofRequest& out);

}  // namespace path_diversity
