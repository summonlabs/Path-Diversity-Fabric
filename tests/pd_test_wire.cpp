// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.

// Wire codec coverage: framing, every implemented payload codec, the exact
// rejection taxonomy of the frame decoder and bounded incremental assembly.

#include <cstdint>
#include <string>
#include <vector>

#include "test_support.hpp"

namespace {

using namespace path_diversity;

constexpr std::uint16_t kReservedIds[3] = {8, 9, 10};  // SNAPSHOT, DIFF, EXPLAIN

bool is_reserved(std::uint16_t raw) {
  for (std::uint16_t candidate : kReservedIds) {
    if (candidate == raw) {
      return true;
    }
  }
  return false;
}

void check_wire(WireStatus actual, WireStatus expected, const std::string& label, const char* file,
                int line) {
  pd_test::check(actual == expected,
                 label + ": observed " + std::string(to_string(actual)) + ", expected " +
                     std::string(to_string(expected)),
                 file, line);
}

void check_decode(DecodeStatus actual, DecodeStatus expected, const std::string& label,
                  const char* file, int line) {
  pd_test::check(actual == expected,
                 label + ": observed " + std::string(to_string(actual)) + ", expected " +
                     std::string(to_string(expected)),
                 file, line);
}

// Encodes a value with its own codec and decodes it again, asserting that the
// record is consumed exactly. The decoded value is handed back to the caller,
// because the payloads that carry an ActingAuthority have no usable equality
// operator: their declared defaulted operator is implicitly deleted.
template <class Value, class Encode, class Decode>
bool payload_consumes_its_record(const Value& original, Encode encode, Decode decode,
                                 const Limits& limits, const std::string& label, Value& decoded) {
  ByteWriter writer;
  encode(writer, original);
  const std::vector<std::uint8_t> bytes = writer.data();
  ByteReader reader(bytes.data(), bytes.size());
  const DecodeStatus status = decode(reader, limits, decoded);
  pd_test::check(status == DecodeStatus::OK && reader.at_end(),
                 label + ": " + std::string(to_string(status)) + ", consumed " +
                     std::to_string(reader.offset()) + " of " + std::to_string(bytes.size()),
                 __FILE__, __LINE__);
  return status == DecodeStatus::OK && reader.at_end();
}

// Value-by-value comparison for the payloads that do have a usable operator.
template <class Value, class Encode, class Decode>
bool payload_round_trips(const Value& original, Encode encode, Decode decode, const Limits& limits,
                         const std::string& label) {
  Value decoded;
  if (!payload_consumes_its_record(original, encode, decode, limits, label, decoded)) {
    return false;
  }
  return decoded == original;
}

bool same_authority(const ActingAuthority& left, const ActingAuthority& right) {
  return left.epoch == right.epoch && left.publisher == right.publisher &&
         left.boot == right.boot && left.scope == right.scope && left.attempt == right.attempt &&
         left.expected_policy_generation == right.expected_policy_generation &&
         left.expected_proof_generation == right.expected_proof_generation;
}

// A committed proof from a real runtime, used wherever a payload carries a
// proof rather than a small fixed record.
struct CommittedProof {
  DiversityProof proof;
  DiversityPolicy policy;
  PublisherId publisher;
  WorkerBootId boot;
  CoordinatorEpoch epoch;
  ActingAuthority authority;
};

CommittedProof make_committed_proof() {
  pd_test::Fixture fixture;
  const DiversityPolicy policy =
      pd_test::make_policy("dpol-wire", {DiversityClass::LINK_DISJOINT},
                           EndpointExemption::SHARED_SOURCE_AND_DESTINATION, 2);
  const MutationResult published = fixture.runtime.publish_policy(policy, fixture.actor("wire-pub"));
  PD_CHECK_EQ(published.status, MutationStatus::APPLIED);
  fixture.evidence.set_path(pd_test::make_path("wire-path-a", 1, {"wire-node-a"}, {"wire-link-a"},
                                               {"wire-dev-a"}, "ep-a", "ep-b"));
  fixture.evidence.set_path(pd_test::make_path("wire-path-b", 1, {"wire-node-b"}, {"wire-link-b"},
                                               {"wire-dev-b"}, "ep-a", "ep-b"));
  ProofRequest request;
  request.policy = published.policy.id;
  request.policy_generation = published.policy.generation;
  request.paths.push_back(
      PathRef{PathId::parse("wire-path-a"), PathAuthorityGeneration::from_value(1)});
  request.paths.push_back(
      PathRef{PathId::parse("wire-path-b"), PathAuthorityGeneration::from_value(1)});
  const MutationResult committed = fixture.runtime.evaluate(request, fixture.actor("wire-eval"));
  PD_CHECK_EQ(committed.status, MutationStatus::APPLIED);

  CommittedProof out;
  out.proof = committed.proof;
  out.policy = *fixture.runtime.policy(request.policy);
  out.publisher = fixture.publisher;
  out.boot = fixture.boot;
  out.epoch = fixture.publication.current_epoch();
  out.authority = fixture.actor("wire-authority");
  out.authority.expected_policy_generation = published.policy.generation;
  return out;
}

HelloPayload hello_payload(const CommittedProof& committed) {
  HelloPayload payload;
  payload.publisher = committed.publisher;
  payload.boot = committed.boot;
  payload.epoch = committed.epoch;
  payload.scope = default_scope();
  return payload;
}

MutationResultPayload mutation_payload(const CommittedProof& committed) {
  MutationResultPayload payload;
  payload.status = MutationStatus::APPLIED;
  payload.detail = "proof committed";
  payload.has_proof = true;
  payload.proof = committed.proof;
  return payload;
}

// The payload the protocol carries for one message identifier.
std::vector<std::uint8_t> payload_for(MessageId message, const CommittedProof& committed) {
  ByteWriter writer;
  switch (message) {
    case MessageId::HELLO:
    case MessageId::HELLO_ACK:
      encode_hello(writer, hello_payload(committed));
      break;
    case MessageId::PUBLISH_POLICY: {
      PublishPolicyPayload payload;
      payload.authority = committed.authority;
      payload.policy = committed.policy;
      encode_publish_policy(writer, payload);
      break;
    }
    case MessageId::PUBLISH_PROOF:
      encode_mutation_result(writer, mutation_payload(committed));
      break;
    case MessageId::REVALIDATE: {
      RevalidatePayload payload;
      payload.authority = committed.authority;
      payload.proof = committed.proof.id;
      encode_revalidate(writer, payload);
      break;
    }
    case MessageId::QUERY: {
      QueryPayload payload;
      payload.selector = 1;
      payload.path = PathId::parse("wire-path-a");
      payload.domain = FailureDomainId::parse("fd-a");
      payload.policy = committed.policy.id;
      payload.entity_kind = EntityKind::LINK;
      payload.entity_id = "wire-link-a";
      encode_query(writer, payload);
      break;
    }
    case MessageId::QUERY_RESULT: {
      QueryResultPayload payload;
      payload.proofs = {committed.proof.id};
      payload.total = 1;
      encode_query_result(writer, payload);
      break;
    }
    case MessageId::FENCE:
      writer.text(committed.boot.view());
      break;
    case MessageId::ERROR_REPLY: {
      ErrorPayload payload;
      payload.status = WireStatus::MALFORMED_PAYLOAD;
      payload.detail = "payload rejected";
      encode_error(writer, payload);
      break;
    }
    default:
      break;
  }
  return writer.data();
}

// The bytes the frame integrity covers: the first twelve header bytes followed
// by the payload. The integrity field itself sits between them.
std::vector<std::uint8_t> covered_bytes(const std::vector<std::uint8_t>& frame) {
  std::vector<std::uint8_t> covered(frame.begin(), frame.begin() + 12);
  covered.insert(covered.end(), frame.begin() + static_cast<std::ptrdiff_t>(kWireHeaderBytes),
                 frame.end());
  return covered;
}

// The query payload layout as the codec defines it: an explicit presence flag
// per optional identity, because an unset identity is a legal state and an
// empty identity is not a legal encoding of any identity.
std::vector<std::uint8_t> query_bytes(const CommittedProof& committed, std::uint8_t selector,
                                      std::uint8_t kind) {
  ByteWriter writer;
  writer.u8(selector);
  writer.boolean(true);
  writer.text(PathId::parse("wire-path-a").view());
  writer.boolean(true);
  writer.text(FailureDomainId::parse("fd-a").view());
  writer.boolean(true);
  writer.text(committed.policy.id.view());
  writer.u8(kind);
  writer.text("wire-link-a");
  return writer.data();
}

// The same layout with every optional identity unset: the shape a selector-only
// query actually uses.
std::vector<std::uint8_t> selector_only_query_bytes(std::uint8_t selector, std::uint8_t kind) {
  ByteWriter writer;
  writer.u8(selector);
  writer.boolean(false);
  writer.boolean(false);
  writer.boolean(false);
  writer.u8(kind);
  writer.text("");
  return writer.data();
}

// A frame header that declares a payload length, used to reach the header-level
// size checks without building the payload itself.
std::vector<std::uint8_t> declared_header(std::uint16_t message_id, std::uint32_t length) {
  std::vector<std::uint8_t> header(kWireHeaderBytes, 0);
  const std::uint32_t magic = kWireFrameMagic;
  for (int i = 0; i < 4; ++i) {
    header[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>((magic >> (8 * i)) & 0xffU);
  }
  header[4] = static_cast<std::uint8_t>(kWireProtocolVersion & 0xffU);
  header[5] = static_cast<std::uint8_t>((kWireProtocolVersion >> 8) & 0xffU);
  header[6] = static_cast<std::uint8_t>(message_id & 0xffU);
  header[7] = static_cast<std::uint8_t>((message_id >> 8) & 0xffU);
  for (int i = 0; i < 4; ++i) {
    header[8 + static_cast<std::size_t>(i)] =
        static_cast<std::uint8_t>((length >> (8 * i)) & 0xffU);
  }
  return header;
}

}  // namespace

PD_TEST(every_implemented_message_round_trips_through_a_frame) {
  const Limits limits;
  const CommittedProof committed = make_committed_proof();
  std::size_t implemented = 0;
  for (std::uint16_t raw = 1; raw <= 15; ++raw) {
    const MessageId message = static_cast<MessageId>(raw);
    PD_CHECK(is_defined_message_id(raw));
    PD_CHECK(to_string(message) != "UNKNOWN");
    if (is_reserved(raw)) {
      continue;
    }
    ++implemented;
    const std::vector<std::uint8_t> payload = payload_for(message, committed);
    const std::vector<std::uint8_t> frame = encode_frame(message, payload, limits);
    PD_REQUIRE(!frame.empty());
    PD_CHECK_EQ(frame.size(), kWireHeaderBytes + payload.size());

    MessageId header_message = MessageId::PING;
    std::uint32_t header_length = 0;
    std::uint64_t header_integrity = 0;
    check_wire(decode_frame_header(frame.data(), frame.size(), limits, header_message,
                                   header_length, header_integrity),
               WireStatus::OK, "header", __FILE__, __LINE__);
    PD_CHECK_EQ(header_message, message);
    PD_CHECK_EQ(header_length, static_cast<std::uint32_t>(payload.size()));
    const std::vector<std::uint8_t> covered = covered_bytes(frame);
    PD_CHECK_EQ(header_integrity, fnv1a64(covered.data(), covered.size()));

    WireFrame decoded;
    check_wire(decode_frame(frame.data(), frame.size(), limits, decoded), WireStatus::OK,
               std::string("round-trip ") + std::string(to_string(message)), __FILE__, __LINE__);
    PD_CHECK_EQ(decoded.message, message);
    PD_CHECK(decoded.payload == payload);
  }
  PD_CHECK_EQ(implemented, std::size_t{12});
  PD_CHECK(is_reserved(static_cast<std::uint16_t>(MessageId::SNAPSHOT)));
  PD_CHECK(is_reserved(static_cast<std::uint16_t>(MessageId::DIFF)));
  PD_CHECK(is_reserved(static_cast<std::uint16_t>(MessageId::EXPLAIN)));
  PD_CHECK(!is_reserved(static_cast<std::uint16_t>(MessageId::PING)));
}

PD_TEST(every_payload_codec_round_trips_and_consumes_its_input) {
  const Limits limits;
  const CommittedProof committed = make_committed_proof();

  PD_CHECK(payload_round_trips(hello_payload(committed), &encode_hello, &decode_hello, limits,
                               "hello"));
  {
    PublishPolicyPayload payload;
    payload.authority = committed.authority;
    payload.policy = committed.policy;
    PublishPolicyPayload decoded;
    PD_CHECK(payload_consumes_its_record(payload, &encode_publish_policy, &decode_publish_policy,
                                         limits, "publish-policy", decoded));
    PD_CHECK(decoded.policy == payload.policy);
    PD_CHECK(same_authority(decoded.authority, payload.authority));
  }
  {
    PublishProofPayload payload;
    payload.authority = committed.authority;
    payload.request = committed.proof.request;
    PublishProofPayload decoded;
    PD_CHECK(payload_consumes_its_record(payload, &encode_publish_proof, &decode_publish_proof,
                                         limits, "publish-proof", decoded));
    PD_CHECK(decoded.request == payload.request);
    PD_CHECK(same_authority(decoded.authority, payload.authority));
  }
  {
    RevalidatePayload payload;
    payload.authority = committed.authority;
    payload.proof = committed.proof.id;
    RevalidatePayload decoded;
    PD_CHECK(payload_consumes_its_record(payload, &encode_revalidate, &decode_revalidate, limits,
                                         "revalidate", decoded));
    PD_CHECK(decoded.proof == payload.proof);
    PD_CHECK(same_authority(decoded.authority, payload.authority));
  }
  {
    QueryPayload payload;
    payload.selector = 5;
    payload.path = PathId::parse("wire-path-a");
    payload.domain = FailureDomainId::parse("fd-a");
    payload.policy = committed.policy.id;
    payload.entity_kind = EntityKind::DEVICE;
    payload.entity_id = "wire-dev-a";
    PD_CHECK(payload_round_trips(payload, &encode_query, &decode_query, limits, "query"));
  }
  {
    QueryResultPayload payload;
    payload.proofs = {committed.proof.id, committed.proof.id};
    payload.truncated = true;
    payload.total = 7;
    PD_CHECK(payload_round_trips(payload, &encode_query_result, &decode_query_result, limits,
                                 "query-result"));
  }
  PD_CHECK(payload_round_trips(mutation_payload(committed), &encode_mutation_result,
                               &decode_mutation_result, limits, "mutation-result"));
  {
    MutationResultPayload payload;
    payload.status = MutationStatus::NOT_FOUND;
    payload.detail = "no proof is stored under this identity";
    PD_CHECK(payload_round_trips(payload, &encode_mutation_result, &decode_mutation_result, limits,
                                 "mutation-result-empty"));
  }
  {
    ErrorPayload payload;
    payload.status = WireStatus::ASSEMBLY_LIMIT_EXCEEDED;
    payload.detail = "assembly bound exceeded";
    PD_CHECK(payload_round_trips(payload, &encode_error, &decode_error, limits, "error"));
  }
  PD_CHECK(payload_round_trips(committed.proof.request, &encode_proof_request,
                               &decode_proof_request, limits, "proof-request"));

  // The acting authority has no equality operator: its encoded form is checked
  // field by field instead.
  {
    ByteWriter writer;
    encode_acting_authority(writer, committed.authority);
    const std::vector<std::uint8_t> bytes = writer.data();
    ByteReader reader(bytes.data(), bytes.size());
    ActingAuthority decoded;
    check_decode(decode_acting_authority(reader, limits, decoded), DecodeStatus::OK, "authority",
                 __FILE__, __LINE__);
    PD_CHECK(reader.at_end());
    PD_CHECK(same_authority(decoded, committed.authority));
  }
}

PD_TEST(magic_version_and_message_identity_are_checked_first) {
  const Limits limits;
  std::vector<std::uint8_t> payload;
  for (int i = 0; i < 6; ++i) {
    payload.push_back(static_cast<std::uint8_t>(i));
  }
  const std::vector<std::uint8_t> frame = encode_frame(MessageId::PING, payload, limits);
  WireFrame out;

  for (std::size_t size = 0; size < kWireHeaderBytes; ++size) {
    check_wire(decode_frame(frame.data(), size, limits, out), WireStatus::INCOMPLETE,
               "short-header", __FILE__, __LINE__);
  }

  std::vector<std::uint8_t> bad_magic = frame;
  for (int i = 0; i < 4; ++i) {
    bad_magic[static_cast<std::size_t>(i)] = 0x00U;
  }
  check_wire(decode_frame(bad_magic.data(), bad_magic.size(), limits, out), WireStatus::BAD_MAGIC,
             "bad-magic", __FILE__, __LINE__);

  const std::uint16_t versions[3] = {0, 2, 0xffff};
  for (std::uint16_t version : versions) {
    std::vector<std::uint8_t> bad_version = frame;
    bad_version[4] = static_cast<std::uint8_t>(version & 0xffU);
    bad_version[5] = static_cast<std::uint8_t>((version >> 8) & 0xffU);
    check_wire(decode_frame(bad_version.data(), bad_version.size(), limits, out),
               WireStatus::UNSUPPORTED_VERSION, "bad-version", __FILE__, __LINE__);
  }

  const std::uint16_t unknown_ids[5] = {0, 16, 42, 999, 0xffff};
  for (std::uint16_t raw : unknown_ids) {
    std::vector<std::uint8_t> unknown = frame;
    unknown[6] = static_cast<std::uint8_t>(raw & 0xffU);
    unknown[7] = static_cast<std::uint8_t>((raw >> 8) & 0xffU);
    check_wire(decode_frame(unknown.data(), unknown.size(), limits, out),
               WireStatus::UNKNOWN_MESSAGE, "unknown-message", __FILE__, __LINE__);
    PD_CHECK(!is_defined_message_id(raw));
  }
  for (std::uint16_t raw : kReservedIds) {
    std::vector<std::uint8_t> reserved = frame;
    reserved[6] = static_cast<std::uint8_t>(raw & 0xffU);
    reserved[7] = 0;
    check_wire(decode_frame(reserved.data(), reserved.size(), limits, out),
               WireStatus::UNKNOWN_MESSAGE, "reserved-message", __FILE__, __LINE__);
    PD_CHECK(is_defined_message_id(raw));
  }

  check_wire(decode_frame(frame.data(), frame.size(), limits, out), WireStatus::OK, "ping",
             __FILE__, __LINE__);
}

PD_TEST(frame_sizes_are_bounded_on_both_sides) {
  Limits limits;
  limits.max_frame_bytes = 64;
  limits.max_wire_assembly_bytes = 4096;

  const std::vector<std::uint8_t> exact(limits.max_frame_bytes, 0x5aU);
  const std::vector<std::uint8_t> frame = encode_frame(MessageId::PING, exact, limits);
  PD_CHECK_EQ(frame.size(), kWireHeaderBytes + exact.size());
  WireFrame out;
  check_wire(decode_frame(frame.data(), frame.size(), limits, out), WireStatus::OK, "exact",
             __FILE__, __LINE__);
  PD_CHECK(out.payload == exact);

  const std::vector<std::uint8_t> one_too_many(
      static_cast<std::size_t>(limits.max_frame_bytes) + 1, 0x5aU);
  PD_CHECK(encode_frame(MessageId::PING, one_too_many, limits).empty());
  const std::vector<std::uint8_t> huge(static_cast<std::size_t>(limits.max_frame_bytes) * 4, 0);
  PD_CHECK(encode_frame(MessageId::PING, huge, limits).empty());

  const std::vector<std::uint8_t> over =
      declared_header(static_cast<std::uint16_t>(MessageId::PING), limits.max_frame_bytes + 1U);
  check_wire(decode_frame(over.data(), over.size(), limits, out), WireStatus::FRAME_TOO_LARGE,
             "declared-too-large", __FILE__, __LINE__);
  const std::vector<std::uint8_t> within =
      declared_header(static_cast<std::uint16_t>(MessageId::PING), limits.max_frame_bytes);
  check_wire(decode_frame(within.data(), within.size(), limits, out), WireStatus::INCOMPLETE,
             "declared-incomplete", __FILE__, __LINE__);

  std::vector<std::uint8_t> extended = frame;
  extended.push_back(0x00U);
  check_wire(decode_frame(extended.data(), extended.size(), limits, out),
             WireStatus::TRAILING_BYTES, "trailing", __FILE__, __LINE__);
  std::vector<std::uint8_t> only_payload = frame;
  check_wire(decode_frame(only_payload.data(), only_payload.size() - 1, limits, out),
             WireStatus::INCOMPLETE, "short-payload", __FILE__, __LINE__);
}

PD_TEST(every_single_bit_flip_in_a_frame_is_refused) {
  const Limits limits;
  const CommittedProof committed = make_committed_proof();
  const std::vector<std::uint8_t> payload = payload_for(MessageId::HELLO, committed);
  PD_REQUIRE(payload.size() > 8);
  const std::vector<std::uint8_t> frame = encode_frame(MessageId::HELLO, payload, limits);
  WireFrame out;

  for (std::size_t offset = 0; offset < frame.size(); ++offset) {
    for (int bit = 0; bit < 8; ++bit) {
      std::vector<std::uint8_t> flipped = frame;
      flipped[offset] = static_cast<std::uint8_t>(flipped[offset] ^ (1U << bit));
      const WireStatus status = decode_frame(flipped.data(), flipped.size(), limits, out);
      PD_CHECK(status != WireStatus::OK);
      if (offset < 4) {
        check_wire(status, WireStatus::BAD_MAGIC, "flip-magic", __FILE__, __LINE__);
      } else if (offset < 6) {
        check_wire(status, WireStatus::UNSUPPORTED_VERSION, "flip-version", __FILE__, __LINE__);
      } else if (offset < 8) {
        // A flipped identifier is either no longer a defined identifier or is a
        // defined one whose tampered header the integrity value catches.
        PD_CHECK(status == WireStatus::UNKNOWN_MESSAGE ||
                 status == WireStatus::INTEGRITY_FAILURE);
      } else if (offset < 12) {
        PD_CHECK(status == WireStatus::INCOMPLETE || status == WireStatus::TRAILING_BYTES ||
                 status == WireStatus::FRAME_TOO_LARGE);
      } else {
        check_wire(status, WireStatus::INTEGRITY_FAILURE, "flip-integrity", __FILE__, __LINE__);
      }
    }
  }

  // The integrity value covers the semantic header as well as the payload, so a
  // retargeted header cannot be hidden by recomputing the payload value.
  std::vector<std::uint8_t> retargeted = frame;
  retargeted[6] = static_cast<std::uint8_t>(MessageId::CLOSE);
  check_wire(decode_frame(retargeted.data(), retargeted.size(), limits, out),
             WireStatus::INTEGRITY_FAILURE, "retargeted-header", __FILE__, __LINE__);
}

PD_TEST(frame_assembler_reassembles_frames_delivered_one_byte_at_a_time) {
  const Limits limits;
  const CommittedProof committed = make_committed_proof();
  const MessageId messages[4] = {MessageId::HELLO, MessageId::QUERY, MessageId::PONG,
                                 MessageId::ERROR_REPLY};
  std::vector<std::vector<std::uint8_t>> frames;
  std::vector<std::vector<std::uint8_t>> payloads;
  for (MessageId message : messages) {
    const std::vector<std::uint8_t> payload = payload_for(message, committed);
    payloads.push_back(payload);
    frames.push_back(encode_frame(message, payload, limits));
  }

  FrameAssembler assembler(limits);
  std::size_t expected_index = 0;
  std::size_t delivered = 0;
  WireFrame out;
  for (const std::vector<std::uint8_t>& frame : frames) {
    for (std::size_t i = 0; i < frame.size(); ++i) {
      assembler.append(&frame[i], 1);
      ++delivered;
      const WireStatus status = assembler.next(out);
      if (i + 1 == frame.size()) {
        check_wire(status, WireStatus::OK, "assembled-frame", __FILE__, __LINE__);
        PD_CHECK_EQ(out.message, messages[expected_index]);
        PD_CHECK(out.payload == payloads[expected_index]);
        PD_CHECK_EQ(assembler.buffered(), std::size_t{0});
        ++expected_index;
      } else {
        check_wire(status, WireStatus::INCOMPLETE, "partial-frame", __FILE__, __LINE__);
        PD_CHECK_EQ(assembler.status(), WireStatus::OK);
        PD_CHECK_EQ(assembler.buffered(), i + 1);
      }
    }
  }
  PD_CHECK_EQ(expected_index, std::size_t{4});
  PD_CHECK_EQ(delivered,
              frames[0].size() + frames[1].size() + frames[2].size() + frames[3].size());
  check_wire(assembler.next(out), WireStatus::INCOMPLETE, "drained", __FILE__, __LINE__);

  // Every frame of one delivery is consumed in order.
  FrameAssembler batched(limits);
  std::vector<std::uint8_t> stream;
  for (const std::vector<std::uint8_t>& frame : frames) {
    stream.insert(stream.end(), frame.begin(), frame.end());
  }
  batched.append(stream.data(), stream.size());
  for (std::size_t index = 0; index < 4; ++index) {
    check_wire(batched.next(out), WireStatus::OK, "batched", __FILE__, __LINE__);
    PD_CHECK_EQ(out.message, messages[index]);
  }
  check_wire(batched.next(out), WireStatus::INCOMPLETE, "batched-drained", __FILE__, __LINE__);
  PD_CHECK_EQ(batched.buffered(), std::size_t{0});
}

PD_TEST(frame_assembler_enforces_its_assembly_bound) {
  Limits limits;
  limits.max_frame_bytes = 64;
  limits.max_wire_assembly_bytes = 96;
  WireFrame out;

  // A partial frame inside the bound is buffered and reported as incomplete.
  const std::vector<std::uint8_t> body(limits.max_frame_bytes, 0x33U);
  const std::vector<std::uint8_t> frame = encode_frame(MessageId::PING, body, limits);
  PD_REQUIRE(frame.size() == kWireHeaderBytes + body.size());
  FrameAssembler partial(limits);
  partial.append(frame.data(), frame.size() - 1);
  check_wire(partial.next(out), WireStatus::INCOMPLETE, "partial", __FILE__, __LINE__);
  PD_CHECK_EQ(partial.buffered(), frame.size() - 1);
  partial.append(frame.data() + frame.size() - 1, 1);
  check_wire(partial.next(out), WireStatus::OK, "partial-complete", __FILE__, __LINE__);
  PD_CHECK(out.payload == body);

  // Exactly the bound is accepted; one byte more is an explicit failure.
  FrameAssembler bounded(limits);
  const std::vector<std::uint8_t> bound(limits.max_wire_assembly_bytes, 0x11U);
  bounded.append(bound.data(), bound.size());
  PD_CHECK_EQ(bounded.buffered(), static_cast<std::size_t>(limits.max_wire_assembly_bytes));
  check_wire(bounded.status(), WireStatus::OK, "bound-exact", __FILE__, __LINE__);
  const std::uint8_t extra = 0x22U;
  bounded.append(&extra, 1);
  check_wire(bounded.status(), WireStatus::ASSEMBLY_LIMIT_EXCEEDED, "bound-status", __FILE__,
             __LINE__);
  check_wire(bounded.next(out), WireStatus::ASSEMBLY_LIMIT_EXCEEDED, "bound-next", __FILE__,
             __LINE__);
  // The failure is sticky until the caller resets the assembler; appending more
  // bytes afterwards never revives it.
  bounded.append(frame.data(), frame.size());
  check_wire(bounded.next(out), WireStatus::ASSEMBLY_LIMIT_EXCEEDED, "bound-sticky", __FILE__,
             __LINE__);
  bounded.clear();
  check_wire(bounded.status(), WireStatus::OK, "bound-cleared", __FILE__, __LINE__);
  PD_CHECK_EQ(bounded.buffered(), std::size_t{0});
  bounded.append(frame.data(), frame.size());
  check_wire(bounded.next(out), WireStatus::OK, "bound-recovered", __FILE__, __LINE__);

  // A fatal frame failure is sticky in exactly the same way.
  FrameAssembler broken(limits);
  std::vector<std::uint8_t> bad = frame;
  bad[0] = 0x00U;
  broken.append(bad.data(), bad.size());
  check_wire(broken.next(out), WireStatus::BAD_MAGIC, "broken-magic", __FILE__, __LINE__);
  check_wire(broken.status(), WireStatus::BAD_MAGIC, "broken-sticky", __FILE__, __LINE__);
  check_wire(broken.next(out), WireStatus::BAD_MAGIC, "broken-next", __FILE__, __LINE__);
  broken.clear();
  check_wire(broken.status(), WireStatus::OK, "broken-cleared", __FILE__, __LINE__);
}

PD_TEST(payload_enums_and_counts_are_validated) {
  const Limits limits;
  const CommittedProof committed = make_committed_proof();

  // QUERY selector.
  const std::uint8_t bad_selectors[3] = {6, 200, 255};
  for (std::uint8_t selector : bad_selectors) {
    const std::vector<std::uint8_t> bytes = query_bytes(committed, selector, 3U);
    QueryPayload decoded;
    ByteReader reader(bytes.data(), bytes.size());
    check_decode(decode_query(reader, limits, decoded), DecodeStatus::INVALID_ENCODING, "selector",
                 __FILE__, __LINE__);
  }
  // QUERY entity kind.
  const std::uint8_t bad_kinds[3] = {0, 5, 255};
  for (std::uint8_t kind : bad_kinds) {
    const std::vector<std::uint8_t> bytes = query_bytes(committed, 0U, kind);
    QueryPayload decoded;
    ByteReader reader(bytes.data(), bytes.size());
    check_decode(decode_query(reader, limits, decoded), DecodeStatus::INVALID_ENCODING, "kind",
                 __FILE__, __LINE__);
  }
  // The same helper produces an accepted query once both fields are defined.
  {
    const std::vector<std::uint8_t> bytes = query_bytes(committed, 0U, 3U);
    QueryPayload decoded;
    ByteReader reader(bytes.data(), bytes.size());
    check_decode(decode_query(reader, limits, decoded), DecodeStatus::OK, "kind-ok", __FILE__,
                 __LINE__);
    PD_CHECK(reader.at_end());
    PD_CHECK(decoded.path.valid());
    PD_CHECK(decoded.domain.valid());
    PD_CHECK(decoded.policy.valid());
  }
  // A selector-only query leaves its optional identities unset, which the codec
  // must accept and round-trip.
  {
    const std::vector<std::uint8_t> bytes = selector_only_query_bytes(5U, 2U);
    QueryPayload decoded;
    ByteReader reader(bytes.data(), bytes.size());
    check_decode(decode_query(reader, limits, decoded), DecodeStatus::OK, "selector-only", __FILE__,
                 __LINE__);
    PD_CHECK(reader.at_end());
    PD_CHECK(!decoded.path.valid());
    PD_CHECK(!decoded.domain.valid());
    PD_CHECK(!decoded.policy.valid());
    PD_CHECK_EQ(static_cast<int>(decoded.selector), 5);
  }

  // ERROR_REPLY status.
  const std::uint8_t bad_wire_status[3] = {0, 12, 255};
  for (std::uint8_t raw : bad_wire_status) {
    ByteWriter writer;
    writer.u8(raw);
    writer.text("detail");
    ErrorPayload decoded;
    ByteReader reader(writer.data().data(), writer.size());
    check_decode(decode_error(reader, limits, decoded), DecodeStatus::INVALID_ENCODING,
                 "error-status", __FILE__, __LINE__);
  }

  // MUTATION_RESULT status.
  const std::uint8_t bad_mutation_status[3] = {0, 15, 255};
  for (std::uint8_t raw : bad_mutation_status) {
    ByteWriter writer;
    writer.u8(raw);
    writer.text("detail");
    writer.boolean(false);
    MutationResultPayload decoded;
    ByteReader reader(writer.data().data(), writer.size());
    check_decode(decode_mutation_result(reader, limits, decoded), DecodeStatus::INVALID_ENCODING,
                 "mutation-status", __FILE__, __LINE__);
  }

  // ACTING_AUTHORITY epoch marker.
  {
    ByteWriter writer;
    writer.text("epoch-maybe");
    writer.u64(1);
    writer.text(committed.publisher.view());
    writer.text(committed.boot.view());
    writer.text(default_scope().view());
    writer.text(committed.authority.attempt.view());
    writer.u64(0);
    writer.u64(0);
    ActingAuthority decoded;
    ByteReader reader(writer.data().data(), writer.size());
    check_decode(decode_acting_authority(reader, limits, decoded), DecodeStatus::INVALID_ENCODING,
                 "authority-marker", __FILE__, __LINE__);
  }

  // A policy that carries an undefined class encoding.
  {
    DiversityPolicy policy = committed.policy;
    policy.required_classes.front() = static_cast<DiversityClass>(200);
    ByteWriter writer;
    encode_policy(writer, policy);
    DiversityPolicy decoded;
    ByteReader reader(writer.data().data(), writer.size());
    check_decode(decode_policy(reader, limits, decoded), DecodeStatus::INVALID_ENCODING,
                 "policy-class", __FILE__, __LINE__);
  }

  // A query result that claims fewer total proofs than it carries.
  {
    QueryResultPayload payload;
    payload.proofs = {committed.proof.id};
    payload.total = 0;
    ByteWriter writer;
    encode_query_result(writer, payload);
    QueryResultPayload decoded;
    ByteReader reader(writer.data().data(), writer.size());
    check_decode(decode_query_result(reader, limits, decoded), DecodeStatus::INVALID_ENCODING,
                 "query-total", __FILE__, __LINE__);
  }
}

PD_TEST(payload_length_is_validated_against_its_own_record) {
  const Limits limits;
  const CommittedProof committed = make_committed_proof();
  const MessageId messages[7] = {MessageId::HELLO,          MessageId::PUBLISH_POLICY,
                                 MessageId::PUBLISH_PROOF,  MessageId::REVALIDATE,
                                 MessageId::QUERY,           MessageId::QUERY_RESULT,
                                 MessageId::ERROR_REPLY};
  for (MessageId message : messages) {
    const std::vector<std::uint8_t> payload = payload_for(message, committed);
    std::vector<std::uint8_t> extended = payload;
    extended.push_back(0x7fU);
    ByteReader reader(extended.data(), extended.size());
    // The codec decodes its own record; the end-of-input rule belongs to the
    // protocol layer, which refuses every payload that leaves bytes behind.
    switch (message) {
      case MessageId::HELLO: {
        HelloPayload value;
        check_decode(decode_hello(reader, limits, value), DecodeStatus::OK, "hello-extra",
                     __FILE__, __LINE__);
        break;
      }
      case MessageId::PUBLISH_POLICY: {
        PublishPolicyPayload value;
        check_decode(decode_publish_policy(reader, limits, value), DecodeStatus::OK,
                     "policy-extra", __FILE__, __LINE__);
        break;
      }
      case MessageId::PUBLISH_PROOF: {
        MutationResultPayload value;
        check_decode(decode_mutation_result(reader, limits, value), DecodeStatus::OK,
                     "proof-extra", __FILE__, __LINE__);
        break;
      }
      case MessageId::REVALIDATE: {
        RevalidatePayload value;
        check_decode(decode_revalidate(reader, limits, value), DecodeStatus::OK,
                     "revalidate-extra", __FILE__, __LINE__);
        break;
      }
      case MessageId::QUERY: {
        QueryPayload value;
        check_decode(decode_query(reader, limits, value), DecodeStatus::OK, "query-extra",
                     __FILE__, __LINE__);
        break;
      }
      case MessageId::QUERY_RESULT: {
        QueryResultPayload value;
        check_decode(decode_query_result(reader, limits, value), DecodeStatus::OK, "result-extra",
                     __FILE__, __LINE__);
        break;
      }
      default: {
        ErrorPayload value;
        check_decode(decode_error(reader, limits, value), DecodeStatus::OK, "error-extra",
                     __FILE__, __LINE__);
        break;
      }
    }
    PD_CHECK(!reader.at_end());
    PD_CHECK_EQ(reader.remaining(), std::size_t{1});
  }

  // The complementary rule: a record that lost a byte is truncated.
  const std::vector<std::uint8_t> hello = payload_for(MessageId::HELLO, committed);
  const std::vector<std::uint8_t> shortened(hello.begin(), hello.end() - 1);
  ByteReader short_reader(shortened.data(), shortened.size());
  HelloPayload decoded;
  // Losing one byte leaves the last length prefix promising more bytes than the
  // record carries, which is reported as a length overrun rather than as a
  // clean end of input.
  check_decode(decode_hello(short_reader, limits, decoded), DecodeStatus::LENGTH_OVERRUN,
               "hello-short", __FILE__, __LINE__);

  // The frame itself is still well formed: framing and body validation are
  // separate layers, and the frame layer never interprets the body.
  std::vector<std::uint8_t> padded = hello;
  padded.push_back(0x00U);
  const std::vector<std::uint8_t> frame = encode_frame(MessageId::HELLO, padded, limits);
  WireFrame out;
  check_wire(decode_frame(frame.data(), frame.size(), limits, out), WireStatus::OK, "padded-frame",
             __FILE__, __LINE__);
  PD_CHECK_EQ(out.payload.size(), hello.size() + 1);
}

PD_TEST_MAIN()
