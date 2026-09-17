// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include <atomic>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <utility>
#include <vector>

#include "path_diversity/canonical.hpp"
#include "path_diversity/persistence.hpp"
#include "path_diversity/version.hpp"

#if defined(_WIN32)
#if !defined(WIN32_LEAN_AND_MEAN)
#define WIN32_LEAN_AND_MEAN
#endif
#include <process.h>
#else
#include <unistd.h>
#endif

namespace path_diversity {

namespace {

constexpr char kStoreMagic[8] = {'P', 'D', 'F', 'S', 'T', 'O', 'R', 'E'};
constexpr std::size_t kStoreTrailerBytes = 8;

void write_id_text(ByteWriter& writer, std::string_view text) { writer.text(text); }

bool read_identifier(ByteReader& reader, const Limits& limits, std::string& out) {
  return reader.text(out, limits.max_identity_length);
}

// A record-level decode failure keeps the exact corruption class its decoder
// recognised; anything the decoder could not classify stays conservatively
// generic. The mapping itself lives in the library so a caller can test it
// directly.
PersistenceStatus from_decode(DecodeStatus status, const DecodeFailure& failure) {
  return persistence_status_for(status, failure);
}

// Records the exact corruption class and fails the reader, mirroring the helper
// the record codecs use.
DecodeStatus fail(ByteReader& reader, DecodeFailure* failure, PersistenceStatus status) {
  if (failure != nullptr) {
    failure->classify(status);
  }
  reader.fail(DecodeStatus::INVALID_ENCODING);
  return DecodeStatus::INVALID_ENCODING;
}

}  // namespace

std::string_view to_string(PersistenceStatus value) noexcept {
  switch (value) {
    case PersistenceStatus::OK:
      return "OK";
    case PersistenceStatus::EMPTY_FILE:
      return "EMPTY_FILE";
    case PersistenceStatus::MALFORMED_MAGIC:
      return "MALFORMED_MAGIC";
    case PersistenceStatus::UNSUPPORTED_VERSION:
      return "UNSUPPORTED_VERSION";
    case PersistenceStatus::TRUNCATED:
      return "TRUNCATED";
    case PersistenceStatus::INTEGRITY_FAILURE:
      return "INTEGRITY_FAILURE";
    case PersistenceStatus::TRAILING_BYTES:
      return "TRAILING_BYTES";
    case PersistenceStatus::RECORD_LIMIT_EXCEEDED:
      return "RECORD_LIMIT_EXCEEDED";
    case PersistenceStatus::SIZE_LIMIT_EXCEEDED:
      return "SIZE_LIMIT_EXCEEDED";
    case PersistenceStatus::DUPLICATE_PATH:
      return "DUPLICATE_PATH";
    case PersistenceStatus::MALFORMED_IDENTITY:
      return "MALFORMED_IDENTITY";
    case PersistenceStatus::INVALID_ENUM:
      return "INVALID_ENUM";
    case PersistenceStatus::IMPOSSIBLE_GENERATION:
      return "IMPOSSIBLE_GENERATION";
    case PersistenceStatus::MATRIX_DIMENSION_MISMATCH:
      return "MATRIX_DIMENSION_MISMATCH";
    case PersistenceStatus::UNKNOWN_REFERENCE:
      return "UNKNOWN_REFERENCE";
    case PersistenceStatus::INCOMPLETE_EVIDENCE_CLAIM:
      return "INCOMPLETE_EVIDENCE_CLAIM";
    case PersistenceStatus::INVALID_WITNESS:
      return "INVALID_WITNESS";
    case PersistenceStatus::ABSURD_COUNT:
      return "ABSURD_COUNT";
    case PersistenceStatus::ARITHMETIC_OVERFLOW:
      return "ARITHMETIC_OVERFLOW";
    case PersistenceStatus::IO_FAILURE:
      return "IO_FAILURE";
    case PersistenceStatus::ATOMIC_REPLACE_FAILURE:
      return "ATOMIC_REPLACE_FAILURE";
    case PersistenceStatus::LIMIT_EXCEEDED:
      return "LIMIT_EXCEEDED";
    case PersistenceStatus::INTERNAL_INCONSISTENCY:
      return "INTERNAL_INCONSISTENCY";
  }
  return "UNKNOWN";
}

bool is_defined_persistence_status(std::uint8_t raw) noexcept {
  return raw >= static_cast<std::uint8_t>(PersistenceStatus::OK) &&
         raw <= static_cast<std::uint8_t>(PersistenceStatus::INTERNAL_INCONSISTENCY);
}

// ---------------------------------------------------------------------------
// Snapshot codec
// ---------------------------------------------------------------------------
namespace {

void encode_class_list(ByteWriter& writer, const std::vector<ClassResult>& classes) {
  writer.varint(classes.size());
  for (const ClassResult& result : classes) {
    writer.u8(static_cast<std::uint8_t>(result.klass));
    writer.u8(static_cast<std::uint8_t>(result.outcome));
    writer.boolean(result.evidence_complete);
    writer.varint(result.shared.size());
    for (const SharedResource& conflict : result.shared) {
      conflict.encode(writer);
    }
    writer.u64(result.shared_total);
    writer.text(result.detail);
  }
}

DecodeStatus decode_class_list(ByteReader& reader, const Limits& limits,
                               std::vector<ClassResult>& out, DecodeFailure* failure) {
  std::uint64_t count = 0;
  if (!reader.varint(count)) {
    return reader.status();
  }
  if (count > limits.max_required_classes) {
    reader.fail(DecodeStatus::LIMIT_EXCEEDED);
    return DecodeStatus::LIMIT_EXCEEDED;
  }
  out.clear();
  for (std::uint64_t i = 0; i < count; ++i) {
    ClassResult result;
    std::uint8_t klass = 0;
    std::uint8_t outcome = 0;
    if (!reader.u8(klass) || !reader.u8(outcome)) {
      return reader.status();
    }
    if (!is_defined_diversity_class(klass) || !is_defined_proof_outcome(outcome)) {
      return fail(reader, failure, PersistenceStatus::INVALID_ENUM);
    }
    result.klass = static_cast<DiversityClass>(klass);
    result.outcome = static_cast<ProofOutcome>(outcome);
    if (!reader.boolean(result.evidence_complete)) {
      return reader.status();
    }
    std::uint64_t conflicts = 0;
    if (!reader.varint(conflicts)) {
      return reader.status();
    }
    if (conflicts > limits.max_conflicts_per_proof) {
      reader.fail(DecodeStatus::LIMIT_EXCEEDED);
      return DecodeStatus::LIMIT_EXCEEDED;
    }
    for (std::uint64_t k = 0; k < conflicts; ++k) {
      std::uint8_t kind = 0;
      std::uint8_t relation = 0;
      if (!reader.u8(kind) || !reader.u8(relation)) {
        return reader.status();
      }
      if (!is_defined_conflict_class(kind) || !is_defined_domain_relation(relation)) {
        return fail(reader, failure, PersistenceStatus::INVALID_ENUM);
      }
      SharedResource conflict;
      conflict.kind = static_cast<ConflictClass>(kind);
      conflict.relation = static_cast<DomainRelation>(relation);
      if (!reader.text(conflict.id, limits.max_identity_length)) {
        return reader.status();
      }
      std::uint64_t path_count = 0;
      if (!reader.varint(path_count)) {
        return reader.status();
      }
      if (path_count > limits.max_paths_per_proof) {
        reader.fail(DecodeStatus::LIMIT_EXCEEDED);
        return DecodeStatus::LIMIT_EXCEEDED;
      }
      for (std::uint64_t p = 0; p < path_count; ++p) {
        std::uint64_t index = 0;
        if (!reader.varint(index)) {
          return reader.status();
        }
        if (index > static_cast<std::uint64_t>(0xffffffffULL)) {
          return fail(reader, failure, PersistenceStatus::ARITHMETIC_OVERFLOW);
        }
        conflict.paths.push_back(static_cast<std::uint32_t>(index));
      }
      result.shared.push_back(std::move(conflict));
    }
    if (!reader.u64(result.shared_total)) {
      return reader.status();
    }
    if (!reader.text(result.detail, limits.max_persistence_record_bytes / 4U)) {
      return reader.status();
    }
    out.push_back(std::move(result));
  }
  return DecodeStatus::OK;
}

void encode_dependency_binding(ByteWriter& writer, const DependencyBinding& value) {
  writer.u64(value.policy_generation.value());
  writer.u64(value.topology_generation.value());
  writer.u64(value.failure_domain_generation.value());
  writer.u64(value.epoch.value());
  writer.u8(static_cast<std::uint8_t>(value.endpoint_exemption));
  writer.varint(value.paths.size());
  for (const PathAuthorityBinding& binding : value.paths) {
    write_id_text(writer, binding.path.view());
    writer.u64(binding.generation.value());
  }
  writer.varint(value.topology_entities.size());
  for (const EntityRef& entity : value.topology_entities) {
    writer.u8(static_cast<std::uint8_t>(entity.kind));
    writer.text(entity.id);
  }
}

DecodeStatus decode_dependency_binding(ByteReader& reader, const Limits& limits,
                                       DependencyBinding& out, DecodeFailure* failure) {
  std::uint64_t policy = 0;
  std::uint64_t topology = 0;
  std::uint64_t domains = 0;
  std::uint64_t epoch = 0;
  if (!reader.u64(policy) || !reader.u64(topology) || !reader.u64(domains) || !reader.u64(epoch)) {
    return reader.status();
  }
  out.policy_generation = DiversityPolicyGeneration::from_value(policy);
  out.topology_generation = TopologyGeneration::from_value(topology);
  out.failure_domain_generation = FailureDomainGeneration::from_value(domains);
  out.epoch = CoordinatorEpoch::from_value(epoch);
  std::uint8_t exemption = 0;
  if (!reader.u8(exemption)) {
    return reader.status();
  }
  if (!is_defined_endpoint_exemption(exemption)) {
    return fail(reader, failure, PersistenceStatus::INVALID_ENUM);
  }
  out.endpoint_exemption = static_cast<EndpointExemption>(exemption);
  std::uint64_t path_count = 0;
  if (!reader.varint(path_count)) {
    return reader.status();
  }
  if (path_count > limits.max_paths_per_proof) {
    reader.fail(DecodeStatus::LIMIT_EXCEEDED);
    return DecodeStatus::LIMIT_EXCEEDED;
  }
  for (std::uint64_t i = 0; i < path_count; ++i) {
    PathAuthorityBinding binding;
    std::string text;
    if (!read_identifier(reader, limits, text)) {
      return reader.status();
    }
    const auto parsed = PathId::from_wire(text);
    if (!parsed.has_value()) {
      return fail(reader, failure, PersistenceStatus::MALFORMED_IDENTITY);
    }
    binding.path = *parsed;
    std::uint64_t generation = 0;
    if (!reader.u64(generation)) {
      return reader.status();
    }
    binding.generation = PathAuthorityGeneration::from_value(generation);
    out.paths.push_back(std::move(binding));
  }
  std::uint64_t entity_count = 0;
  if (!reader.varint(entity_count)) {
    return reader.status();
  }
  if (entity_count > limits.max_topology_dependencies) {
    reader.fail(DecodeStatus::LIMIT_EXCEEDED);
    return DecodeStatus::LIMIT_EXCEEDED;
  }
  for (std::uint64_t i = 0; i < entity_count; ++i) {
    std::uint8_t kind = 0;
    if (!reader.u8(kind)) {
      return reader.status();
    }
    if (!is_defined_entity_kind(kind)) {
      return fail(reader, failure, PersistenceStatus::INVALID_ENUM);
    }
    EntityRef entity;
    entity.kind = static_cast<EntityKind>(kind);
    if (!reader.text(entity.id, limits.max_identity_length)) {
      return reader.status();
    }
    out.topology_entities.push_back(std::move(entity));
  }
  return DecodeStatus::OK;
}

}  // namespace

void encode_snapshot(ByteWriter& writer, const ProofSnapshot& snapshot) {
  write_id_text(writer, snapshot.id.view());
  write_id_text(writer, snapshot.proof.view());
  writer.u64(snapshot.generation.value());
  write_id_text(writer, snapshot.policy.view());
  writer.u64(snapshot.policy_generation.value());
  writer.varint(snapshot.paths.size());
  for (const PathRef& reference : snapshot.paths) {
    write_id_text(writer, reference.path.view());
    writer.u64(reference.authority_generation.value());
  }
  writer.u8(static_cast<std::uint8_t>(snapshot.outcome));
  encode_class_list(writer, snapshot.classes);
  writer.varint(snapshot.conflicts.size());
  for (const SharedResource& conflict : snapshot.conflicts) {
    conflict.encode(writer);
  }
  writer.boolean(snapshot.witness.present);
  writer.varint(snapshot.witness.requested_k);
  writer.varint(snapshot.witness.achieved);
  writer.boolean(snapshot.witness.maximum_exact);
  writer.varint(snapshot.witness.indices.size());
  for (std::uint32_t index : snapshot.witness.indices) {
    writer.varint(index);
  }
  encode_dependency_binding(writer, snapshot.dependencies);
  writer.u8(static_cast<std::uint8_t>(snapshot.lifecycle));
  writer.u8(static_cast<std::uint8_t>(snapshot.currentness));
  writer.u64(snapshot.provenance.epoch.value());
  write_id_text(writer, snapshot.provenance.publisher.view());
  write_id_text(writer, snapshot.provenance.boot.view());
  write_id_text(writer, snapshot.provenance.attempt.view());
  writer.bytes(snapshot.digest.bytes().data(), snapshot.digest.bytes().size());
}

DecodeStatus decode_snapshot(ByteReader& reader, const Limits& limits, ProofSnapshot& out,
                             DecodeFailure* failure) {
  std::string text;
  if (!read_identifier(reader, limits, text)) {
    return reader.status();
  }
  const auto id = SnapshotId::from_wire(text);
  if (!id.has_value()) {
    return fail(reader, failure, PersistenceStatus::MALFORMED_IDENTITY);
  }
  out.id = *id;
  if (!read_identifier(reader, limits, text)) {
    return reader.status();
  }
  const auto proof = DiversityProofId::from_wire(text);
  if (!proof.has_value()) {
    return fail(reader, failure, PersistenceStatus::MALFORMED_IDENTITY);
  }
  out.proof = *proof;
  std::uint64_t generation = 0;
  if (!reader.u64(generation)) {
    return reader.status();
  }
  out.generation = DiversityProofGeneration::from_value(generation);
  if (!read_identifier(reader, limits, text)) {
    return reader.status();
  }
  const auto policy = DiversityPolicyId::from_wire(text);
  if (!policy.has_value()) {
    return fail(reader, failure, PersistenceStatus::MALFORMED_IDENTITY);
  }
  out.policy = *policy;
  std::uint64_t policy_generation = 0;
  if (!reader.u64(policy_generation)) {
    return reader.status();
  }
  out.policy_generation = DiversityPolicyGeneration::from_value(policy_generation);
  std::uint64_t path_count = 0;
  if (!reader.varint(path_count)) {
    return reader.status();
  }
  if (path_count > limits.max_snapshot_paths) {
    reader.fail(DecodeStatus::LIMIT_EXCEEDED);
    return DecodeStatus::LIMIT_EXCEEDED;
  }
  out.paths.clear();
  for (std::uint64_t i = 0; i < path_count; ++i) {
    PathRef reference;
    if (!read_identifier(reader, limits, text)) {
      return reader.status();
    }
    const auto parsed = PathId::from_wire(text);
    if (!parsed.has_value()) {
      return fail(reader, failure, PersistenceStatus::MALFORMED_IDENTITY);
    }
    reference.path = *parsed;
    std::uint64_t authority = 0;
    if (!reader.u64(authority)) {
      return reader.status();
    }
    reference.authority_generation = PathAuthorityGeneration::from_value(authority);
    out.paths.push_back(std::move(reference));
  }
  std::uint8_t outcome = 0;
  if (!reader.u8(outcome)) {
    return reader.status();
  }
  if (!is_defined_proof_outcome(outcome)) {
    return fail(reader, failure, PersistenceStatus::INVALID_ENUM);
  }
  out.outcome = static_cast<ProofOutcome>(outcome);
  DecodeStatus status = decode_class_list(reader, limits, out.classes, failure);
  if (status != DecodeStatus::OK) {
    return status;
  }
  std::uint64_t conflicts = 0;
  if (!reader.varint(conflicts)) {
    return reader.status();
  }
  if (conflicts > limits.max_conflicts_per_proof) {
    reader.fail(DecodeStatus::LIMIT_EXCEEDED);
    return DecodeStatus::LIMIT_EXCEEDED;
  }
  out.conflicts.clear();
  for (std::uint64_t i = 0; i < conflicts; ++i) {
    std::uint8_t kind = 0;
    std::uint8_t relation = 0;
    if (!reader.u8(kind) || !reader.u8(relation)) {
      return reader.status();
    }
    if (!is_defined_conflict_class(kind) || !is_defined_domain_relation(relation)) {
      return fail(reader, failure, PersistenceStatus::INVALID_ENUM);
    }
    SharedResource conflict;
    conflict.kind = static_cast<ConflictClass>(kind);
    conflict.relation = static_cast<DomainRelation>(relation);
    if (!reader.text(conflict.id, limits.max_identity_length)) {
      return reader.status();
    }
    std::uint64_t count = 0;
    if (!reader.varint(count)) {
      return reader.status();
    }
    if (count > limits.max_paths_per_proof) {
      reader.fail(DecodeStatus::LIMIT_EXCEEDED);
      return DecodeStatus::LIMIT_EXCEEDED;
    }
    for (std::uint64_t p = 0; p < count; ++p) {
      std::uint64_t index = 0;
      if (!reader.varint(index)) {
        return reader.status();
      }
      if (index >= path_count) {
        return fail(reader, failure, PersistenceStatus::UNKNOWN_REFERENCE);
      }
      conflict.paths.push_back(static_cast<std::uint32_t>(index));
    }
    out.conflicts.push_back(std::move(conflict));
  }
  if (!reader.boolean(out.witness.present)) {
    return reader.status();
  }
  std::uint64_t requested = 0;
  std::uint64_t achieved = 0;
  if (!reader.varint(requested) || !reader.varint(achieved)) {
    return reader.status();
  }
  if (!reader.boolean(out.witness.maximum_exact)) {
    return reader.status();
  }
  out.witness.requested_k = static_cast<std::uint32_t>(requested);
  out.witness.achieved = static_cast<std::uint32_t>(achieved);
  std::uint64_t witness_count = 0;
  if (!reader.varint(witness_count)) {
    return reader.status();
  }
  if (witness_count > limits.max_paths_per_proof) {
    reader.fail(DecodeStatus::LIMIT_EXCEEDED);
    return DecodeStatus::LIMIT_EXCEEDED;
  }
  out.witness.indices.clear();
  for (std::uint64_t i = 0; i < witness_count; ++i) {
    std::uint64_t index = 0;
    if (!reader.varint(index)) {
      return reader.status();
    }
    if (index >= path_count) {
      return fail(reader, failure, PersistenceStatus::INVALID_WITNESS);
    }
    out.witness.indices.push_back(static_cast<std::uint32_t>(index));
  }
  status = decode_dependency_binding(reader, limits, out.dependencies, failure);
  if (status != DecodeStatus::OK) {
    return status;
  }
  std::uint8_t lifecycle = 0;
  std::uint8_t currentness = 0;
  if (!reader.u8(lifecycle) || !reader.u8(currentness)) {
    return reader.status();
  }
  if (!is_defined_lifecycle_state(lifecycle) || !is_defined_currentness(currentness)) {
    return fail(reader, failure, PersistenceStatus::INVALID_ENUM);
  }
  out.lifecycle = static_cast<LifecycleState>(lifecycle);
  out.currentness = static_cast<Currentness>(currentness);
  std::uint64_t epoch = 0;
  if (!reader.u64(epoch)) {
    return reader.status();
  }
  out.provenance.epoch = CoordinatorEpoch::from_value(epoch);
  if (!read_identifier(reader, limits, text)) {
    return reader.status();
  }
  const auto publisher = PublisherId::from_wire(text);
  if (!publisher.has_value()) {
    return fail(reader, failure, PersistenceStatus::MALFORMED_IDENTITY);
  }
  out.provenance.publisher = *publisher;
  if (!read_identifier(reader, limits, text)) {
    return reader.status();
  }
  const auto boot = WorkerBootId::from_wire(text);
  if (!boot.has_value()) {
    return fail(reader, failure, PersistenceStatus::MALFORMED_IDENTITY);
  }
  out.provenance.boot = *boot;
  if (!read_identifier(reader, limits, text)) {
    return reader.status();
  }
  const auto attempt = MutationAttemptId::from_wire(text);
  if (!attempt.has_value()) {
    return fail(reader, failure, PersistenceStatus::MALFORMED_IDENTITY);
  }
  out.provenance.attempt = *attempt;

  std::string digest_bytes;
  if (!reader.bytes(digest_bytes, 16)) {
    return reader.status();
  }
  Digest::bytes_type encoded{};
  for (std::size_t i = 0; i < 16; ++i) {
    encoded[i] = static_cast<std::uint8_t>(digest_bytes[i]);
  }
  const Digest decoded(encoded);
  // The decoded digest is never trusted: it is recomputed from the decoded
  // content and a mismatch is a refusal.
  const Digest recomputed = snapshot_digest(out);
  if (!(recomputed == decoded)) {
    // The record's own digest disagrees with its content. No more specific
    // public status names this, so it stays conservatively unclassified.
    return fail(reader, failure, PersistenceStatus::INTERNAL_INCONSISTENCY);
  }
  out.digest = recomputed;
  out.id = derived_snapshot_id(recomputed);
  return DecodeStatus::OK;
}

// ---------------------------------------------------------------------------
// Whole store
// ---------------------------------------------------------------------------
std::vector<std::uint8_t> encode_store(const StoreContents& contents, const Limits& limits) {
  (void)limits;
  ByteWriter writer;
  // The magic is a fixed eight-byte literal with no length prefix: decode_store
  // validates it with a raw comparison against the same array. Writing it
  // through the length-prefixed byte-string helper would emit a leading length
  // varint and make every store this encoder produces unreadable.
  for (std::size_t i = 0; i < sizeof(kStoreMagic); ++i) {
    writer.u8(static_cast<std::uint8_t>(kStoreMagic[i]));
  }
  writer.u32(kPersistenceFormatVersion);
  writer.u64(contents.epoch.value());

  writer.varint(contents.policies.size());
  for (const DiversityPolicy& policy : contents.policies) {
    encode_policy(writer, policy);
  }
  writer.varint(contents.proofs.size());
  for (const DiversityProof& proof : contents.proofs) {
    encode_proof(writer, proof);
  }
  writer.varint(contents.sessions.size());
  for (const PublisherSession& session : contents.sessions) {
    writer.text(session.publisher.view());
    writer.text(session.boot.view());
    writer.u64(session.epoch.value());
    writer.text(session.scope.view());
    writer.boolean(session.fenced);
  }
  writer.varint(contents.fenced_boots.size());
  for (const WorkerBootId& boot : contents.fenced_boots) {
    writer.text(boot.view());
  }
  writer.varint(contents.attempts.size());
  for (const MutationAttemptRecord& attempt : contents.attempts) {
    writer.text(attempt.attempt.view());
    writer.bytes(attempt.payload.bytes().data(), attempt.payload.bytes().size());
    writer.text(attempt.proof.view());
  }
  writer.varint(contents.history.size());
  for (const auto& entry : contents.history) {
    writer.text(entry.first.view());
    writer.varint(entry.second.size());
    for (const DiversityProof& proof : entry.second) {
      encode_proof(writer, proof);
    }
  }
  writer.varint(contents.snapshots.size());
  for (const ProofSnapshot& snapshot : contents.snapshots) {
    encode_snapshot(writer, snapshot);
  }

  const std::uint64_t trailer =
      fnv1a64(writer.data().data(), writer.data().size());
  std::vector<std::uint8_t> out = writer.data();
  for (int i = 0; i < 8; ++i) {
    out.push_back(static_cast<std::uint8_t>((trailer >> (8 * i)) & 0xffULL));
  }
  return out;
}

PersistenceStatus decode_store(const std::uint8_t* data, std::size_t size, const Limits& limits,
                               StoreContents& out, std::string& detail) {
  detail.clear();
  if (data == nullptr || size == 0) {
    detail = "store is empty";
    return PersistenceStatus::EMPTY_FILE;
  }
  if (size > limits.max_store_bytes) {
    detail = "store exceeds max_store_bytes";
    return PersistenceStatus::SIZE_LIMIT_EXCEEDED;
  }
  if (size < sizeof(kStoreMagic) + 4 + 8 + kStoreTrailerBytes) {
    detail = "store is shorter than its fixed header and trailer";
    return PersistenceStatus::TRUNCATED;
  }
  if (std::memcmp(data, kStoreMagic, sizeof(kStoreMagic)) != 0) {
    detail = "store magic does not match";
    return PersistenceStatus::MALFORMED_MAGIC;
  }
  const std::size_t payload_size = size - kStoreTrailerBytes;
  std::uint64_t stored_trailer = 0;
  for (int i = 0; i < 8; ++i) {
    stored_trailer |= static_cast<std::uint64_t>(data[payload_size + static_cast<std::size_t>(i)])
                      << (8 * i);
  }
  const std::uint64_t computed_trailer = fnv1a64(data, payload_size);
  if (stored_trailer != computed_trailer) {
    detail = "integrity trailer does not match the store content";
    return PersistenceStatus::INTEGRITY_FAILURE;
  }

  ByteReader reader(data, payload_size);
  std::uint32_t version = 0;
  {
    const std::size_t skip = sizeof(kStoreMagic);
    for (std::size_t i = 0; i < skip; ++i) {
      std::uint8_t ignored = 0;
      if (!reader.u8(ignored)) {
        return PersistenceStatus::TRUNCATED;
      }
    }
  }
  if (!reader.u32(version)) {
    return PersistenceStatus::TRUNCATED;
  }
  if (version != kPersistenceFormatVersion) {
    detail = "unsupported persistence format version";
    return PersistenceStatus::UNSUPPORTED_VERSION;
  }
  std::uint64_t epoch = 0;
  if (!reader.u64(epoch)) {
    return PersistenceStatus::TRUNCATED;
  }
  out = StoreContents();
  out.epoch = CoordinatorEpoch::from_value(epoch);

  auto read_section_count = [&](const char* what, std::uint32_t& count) -> PersistenceStatus {
    std::uint64_t value = 0;
    if (!reader.varint(value)) {
      detail = std::string("truncated while reading the ") + what + " section count";
      return PersistenceStatus::TRUNCATED;
    }
    if (value > static_cast<std::uint64_t>(limits.max_store_records)) {
      detail = std::string("the ") + what + " section declares more records than a store may hold";
      return PersistenceStatus::RECORD_LIMIT_EXCEEDED;
    }
    if (value > static_cast<std::uint64_t>(payload_size)) {
      detail = std::string("the ") + what + " section declares more records than there are bytes";
      return PersistenceStatus::ABSURD_COUNT;
    }
    count = static_cast<std::uint32_t>(value);
    return PersistenceStatus::OK;
  };

  std::uint32_t count = 0;
  PersistenceStatus section = read_section_count("policy", count);
  if (section != PersistenceStatus::OK) {
    return section;
  }
  for (std::uint32_t i = 0; i < count; ++i) {
    DiversityPolicy policy;
    DecodeFailure failure;
    const DecodeStatus status = decode_policy(reader, limits, policy, &failure);
    if (status != DecodeStatus::OK) {
      detail = "policy record " + std::to_string(i) + " failed to decode (" +
               std::string(to_string(persistence_status_for(status, failure))) + ")";
      return from_decode(status, failure);
    }
    out.policies.push_back(std::move(policy));
  }

  section = read_section_count("proof", count);
  if (section != PersistenceStatus::OK) {
    return section;
  }
  for (std::uint32_t i = 0; i < count; ++i) {
    DiversityProof proof;
    DecodeFailure failure;
    const DecodeStatus status = decode_proof(reader, limits, proof, &failure);
    if (status != DecodeStatus::OK) {
      detail = "proof record " + std::to_string(i) + " failed to decode (" +
               std::string(to_string(persistence_status_for(status, failure))) + ")";
      return from_decode(status, failure);
    }
    out.proofs.push_back(std::move(proof));
  }

  section = read_section_count("session", count);
  if (section != PersistenceStatus::OK) {
    return section;
  }
  for (std::uint32_t i = 0; i < count; ++i) {
    std::string publisher_text;
    std::string boot_text;
    std::string scope_text;
    PublisherSession session;
    std::uint64_t session_epoch = 0;
    if (!reader.text(publisher_text, limits.max_identity_length) ||
        !reader.text(boot_text, limits.max_identity_length) || !reader.u64(session_epoch) ||
        !reader.text(scope_text, limits.max_identity_length) ||
        !reader.boolean(session.fenced)) {
      detail = "session record " + std::to_string(i) + " failed to decode";
      return PersistenceStatus::TRUNCATED;
    }
    const auto publisher = PublisherId::from_wire(publisher_text);
    const auto boot = WorkerBootId::from_wire(boot_text);
    const auto scope = ScopeId::from_wire(scope_text);
    if (!publisher.has_value() || !boot.has_value() || !scope.has_value()) {
      detail = "session record " + std::to_string(i) + " carries a malformed identity";
      return PersistenceStatus::MALFORMED_IDENTITY;
    }
    session.publisher = *publisher;
    session.boot = *boot;
    session.scope = *scope;
    session.epoch = CoordinatorEpoch::from_value(session_epoch);
    out.sessions.push_back(std::move(session));
  }

  section = read_section_count("fenced-boot", count);
  if (section != PersistenceStatus::OK) {
    return section;
  }
  for (std::uint32_t i = 0; i < count; ++i) {
    std::string text;
    if (!reader.text(text, limits.max_identity_length)) {
      detail = "fenced boot record " + std::to_string(i) + " failed to decode";
      return PersistenceStatus::TRUNCATED;
    }
    const auto boot = WorkerBootId::from_wire(text);
    if (!boot.has_value()) {
      detail = "fenced boot record " + std::to_string(i) + " carries a malformed identity";
      return PersistenceStatus::MALFORMED_IDENTITY;
    }
    out.fenced_boots.push_back(*boot);
  }

  section = read_section_count("attempt", count);
  if (section != PersistenceStatus::OK) {
    return section;
  }
  for (std::uint32_t i = 0; i < count; ++i) {
    MutationAttemptRecord record;
    std::string attempt_text;
    std::string digest_text;
    std::string proof_text;
    if (!reader.text(attempt_text, limits.max_identity_length) ||
        !reader.bytes(digest_text, 16) ||
        !reader.text(proof_text, limits.max_identity_length)) {
      detail = "attempt record " + std::to_string(i) + " failed to decode";
      return PersistenceStatus::TRUNCATED;
    }
    const auto attempt = MutationAttemptId::from_wire(attempt_text);
    const auto proof_id = DiversityProofId::from_wire(proof_text);
    if (!attempt.has_value() || !proof_id.has_value()) {
      detail = "attempt record " + std::to_string(i) + " carries a malformed identity";
      return PersistenceStatus::MALFORMED_IDENTITY;
    }
    Digest::bytes_type bytes{};
    for (std::size_t k = 0; k < 16; ++k) {
      bytes[k] = static_cast<std::uint8_t>(digest_text[k]);
    }
    record.attempt = *attempt;
    record.payload = Digest(bytes);
    record.proof = *proof_id;
    out.attempts.push_back(std::move(record));
  }

  section = read_section_count("history", count);
  if (section != PersistenceStatus::OK) {
    return section;
  }
  for (std::uint32_t i = 0; i < count; ++i) {
    std::string text;
    if (!reader.text(text, limits.max_identity_length)) {
      detail = "history record " + std::to_string(i) + " failed to decode";
      return PersistenceStatus::TRUNCATED;
    }
    const auto identity = DiversityProofId::from_wire(text);
    if (!identity.has_value()) {
      detail = "history record " + std::to_string(i) + " carries a malformed identity";
      return PersistenceStatus::MALFORMED_IDENTITY;
    }
    std::uint64_t revisions = 0;
    if (!reader.varint(revisions)) {
      detail = "history record " + std::to_string(i) + " failed to decode";
      return PersistenceStatus::TRUNCATED;
    }
    if (revisions > limits.max_history) {
      detail = "history record " + std::to_string(i) + " exceeds max_history";
      return PersistenceStatus::RECORD_LIMIT_EXCEEDED;
    }
    std::vector<DiversityProof> retained;
    for (std::uint64_t k = 0; k < revisions; ++k) {
      DiversityProof proof;
      DecodeFailure failure;
      const DecodeStatus status = decode_proof(reader, limits, proof, &failure);
      if (status != DecodeStatus::OK) {
        detail = "history revision " + std::to_string(k) + " of record " + std::to_string(i) +
                 " failed to decode (" +
                 std::string(to_string(persistence_status_for(status, failure))) + ")";
        return from_decode(status, failure);
      }
      retained.push_back(std::move(proof));
    }
    out.history.emplace_back(*identity, std::move(retained));
  }

  section = read_section_count("snapshot", count);
  if (section != PersistenceStatus::OK) {
    return section;
  }
  for (std::uint32_t i = 0; i < count; ++i) {
    ProofSnapshot snapshot;
    DecodeFailure failure;
    const DecodeStatus status = decode_snapshot(reader, limits, snapshot, &failure);
    if (status != DecodeStatus::OK) {
      detail = "snapshot record " + std::to_string(i) + " failed to decode (" +
               std::string(to_string(persistence_status_for(status, failure))) + ")";
      return from_decode(status, failure);
    }
    out.snapshots.push_back(std::move(snapshot));
  }

  if (!reader.at_end()) {
    detail = "store carries trailing bytes after the last section";
    return PersistenceStatus::TRAILING_BYTES;
  }
  return PersistenceStatus::OK;
}

PersistenceStatus write_store_atomic(const std::string& path,
                                     const std::vector<std::uint8_t>& bytes) {
  static std::atomic<std::uint64_t> serial{0};
  const std::uint64_t tag = serial.fetch_add(1) + 1;
#if defined(_WIN32)
  const long process = static_cast<long>(_getpid());
#else
  const long process = static_cast<long>(getpid());
#endif
  const std::filesystem::path target(path);
  const std::filesystem::path temporary =
      target.parent_path() /
      (target.filename().string() + ".tmp-" + std::to_string(process) + "-" + std::to_string(tag));
  {
    std::ofstream stream(temporary, std::ios::binary | std::ios::trunc);
    if (!stream.is_open()) {
      return PersistenceStatus::IO_FAILURE;
    }
    if (!bytes.empty()) {
      stream.write(reinterpret_cast<const char*>(bytes.data()),
                   static_cast<std::streamsize>(bytes.size()));
    }
    stream.flush();
    if (!stream.good()) {
      stream.close();
      std::error_code ignored;
      std::filesystem::remove(temporary, ignored);
      return PersistenceStatus::IO_FAILURE;
    }
  }
  std::error_code error;
  std::filesystem::rename(temporary, target, error);
  if (error) {
    std::error_code ignored;
    std::filesystem::remove(temporary, ignored);
    return PersistenceStatus::ATOMIC_REPLACE_FAILURE;
  }
  return PersistenceStatus::OK;
}

PersistenceStatus read_store_bytes(const std::string& path, const Limits& limits,
                                   std::vector<std::uint8_t>& out) {
  std::error_code error;
  const std::uintmax_t size = std::filesystem::file_size(path, error);
  if (error) {
    return PersistenceStatus::IO_FAILURE;
  }
  if (size == 0) {
    return PersistenceStatus::EMPTY_FILE;
  }
  if (size > limits.max_store_bytes) {
    return PersistenceStatus::SIZE_LIMIT_EXCEEDED;
  }
  std::ifstream stream(path, std::ios::binary);
  if (!stream.is_open()) {
    return PersistenceStatus::IO_FAILURE;
  }
  out.assign(static_cast<std::size_t>(size), 0);
  stream.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(size));
  if (stream.gcount() != static_cast<std::streamsize>(size)) {
    return PersistenceStatus::IO_FAILURE;
  }
  return PersistenceStatus::OK;
}

}  // namespace path_diversity
