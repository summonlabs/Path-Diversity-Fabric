// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include <string>
#include <utility>
#include <vector>

#include "path_diversity/persistence.hpp"

namespace path_diversity {

namespace {

template <class Id>
DecodeStatus read_id(ByteReader& reader, const Limits& limits, Id& out) {
  std::string text;
  const std::size_t bound = limits.max_identity_length < Id::max_length
                                ? limits.max_identity_length
                                : Id::max_length;
  if (!reader.text(text, bound)) {
    return reader.status() == DecodeStatus::LIMIT_EXCEEDED ? DecodeStatus::LIMIT_EXCEEDED
                                                           : reader.status();
  }
  const auto parsed = Id::from_wire(text);
  if (!parsed.has_value()) {
    reader.fail(DecodeStatus::INVALID_ENCODING);
    return DecodeStatus::INVALID_ENCODING;
  }
  out = *parsed;
  return DecodeStatus::OK;
}

template <class Id>
void write_id(ByteWriter& writer, const Id& value) {
  writer.text(value.view());
}

// Reads a bounded count. The bound is supplied by the caller, which is the only
// place that knows which limit applies to the collection being read.
DecodeStatus read_count(ByteReader& reader, std::uint32_t max_allowed, std::uint32_t& out) {
  std::uint64_t value = 0;
  if (!reader.varint(value)) {
    return reader.status();
  }
  if (value > static_cast<std::uint64_t>(max_allowed)) {
    reader.fail(DecodeStatus::LIMIT_EXCEEDED);
    return DecodeStatus::LIMIT_EXCEEDED;
  }
  out = static_cast<std::uint32_t>(value);
  return DecodeStatus::OK;
}

void write_conflict(ByteWriter& writer, const SharedResource& conflict) { conflict.encode(writer); }

DecodeStatus read_conflict(ByteReader& reader, const Limits& limits, SharedResource& out) {
  std::uint8_t kind = 0;
  if (!reader.u8(kind)) {
    return reader.status();
  }
  std::uint8_t relation = 0;
  if (!reader.u8(relation)) {
    return reader.status();
  }
  if (!is_defined_conflict_class(kind) || !is_defined_domain_relation(relation)) {
    reader.fail(DecodeStatus::INVALID_ENCODING);
    return DecodeStatus::INVALID_ENCODING;
  }
  out.kind = static_cast<ConflictClass>(kind);
  out.relation = static_cast<DomainRelation>(relation);
  if (!reader.text(out.id, limits.max_identity_length)) {
    return reader.status();
  }
  std::uint32_t count = 0;
  if (read_count(reader, limits.max_paths_per_proof, count) != DecodeStatus::OK) {
    return reader.status();
  }
  out.paths.clear();
  for (std::uint32_t i = 0; i < count; ++i) {
    std::uint64_t index = 0;
    if (!reader.varint(index)) {
      return reader.status();
    }
    if (index > 0xffffffffULL) {
      reader.fail(DecodeStatus::INVALID_ENCODING);
      return DecodeStatus::INVALID_ENCODING;
    }
    out.paths.push_back(static_cast<std::uint32_t>(index));
  }
  return DecodeStatus::OK;
}

void write_class(ByteWriter& writer, const ClassResult& result) {
  writer.u8(static_cast<std::uint8_t>(result.klass));
  writer.u8(static_cast<std::uint8_t>(result.outcome));
  writer.boolean(result.evidence_complete);
  writer.varint(result.shared.size());
  for (const SharedResource& conflict : result.shared) {
    write_conflict(writer, conflict);
  }
  writer.u64(result.shared_total);
  writer.text(result.detail);
}

DecodeStatus read_class(ByteReader& reader, const Limits& limits, ClassResult& out) {
  std::uint8_t klass = 0;
  if (!reader.u8(klass)) {
    return reader.status();
  }
  std::uint8_t outcome = 0;
  if (!reader.u8(outcome)) {
    return reader.status();
  }
  if (!is_defined_diversity_class(klass) || !is_defined_proof_outcome(outcome)) {
    reader.fail(DecodeStatus::INVALID_ENCODING);
    return DecodeStatus::INVALID_ENCODING;
  }
  out.klass = static_cast<DiversityClass>(klass);
  out.outcome = static_cast<ProofOutcome>(outcome);
  if (!reader.boolean(out.evidence_complete)) {
    return reader.status();
  }
  std::uint32_t count = 0;
  if (read_count(reader, limits.max_conflicts_per_proof, count) != DecodeStatus::OK) {
    return reader.status();
  }
  out.shared.clear();
  for (std::uint32_t i = 0; i < count; ++i) {
    SharedResource conflict;
    const DecodeStatus status = read_conflict(reader, limits, conflict);
    if (status != DecodeStatus::OK) {
      return status;
    }
    out.shared.push_back(std::move(conflict));
  }
  if (!reader.u64(out.shared_total)) {
    return reader.status();
  }
  if (out.shared_total < out.shared.size()) {
    reader.fail(DecodeStatus::INVALID_ENCODING);
    return DecodeStatus::INVALID_ENCODING;
  }
  if (!reader.text(out.detail, limits.max_persistence_record_bytes / 4U)) {
    return reader.status();
  }
  if (out.outcome == ProofOutcome::PROVEN_DIVERSE && !out.evidence_complete) {
    // An encoded claim of proven diversity with incomplete evidence is refused
    // rather than trusted.
    reader.fail(DecodeStatus::INVALID_ENCODING);
    return DecodeStatus::INVALID_ENCODING;
  }
  return DecodeStatus::OK;
}

void write_dependencies(ByteWriter& writer, const DependencyBinding& value) {
  writer.u64(value.policy_generation.value());
  writer.u64(value.topology_generation.value());
  writer.u64(value.failure_domain_generation.value());
  writer.u64(value.epoch.value());
  writer.u8(static_cast<std::uint8_t>(value.endpoint_exemption));
  writer.varint(value.paths.size());
  for (const PathAuthorityBinding& binding : value.paths) {
    write_id(writer, binding.path);
    writer.u64(binding.generation.value());
  }
  writer.varint(value.topology_entities.size());
  for (const EntityRef& entity : value.topology_entities) {
    writer.u8(static_cast<std::uint8_t>(entity.kind));
    writer.text(entity.id);
  }
}

DecodeStatus read_dependencies(ByteReader& reader, const Limits& limits, DependencyBinding& out) {
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
    reader.fail(DecodeStatus::INVALID_ENCODING);
    return DecodeStatus::INVALID_ENCODING;
  }
  out.endpoint_exemption = static_cast<EndpointExemption>(exemption);
  std::uint32_t path_count = 0;
  if (read_count(reader, limits.max_paths_per_proof, path_count) != DecodeStatus::OK) {
    return reader.status();
  }
  out.paths.clear();
  for (std::uint32_t i = 0; i < path_count; ++i) {
    PathAuthorityBinding binding;
    const DecodeStatus status = read_id(reader, limits, binding.path);
    if (status != DecodeStatus::OK) {
      return status;
    }
    std::uint64_t generation = 0;
    if (!reader.u64(generation)) {
      return reader.status();
    }
    binding.generation = PathAuthorityGeneration::from_value(generation);
    out.paths.push_back(std::move(binding));
  }
  std::uint32_t entity_count = 0;
  if (read_count(reader, limits.max_topology_dependencies, entity_count) !=
      DecodeStatus::OK) {
    return reader.status();
  }
  out.topology_entities.clear();
  for (std::uint32_t i = 0; i < entity_count; ++i) {
    std::uint8_t kind = 0;
    if (!reader.u8(kind)) {
      return reader.status();
    }
    if (!is_defined_entity_kind(kind)) {
      reader.fail(DecodeStatus::INVALID_ENCODING);
      return DecodeStatus::INVALID_ENCODING;
    }
    EntityRef entity;
    entity.kind = static_cast<EntityKind>(kind);
    if (!reader.text(entity.id, Limits().max_identity_length)) {
      return reader.status();
    }
    out.topology_entities.push_back(std::move(entity));
  }
  return DecodeStatus::OK;
}

void write_witness(ByteWriter& writer, const WitnessSubset& value) {
  writer.boolean(value.present);
  writer.varint(value.requested_k);
  writer.varint(value.achieved);
  writer.boolean(value.maximum_exact);
  writer.varint(value.indices.size());
  for (std::uint32_t index : value.indices) {
    writer.varint(index);
  }
}

DecodeStatus read_witness(ByteReader& reader, const Limits& limits, WitnessSubset& out) {
  if (!reader.boolean(out.present)) {
    return reader.status();
  }
  std::uint64_t requested = 0;
  std::uint64_t achieved = 0;
  if (!reader.varint(requested) || !reader.varint(achieved)) {
    return reader.status();
  }
  if (!reader.boolean(out.maximum_exact)) {
    return reader.status();
  }
  out.requested_k = static_cast<std::uint32_t>(requested);
  out.achieved = static_cast<std::uint32_t>(achieved);
  std::uint32_t count = 0;
  if (read_count(reader, limits.max_paths_per_proof, count) != DecodeStatus::OK) {
    return reader.status();
  }
  out.indices.clear();
  for (std::uint32_t i = 0; i < count; ++i) {
    std::uint64_t index = 0;
    if (!reader.varint(index)) {
      return reader.status();
    }
    out.indices.push_back(static_cast<std::uint32_t>(index));
  }
  // The named subset may be larger than the proven achievement: an evaluation
  // whose outstanding evidence is unresolved names the optimistic witness so a
  // caller can see which paths would be independent once that evidence arrives.
  // A named subset smaller than the proven achievement is a contradiction.
  if (out.indices.size() < out.achieved) {
    reader.fail(DecodeStatus::INVALID_ENCODING);
    return DecodeStatus::INVALID_ENCODING;
  }
  for (std::size_t i = 1; i < out.indices.size(); ++i) {
    if (!(out.indices[i - 1] < out.indices[i])) {
      reader.fail(DecodeStatus::INVALID_ENCODING);
      return DecodeStatus::INVALID_ENCODING;
    }
  }
  return DecodeStatus::OK;
}

}  // namespace

void encode_policy(ByteWriter& writer, const DiversityPolicy& policy) {
  write_id(writer, policy.id);
  writer.u64(policy.generation.value());
  write_id(writer, policy.scope);
  writer.varint(policy.required_classes.size());
  for (DiversityClass klass : policy.required_classes) {
    writer.u8(static_cast<std::uint8_t>(klass));
  }
  writer.u8(static_cast<std::uint8_t>(policy.endpoint_exemption));
  writer.varint(policy.minimum_independent_paths);
  writer.u8(static_cast<std::uint8_t>(policy.semantics));
  writer.u8(static_cast<std::uint8_t>(policy.completeness));
  writer.u8(static_cast<std::uint8_t>(policy.unknown_behavior));
  writer.varint(policy.allowed_failure_domain_relations.size());
  for (DomainRelation relation : policy.allowed_failure_domain_relations) {
    writer.u8(static_cast<std::uint8_t>(relation));
  }
  writer.boolean(policy.require_path_authority_current);
  writer.text(policy.description);
}

DecodeStatus decode_policy(ByteReader& reader, const Limits& limits, DiversityPolicy& out) {
  const DecodeStatus id_status = read_id(reader, limits, out.id);
  if (id_status != DecodeStatus::OK) {
    return id_status;
  }
  std::uint64_t generation = 0;
  if (!reader.u64(generation)) {
    return reader.status();
  }
  out.generation = DiversityPolicyGeneration::from_value(generation);
  const DecodeStatus scope_status = read_id(reader, limits, out.scope);
  if (scope_status != DecodeStatus::OK) {
    return scope_status;
  }
  std::uint32_t class_count = 0;
  if (read_count(reader, limits.max_required_classes, class_count) != DecodeStatus::OK) {
    return reader.status();
  }
  out.required_classes.clear();
  for (std::uint32_t i = 0; i < class_count; ++i) {
    std::uint8_t klass = 0;
    if (!reader.u8(klass)) {
      return reader.status();
    }
    if (!is_defined_diversity_class(klass)) {
      reader.fail(DecodeStatus::INVALID_ENCODING);
      return DecodeStatus::INVALID_ENCODING;
    }
    out.required_classes.push_back(static_cast<DiversityClass>(klass));
  }
  std::uint8_t exemption = 0;
  if (!reader.u8(exemption)) {
    return reader.status();
  }
  if (!is_defined_endpoint_exemption(exemption)) {
    reader.fail(DecodeStatus::INVALID_ENCODING);
    return DecodeStatus::INVALID_ENCODING;
  }
  out.endpoint_exemption = static_cast<EndpointExemption>(exemption);
  std::uint64_t minimum = 0;
  if (!reader.varint(minimum)) {
    return reader.status();
  }
  out.minimum_independent_paths = static_cast<std::uint32_t>(minimum);
  std::uint8_t semantics = 0;
  std::uint8_t completeness = 0;
  std::uint8_t unknown = 0;
  if (!reader.u8(semantics) || !reader.u8(completeness) || !reader.u8(unknown)) {
    return reader.status();
  }
  if (!is_defined_set_semantics(semantics) ||
      !is_defined_completeness_requirement(completeness) ||
      !is_defined_unknown_behavior(unknown)) {
    reader.fail(DecodeStatus::INVALID_ENCODING);
    return DecodeStatus::INVALID_ENCODING;
  }
  out.semantics = static_cast<SetSemantics>(semantics);
  out.completeness = static_cast<CompletenessRequirement>(completeness);
  out.unknown_behavior = static_cast<UnknownBehavior>(unknown);
  std::uint32_t relation_count = 0;
  if (read_count(reader, 8, relation_count) != DecodeStatus::OK) {
    return reader.status();
  }
  out.allowed_failure_domain_relations.clear();
  for (std::uint32_t i = 0; i < relation_count; ++i) {
    std::uint8_t relation = 0;
    if (!reader.u8(relation)) {
      return reader.status();
    }
    if (!is_defined_domain_relation(relation)) {
      reader.fail(DecodeStatus::INVALID_ENCODING);
      return DecodeStatus::INVALID_ENCODING;
    }
    out.allowed_failure_domain_relations.push_back(static_cast<DomainRelation>(relation));
  }
  if (!reader.boolean(out.require_path_authority_current)) {
    return reader.status();
  }
  if (!reader.text(out.description, limits.max_persistence_record_bytes / 4U)) {
    return reader.status();
  }
  const PolicyValidation validation = validate_policy(out, limits);
  if (!validation.ok()) {
    reader.fail(DecodeStatus::INVALID_ENCODING);
    return DecodeStatus::INVALID_ENCODING;
  }
  return DecodeStatus::OK;
}

void encode_proof(ByteWriter& writer, const DiversityProof& proof) {
  write_id(writer, proof.id);
  writer.u64(proof.generation.value());
  write_id(writer, proof.request.policy);
  writer.u64(proof.request.policy_generation.value());
  writer.varint(proof.request.paths.size());
  for (const PathRef& reference : proof.request.paths) {
    write_id(writer, reference.path);
    writer.u64(reference.authority_generation.value());
  }
  writer.bytes(proof.request_digest.bytes().data(), proof.request_digest.bytes().size());
  writer.bytes(proof.semantic_digest.bytes().data(), proof.semantic_digest.bytes().size());
  writer.u8(static_cast<std::uint8_t>(proof.outcome));
  writer.text(proof.detail);
  writer.boolean(proof.limit.has_value());
  if (proof.limit.has_value()) {
    writer.u8(static_cast<std::uint8_t>(proof.limit->bound));
    writer.u64(proof.limit->observed);
    writer.u64(proof.limit->allowed);
  }
  writer.varint(proof.classes.size());
  for (const ClassResult& result : proof.classes) {
    write_class(writer, result);
  }
  writer.varint(proof.advisories.size());
  for (const ClassResult& result : proof.advisories) {
    write_class(writer, result);
  }
  writer.varint(proof.conflicts.size());
  for (const SharedResource& conflict : proof.conflicts) {
    write_conflict(writer, conflict);
  }
  writer.u64(proof.conflicts_total);
  writer.varint(proof.matrix.order.size());
  for (const PathId& path : proof.matrix.order) {
    write_id(writer, path);
  }
  writer.varint(proof.matrix.cells.size());
  for (const PairwiseCell& cell : proof.matrix.cells) {
    writer.varint(cell.left);
    writer.varint(cell.right);
    writer.boolean(cell.independent);
    writer.boolean(cell.evidence_complete);
    writer.varint(cell.classes.size());
    for (const ClassResult& result : cell.classes) {
      write_class(writer, result);
    }
    writer.boolean(cell.primary_conflict.has_value());
    if (cell.primary_conflict.has_value()) {
      write_conflict(writer, *cell.primary_conflict);
    }
  }
  write_witness(writer, proof.witness);
  write_dependencies(writer, proof.dependencies);
  writer.u64(proof.provenance.epoch.value());
  write_id(writer, proof.provenance.publisher);
  write_id(writer, proof.provenance.boot);
  write_id(writer, proof.provenance.attempt);
  writer.u8(static_cast<std::uint8_t>(proof.lifecycle));
  writer.u8(static_cast<std::uint8_t>(proof.currentness));
}

DecodeStatus decode_proof(ByteReader& reader, const Limits& limits, DiversityProof& out) {
  const DecodeStatus id_status = read_id(reader, limits, out.id);
  if (id_status != DecodeStatus::OK) {
    return id_status;
  }
  std::uint64_t generation = 0;
  if (!reader.u64(generation)) {
    return reader.status();
  }
  out.generation = DiversityProofGeneration::from_value(generation);
  const DecodeStatus policy_status = read_id(reader, limits, out.request.policy);
  if (policy_status != DecodeStatus::OK) {
    return policy_status;
  }
  std::uint64_t policy_generation = 0;
  if (!reader.u64(policy_generation)) {
    return reader.status();
  }
  out.request.policy_generation = DiversityPolicyGeneration::from_value(policy_generation);
  std::uint32_t path_count = 0;
  if (read_count(reader, limits.max_paths_per_proof, path_count) != DecodeStatus::OK) {
    return reader.status();
  }
  out.request.paths.clear();
  for (std::uint32_t i = 0; i < path_count; ++i) {
    PathRef reference;
    const DecodeStatus status = read_id(reader, limits, reference.path);
    if (status != DecodeStatus::OK) {
      return status;
    }
    std::uint64_t authority = 0;
    if (!reader.u64(authority)) {
      return reader.status();
    }
    reference.authority_generation = PathAuthorityGeneration::from_value(authority);
    out.request.paths.push_back(std::move(reference));
  }
  std::string digest_bytes;
  if (!reader.bytes(digest_bytes, 16)) {
    return reader.status();
  }
  Digest::bytes_type request_bytes{};
  for (std::size_t i = 0; i < 16; ++i) {
    request_bytes[i] = static_cast<std::uint8_t>(digest_bytes[i]);
  }
  out.request_digest = Digest(request_bytes);
  if (!reader.bytes(digest_bytes, 16)) {
    return reader.status();
  }
  Digest::bytes_type semantic_bytes{};
  for (std::size_t i = 0; i < 16; ++i) {
    semantic_bytes[i] = static_cast<std::uint8_t>(digest_bytes[i]);
  }
  out.semantic_digest = Digest(semantic_bytes);

  std::uint8_t outcome = 0;
  if (!reader.u8(outcome)) {
    return reader.status();
  }
  if (!is_defined_proof_outcome(outcome)) {
    reader.fail(DecodeStatus::INVALID_ENCODING);
    return DecodeStatus::INVALID_ENCODING;
  }
  out.outcome = static_cast<ProofOutcome>(outcome);
  if (!reader.text(out.detail, limits.max_persistence_record_bytes / 4U)) {
    return reader.status();
  }
  bool has_limit = false;
  if (!reader.boolean(has_limit)) {
    return reader.status();
  }
  if (has_limit) {
    std::uint8_t bound = 0;
    if (!reader.u8(bound)) {
      return reader.status();
    }
    if (!is_defined_resource_bound(bound)) {
      reader.fail(DecodeStatus::INVALID_ENCODING);
      return DecodeStatus::INVALID_ENCODING;
    }
    ResourceLimitNotice notice;
    notice.bound = static_cast<ResourceBound>(bound);
    if (!reader.u64(notice.observed) || !reader.u64(notice.allowed)) {
      return reader.status();
    }
    out.limit = notice;
  }

  std::uint32_t class_count = 0;
  if (read_count(reader, limits.max_required_classes, class_count) != DecodeStatus::OK) {
    return reader.status();
  }
  out.classes.clear();
  for (std::uint32_t i = 0; i < class_count; ++i) {
    ClassResult result;
    const DecodeStatus status = read_class(reader, limits, result);
    if (status != DecodeStatus::OK) {
      return status;
    }
    out.classes.push_back(std::move(result));
  }
  std::uint32_t advisory_count = 0;
  if (read_count(reader, limits.max_required_classes, advisory_count) != DecodeStatus::OK) {
    return reader.status();
  }
  out.advisories.clear();
  for (std::uint32_t i = 0; i < advisory_count; ++i) {
    ClassResult result;
    const DecodeStatus status = read_class(reader, limits, result);
    if (status != DecodeStatus::OK) {
      return status;
    }
    out.advisories.push_back(std::move(result));
  }
  std::uint32_t conflict_count = 0;
  if (read_count(reader, limits.max_conflicts_per_proof, conflict_count) !=
      DecodeStatus::OK) {
    return reader.status();
  }
  out.conflicts.clear();
  for (std::uint32_t i = 0; i < conflict_count; ++i) {
    SharedResource conflict;
    const DecodeStatus status = read_conflict(reader, limits, conflict);
    if (status != DecodeStatus::OK) {
      return status;
    }
    out.conflicts.push_back(std::move(conflict));
  }
  if (!reader.u64(out.conflicts_total)) {
    return reader.status();
  }
  if (out.conflicts_total < out.conflicts.size()) {
    reader.fail(DecodeStatus::INVALID_ENCODING);
    return DecodeStatus::INVALID_ENCODING;
  }

  std::uint32_t order_count = 0;
  if (read_count(reader, limits.max_paths_per_proof, order_count) != DecodeStatus::OK) {
    return reader.status();
  }
  out.matrix.order.clear();
  for (std::uint32_t i = 0; i < order_count; ++i) {
    PathId path;
    const DecodeStatus status = read_id(reader, limits, path);
    if (status != DecodeStatus::OK) {
      return status;
    }
    out.matrix.order.push_back(std::move(path));
  }
  std::uint32_t cell_count = 0;
  if (read_count(reader, limits.max_pairwise_cells, cell_count) != DecodeStatus::OK) {
    return reader.status();
  }
  if (cell_count != PairwiseMatrix::cell_count(order_count)) {
    // A matrix whose dimensions do not match its own path order is refused;
    // there is no repair that would preserve the meaning of the cells.
    reader.fail(DecodeStatus::INVALID_ENCODING);
    return DecodeStatus::INVALID_ENCODING;
  }
  out.matrix.cells.clear();
  for (std::uint32_t i = 0; i < cell_count; ++i) {
    PairwiseCell cell;
    std::uint64_t left = 0;
    std::uint64_t right = 0;
    if (!reader.varint(left) || !reader.varint(right)) {
      return reader.status();
    }
    if (left >= order_count || right >= order_count || !(left < right)) {
      reader.fail(DecodeStatus::INVALID_ENCODING);
      return DecodeStatus::INVALID_ENCODING;
    }
    cell.left = static_cast<std::uint32_t>(left);
    cell.right = static_cast<std::uint32_t>(right);
    if (!reader.boolean(cell.independent) || !reader.boolean(cell.evidence_complete)) {
      return reader.status();
    }
    std::uint32_t pair_classes = 0;
    if (read_count(reader, limits.max_required_classes, pair_classes) != DecodeStatus::OK) {
      return reader.status();
    }
    for (std::uint32_t k = 0; k < pair_classes; ++k) {
      ClassResult result;
      const DecodeStatus status = read_class(reader, limits, result);
      if (status != DecodeStatus::OK) {
        return status;
      }
      cell.classes.push_back(std::move(result));
    }
    bool has_primary = false;
    if (!reader.boolean(has_primary)) {
      return reader.status();
    }
    if (has_primary) {
      SharedResource conflict;
      const DecodeStatus status = read_conflict(reader, limits, conflict);
      if (status != DecodeStatus::OK) {
        return status;
      }
      cell.primary_conflict = std::move(conflict);
    }
    out.matrix.cells.push_back(std::move(cell));
  }

  const DecodeStatus witness_status = read_witness(reader, limits, out.witness);
  if (witness_status != DecodeStatus::OK) {
    return witness_status;
  }
  const DecodeStatus dependency_status = read_dependencies(reader, limits, out.dependencies);
  if (dependency_status != DecodeStatus::OK) {
    return dependency_status;
  }
  std::uint64_t provenance_epoch = 0;
  if (!reader.u64(provenance_epoch)) {
    return reader.status();
  }
  out.provenance.epoch = CoordinatorEpoch::from_value(provenance_epoch);
  DecodeStatus status = read_id(reader, limits, out.provenance.publisher);
  if (status != DecodeStatus::OK) {
    return status;
  }
  status = read_id(reader, limits, out.provenance.boot);
  if (status != DecodeStatus::OK) {
    return status;
  }
  status = read_id(reader, limits, out.provenance.attempt);
  if (status != DecodeStatus::OK) {
    return status;
  }
  std::uint8_t lifecycle = 0;
  std::uint8_t currentness = 0;
  if (!reader.u8(lifecycle) || !reader.u8(currentness)) {
    return reader.status();
  }
  if (!is_defined_lifecycle_state(lifecycle) || !is_defined_currentness(currentness)) {
    reader.fail(DecodeStatus::INVALID_ENCODING);
    return DecodeStatus::INVALID_ENCODING;
  }
  out.lifecycle = static_cast<LifecycleState>(lifecycle);
  out.currentness = static_cast<Currentness>(currentness);

  // --- Semantic validation of the decoded revision ------------------------
  if (has_duplicate_paths(out.request.paths)) {
    reader.fail(DecodeStatus::INVALID_ENCODING);
    return DecodeStatus::INVALID_ENCODING;
  }
  for (std::size_t i = 0; i < out.matrix.order.size(); ++i) {
    if (!(out.matrix.order[i] == out.request.paths[i].path)) {
      reader.fail(DecodeStatus::INVALID_ENCODING);
      return DecodeStatus::INVALID_ENCODING;
    }
  }
  for (const SharedResource& conflict : out.conflicts) {
    for (std::uint32_t index : conflict.paths) {
      if (index >= out.request.paths.size()) {
        reader.fail(DecodeStatus::INVALID_ENCODING);
        return DecodeStatus::INVALID_ENCODING;
      }
    }
  }
  for (const ClassResult& result : out.classes) {
    for (const SharedResource& conflict : result.shared) {
      for (std::uint32_t index : conflict.paths) {
        if (index >= out.request.paths.size()) {
          reader.fail(DecodeStatus::INVALID_ENCODING);
          return DecodeStatus::INVALID_ENCODING;
        }
      }
    }
  }
  if (out.outcome == ProofOutcome::PROVEN_DIVERSE) {
    for (const ClassResult& result : out.classes) {
      if (!result.evidence_complete) {
        reader.fail(DecodeStatus::INVALID_ENCODING);
        return DecodeStatus::INVALID_ENCODING;
      }
    }
    if (!out.conflicts.empty()) {
      reader.fail(DecodeStatus::INVALID_ENCODING);
      return DecodeStatus::INVALID_ENCODING;
    }
  }
  for (std::uint32_t index : out.witness.indices) {
    if (index >= out.request.paths.size()) {
      reader.fail(DecodeStatus::INVALID_ENCODING);
      return DecodeStatus::INVALID_ENCODING;
    }
  }
  if (out.lifecycle == LifecycleState::CURRENT) {
    if (!out.dependencies.policy_generation.is_set() ||
        !out.dependencies.topology_generation.is_set() ||
        !out.dependencies.failure_domain_generation.is_set() ||
        !out.dependencies.epoch.is_set()) {
      reader.fail(DecodeStatus::INVALID_ENCODING);
      return DecodeStatus::INVALID_ENCODING;
    }
  }
  return DecodeStatus::OK;
}

}  // namespace path_diversity
