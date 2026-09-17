// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include "path_diversity/limits.hpp"

#include <string>

#include "path_diversity/digest.hpp"
#include "path_diversity/ids.hpp"

namespace path_diversity {

std::string_view to_string(ResourceBound bound) noexcept {
  switch (bound) {
    case ResourceBound::MAX_POLICIES:
      return "max_policies";
    case ResourceBound::MAX_PROOFS:
      return "max_proofs";
    case ResourceBound::MAX_PATHS_PER_PROOF:
      return "max_paths_per_proof";
    case ResourceBound::MAX_REQUIRED_CLASSES:
      return "max_required_classes";
    case ResourceBound::MAX_CONFLICTS_PER_PROOF:
      return "max_conflicts_per_proof";
    case ResourceBound::MAX_PAIRWISE_CELLS:
      return "max_pairwise_cells";
    case ResourceBound::MAX_DOMAIN_EVIDENCE_ENTRIES:
      return "max_domain_evidence_entries";
    case ResourceBound::MAX_QUERY_RESULTS:
      return "max_query_results";
    case ResourceBound::MAX_HISTORY:
      return "max_history";
    case ResourceBound::MAX_BATCH_SIZE:
      return "max_batch_size";
    case ResourceBound::MAX_PUBLISHERS:
      return "max_publishers";
    case ResourceBound::MAX_FRAME_BYTES:
      return "max_frame_bytes";
    case ResourceBound::MAX_PERSISTENCE_RECORD_BYTES:
      return "max_persistence_record_bytes";
    case ResourceBound::MAX_EXPLANATION_ENTRIES:
      return "max_explanation_entries";
    case ResourceBound::MAX_K_SUBSET_PATHS:
      return "max_k_subset_paths";
    case ResourceBound::MAX_SNAPSHOT_PATHS:
      return "max_snapshot_paths";
    case ResourceBound::MAX_IDENTITY_LENGTH:
      return "max_identity_length";
    case ResourceBound::MAX_ATTEMPTS_TRACKED:
      return "max_attempts_tracked";
    case ResourceBound::MAX_WIRE_ASSEMBLY_BYTES:
      return "max_wire_assembly_bytes";
    case ResourceBound::MAX_STORE_RECORDS:
      return "max_store_records";
    case ResourceBound::MAX_STORE_BYTES:
      return "max_store_bytes";
    case ResourceBound::MAX_DIFF_ENTRIES:
      return "max_diff_entries";
    case ResourceBound::MAX_TOPOLOGY_DEPENDENCIES:
      return "max_topology_dependencies";
  }
  return "unknown_bound";
}

bool is_defined_resource_bound(std::uint8_t raw) noexcept {
  return raw >= static_cast<std::uint8_t>(ResourceBound::MAX_POLICIES) &&
         raw <= static_cast<std::uint8_t>(ResourceBound::MAX_TOPOLOGY_DEPENDENCIES);
}

std::string ResourceLimitNotice::render() const {
  std::string out = "RESOURCE_LIMIT ";
  out += to_string(bound);
  out += ": observed ";
  out += std::to_string(observed);
  out += ", allowed ";
  out += std::to_string(allowed);
  return out;
}

bool Limits::self_consistent() const noexcept {
  // A limit that cannot express its own subject is a defect: it would make a
  // supported operation unconditionally impossible rather than bounded.
  if (max_policies == 0 || max_proofs == 0 || max_paths_per_proof < 2 ||
      max_required_classes == 0 || max_conflicts_per_proof == 0 || max_pairwise_cells == 0 ||
      max_domain_evidence_entries == 0 || max_query_results == 0 || max_history == 0 ||
      max_batch_size == 0 || max_publishers == 0 || max_frame_bytes == 0 ||
      max_persistence_record_bytes == 0 || max_explanation_entries == 0 ||
      max_k_subset_paths < 2 || max_snapshot_paths < 2 || max_identity_length == 0 ||
      max_attempts_tracked == 0 || max_wire_assembly_bytes < max_frame_bytes ||
      max_store_records == 0 || max_store_bytes == 0 || max_diff_entries == 0 ||
      max_topology_dependencies == 0) {
    return false;
  }
  // max_paths_per_proof must be expressible inside max_pairwise_cells:
  // N*(N-1)/2 <= max_pairwise_cells for N = max_paths_per_proof.
  const std::uint64_t n = max_paths_per_proof;
  const std::uint64_t cells = (n * (n - 1)) / 2;
  if (cells > static_cast<std::uint64_t>(max_pairwise_cells)) {
    return false;
  }
  // The exact K-subset solver is bounded by the supported path-set size.
  if (max_k_subset_paths > max_paths_per_proof) {
    return false;
  }
  if (max_snapshot_paths > max_paths_per_proof) {
    return false;
  }
  return true;
}

std::string Limits::render() const {
  std::string out;
  out += "max_policies=" + std::to_string(max_policies);
  out += " max_proofs=" + std::to_string(max_proofs);
  out += " max_paths_per_proof=" + std::to_string(max_paths_per_proof);
  out += " max_required_classes=" + std::to_string(max_required_classes);
  out += " max_conflicts_per_proof=" + std::to_string(max_conflicts_per_proof);
  out += " max_pairwise_cells=" + std::to_string(max_pairwise_cells);
  out += " max_domain_evidence_entries=" + std::to_string(max_domain_evidence_entries);
  out += " max_query_results=" + std::to_string(max_query_results);
  out += " max_history=" + std::to_string(max_history);
  out += " max_batch_size=" + std::to_string(max_batch_size);
  out += " max_publishers=" + std::to_string(max_publishers);
  out += " max_frame_bytes=" + std::to_string(max_frame_bytes);
  out += " max_persistence_record_bytes=" + std::to_string(max_persistence_record_bytes);
  out += " max_explanation_entries=" + std::to_string(max_explanation_entries);
  out += " max_k_subset_paths=" + std::to_string(max_k_subset_paths);
  out += " max_snapshot_paths=" + std::to_string(max_snapshot_paths);
  out += " max_identity_length=" + std::to_string(max_identity_length);
  out += " max_attempts_tracked=" + std::to_string(max_attempts_tracked);
  out += " max_wire_assembly_bytes=" + std::to_string(max_wire_assembly_bytes);
  out += " max_store_records=" + std::to_string(max_store_records);
  out += " max_store_bytes=" + std::to_string(max_store_bytes);
  out += " max_diff_entries=" + std::to_string(max_diff_entries);
  out += " max_topology_dependencies=" + std::to_string(max_topology_dependencies);
  return out;
}

// ---------------------------------------------------------------------------
// Identities derived from canonical content.
// ---------------------------------------------------------------------------
PathSetId derived_path_set_id(const Digest& digest) {
  return PathSetId::parse(mint_prefixed("pset-", digest));
}

DiversityProofId derived_proof_id(const Digest& request_digest) {
  return DiversityProofId::parse(mint_prefixed("dproof-", request_digest));
}

SnapshotId derived_snapshot_id(const Digest& digest) {
  return SnapshotId::parse(mint_prefixed("dsnap-", digest));
}

ScopeId default_scope() noexcept { return ScopeId::parse("scope-default"); }

}  // namespace path_diversity
