// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

#include <cstdint>
#include <string>

#include "path_diversity/export.hpp"

namespace path_diversity {

// Every bound below is consulted by exactly the subsystem named in its comment.
// A bound that no code path reads is a dead limit and is not allowed to exist
// here. Each is independently overridable so an embedding product can tighten
// or relax it without recompiling the library.
struct PATH_DIVERSITY_API Limits {
  // Policy registry capacity (DiversityRuntime::publish_policy).
  std::uint32_t max_policies = 4096;
  // Proof registry capacity (DiversityRuntime::commit).
  std::uint32_t max_proofs = 100000;
  // Paths accepted in one proof request (evaluate_diversity).
  std::uint32_t max_paths_per_proof = 64;
  // Required diversity classes accepted in one policy (validate_policy).
  std::uint32_t max_required_classes = 8;
  // Shared resources retained in one proof conflict list (evaluation, decode).
  std::uint32_t max_conflicts_per_proof = 256;
  // Upper bound on N*(N-1)/2 pairwise cells (evaluation, decode).
  std::uint32_t max_pairwise_cells = 4096;
  // Failure-domain / risk-group members retained per entity (evidence lookup).
  std::uint32_t max_domain_evidence_entries = 4096;
  // Results returned by one query (DiversityRuntime::query_*).
  std::uint32_t max_query_results = 1024;
  // Retained historical proof revisions per proof identity (commit).
  std::uint32_t max_history = 4096;
  // Proof requests accepted in one batch (evaluate_batch).
  std::uint32_t max_batch_size = 256;
  // Registered publisher sessions (PublicationAuthority).
  std::uint32_t max_publishers = 64;
  // Encoded wire frame payload bound (wire codec, frame assembly).
  std::uint32_t max_frame_bytes = 65536;
  // Encoded persistence record bound (persistence encode/decode).
  std::uint32_t max_persistence_record_bytes = 65536;
  // Entries retained in one structured explanation (explain).
  std::uint32_t max_explanation_entries = 256;
  // Path-set size for which the exact K-independent maximum is computed
  // (K-subset solver). Larger sets under AT_LEAST_K semantics are refused with
  // RESOURCE_LIMIT rather than answered by a heuristic.
  std::uint32_t max_k_subset_paths = 10;
  // Paths retained in one snapshot (snapshot capture).
  std::uint32_t max_snapshot_paths = 64;
  // Identity text length accepted on decode paths (canonical decode helpers).
  std::uint32_t max_identity_length = 128;
  // Publication attempts retained for replay detection (PublicationAuthority).
  std::uint32_t max_attempts_tracked = 4096;
  // Bytes buffered while assembling one partial wire frame (frame assembly).
  std::uint32_t max_wire_assembly_bytes = 262144;
  // Records accepted from one persistence file (persistence load).
  std::uint32_t max_store_records = 200000;
  // Total bytes accepted from one persistence file (persistence load).
  std::uint64_t max_store_bytes = 268435456;
  // Retained entries in one deterministic diff (diff).
  std::uint32_t max_diff_entries = 1024;
  // Structural entities retained in one proof topology dependency footprint
  // (evaluation). Bounds the precise topology invalidation index.
  std::uint32_t max_topology_dependencies = 4096;

  // Structural sanity: a limit set that cannot express its own subject is a
  // defect and is rejected at construction rather than clamped silently.
  bool self_consistent() const noexcept;
  // Deterministic rendering used by RESOURCE_LIMIT diagnostics.
  std::string render() const;
};

// Names the bound that refused an operation. Every RESOURCE_LIMIT outcome
// carries the exact bound, so an operator never has to guess which limit fired.
enum class ResourceBound : std::uint8_t {
  MAX_POLICIES = 1,
  MAX_PROOFS = 2,
  MAX_PATHS_PER_PROOF = 3,
  MAX_REQUIRED_CLASSES = 4,
  MAX_CONFLICTS_PER_PROOF = 5,
  MAX_PAIRWISE_CELLS = 6,
  MAX_DOMAIN_EVIDENCE_ENTRIES = 7,
  MAX_QUERY_RESULTS = 8,
  MAX_HISTORY = 9,
  MAX_BATCH_SIZE = 10,
  MAX_PUBLISHERS = 11,
  MAX_FRAME_BYTES = 12,
  MAX_PERSISTENCE_RECORD_BYTES = 13,
  MAX_EXPLANATION_ENTRIES = 14,
  MAX_K_SUBSET_PATHS = 15,
  MAX_SNAPSHOT_PATHS = 16,
  MAX_IDENTITY_LENGTH = 17,
  MAX_ATTEMPTS_TRACKED = 18,
  MAX_WIRE_ASSEMBLY_BYTES = 19,
  MAX_STORE_RECORDS = 20,
  MAX_STORE_BYTES = 21,
  MAX_DIFF_ENTRIES = 22,
  MAX_TOPOLOGY_DEPENDENCIES = 23,
};

PATH_DIVERSITY_API std::string_view to_string(ResourceBound bound) noexcept;
PATH_DIVERSITY_API bool is_defined_resource_bound(std::uint8_t raw) noexcept;

// The exact bound that refused an operation together with the observed and
// allowed magnitudes. Returned with every RESOURCE_LIMIT outcome.
struct PATH_DIVERSITY_API ResourceLimitNotice {
  ResourceBound bound = ResourceBound::MAX_PROOFS;
  std::uint64_t observed = 0;
  std::uint64_t allowed = 0;

  friend bool operator==(const ResourceLimitNotice&, const ResourceLimitNotice&) = default;
  std::string render() const;
};

}  // namespace path_diversity
