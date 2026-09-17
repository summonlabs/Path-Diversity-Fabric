// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "path_diversity/digest.hpp"
#include "path_diversity/export.hpp"
#include "path_diversity/ids.hpp"
#include "path_diversity/limits.hpp"
#include "path_diversity/outcome.hpp"
#include "path_diversity/path.hpp"
#include "path_diversity/proof.hpp"

namespace path_diversity {

// An immutable point-in-time capture of one proof revision. Contains no
// timestamp, no socket, no thread id and no memory address: two captures of the
// same proof state are byte-identical and share one SnapshotId.
struct PATH_DIVERSITY_API ProofSnapshot {
  SnapshotId id;
  DiversityProofId proof;
  DiversityProofGeneration generation;
  DiversityPolicyId policy;
  DiversityPolicyGeneration policy_generation;
  std::vector<PathRef> paths;
  ProofOutcome outcome;
  std::vector<ClassResult> classes;
  std::vector<SharedResource> conflicts;
  WitnessSubset witness;
  DependencyBinding dependencies;
  LifecycleState lifecycle = LifecycleState::DECLARED;
  Currentness currentness = Currentness::REVALIDATION_REQUIRED;
  Provenance provenance;
  Digest digest;

  friend bool operator==(const ProofSnapshot&, const ProofSnapshot&) = default;
  std::string render() const;
};

PATH_DIVERSITY_API Digest snapshot_digest(const ProofSnapshot& snapshot);
PATH_DIVERSITY_API ProofSnapshot capture_snapshot(const DiversityProof& proof);
// Recomputes and stamps id/digest. Used by the decoder, which must never trust
// an encoded digest.
PATH_DIVERSITY_API void finalize_snapshot(ProofSnapshot& snapshot);

enum class DiffKind : std::uint8_t {
  PATH_ADDED = 1,
  PATH_REMOVED = 2,
  POLICY_CHANGED = 3,
  CONFLICT_APPEARED = 4,
  CONFLICT_DISAPPEARED = 5,
  EVIDENCE_COMPLETENESS_CHANGED = 6,
  TOPOLOGY_GENERATION_CHANGED = 7,
  FAILURE_DOMAIN_GENERATION_CHANGED = 8,
  PATH_AUTHORITY_GENERATION_CHANGED = 9,
  POLICY_GENERATION_CHANGED = 10,
  EPOCH_CHANGED = 11,
  PROOF_RESULT_CHANGED = 12,
  CURRENTNESS_CHANGED = 13,
  LIFECYCLE_CHANGED = 14,
  WITNESS_CHANGED = 15,
  CLASS_RESULT_CHANGED = 16,
  PROOF_GENERATION_CHANGED = 17,
  PROVENANCE_CHANGED = 18,
};

PATH_DIVERSITY_API std::string_view to_string(DiffKind value) noexcept;
PATH_DIVERSITY_API bool is_defined_diff_kind(std::uint8_t raw) noexcept;

struct PATH_DIVERSITY_API DiffEntry {
  DiffKind kind = DiffKind::PROOF_RESULT_CHANGED;
  std::string subject;
  std::string before;
  std::string after;
  friend bool operator==(const DiffEntry&, const DiffEntry&) = default;
  std::string render() const;
};

struct PATH_DIVERSITY_API ProofDiff {
  SnapshotId left;
  SnapshotId right;
  std::vector<DiffEntry> entries;
  bool truncated = false;
  std::uint64_t entries_total = 0;
  bool empty() const noexcept { return entries.empty(); }
  friend bool operator==(const ProofDiff&, const ProofDiff&) = default;
  std::string render() const;
};

PATH_DIVERSITY_API ProofDiff diff_snapshots(const ProofSnapshot& left, const ProofSnapshot& right,
                                            const Limits& limits);

}  // namespace path_diversity
