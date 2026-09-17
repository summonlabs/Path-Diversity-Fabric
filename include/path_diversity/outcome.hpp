// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "path_diversity/canonical.hpp"
#include "path_diversity/diversity_class.hpp"
#include "path_diversity/domain.hpp"
#include "path_diversity/export.hpp"
#include "path_diversity/limits.hpp"

namespace path_diversity {

// Structured outcomes. There is no bool anywhere in the evaluation result: a
// caller must handle "proven", "disproven", "cannot be established under the
// evidence I can see", "my evidence is stale" and "you are not authorized" as
// four different things.
enum class ProofOutcome : std::uint8_t {
  PROVEN_DIVERSE = 1,
  NOT_DIVERSE = 2,
  UNKNOWN_INCOMPLETE_EVIDENCE = 3,
  STALE_PATH_AUTHORITY = 4,
  STALE_TOPOLOGY = 5,
  STALE_FAILURE_DOMAIN = 6,
  STALE_POLICY = 7,
  REVALIDATION_REQUIRED = 8,
  UNAUTHORIZED = 9,
  RESOURCE_LIMIT = 10,
  MALFORMED = 11,
};

PATH_DIVERSITY_API std::string_view to_string(ProofOutcome value) noexcept;
PATH_DIVERSITY_API std::optional<ProofOutcome> proof_outcome_from_string(
    std::string_view text) noexcept;
PATH_DIVERSITY_API bool is_defined_proof_outcome(std::uint8_t raw) noexcept;

// A PROVEN outcome asserts independence. A NOT_DIVERSE outcome asserts a
// concrete shared resource. Everything else asserts nothing about independence.
PATH_DIVERSITY_API bool outcome_asserts_independence(ProofOutcome value) noexcept;
PATH_DIVERSITY_API bool outcome_asserts_conflict(ProofOutcome value) noexcept;
PATH_DIVERSITY_API bool outcome_is_decisive(ProofOutcome value) noexcept;

// ---------------------------------------------------------------------------
// Shared resources / conflicts.
//
// Precedence is fixed and total, so an independent input ordering cannot change
// the primary reason: correlated-failure relations first (they cross otherwise
// disjoint topology), then devices, then transit nodes, then links. Within one
// precedence level resources are ordered by identity text.
// ---------------------------------------------------------------------------
enum class ConflictClass : std::uint8_t {
  SHARED_FAILURE_DOMAIN = 1,
  SHARED_RISK_GROUP = 2,
  SHARED_SITE = 3,
  SHARED_POD = 4,
  SHARED_RACK = 5,
  SHARED_POWER_DOMAIN = 6,
  SHARED_CONDUIT = 7,
  SHARED_COOLING = 8,
  SHARED_DEVICE = 9,
  SHARED_TRANSIT_NODE = 10,
  SHARED_LINK = 11,
  SHARED_ENDPOINT = 12,
  INCOMPLETE_EVIDENCE = 13,
  STALE_DEPENDENCY = 14,
};

PATH_DIVERSITY_API std::string_view to_string(ConflictClass value) noexcept;
PATH_DIVERSITY_API bool is_defined_conflict_class(std::uint8_t raw) noexcept;
PATH_DIVERSITY_API ConflictClass conflict_class_for_relation(DomainRelation relation) noexcept;
PATH_DIVERSITY_API std::optional<DomainRelation> relation_for_conflict_class(
    ConflictClass value) noexcept;

struct PATH_DIVERSITY_API SharedResource {
  ConflictClass kind = ConflictClass::SHARED_LINK;
  // Meaningful only for the domain-backed conflict classes; held explicitly so
  // an explanation can name the exact relation that produced the conflict.
  DomainRelation relation = DomainRelation::FAILURE_DOMAIN;
  // Canonical identity text of the shared resource, exactly as the owning
  // authority spells it.
  std::string id;
  // Canonical indices (into the proof's canonical path order) that share it,
  // ascending, at least two entries.
  std::vector<std::uint32_t> paths;

  friend bool operator==(const SharedResource&, const SharedResource&) = default;
  std::uint8_t precedence() const noexcept { return static_cast<std::uint8_t>(kind); }
  std::string render() const;
  void encode(ByteWriter& writer) const;
};

// Total, deterministic conflict ordering used for the primary reason and for
// the bounded complete conflict list.
PATH_DIVERSITY_API bool conflict_less(const SharedResource& lhs, const SharedResource& rhs);
PATH_DIVERSITY_API void canonical_conflict_order(std::vector<SharedResource>& conflicts);

// ---------------------------------------------------------------------------
// Per-class and aggregate results.
// ---------------------------------------------------------------------------
struct PATH_DIVERSITY_API ClassResult {
  DiversityClass klass = DiversityClass::LINK_DISJOINT;
  // One of PROVEN_DIVERSE, NOT_DIVERSE, UNKNOWN_INCOMPLETE_EVIDENCE.
  ProofOutcome outcome = ProofOutcome::UNKNOWN_INCOMPLETE_EVIDENCE;
  // Whether the evidence required to decide this class was complete for every
  // path in the set (or, for pairwise evaluation, for the pair).
  bool evidence_complete = false;
  // Bounded, canonically ordered. Empty for PROVEN_DIVERSE.
  std::vector<SharedResource> shared;
  // Total shared-resource count before bounding; a bounded list always reports
  // how much it dropped.
  std::uint64_t shared_total = 0;
  // Human-readable reason when the class is not PROVEN_DIVERSE.
  std::string detail;

  bool proven() const noexcept { return outcome == ProofOutcome::PROVEN_DIVERSE; }
  friend bool operator==(const ClassResult&, const ClassResult&) = default;
};

struct PATH_DIVERSITY_API PairwiseCell {
  // Canonical indices into the proof's canonical path order; left < right.
  std::uint32_t left = 0;
  std::uint32_t right = 0;
  // True only when every required class is PROVEN_DIVERSE for this pair.
  bool independent = false;
  bool evidence_complete = false;
  // One entry per required class, in the policy's canonical class order.
  std::vector<ClassResult> classes;
  std::optional<SharedResource> primary_conflict;
  friend bool operator==(const PairwiseCell&, const PairwiseCell&) = default;
};

// Deterministic pairwise matrix. Row-major upper triangle over the canonical
// path order; identity and order never depend on arrival order.
struct PATH_DIVERSITY_API PairwiseMatrix {
  std::vector<PathId> order;
  std::vector<PairwiseCell> cells;

  // Row-major upper-triangle index for the pair (i, j) of a path set of
  // path_count paths. Deterministic and independent of insertion order.
  static std::size_t cell_index(std::size_t path_count, std::uint32_t i, std::uint32_t j) noexcept;
  static std::size_t cell_count(std::size_t path_count) noexcept;
  const PairwiseCell* at(std::uint32_t i, std::uint32_t j) const noexcept;
  friend bool operator==(const PairwiseMatrix&, const PairwiseMatrix&) = default;
};

// Witness subset for AT_LEAST_K semantics.
struct PATH_DIVERSITY_API WitnessSubset {
  // False when the semantics did not request a witness (ALL_PAIRS).
  bool present = false;
  std::uint32_t requested_k = 0;
  // Canonical indices of the named subset, ascending. When achieved >=
  // requested_k it is a genuinely verified independent set. When the outcome is
  // UNKNOWN_INCOMPLETE_EVIDENCE it is the largest subset that would be
  // independent if the outstanding evidence were resolved, and it is therefore
  // reported as a candidate, never as a proof.
  std::vector<std::uint32_t> indices;
  // Largest mutually independent subset size found. Equals the exact maximum
  // when maximum_exact is true.
  std::uint32_t achieved = 0;
  // True only when the exact maximum was computed over the whole path set
  // (bounded N), never when a heuristic or a truncated search produced it.
  bool maximum_exact = false;
  friend bool operator==(const WitnessSubset&, const WitnessSubset&) = default;
  std::string render() const;
};

}  // namespace path_diversity
