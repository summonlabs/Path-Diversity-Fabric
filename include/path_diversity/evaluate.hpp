// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "path_diversity/digest.hpp"
#include "path_diversity/export.hpp"
#include "path_diversity/limits.hpp"
#include "path_diversity/outcome.hpp"
#include "path_diversity/path.hpp"
#include "path_diversity/policy.hpp"
#include "path_diversity/proof.hpp"

namespace path_diversity {

// The exact evidence a caller must supply for one pure evaluation.
struct PATH_DIVERSITY_API EvaluationInputs {
  const PathAuthorityView* authority = nullptr;
  const PathStructureView* structure = nullptr;
  const FailureDomainView* domains = nullptr;
  const Limits* limits = nullptr;
};

// The complete, deterministic result of evaluating one canonical path set
// against one policy and one evidence snapshot. Pure data: no locks, no I/O, no
// publication, no time.
struct PATH_DIVERSITY_API EvaluationResult {
  ProofOutcome outcome = ProofOutcome::MALFORMED;
  std::string detail;
  std::optional<ResourceLimitNotice> limit;

  std::vector<ClassResult> classes;
  std::vector<ClassResult> advisories;
  std::vector<SharedResource> conflicts;
  std::uint64_t conflicts_total = 0;

  PairwiseMatrix matrix;
  WitnessSubset witness;
  DependencyBinding dependencies;
  // Generations actually observed from the evidence views during evaluation.
  // watermarks_observed is false only when evaluation could not reach the
  // evidence views at all; a caller that guards on it never mistakes an
  // unobserved generation for a moved one.
  TopologyGeneration observed_topology;
  FailureDomainGeneration observed_failure_domain;
  bool watermarks_observed = false;
  // Exact failure-domain and shared-risk-group identities consulted while
  // evaluating this set, canonical and unique. They feed the precise
  // FailureDomainId/SRLG to dependents index. The index is bounded by
  // max_domain_evidence_entries; generation-based invalidation stays exact
  // regardless of that bound.
  std::vector<FailureDomainId> consulted_domains;
  std::vector<SharedRiskGroupId> consulted_risk_groups;

  bool proven() const noexcept { return outcome == ProofOutcome::PROVEN_DIVERSE; }
};

// Evaluates a canonicalized request. The request is re-canonicalized
// defensively and duplicates are rejected.
//
// Evaluation order is fixed:
//   1. shape and limit checks (MALFORMED / RESOURCE_LIMIT);
//   2. Path Authority currentness for every path (UNAUTHORIZED / STALE_PATH_AUTHORITY);
//   3. structure resolution, coverage and malformedness (STALE_TOPOLOGY / MALFORMED);
//   4. per-class pairwise evidence collection;
//   5. set-wise aggregation, conflict graph and witness subset;
//   6. outcome classification under the policy completeness and UNKNOWN rules.
PATH_DIVERSITY_API EvaluationResult evaluate_diversity(const ProofRequest& request,
                                                       const DiversityPolicy& policy,
                                                       const EvaluationInputs& inputs);

// The exact per-pair class evaluation used by evaluate_diversity, exposed so
// that an operator can ask why two exact paths are not independent without
// evaluating the whole set. Deterministic for a fixed evidence snapshot.
//
// Shared resources are reported against the pair-local indices 0 and 1;
// evaluate_diversity remaps them onto the canonical set indices.
PATH_DIVERSITY_API std::vector<ClassResult> classify_pair(
    const PathComposition& left, const PathComposition& right, const DiversityPolicy& policy,
    const EvaluationInputs& inputs, std::uint32_t max_shared_per_class,
    std::vector<FailureDomainId>* consulted_domains = nullptr,
    std::vector<SharedRiskGroupId>* consulted_risk_groups = nullptr);

// Exact maximum mutually independent subset for a bounded path set. Returns
// nullopt when the path count exceeds limits.max_k_subset_paths: this function
// never guesses, so a caller that needs an answer for a larger set must supply
// stronger evidence rather than receive a heuristic.
PATH_DIVERSITY_API std::optional<WitnessSubset> maximum_independent_subset(
    const PairwiseMatrix& matrix, std::uint32_t requested_k, const Limits& limits);

// Independent verification of a witness: re-derives independence directly from
// the matrix cells and confirms the subset is genuinely mutually independent.
PATH_DIVERSITY_API bool verify_witness(const PairwiseMatrix& matrix,
                                       const std::vector<std::uint32_t>& indices) noexcept;

// Conflict graph view: adjacency over the canonical path order, edge iff the
// pair is not independent. Exposed because K mutually independent paths are
// exactly an independent set of size K in this graph, and because the
// computational limit is a product fact, not an implementation detail.
struct PATH_DIVERSITY_API ConflictGraph {
  std::uint32_t path_count = 0;
  // Row-major adjacency over path_count vertices.
  std::vector<std::uint8_t> adjacent;
  bool edge(std::uint32_t i, std::uint32_t j) const noexcept;
  std::uint64_t edge_count() const noexcept;
  std::vector<std::uint32_t> neighbours(std::uint32_t vertex) const;
  friend bool operator==(const ConflictGraph&, const ConflictGraph&) = default;
};

PATH_DIVERSITY_API ConflictGraph build_conflict_graph(const PairwiseMatrix& matrix);

}  // namespace path_diversity
