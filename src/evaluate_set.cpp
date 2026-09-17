// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#include "evaluate_internal.hpp"
#include "path_diversity/evaluate.hpp"

namespace path_diversity {

namespace {

using internal::aggregate_class;
using internal::cell_has_conflict;
using internal::gather;
using internal::graph_from_matrix;
using internal::is_required;
using internal::mis_exhaustive;
using internal::mis_witness;
using internal::remap_cell;
using internal::sorted_indices_of;

// The generations observed before any other work. Every result carries them so
// that a caller comparing watermarks is always comparing like with like: an
// unobserved generation must never look like a moved one.
struct Observation {
  TopologyGeneration topology;
  FailureDomainGeneration domains;
  bool observed = false;
};

EvaluationResult reject(const Observation& observation, ProofOutcome outcome,
                        std::string detail) {
  EvaluationResult result;
  result.outcome = outcome;
  result.detail = std::move(detail);
  result.observed_topology = observation.topology;
  result.observed_failure_domain = observation.domains;
  result.watermarks_observed = observation.observed;
  return result;
}

EvaluationResult reject_limit(const Observation& observation, ResourceBound bound,
                              std::uint64_t observed, std::uint64_t allowed,
                              std::string detail) {
  EvaluationResult result = reject(observation, ProofOutcome::RESOURCE_LIMIT, std::move(detail));
  ResourceLimitNotice notice;
  notice.bound = bound;
  notice.observed = observed;
  notice.allowed = allowed;
  result.limit = notice;
  return result;
}

ProofOutcome unknown_outcome(const DiversityPolicy& policy) {
  return policy.unknown_behavior == UnknownBehavior::DEMOTE_TO_REVALIDATION
             ? ProofOutcome::REVALIDATION_REQUIRED
             : ProofOutcome::UNKNOWN_INCOMPLETE_EVIDENCE;
}

std::vector<PairwiseCell> cells_within(const PairwiseMatrix& matrix,
                                       const std::vector<std::uint32_t>& subset) {
  std::vector<PairwiseCell> out;
  for (std::size_t a = 0; a < subset.size(); ++a) {
    for (std::size_t b = a + 1; b < subset.size(); ++b) {
      const PairwiseCell* cell = matrix.at(subset[a], subset[b]);
      if (cell != nullptr) {
        out.push_back(*cell);
      }
    }
  }
  return out;
}

std::string indices_text(const std::vector<std::uint32_t>& indices) {
  std::string out = "[";
  for (std::size_t i = 0; i < indices.size(); ++i) {
    if (i != 0) {
      out += ",";
    }
    out += std::to_string(indices[i]);
  }
  out += "]";
  return out;
}

}  // namespace

EvaluationResult evaluate_diversity(const ProofRequest& request, const DiversityPolicy& policy,
                                    const EvaluationInputs& inputs) {
  Observation observation;
  if (inputs.authority == nullptr || inputs.structure == nullptr || inputs.domains == nullptr ||
      inputs.limits == nullptr) {
    return reject(observation, ProofOutcome::MALFORMED,
                  "evaluation requires Path Authority, topology, failure-domain and limit inputs");
  }
  observation.topology = inputs.structure->topology_generation();
  observation.domains = inputs.domains->generation();
  observation.observed = true;
  const Limits& limits = *inputs.limits;
  if (!limits.self_consistent()) {
    return reject(observation, ProofOutcome::MALFORMED, "configured limits are not self-consistent");
  }

  DiversityPolicy canonical_policy = policy;
  canonical_policy.canonicalize();
  const PolicyValidation policy_validation = validate_policy(canonical_policy, limits);
  if (!policy_validation.ok()) {
    return reject(observation, ProofOutcome::MALFORMED,
                  std::string("policy is not valid: ") +
                      std::string(to_string(policy_validation.status)) + " (" +
                      policy_validation.detail + ")");
  }

  ProofRequest canonical = request;
  if (!canonical.canonicalize()) {
    return reject(observation, ProofOutcome::MALFORMED,
                  "proof set contains a duplicate path identity; 1.0.0 gives duplicates no "
                  "semantics and rejects them");
  }
  const std::size_t path_count = canonical.paths.size();
  if (path_count < 2) {
    return reject(observation, ProofOutcome::MALFORMED, "a diversity proof requires at least two paths");
  }
  if (path_count < canonical_policy.minimum_independent_paths) {
    return reject(observation, ProofOutcome::MALFORMED,
                  "path set of " + std::to_string(path_count) +
                      " is smaller than the policy minimum of " +
                      std::to_string(canonical_policy.minimum_independent_paths));
  }
  if (path_count > limits.max_paths_per_proof) {
    return reject_limit(observation, ResourceBound::MAX_PATHS_PER_PROOF, path_count,
                        limits.max_paths_per_proof, "path set exceeds max_paths_per_proof");
  }
  const std::uint64_t cell_count =
      (static_cast<std::uint64_t>(path_count) * (static_cast<std::uint64_t>(path_count) - 1ULL)) /
      2ULL;
  if (cell_count > limits.max_pairwise_cells) {
    return reject_limit(observation, ResourceBound::MAX_PAIRWISE_CELLS, cell_count, limits.max_pairwise_cells,
                        "pairwise matrix exceeds max_pairwise_cells");
  }

  EvaluationResult result;
  result.dependencies.policy_generation = canonical_policy.generation;
  result.dependencies.endpoint_exemption = canonical_policy.endpoint_exemption;
  for (const PathRef& reference : canonical.paths) {
    PathAuthorityBinding binding;
    binding.path = reference.path;
    binding.generation = reference.authority_generation;
    result.dependencies.paths.push_back(binding);
  }

  // --- Step 2: Path Authority currentness --------------------------------
  if (canonical_policy.require_path_authority_current) {
    for (const PathRef& reference : canonical.paths) {
      const std::optional<PathAuthorityGeneration> current =
          inputs.authority->current_generation(reference.path);
      if (!current.has_value()) {
        return reject(observation, ProofOutcome::UNAUTHORIZED,
                      "path " + reference.path.str() +
                          " has no currently authorized generation in Path Authority");
      }
      if (*current != reference.authority_generation) {
        return reject(observation, ProofOutcome::STALE_PATH_AUTHORITY,
                      "path " + reference.path.str() + " is bound to Path Authority generation " +
                          std::to_string(reference.authority_generation.value()) +
                          " but Path Authority is at generation " +
                          std::to_string(current->value()));
      }
      if (!inputs.authority->is_authorized(reference.path, reference.authority_generation)) {
        return reject(observation, ProofOutcome::UNAUTHORIZED,
                      "path " + reference.path.str() + " at generation " +
                          std::to_string(reference.authority_generation.value()) +
                          " is not currently authorized");
      }
    }
  }

  // --- Step 3: exact structure, generations and malformedness -------------
  // The watermarks carried by the result are the ones observed at the very top:
  // no later observation may be substituted for them, or a caller comparing
  // before and after would be comparing different moments.
  const TopologyGeneration observed_topology = observation.topology;
  const FailureDomainGeneration observed_domains = observation.domains;
  result.observed_topology = observed_topology;
  result.observed_failure_domain = observed_domains;
  result.watermarks_observed = true;
  result.dependencies.topology_generation = observed_topology;
  result.dependencies.failure_domain_generation = observed_domains;

  std::vector<PathComposition> compositions;
  compositions.reserve(path_count);
  std::vector<EntityRef> footprint;
  for (const PathRef& reference : canonical.paths) {
    std::optional<PathComposition> composition = inputs.structure->composition(reference.path);
    if (!composition.has_value()) {
      return reject(observation, ProofOutcome::MALFORMED,
                    "topology holds no composition for path " + reference.path.str());
    }
    if (composition->authority_generation != reference.authority_generation) {
      return reject(observation, ProofOutcome::STALE_PATH_AUTHORITY,
                    "composition for path " + reference.path.str() +
                        " was derived under Path Authority generation " +
                        std::to_string(composition->authority_generation.value()) +
                        " but the proof binds generation " +
                        std::to_string(reference.authority_generation.value()));
    }
    if (composition->topology_generation != observed_topology) {
      return reject(observation, ProofOutcome::STALE_TOPOLOGY,
                    "composition for path " + reference.path.str() +
                        " was derived under topology generation " +
                        std::to_string(composition->topology_generation.value()) +
                        " but the topology view serves generation " +
                        std::to_string(observed_topology.value()));
    }
    composition->canonicalize();
    if (composition->has_repeated_topology_elements()) {
      return reject(observation, ProofOutcome::MALFORMED,
                    "composition for path " + reference.path.str() +
                        " repeats a structural element; the upstream contract disallows "
                        "repeated elements and this runtime does not normalize them away");
    }
    for (const LinkId& link : composition->links) {
      footprint.push_back(EntityRef{EntityKind::LINK, link.str()});
    }
    for (const NodeId& node : composition->transit_nodes) {
      footprint.push_back(EntityRef{EntityKind::NODE, node.str()});
    }
    for (const NodeId& node : composition->sources) {
      footprint.push_back(EntityRef{EntityKind::ENDPOINT, node.str()});
    }
    for (const NodeId& node : composition->destinations) {
      footprint.push_back(EntityRef{EntityKind::ENDPOINT, node.str()});
    }
    for (const DeviceId& device : composition->devices) {
      footprint.push_back(EntityRef{EntityKind::DEVICE, device.str()});
    }
    compositions.push_back(std::move(*composition));
  }
  std::sort(footprint.begin(), footprint.end());
  footprint.erase(std::unique(footprint.begin(), footprint.end()), footprint.end());
  if (footprint.size() > limits.max_topology_dependencies) {
    return reject_limit(observation, ResourceBound::MAX_TOPOLOGY_DEPENDENCIES, footprint.size(),
                        limits.max_topology_dependencies,
                        "topology dependency footprint exceeds max_topology_dependencies");
  }
  result.dependencies.topology_entities = footprint;

  // --- Step 4: pairwise evidence collection ------------------------------
  result.matrix.order.clear();
  for (const PathRef& reference : canonical.paths) {
    result.matrix.order.push_back(reference.path);
  }
  result.matrix.cells.resize(static_cast<std::size_t>(cell_count));
  std::vector<FailureDomainId> consulted_domains;
  std::vector<SharedRiskGroupId> consulted_risk_groups;
  for (std::uint32_t i = 0; i < path_count; ++i) {
    for (std::uint32_t j = i + 1; j < path_count; ++j) {
      std::vector<ClassResult> classes = classify_pair(
          compositions[i], compositions[j], canonical_policy, inputs,
          limits.max_conflicts_per_proof, &consulted_domains, &consulted_risk_groups);
      remap_cell(classes, i, j);
      PairwiseCell cell;
      cell.left = i;
      cell.right = j;
      cell.classes.reserve(classes.size());
      for (ClassResult& class_result : classes) {
        if (is_required(canonical_policy, class_result.klass)) {
          cell.classes.push_back(std::move(class_result));
        }
      }
      cell.independent = true;
      cell.evidence_complete = true;
      for (const ClassResult& class_result : cell.classes) {
        if (class_result.outcome != ProofOutcome::PROVEN_DIVERSE || !class_result.evidence_complete) {
          cell.independent = false;
        }
        if (!class_result.evidence_complete) {
          cell.evidence_complete = false;
        }
      }
      std::vector<SharedResource> conflicts;
      for (const ClassResult& class_result : cell.classes) {
        for (const SharedResource& conflict : class_result.shared) {
          conflicts.push_back(conflict);
        }
      }
      canonical_conflict_order(conflicts);
      if (!conflicts.empty()) {
        cell.primary_conflict = conflicts.front();
      }
      const std::size_t index = PairwiseMatrix::cell_index(path_count, i, j);
      result.matrix.cells[index] = std::move(cell);
    }
  }

  // The dependency index is bounded; the class results above are not affected
  // by the bound, and generation-based invalidation stays exact regardless.
  canonical_sort_unique(consulted_domains);
  canonical_sort_unique(consulted_risk_groups);
  if (consulted_domains.size() > limits.max_domain_evidence_entries) {
    consulted_domains.resize(limits.max_domain_evidence_entries);
  }
  if (consulted_risk_groups.size() > limits.max_domain_evidence_entries) {
    consulted_risk_groups.resize(limits.max_domain_evidence_entries);
  }
  result.consulted_domains = std::move(consulted_domains);
  result.consulted_risk_groups = std::move(consulted_risk_groups);

  // --- Step 5: set-wise aggregation ---------------------------------------
  const std::uint32_t max_shared = limits.max_conflicts_per_proof;
  std::vector<PairwiseCell> aggregation_cells = result.matrix.cells;
  bool witness_found = false;

  if (canonical_policy.semantics == SetSemantics::AT_LEAST_K_INDEPENDENT) {
    if (path_count > limits.max_k_subset_paths || path_count > 32) {
      return reject_limit(observation, ResourceBound::MAX_K_SUBSET_PATHS, path_count,
                          limits.max_k_subset_paths,
                          "exact K-independent analysis is bounded by max_k_subset_paths; "
                          "no heuristic substitution is offered");
    }
    const ConflictGraph certain = graph_from_matrix(result.matrix, false);
    const ConflictGraph optimistic = graph_from_matrix(result.matrix, true);
    std::vector<std::uint32_t> certain_witness = sorted_indices_of(mis_witness(certain));
    bool exact = true;
    if (path_count <= 16) {
      const std::vector<std::uint32_t> brute = sorted_indices_of(mis_exhaustive(certain));
      if (brute.size() != certain_witness.size()) {
        exact = false;
        if (brute.size() > certain_witness.size()) {
          certain_witness = brute;
        }
      }
    }
    const std::vector<std::uint32_t> optimistic_witness = sorted_indices_of(mis_witness(optimistic));
    const std::uint32_t requested_k = canonical_policy.minimum_independent_paths;
    result.witness.present = true;
    result.witness.requested_k = requested_k;
    result.witness.achieved = static_cast<std::uint32_t>(certain_witness.size());
    result.witness.maximum_exact = exact;

    if (certain_witness.size() >= requested_k) {
      result.witness.indices = certain_witness;
      witness_found = true;
      aggregation_cells = cells_within(result.matrix, certain_witness);
    } else if (optimistic_witness.size() >= requested_k) {
      result.witness.indices = optimistic_witness;
      result.outcome = unknown_outcome(canonical_policy);
      result.detail =
          "at most " + std::to_string(certain_witness.size()) +
          " mutually independent paths are provable with complete evidence, but " +
          std::to_string(optimistic_witness.size()) +
          " would be independent if the outstanding evidence were resolved";
    } else if (exact) {
      result.witness.indices = certain_witness;
      result.outcome = ProofOutcome::NOT_DIVERSE;
      result.detail = "no subset of " + std::to_string(requested_k) +
                      " mutually independent paths exists; the largest provable subset has " +
                      std::to_string(certain_witness.size()) + " paths";
    } else {
      // A negative conclusion needs an exact maximum. Two independent
      // computations disagreed, so no negative claim is made.
      result.witness.indices = certain_witness;
      result.outcome = ProofOutcome::REVALIDATION_REQUIRED;
      result.detail =
          "the exact maximum independent subset could not be established: the branch-and-bound "
          "and exhaustive computations disagreed, so no negative claim is made";
    }
  }

  std::vector<ClassResult> required_results;
  for (DiversityClass klass : canonical_policy.required_classes) {
    ClassResult aggregated;
    aggregate_class(gather(aggregation_cells, klass), klass, aggregated, max_shared);
    required_results.push_back(std::move(aggregated));
  }
  std::vector<ClassResult> advisory_results;
  for (std::uint8_t raw = static_cast<std::uint8_t>(DiversityClass::LINK_DISJOINT);
       raw <= static_cast<std::uint8_t>(DiversityClass::SHARED_RISK_GROUP_DISJOINT); ++raw) {
    const DiversityClass klass = static_cast<DiversityClass>(raw);
    if (is_required(canonical_policy, klass)) {
      continue;
    }
    ClassResult aggregated;
    aggregate_class(gather(aggregation_cells, klass), klass, aggregated, max_shared);
    advisory_results.push_back(std::move(aggregated));
  }
  result.classes = required_results;
  result.advisories = advisory_results;

  // --- Step 6: outcome classification -------------------------------------
  if (result.outcome != ProofOutcome::NOT_DIVERSE &&
      result.outcome != ProofOutcome::REVALIDATION_REQUIRED &&
      result.outcome != ProofOutcome::UNKNOWN_INCOMPLETE_EVIDENCE) {
    bool any_conflict = false;
    bool any_unknown = false;
    bool any_malformed = false;
    std::string first_detail;
    for (const ClassResult& class_result : required_results) {
      if (class_result.outcome == ProofOutcome::NOT_DIVERSE) {
        any_conflict = true;
      } else if (class_result.outcome == ProofOutcome::UNKNOWN_INCOMPLETE_EVIDENCE) {
        any_unknown = true;
      } else if (class_result.outcome != ProofOutcome::PROVEN_DIVERSE) {
        any_malformed = true;
      }
      if (first_detail.empty() && !class_result.detail.empty()) {
        first_detail = class_result.detail;
      }
    }
    if (any_malformed) {
      result.outcome = ProofOutcome::MALFORMED;
      result.detail = "a required diversity class could not be evaluated";
    } else if (any_unknown &&
               canonical_policy.completeness == CompletenessRequirement::REQUIRE_COMPLETE_EVIDENCE) {
      // Conservative: incomplete evidence dominates, even over a conflict that
      // was already observed.
      result.outcome = unknown_outcome(canonical_policy);
      result.detail = "required evidence is incomplete: " + first_detail;
    } else if (any_conflict) {
      result.outcome = ProofOutcome::NOT_DIVERSE;
      result.detail = first_detail;
    } else if (any_unknown) {
      result.outcome = unknown_outcome(canonical_policy);
      result.detail = "required evidence is incomplete: " + first_detail;
    } else {
      result.outcome = ProofOutcome::PROVEN_DIVERSE;
      if (canonical_policy.semantics == SetSemantics::AT_LEAST_K_INDEPENDENT && witness_found) {
        result.detail = "witness subset " + indices_text(result.witness.indices) +
                        " of " + std::to_string(canonical_policy.minimum_independent_paths) +
                        " mutually independent paths";
      } else {
        result.detail = "every pair satisfies every required diversity class";
      }
    }
  }
  if (result.detail.empty() && result.outcome == ProofOutcome::PROVEN_DIVERSE) {
    result.detail = "every pair satisfies every required diversity class";
  }

  for (const ClassResult& class_result : required_results) {
    for (const SharedResource& conflict : class_result.shared) {
      result.conflicts_total += 1;
      if (result.conflicts.size() < max_shared) {
        result.conflicts.push_back(conflict);
      }
    }
  }
  canonical_conflict_order(result.conflicts);
  return result;
}

}  // namespace path_diversity
