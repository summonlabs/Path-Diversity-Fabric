// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.

// Documented properties, each exercised over seeded random scenarios. Every
// scenario is reproducible from its seed and every failure prints that seed.

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <sstream>
#include <string>
#include <type_traits>
#include <vector>

#include "test_support.hpp"

namespace {

using namespace path_diversity;

constexpr std::uint32_t kScenarios = 320;

// Deterministic xorshift64: the same seed always builds the same scenario.
struct Rng {
  explicit Rng(std::uint64_t seed) : state(seed * 0x9e3779b97f4a7c15ULL + 0x2545f4914f6cdd1dULL) {}
  std::uint64_t state = 1;

  std::uint64_t next() {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    return state;
  }
  std::uint32_t below(std::uint32_t bound) {
    return bound == 0 ? 0 : static_cast<std::uint32_t>(next() % bound);
  }
  bool chance(std::uint32_t percent) { return below(100) < percent; }
};

void seeded_check(bool condition, std::uint64_t seed, const std::string& property, const char* file,
                  int line) {
  pd_test::check(condition, "seed=" + std::to_string(seed) + " property=" + property, file, line);
}

template <class T>
std::string describe(const T& value) {
  if constexpr (std::is_enum_v<T>) {
    return std::to_string(static_cast<long long>(value));
  } else if constexpr (std::is_arithmetic_v<T>) {
    return std::to_string(value);
  } else {
    std::ostringstream stream;
    stream << value;
    return stream.str();
  }
}

template <class T, class U>
void seeded_check_eq(const T& actual, const U& expected, std::uint64_t seed,
                     const std::string& property, const char* file, int line) {
  pd_test::check(actual == expected,
                 "seed=" + std::to_string(seed) + " property=" + property + " observed " +
                     describe(actual) + " expected " + describe(expected),
                 file, line);
}

struct PublishedPolicy {
  DiversityPolicyId id;
  DiversityPolicyGeneration generation;
};

struct Scenario {
  std::vector<std::string> names;
  std::vector<PathComposition> compositions;
  PublishedPolicy policy;
  DiversityPolicy policy_content;
  ProofRequest request;
  DiversityProof proof;
};

Scenario build_scenario(pd_test::Fixture& fixture, std::uint64_t seed) {
  Rng rng(seed);
  Scenario out;
  const std::uint32_t path_count = 2 + rng.below(3);
  const std::uint32_t link_pool = 2 + rng.below(4);
  const std::uint32_t node_pool = 2 + rng.below(3);
  const std::uint32_t device_pool = 2 + rng.below(3);
  // Half of the scenarios give every path its own structural namespace, so the
  // paths share no entity at all and the correlated-failure evidence is what
  // decides the outcome. The other half draws from a shared pool, so sharing is
  // the common case.
  const bool scoped = rng.chance(50);

  for (std::uint32_t index = 0; index < path_count; ++index) {
    const std::string name = "prop-path-" + std::to_string(index);
    const std::string scope = "prop-" + std::to_string(scoped ? index : 0) + "-";
    const std::string link = scope + "link-" + std::to_string(rng.below(link_pool));
    std::vector<std::string> links = {link};
    if (rng.chance(30)) {
      const std::string extra = scope + "link-" + std::to_string(rng.below(link_pool));
      if (!(extra == link)) {
        links.push_back(extra);
      }
    }
    fixture.evidence.set_path(pd_test::make_path(
        name, 1, {scope + "node-" + std::to_string(rng.below(node_pool))}, links,
        {scope + "dev-" + std::to_string(rng.below(device_pool))},
        scope + "src-" + std::to_string(rng.below(2)), scope + "dst-" + std::to_string(rng.below(2))));
    const std::optional<PathComposition> composition =
        fixture.evidence.composition(PathId::parse(name));
    PD_CHECK(composition.has_value());
    if (!composition.has_value()) {
      return out;
    }
    out.compositions.push_back(*composition);
    out.names.push_back(name);
  }

  const DomainRelation relations[3] = {DomainRelation::FAILURE_DOMAIN, DomainRelation::RACK,
                                       DomainRelation::SITE};
  for (const PathComposition& composition : out.compositions) {
    for (const EntityRef& entity : pd_test::entities_of(composition)) {
      for (DomainRelation relation : relations) {
        const std::uint32_t roll = rng.below(10);
        const EvidenceCoverage coverage = roll < 5   ? EvidenceCoverage::COMPLETE
                                          : roll < 8 ? EvidenceCoverage::PARTIAL
                                                     : EvidenceCoverage::ABSENT;
        std::vector<FailureDomainId> domains;
        const std::uint32_t domain_count = rng.below(3);
        for (std::uint32_t index = 0; index < domain_count; ++index) {
          domains.push_back(FailureDomainId::parse("prop-dom-" + std::to_string(rng.below(3))));
        }
        fixture.evidence.set_domain_membership(entity, relation, coverage, domains);
      }
      const std::uint32_t roll = rng.below(10);
      const EvidenceCoverage coverage = roll < 6   ? EvidenceCoverage::COMPLETE
                                        : roll < 8 ? EvidenceCoverage::PARTIAL
                                                   : EvidenceCoverage::ABSENT;
      std::vector<SharedRiskGroupId> groups;
      const std::uint32_t group_count = rng.below(3);
      for (std::uint32_t index = 0; index < group_count; ++index) {
        groups.push_back(SharedRiskGroupId::parse("prop-srlg-" + std::to_string(rng.below(2))));
      }
      fixture.evidence.set_srlg_membership(entity, coverage, groups);
    }
  }

  const DiversityClass class_pool[7] = {
      DiversityClass::LINK_DISJOINT,       DiversityClass::TRANSIT_NODE_DISJOINT,
      DiversityClass::DEVICE_DISJOINT,     DiversityClass::RACK_DISJOINT,
      DiversityClass::SITE_DISJOINT,       DiversityClass::FAILURE_DOMAIN_DISJOINT,
      DiversityClass::SHARED_RISK_GROUP_DISJOINT};
  std::vector<DiversityClass> classes = {class_pool[rng.below(7)]};
  if (rng.chance(50)) {
    const DiversityClass extra = class_pool[rng.below(7)];
    if (!(extra == classes.front())) {
      classes.push_back(extra);
    }
  }
  const EndpointExemption exemptions[3] = {EndpointExemption::NONE,
                                           EndpointExemption::SHARED_SOURCE_AND_DESTINATION,
                                           EndpointExemption::ANY_ENDPOINT};
  const CompletenessRequirement completeness[2] = {
      CompletenessRequirement::REQUIRE_COMPLETE_EVIDENCE,
      CompletenessRequirement::PROVEN_CONFLICT_DECISIVE};
  const UnknownBehavior unknown[2] = {UnknownBehavior::REJECT_PROOF,
                                      UnknownBehavior::DEMOTE_TO_REVALIDATION};
  const std::uint32_t minimum = 2 + rng.below(path_count - 1);
  const SetSemantics semantics = rng.chance(40) ? SetSemantics::AT_LEAST_K_INDEPENDENT
                                                : SetSemantics::ALL_PAIRS;
  DiversityPolicy policy = pd_test::make_policy("dpol-property", classes, exemptions[rng.below(3)],
                                                minimum, semantics, completeness[rng.below(2)]);
  policy.unknown_behavior = unknown[rng.below(2)];
  policy.description = "seeded scenario " + std::to_string(seed);
  policy.canonicalize();

  const MutationResult published =
      fixture.runtime.publish_policy(policy, fixture.actor("property-policy"));
  PD_CHECK_EQ(published.status, MutationStatus::APPLIED);
  out.policy = PublishedPolicy{published.policy.id, published.policy.generation};
  out.policy_content = published.policy;
  out.request.policy = out.policy.id;
  out.request.policy_generation = out.policy.generation;
  for (const std::string& name : out.names) {
    out.request.paths.push_back(PathRef{PathId::parse(name),
                                        PathAuthorityGeneration::from_value(1)});
  }
  const MutationResult evaluated = fixture.runtime.evaluate(out.request, fixture.actor("property-eval"));
  PD_CHECK_EQ(evaluated.status, MutationStatus::APPLIED);
  out.proof = evaluated.proof;
  return out;
}

// Every property below is derived from the proof itself, so a failure names the
// exact scenario that produced it.
void check_proof_invariants(const DiversityProof& proof, const DiversityPolicy& policy,
                            std::uint64_t seed) {
  const std::size_t path_count = proof.request.paths.size();
  for (std::size_t index = 1; index < path_count; ++index) {
    seeded_check(proof.request.paths[index - 1].path < proof.request.paths[index].path, seed,
                 "request paths are canonically ordered", __FILE__, __LINE__);
    seeded_check(proof.dependencies.paths[index - 1].path <
                     proof.dependencies.paths[index].path,
                 seed, "dependency paths are canonically ordered", __FILE__, __LINE__);
  }
  seeded_check_eq(proof.matrix.order.size(), path_count, seed, "matrix order size", __FILE__,
                  __LINE__);
  seeded_check_eq(proof.matrix.cells.size(), PairwiseMatrix::cell_count(path_count), seed,
                  "matrix cell count", __FILE__, __LINE__);
  for (std::size_t index = 0; index < path_count; ++index) {
    seeded_check(proof.matrix.order[index] == proof.request.paths[index].path, seed,
                 "matrix order mirrors the request", __FILE__, __LINE__);
  }

  bool every_cell_independent = true;
  for (std::uint32_t left = 0; left < path_count; ++left) {
    for (std::uint32_t right = left + 1; right < path_count; ++right) {
      const PairwiseCell* cell = proof.matrix.at(left, right);
      PD_REQUIRE(cell != nullptr);
      seeded_check_eq(cell->left, left, seed, "cell left index", __FILE__, __LINE__);
      seeded_check_eq(cell->right, right, seed, "cell right index", __FILE__, __LINE__);
      bool all_proven = true;
      bool all_complete = true;
      for (const ClassResult& result : cell->classes) {
        all_proven = all_proven && result.outcome == ProofOutcome::PROVEN_DIVERSE;
        all_complete = all_complete && result.evidence_complete;
        seeded_check(result.outcome != ProofOutcome::PROVEN_DIVERSE || result.evidence_complete,
                     seed, "proven class carries complete evidence", __FILE__, __LINE__);
        seeded_check(result.shared_total >= static_cast<std::uint64_t>(result.shared.size()), seed,
                     "class conflict total covers the retained list", __FILE__, __LINE__);
        if (result.shared_total > 0) {
          seeded_check(!cell->independent, seed,
                       "a shared required resource means the pair is not independent", __FILE__,
                       __LINE__);
        }
      }
      seeded_check(cell->independent == all_proven, seed, "cell independence", __FILE__, __LINE__);
      seeded_check(cell->evidence_complete == all_complete, seed, "cell completeness", __FILE__,
                   __LINE__);
      if (!cell->independent) {
        every_cell_independent = false;
      }
    }
  }

  bool any_conflict = false;
  bool any_unknown = false;
  bool all_complete = true;
  for (const ClassResult& result : proof.classes) {
    any_conflict = any_conflict || result.outcome == ProofOutcome::NOT_DIVERSE;
    any_unknown = any_unknown || result.outcome == ProofOutcome::UNKNOWN_INCOMPLETE_EVIDENCE;
    all_complete = all_complete && result.evidence_complete;
    seeded_check(result.outcome != ProofOutcome::PROVEN_DIVERSE || result.shared_total == 0, seed,
                 "a proven class reports no shared resource", __FILE__, __LINE__);
    seeded_check(result.outcome != ProofOutcome::PROVEN_DIVERSE || result.evidence_complete, seed,
                 "a proven class carries complete evidence", __FILE__, __LINE__);
  }
  for (std::size_t index = 1; index < proof.classes.size(); ++index) {
    seeded_check(proof.classes[index - 1].klass < proof.classes[index].klass, seed,
                 "required classes are canonically ordered", __FILE__, __LINE__);
  }
  for (const ClassResult& result : proof.classes) {
    bool required = false;
    for (DiversityClass klass : policy.required_classes) {
      required = required || (klass == result.klass);
    }
    seeded_check(required, seed, "reported classes are required by the policy", __FILE__,
                 __LINE__);
  }

  if (proof.outcome == ProofOutcome::PROVEN_DIVERSE) {
    seeded_check(proof.conflicts.empty(), seed, "a proven proof carries no conflict", __FILE__,
                 __LINE__);
    seeded_check(all_complete, seed, "PROVEN_DIVERSE implies complete required evidence", __FILE__,
                 __LINE__);
    seeded_check(proof.current(), seed, "a proven proof is current", __FILE__, __LINE__);
    if (policy.semantics == SetSemantics::ALL_PAIRS) {
      seeded_check(every_cell_independent, seed,
                   "PROVEN_DIVERSE under ALL_PAIRS implies every pair is independent", __FILE__,
                   __LINE__);
    } else {
      // AT_LEAST_K proves the existence of a witness subset, not that every
      // pair of the whole set is independent.
      seeded_check(proof.witness.present, seed, "AT_LEAST_K reports a witness", __FILE__,
                   __LINE__);
      seeded_check(proof.witness.indices.size() >= policy.minimum_independent_paths, seed,
                   "a proven witness reaches the policy minimum", __FILE__, __LINE__);
      seeded_check(verify_witness(proof.matrix, proof.witness.indices), seed,
                   "a proven witness verifies pairwise", __FILE__, __LINE__);
    }
  }
  // Only ALL_PAIRS aggregates every pair, so only there does an observed
  // conflict decide the set-level outcome; the witness solver deliberately
  // reports an unresolvable K-subset as unknown instead.
  if (policy.semantics == SetSemantics::ALL_PAIRS) {
    const bool conflict_decides =
        all_complete || policy.completeness == CompletenessRequirement::PROVEN_CONFLICT_DECISIVE;
    if (any_conflict && conflict_decides) {
      seeded_check_eq(proof.outcome, ProofOutcome::NOT_DIVERSE, seed,
                      "a shared required resource decides NOT_DIVERSE", __FILE__, __LINE__);
    }
    if (!any_conflict && !any_unknown && all_complete) {
      seeded_check_eq(proof.outcome, ProofOutcome::PROVEN_DIVERSE, seed,
                      "complete evidence without a conflict proves diversity", __FILE__,
                      __LINE__);
    }
    if (any_unknown && policy.completeness == CompletenessRequirement::REQUIRE_COMPLETE_EVIDENCE) {
      seeded_check(proof.outcome != ProofOutcome::PROVEN_DIVERSE, seed,
                   "incomplete evidence never becomes PROVEN", __FILE__, __LINE__);
    }
  }

  if (proof.witness.present) {
    const std::uint32_t count = static_cast<std::uint32_t>(proof.witness.indices.size());
    // The reported subset is the proven witness when the outcome is proven, and
    // may name a larger optimistic witness while the evidence is still
    // incomplete; the achievement never exceeds the named subset.
    seeded_check(count >= proof.witness.achieved, seed,
                 "the witness names at least as many paths as were achieved", __FILE__, __LINE__);
    if (proof.outcome == ProofOutcome::PROVEN_DIVERSE) {
      seeded_check_eq(count, proof.witness.achieved, seed,
                      "a proven witness names exactly the achieved subset", __FILE__, __LINE__);
    }
    for (std::uint32_t index = 0; index < count; ++index) {
      seeded_check(proof.witness.indices[index] < path_count, seed, "witness index in range",
                   __FILE__, __LINE__);
      if (index > 0) {
        seeded_check(proof.witness.indices[index - 1] < proof.witness.indices[index], seed,
                     "witness indices ascend", __FILE__, __LINE__);
      }
    }
    if (proof.outcome == ProofOutcome::PROVEN_DIVERSE) {
      seeded_check(verify_witness(proof.matrix, proof.witness.indices), seed,
                   "an independent witness verifies", __FILE__, __LINE__);
    }
  }

  seeded_check_eq(proof.dependencies.paths.size(), path_count, seed, "dependency path count",
                  __FILE__, __LINE__);
  for (std::size_t index = 0; index < path_count; ++index) {
    seeded_check(proof.dependencies.paths[index].path == proof.request.paths[index].path, seed,
                 "dependency mirrors the canonical path order", __FILE__, __LINE__);
    seeded_check_eq(proof.dependencies.paths[index].generation,
                    proof.request.paths[index].authority_generation, seed,
                    "dependency mirrors the authority generation", __FILE__, __LINE__);
  }
  seeded_check(proof.dependencies.policy_generation == proof.request.policy_generation, seed,
               "dependency mirrors the policy generation", __FILE__, __LINE__);
  seeded_check(proof.generation.is_set(), seed, "a committed revision has a generation", __FILE__,
               __LINE__);
  for (std::size_t index = 1; index < proof.conflicts.size(); ++index) {
    seeded_check(!conflict_less(proof.conflicts[index], proof.conflicts[index - 1]), seed,
                 "conflicts are canonically ordered", __FILE__, __LINE__);
  }
  for (std::size_t index = 1; index < proof.dependencies.topology_entities.size(); ++index) {
    seeded_check(proof.dependencies.topology_entities[index - 1] <
                     proof.dependencies.topology_entities[index],
                 seed, "topology footprint is canonical and unique", __FILE__, __LINE__);
  }
}

// Nothing that claims to be current may bind a generation an authority has
// moved past.
void check_currentness(const pd_test::Fixture& fixture, std::uint64_t seed) {
  const DiversityRuntime::QueryResult all = fixture.runtime.all_proofs();
  for (const DiversityProofId& id : all.proofs) {
    const std::optional<DiversityProof> proof = fixture.runtime.proof(id);
    if (!proof.has_value() || !proof->current()) {
      continue;
    }
    for (const PathAuthorityBinding& binding : proof->dependencies.paths) {
      const std::optional<PathAuthorityGeneration> current =
          fixture.evidence.current_generation(binding.path);
      seeded_check(current.has_value() && *current == binding.generation, seed,
                   "current proof binds the current Path Authority generation", __FILE__,
                   __LINE__);
      seeded_check(fixture.evidence.is_authorized(binding.path, binding.generation), seed,
                   "current proof binds an authorized path", __FILE__, __LINE__);
    }
    seeded_check_eq(proof->dependencies.topology_generation, fixture.evidence.topology_generation(),
                    seed, "current proof binds the current topology generation", __FILE__,
                    __LINE__);
    seeded_check_eq(proof->dependencies.failure_domain_generation, fixture.evidence.generation(),
                    seed, "current proof binds the current failure-domain generation", __FILE__,
                    __LINE__);
    seeded_check_eq(proof->dependencies.policy_generation,
                    fixture.runtime.policy_generation(proof->request.policy), seed,
                    "current proof binds the published policy generation", __FILE__, __LINE__);
  }
}

void complete_evidence(pd_test::Fixture& fixture, const Scenario& scenario) {
  const DomainRelation relations[3] = {DomainRelation::FAILURE_DOMAIN, DomainRelation::RACK,
                                       DomainRelation::SITE};
  for (std::size_t index = 0; index < scenario.compositions.size(); ++index) {
    for (const EntityRef& entity : pd_test::entities_of(scenario.compositions[index])) {
      for (DomainRelation relation : relations) {
        std::vector<FailureDomainId> domains = {
            FailureDomainId::parse("dom-path-" + std::to_string(index))};
        if (index % 2 == 0) {
          domains.push_back(FailureDomainId::parse("dom-shared"));
        }
        fixture.evidence.set_domain_membership(entity, relation, EvidenceCoverage::COMPLETE,
                                               domains);
      }
      fixture.evidence.set_srlg_membership(
          entity, EvidenceCoverage::COMPLETE,
          {SharedRiskGroupId::parse("srlg-path-" + std::to_string(index % 2))});
    }
  }
}

}  // namespace

PD_TEST(proven_diverse_implies_complete_required_evidence) {
  for (std::uint32_t index = 0; index < kScenarios; ++index) {
    const std::uint64_t seed = 0x1000ULL + index;
    pd_test::Fixture fixture;
    const Scenario scenario = build_scenario(fixture, seed);
    check_proof_invariants(scenario.proof, scenario.policy_content, seed);
  }
}

PD_TEST(shared_required_resource_implies_not_diverse) {
  std::uint32_t proven = 0;
  std::uint32_t conflicted = 0;
  for (std::uint32_t index = 0; index < kScenarios; ++index) {
    const std::uint64_t seed = 0x2000ULL + index;
    pd_test::Fixture fixture;
    const Scenario scenario = build_scenario(fixture, seed);
    const DiversityProof& proof = scenario.proof;
    check_proof_invariants(proof, scenario.policy_content, seed);
    if (proof.outcome == ProofOutcome::PROVEN_DIVERSE) {
      ++proven;
      for (const ClassResult& result : proof.classes) {
        seeded_check_eq(result.shared_total, std::uint64_t{0}, seed,
                        "proven proof reports no shared resource", __FILE__, __LINE__);
      }
      if (scenario.policy_content.semantics == SetSemantics::ALL_PAIRS) {
        for (const PairwiseCell& cell : proof.matrix.cells) {
          seeded_check(cell.independent, seed, "proven proof has only independent pairs", __FILE__,
                       __LINE__);
        }
      }
    }
    if (proof.outcome == ProofOutcome::NOT_DIVERSE) {
      ++conflicted;
      bool named = false;
      for (const ClassResult& result : proof.classes) {
        named = named || result.shared_total > 0;
      }
      seeded_check(named, seed, "a conflict names at least one required class", __FILE__,
                   __LINE__);
    }
  }
  // The mix must exercise both outcomes; a suite that only ever proves diversity
  // would not be testing the conflict path at all.
  PD_CHECK(proven > 0);
  PD_CHECK(conflicted > 0);
}

PD_TEST(unknown_never_becomes_proven_without_new_evidence) {
  std::uint32_t unknown_seen = 0;
  for (std::uint32_t index = 0; index < kScenarios; ++index) {
    const std::uint64_t seed = 0x3000ULL + index;
    pd_test::Fixture fixture;
    const Scenario scenario = build_scenario(fixture, seed);
    if (scenario.proof.outcome != ProofOutcome::UNKNOWN_INCOMPLETE_EVIDENCE) {
      continue;
    }
    ++unknown_seen;
    const DiversityProof before = scenario.proof;
    // The same request with a fresh attempt and the same evidence reproduces the
    // unknown verdict exactly, and nothing advances.
    const MutationResult repeated =
        fixture.runtime.evaluate(scenario.request, fixture.actor("property-repeat"));
    seeded_check_eq(repeated.status, MutationStatus::UNCHANGED, seed,
                    "an unchanged re-evaluation reports UNCHANGED", __FILE__, __LINE__);
    seeded_check(repeated.proof.outcome != ProofOutcome::PROVEN_DIVERSE, seed,
                 "UNKNOWN never becomes PROVEN without new evidence", __FILE__, __LINE__);
    seeded_check(repeated.proof.semantic_digest == before.semantic_digest, seed,
                 "an unchanged re-evaluation keeps the semantic digest", __FILE__, __LINE__);
    seeded_check_eq(repeated.proof.generation, before.generation, seed,
                    "an unchanged re-evaluation advances nothing", __FILE__, __LINE__);

    // With complete evidence for every required relation the verdict must be
    // decisive, because no required class can still be unknown.
    complete_evidence(fixture, scenario);
    const MutationResult completed =
        fixture.runtime.evaluate(scenario.request, fixture.actor("property-complete"));
    seeded_check(completed.proof.outcome == ProofOutcome::PROVEN_DIVERSE ||
                     completed.proof.outcome == ProofOutcome::NOT_DIVERSE,
                 seed, "complete evidence decides", __FILE__, __LINE__);
    seeded_check(completed.proof.generation >= before.generation, seed,
                 "generations never decrease", __FILE__, __LINE__);
  }
  PD_CHECK(unknown_seen > 0);
}

PD_TEST(stale_generations_never_remain_current) {
  for (std::uint32_t index = 0; index < kScenarios; ++index) {
    const std::uint64_t seed = 0x4000ULL + index;
    pd_test::Fixture fixture;
    const Scenario scenario = build_scenario(fixture, seed);
    check_currentness(fixture, seed);

    // Path Authority moves for one path.
    const PathId first = PathId::parse(scenario.names.front());
    const std::optional<PathAuthorityGeneration> generation =
        fixture.evidence.current_generation(first);
    PD_REQUIRE(generation.has_value());
    fixture.evidence.set_path_authority(first, generation->next(), true);
    fixture.runtime.refresh_currentness();
    check_currentness(fixture, seed);

    const std::optional<DiversityProof> after_path = fixture.runtime.proof(scenario.proof.id);
    PD_REQUIRE(after_path.has_value());
    if (after_path->current()) {
      for (const PathAuthorityBinding& binding : after_path->dependencies.paths) {
        if (binding.path == first) {
          seeded_check_eq(binding.generation, generation->next(), seed,
                          "a proof that stays current rebinds the new authority generation",
                          __FILE__, __LINE__);
        }
      }
    }

    // Topology advances past every recorded dependency.
    fixture.evidence.advance_topology_generation();
    fixture.runtime.demote_topology_generation(fixture.evidence.topology_generation());
    check_currentness(fixture, seed);
    const std::optional<DiversityProof> after_topology = fixture.runtime.proof(scenario.proof.id);
    PD_REQUIRE(after_topology.has_value());
    seeded_check(!after_topology->current(), seed,
                 "a stale topology generation never remains current", __FILE__, __LINE__);

    // Failure-domain classification advances past every recorded dependency.
    fixture.evidence.advance_failure_domain_generation();
    fixture.runtime.demote_failure_domain_generation(fixture.evidence.generation());
    check_currentness(fixture, seed);
    const std::optional<DiversityProof> after_domains = fixture.runtime.proof(scenario.proof.id);
    PD_REQUIRE(after_domains.has_value());
    seeded_check(!after_domains->current(), seed,
                 "a stale failure-domain generation never remains current", __FILE__, __LINE__);
  }
}

PD_TEST(canonical_path_order_does_not_change_semantics) {
  for (std::uint32_t index = 0; index < kScenarios; ++index) {
    const std::uint64_t seed = 0x5000ULL + index;
    pd_test::Fixture first_fixture;
    const Scenario scenario = build_scenario(first_fixture, seed);

    // The same scenario rebuilt from scratch, evaluated with the path list
    // reversed: identity, digest and every semantic field must agree.
    pd_test::Fixture second_fixture;
    const Scenario rebuilt = build_scenario(second_fixture, seed);
    ProofRequest reversed = rebuilt.request;
    std::reverse(reversed.paths.begin(), reversed.paths.end());
    const MutationResult shuffled =
        second_fixture.runtime.evaluate(reversed, second_fixture.actor("property-reversed"));

    seeded_check_eq(shuffled.proof.id, scenario.proof.id, seed,
                    "path arrival order does not change proof identity", __FILE__, __LINE__);
    seeded_check(shuffled.proof.semantic_digest == scenario.proof.semantic_digest, seed,
                 "path arrival order does not change the semantic digest", __FILE__, __LINE__);
    seeded_check_eq(shuffled.proof.outcome, scenario.proof.outcome, seed,
                    "path arrival order does not change the outcome", __FILE__, __LINE__);
    seeded_check(shuffled.proof.matrix == scenario.proof.matrix, seed,
                 "path arrival order does not change the matrix", __FILE__, __LINE__);
    seeded_check(shuffled.proof.conflicts == scenario.proof.conflicts, seed,
                 "path arrival order does not change the conflicts", __FILE__, __LINE__);
    seeded_check(shuffled.proof.witness == scenario.proof.witness, seed,
                 "path arrival order does not change the witness", __FILE__, __LINE__);
    seeded_check(shuffled.proof.dependencies == scenario.proof.dependencies, seed,
                 "path arrival order does not change the dependencies", __FILE__, __LINE__);
    seeded_check(shuffled.proof.classes == scenario.proof.classes, seed,
                 "path arrival order does not change the class results", __FILE__, __LINE__);
  }
}

PD_TEST(a_terminal_proof_never_reactivates) {
  for (std::uint32_t index = 0; index < kScenarios; ++index) {
    const std::uint64_t seed = 0x6000ULL + index;
    pd_test::Fixture fixture;
    const Scenario scenario = build_scenario(fixture, seed);
    const DiversityProofId id = scenario.proof.id;

    const MutationResult retired =
        fixture.runtime.retire(id, fixture.actor("property-retire"), "retired by property test");
    PD_REQUIRE(retired.status == MutationStatus::APPLIED ||
               retired.status == MutationStatus::UNCHANGED);
    const std::optional<DiversityProof> after_retire = fixture.runtime.proof(id);
    PD_REQUIRE(after_retire.has_value());
    seeded_check_eq(after_retire->lifecycle, LifecycleState::RETIRED, seed, "retire reaches RETIRED",
                    __FILE__, __LINE__);
    seeded_check(!after_retire->current(), seed, "a retired proof is not current", __FILE__,
                 __LINE__);

    // No transition table entry leaves a terminal state.
    for (std::uint8_t raw = static_cast<std::uint8_t>(LifecycleState::DECLARED);
         raw <= static_cast<std::uint8_t>(LifecycleState::HISTORICAL); ++raw) {
      const LifecycleState target = static_cast<LifecycleState>(raw);
      if (target == LifecycleState::RETIRED) {
        continue;
      }
      seeded_check(!lifecycle_transition_allowed(LifecycleState::RETIRED, target), seed,
                   "RETIRED is terminal in the transition table", __FILE__, __LINE__);
    }

    // Every public transition out of RETIRED is refused and the revision stays
    // retired; revoke, historical and supersede are the only other targets.
    const MutationResult revoked =
        fixture.runtime.revoke(id, fixture.actor("property-revoke"), "attempt");
    const MutationResult historical =
        fixture.runtime.mark_historical(id, fixture.actor("property-historical"), "attempt");
    const MutationResult superseded = fixture.runtime.supersede(id, fixture.actor("property-supersede"));
    seeded_check_eq(revoked.status, MutationStatus::ILLEGAL_TRANSITION, seed,
                    "a retired proof is never revoked", __FILE__, __LINE__);
    seeded_check_eq(historical.status, MutationStatus::ILLEGAL_TRANSITION, seed,
                    "a retired proof never becomes historical", __FILE__, __LINE__);
    seeded_check_eq(superseded.status, MutationStatus::ILLEGAL_TRANSITION, seed,
                    "a retired proof is never superseded", __FILE__, __LINE__);

    // A retired revision is never revalidated back into service.
    const MutationResult revalidated =
        fixture.runtime.revalidate(id, fixture.actor("property-revalidate"));
    seeded_check_eq(revalidated.status, MutationStatus::ILLEGAL_TRANSITION, seed,
                    "a terminal proof is never revalidated", __FILE__, __LINE__);
    const std::optional<DiversityProof> still = fixture.runtime.proof(id);
    PD_REQUIRE(still.has_value());
    seeded_check_eq(still->lifecycle, LifecycleState::RETIRED, seed,
                    "a retired revision stays retired", __FILE__, __LINE__);
    seeded_check(!still->current(), seed, "a retired revision is never current again", __FILE__,
                 __LINE__);
  }
}

PD_TEST(a_stale_worker_or_epoch_cannot_mutate) {
  for (std::uint32_t index = 0; index < kScenarios; ++index) {
    const std::uint64_t seed = 0x7000ULL + index;
    pd_test::Fixture fixture;
    const Scenario scenario = build_scenario(fixture, seed);

    // Fencing the publishing boot makes every later mutation with that boot
    // impossible, and nothing in the registry moves.
    const ActingAuthority fenced_actor = fixture.actor("property-fenced");
    PD_CHECK_EQ(fixture.publication.fence_boot(fixture.boot), AuthorityStatus::ACCEPTED);
    const std::size_t proofs_before = fixture.runtime.proof_count();
    const std::size_t policies_before = fixture.runtime.policy_count();
    const MutationStatus fenced = fixture.runtime.evaluate(scenario.request, fenced_actor).status;
    seeded_check_eq(fenced, MutationStatus::FENCED_PUBLISHER, seed,
                    "a fenced boot cannot mutate", __FILE__, __LINE__);
    seeded_check_eq(fixture.runtime.proof_count(), proofs_before, seed,
                    "a refused mutation changes no proof", __FILE__, __LINE__);
    seeded_check_eq(fixture.runtime.policy_count(), policies_before, seed,
                    "a refused mutation changes no policy", __FILE__, __LINE__);

    // An epoch that has moved past the presenter's epoch is refused too.
    pd_test::Fixture second;
    const Scenario other = build_scenario(second, seed);
    const ActingAuthority stale_actor = second.actor("property-stale");
    PD_CHECK_EQ(second.publication.restore_epoch(second.publication.current_epoch().next()),
                AuthorityStatus::ACCEPTED);
    const std::size_t other_proofs = second.runtime.proof_count();
    const std::size_t other_policies = second.runtime.policy_count();
    const MutationStatus stale = second.runtime.evaluate(other.request, stale_actor).status;
    seeded_check(stale == MutationStatus::STALE_EPOCH || stale == MutationStatus::FENCED_PUBLISHER,
                 seed, "a stale epoch cannot mutate", __FILE__, __LINE__);
    seeded_check_eq(second.runtime.proof_count(), other_proofs, seed,
                    "a stale epoch changes no proof", __FILE__, __LINE__);
    seeded_check_eq(second.runtime.policy_count(), other_policies, seed,
                    "a stale epoch changes no policy", __FILE__, __LINE__);
  }
}

PD_TEST(exact_replay_advances_nothing) {
  for (std::uint32_t index = 0; index < kScenarios; ++index) {
    const std::uint64_t seed = 0x8000ULL + index;
    pd_test::Fixture fixture;
    const Scenario scenario = build_scenario(fixture, seed);
    const DiversityProofGeneration generation = scenario.proof.generation;

    // A fresh attempt with identical inputs is UNCHANGED: the exact same
    // revision is returned and nothing advances.
    const MutationResult unchanged =
        fixture.runtime.evaluate(scenario.request, fixture.actor("property-unchanged"));
    seeded_check_eq(unchanged.status, MutationStatus::UNCHANGED, seed,
                    "an identical re-evaluation is UNCHANGED", __FILE__, __LINE__);
    seeded_check_eq(unchanged.proof.generation, generation, seed,
                    "an unchanged re-evaluation advances nothing", __FILE__, __LINE__);
    seeded_check(unchanged.proof.semantic_digest == scenario.proof.semantic_digest, seed,
                 "an unchanged re-evaluation returns the same revision", __FILE__, __LINE__);

    // Re-presenting the exact same attempt is IDEMPOTENT and equally inert.
    const ActingAuthority actor = fixture.actor("property-unchanged");
    const RuntimeStats before = fixture.runtime.stats();
    const MutationResult replay = fixture.runtime.evaluate(scenario.request, actor);
    seeded_check_eq(replay.status, MutationStatus::IDEMPOTENT, seed,
                    "an exact replay is idempotent", __FILE__, __LINE__);
    seeded_check_eq(replay.proof.generation, generation, seed,
                    "an exact replay does not advance the proof generation", __FILE__, __LINE__);
    const RuntimeStats after = fixture.runtime.stats();
    seeded_check_eq(after.idempotent_replays, before.idempotent_replays + 1, seed,
                    "an idempotent replay is counted, not committed", __FILE__, __LINE__);
    seeded_check_eq(after.commits, before.commits, seed, "an idempotent replay does not commit",
                    __FILE__, __LINE__);
  }
}

PD_TEST(generations_never_decrease_or_wrap) {
  // The pure guard first: zero is never a legal generation and the maximum can
  // never be advanced.
  PD_CHECK(!DiversityProofGeneration::from_wire(0).has_value());
  PD_CHECK(!TopologyGeneration::from_wire(0).has_value());
  PD_CHECK(!CoordinatorEpoch::from_wire(0).has_value());
  PD_CHECK(DiversityProofGeneration::from_wire(1).has_value());
  PD_CHECK(!DiversityProofGeneration::can_advance(static_cast<std::uint64_t>(-1)));
  PD_CHECK(DiversityProofGeneration::can_advance(1));
  PD_CHECK_EQ(DiversityProofGeneration::from_value(7).next().value(), std::uint64_t{8});

  for (std::uint32_t index = 0; index < kScenarios; ++index) {
    const std::uint64_t seed = 0x9000ULL + index;
    pd_test::Fixture fixture;
    const Scenario scenario = build_scenario(fixture, seed);
    const DiversityProofId id = scenario.proof.id;
    DiversityProofGeneration previous = scenario.proof.generation;
    seeded_check(previous.is_set(), seed, "a committed revision carries a generation", __FILE__,
                 __LINE__);

    for (int revision = 0; revision < 3; ++revision) {
      // Toggling one link forces a new revision without leaving the scenario.
      const std::string name = scenario.names.back();
      const std::string link = revision % 2 == 0 ? "prop-link-0" : "prop-link-9";
      fixture.evidence.set_path(pd_test::make_path(name, 1, {"prop-node-0"}, {link},
                                                   {"prop-dev-0"}, "prop-src-0", "prop-dst-0"));
      const MutationResult result = fixture.runtime.evaluate(
          scenario.request, fixture.actor("property-generation-" + std::to_string(revision)));
      seeded_check(result.proof.generation >= previous, seed,
                   "a proof generation never decreases", __FILE__, __LINE__);
      if (result.status == MutationStatus::APPLIED) {
        seeded_check(result.proof.generation > previous, seed,
                     "an applied revision advances the generation", __FILE__, __LINE__);
      }
      previous = result.proof.generation;
    }

    // Publishing updated content under the same identity advances the policy
    // generation, never rewinds it.
    ActingAuthority publisher = fixture.actor("property-policy-update");
    publisher.expected_policy_generation = fixture.runtime.policy_generation(scenario.policy.id);
    DiversityPolicy updated = scenario.policy_content;
    updated.description = "updated policy " + std::to_string(seed);
    const MutationResult republished = fixture.runtime.publish_policy(updated, publisher);
    PD_CHECK_EQ(republished.status, MutationStatus::APPLIED);
    seeded_check(republished.policy.generation > scenario.policy.generation, seed,
                 "a policy generation advances on update", __FILE__, __LINE__);
    const std::optional<DiversityProof> after = fixture.runtime.proof(id);
    PD_REQUIRE(after.has_value());
    seeded_check(after->generation >= previous, seed, "the stored proof keeps its generation",
                 __FILE__, __LINE__);
  }
}

PD_TEST(reverse_indexes_match_dependencies) {
  for (std::uint32_t index = 0; index < kScenarios; ++index) {
    const std::uint64_t seed = 0xA000ULL + index;
    pd_test::Fixture fixture;
    const Scenario scenario = build_scenario(fixture, seed);
    const DiversityProof& proof = scenario.proof;

    const auto contains = [](const DiversityRuntime::QueryResult& result,
                             const DiversityProofId& id) {
      for (const DiversityProofId& candidate : result.proofs) {
        if (candidate == id) {
          return true;
        }
      }
      return false;
    };

    for (const PathRef& reference : proof.request.paths) {
      const DiversityRuntime::QueryResult found = fixture.runtime.proofs_for_path(reference.path);
      seeded_check(contains(found, proof.id), seed, "the path index resolves the proof", __FILE__,
                   __LINE__);
      seeded_check(found.total >= 1, seed, "the path index reports a total", __FILE__, __LINE__);
    }
    for (const EntityRef& entity : proof.dependencies.topology_entities) {
      seeded_check(contains(fixture.runtime.proofs_for_entity(entity), proof.id), seed,
                   "the entity index resolves every dependency", __FILE__, __LINE__);
    }
    for (const ClassResult& result : proof.classes) {
      for (const SharedResource& conflict : result.shared) {
        // Only the domain-backed conflict classes feed the failure-domain index;
        // structural conflicts name a link, node or device and risk groups are
        // indexed by identity instead.
        if (conflict.kind == ConflictClass::SHARED_RISK_GROUP ||
            !relation_for_conflict_class(conflict.kind).has_value()) {
          continue;
        }
        const auto domain = FailureDomainId::try_parse(conflict.id);
        if (!domain.has_value()) {
          continue;
        }
        seeded_check(contains(fixture.runtime.proofs_for_domain(*domain), proof.id), seed,
                     "the domain index resolves every consulted domain", __FILE__, __LINE__);
      }
    }
    seeded_check(contains(fixture.runtime.proofs_for_policy(proof.request.policy), proof.id), seed,
                 "the policy index resolves the proof", __FILE__, __LINE__);
    seeded_check(contains(fixture.runtime.proofs_for_boot(proof.provenance.boot), proof.id), seed,
                 "the boot index resolves the proof", __FILE__, __LINE__);
    seeded_check(contains(fixture.runtime.current_proofs(), proof.id) == proof.current(), seed,
                 "the current set matches the proof currentness", __FILE__, __LINE__);
  }
}

PD_TEST(persistence_round_trips) {
  for (std::uint32_t index = 0; index < kScenarios; ++index) {
    const std::uint64_t seed = 0xB000ULL + index;
    pd_test::Fixture fixture;
    const Scenario scenario = build_scenario(fixture, seed);

    const std::filesystem::path path = pd_test::unique_test_path("property.pds");
    PD_CHECK_EQ(fixture.runtime.save(path.string()), PersistenceStatus::OK);
    std::vector<std::uint8_t> bytes;
    PD_CHECK_EQ(read_store_bytes(path.string(), fixture.limits, bytes), PersistenceStatus::OK);

    StoreContents contents;
    std::string detail;
    seeded_check_eq(decode_store(bytes.data(), bytes.size(), fixture.limits, contents, detail),
                    PersistenceStatus::OK, seed, "the encoded store decodes", __FILE__, __LINE__);
    seeded_check(encode_store(contents, fixture.limits) == bytes, seed,
                 "a re-encode reproduces the exact bytes", __FILE__, __LINE__);
    seeded_check_eq(contents.proofs.size(), fixture.runtime.proof_count(), seed,
                    "every proof survives the round trip", __FILE__, __LINE__);
    seeded_check_eq(contents.policies.size(), fixture.runtime.policy_count(), seed,
                    "every policy survives the round trip", __FILE__, __LINE__);
    PD_REQUIRE(!contents.proofs.empty());
    seeded_check(contents.proofs.front() == scenario.proof, seed,
                 "the proof content round-trips exactly", __FILE__, __LINE__);

    // Every sixteenth scenario also crosses the file boundary into a fresh
    // runtime, which is where a partial or reordered write would show up.
    if (index % 16 == 0) {
      pd_test::Fixture recovered;
      seeded_check_eq(recovered.runtime.load(path.string()), PersistenceStatus::OK, seed,
                      "the store loads into a fresh runtime", __FILE__, __LINE__);
      seeded_check_eq(recovered.runtime.proof_count(), fixture.runtime.proof_count(), seed,
                      "the recovered runtime holds every proof", __FILE__, __LINE__);
      const std::optional<DiversityProof> restored =
          recovered.runtime.proof(scenario.proof.id);
      seeded_check(restored.has_value(), seed, "the recovered runtime resolves the proof", __FILE__,
                   __LINE__);
      if (restored.has_value()) {
        seeded_check(*restored == scenario.proof, seed, "the recovered proof is identical",
                     __FILE__, __LINE__);
      }
    }
    std::error_code error;
    std::filesystem::remove(path, error);
  }
}

PD_TEST(digests_are_deterministic) {
  for (std::uint32_t index = 0; index < kScenarios; ++index) {
    const std::uint64_t seed = 0xC000ULL + index;
    pd_test::Fixture fixture;
    const Scenario scenario = build_scenario(fixture, seed);
    const DiversityProof& proof = scenario.proof;

    seeded_check(proof_semantic_digest(proof) == proof_semantic_digest(proof), seed,
                 "the proof digest is stable", __FILE__, __LINE__);
    seeded_check(scenario.policy_content.semantic_digest() ==
                     scenario.policy_content.semantic_digest(),
                 seed, "the policy digest is stable", __FILE__, __LINE__);
    const ProofSnapshot snapshot = capture_snapshot(proof);
    seeded_check(snapshot_digest(snapshot) == snapshot_digest(snapshot), seed,
                 "the snapshot digest is stable", __FILE__, __LINE__);
    seeded_check(proof.request.digest() == proof.request.digest(), seed,
                 "the request digest is stable", __FILE__, __LINE__);
    seeded_check_eq(proof_identity(proof.request), proof_identity(proof.request), seed,
                    "proof identity is stable", __FILE__, __LINE__);
    seeded_check_eq(proof.request.path_set(), proof.request.path_set(), seed,
                    "the path-set identity is stable", __FILE__, __LINE__);
    seeded_check(proof.id == derived_proof_id(proof.request.digest()), seed,
                 "the proof identity is derived from its request digest", __FILE__, __LINE__);

    // A rebuild of the same scenario in a fresh runtime, under a different
    // worker boot and attempt, must reach the same semantic digest.
    pd_test::Fixture rebuilder;
    const Scenario rebuilt = build_scenario(rebuilder, seed);
    seeded_check(proof_semantic_digest(rebuilt.proof) == proof_semantic_digest(proof), seed,
                 "independent evaluation reaches the same semantic digest", __FILE__, __LINE__);

    // Encoding a record and decoding it again preserves the value and the digest.
    ByteWriter writer;
    encode_proof(writer, proof);
    ByteReader reader(writer.data().data(), writer.size());
    DiversityProof decoded;
    seeded_check_eq(decode_proof(reader, fixture.limits, decoded), DecodeStatus::OK, seed,
                    "the record decodes", __FILE__, __LINE__);
    seeded_check(decoded == proof, seed, "the record round-trips exactly", __FILE__, __LINE__);
    seeded_check(proof_semantic_digest(decoded) == proof_semantic_digest(proof), seed,
                 "the digest survives a round trip", __FILE__, __LINE__);
  }
}

PD_TEST_MAIN()
