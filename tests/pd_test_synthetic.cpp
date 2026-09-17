// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.

// The synthetic fabric generator and its deterministic random stream: the same
// seed and options always produce the same fabric, different seeds behave as
// documented, complete and incomplete coverage modes differ in exactly the way
// the options say, and the generated policy validates.

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "test_support.hpp"

namespace {

using namespace path_diversity;

SyntheticFabricOptions small_options(std::uint64_t seed, bool complete_coverage) {
  SyntheticFabricOptions options;
  options.spine_count = 2;
  options.leaf_count = 4;
  options.racks = 2;
  options.pods = 2;
  options.sites = 1;
  options.paths_per_pair = 2;
  options.complete_domain_coverage = complete_coverage;
  options.seed = seed;
  return options;
}

std::vector<EntityRef> entities_of(const PathComposition& composition) {
  std::vector<EntityRef> entities;
  for (const LinkId& link : composition.links) {
    entities.push_back(EntityRef{EntityKind::LINK, link.str()});
  }
  for (const NodeId& node : composition.transit_nodes) {
    entities.push_back(EntityRef{EntityKind::NODE, node.str()});
  }
  for (const NodeId& node : composition.sources) {
    entities.push_back(EntityRef{EntityKind::ENDPOINT, node.str()});
  }
  for (const NodeId& node : composition.destinations) {
    entities.push_back(EntityRef{EntityKind::ENDPOINT, node.str()});
  }
  for (const DeviceId& device : composition.devices) {
    entities.push_back(EntityRef{EntityKind::DEVICE, device.str()});
  }
  return entities;
}

// Canonical per-entity classification report, so two seeds can be compared
// without depending on any iteration order.
std::vector<std::string> coverage_map(const InMemoryEvidence& evidence,
                                      const SyntheticFabric& fabric) {
  std::vector<std::string> entries;
  for (const SyntheticPath& path : fabric.paths) {
    const std::optional<PathComposition> composition = evidence.composition(path.path);
    if (!composition.has_value()) {
      continue;
    }
    for (const EntityRef& entity : entities_of(*composition)) {
      const DomainEvidence membership =
          evidence.domain_membership(entity, DomainRelation::FAILURE_DOMAIN);
      entries.push_back(entity.render() + "=" + std::string(to_string(membership.coverage)));
    }
  }
  canonical_sort_unique(entries);
  return entries;
}

std::size_t count_coverage(const InMemoryEvidence& evidence, const SyntheticFabric& fabric,
                           EvidenceCoverage wanted) {
  std::size_t count = 0;
  for (const SyntheticPath& path : fabric.paths) {
    const std::optional<PathComposition> composition = evidence.composition(path.path);
    if (!composition.has_value()) {
      continue;
    }
    for (const EntityRef& entity : entities_of(*composition)) {
      if (evidence.domain_membership(entity, DomainRelation::FAILURE_DOMAIN).coverage == wanted) {
        ++count;
      }
    }
  }
  return count;
}

}  // namespace

PD_TEST(populate_is_a_pure_function_of_seed_and_options) {
  pd_test::InMemoryEvidence first_evidence;
  pd_test::InMemoryEvidence second_evidence;
  const SyntheticFabricOptions options = small_options(4242, true);
  const SyntheticFabric first = populate_synthetic_fabric(first_evidence, options);
  const SyntheticFabric second = populate_synthetic_fabric(second_evidence, options);

  PD_CHECK(first.paths == second.paths);
  PD_CHECK_EQ(first.paths.size(),
              static_cast<std::size_t>(options.leaf_count) * options.paths_per_pair);
  PD_CHECK_EQ(first.render(), second.render());
  PD_CHECK_EQ(first_evidence.render(), second_evidence.render());
  PD_CHECK_EQ(first_evidence.path_count(), second_evidence.path_count());
  PD_CHECK_EQ(first_evidence.path_count(), first.paths.size());
  PD_CHECK_EQ(first_evidence.membership_count(), second_evidence.membership_count());
  PD_CHECK(first_evidence.membership_count() > first.paths.size());
  PD_CHECK_EQ(first.topology_generation.value(), std::uint64_t{1});
  PD_CHECK_EQ(first.failure_domain_generation.value(), std::uint64_t{1});
  PD_CHECK_EQ(first.options.seed, options.seed);
  PD_CHECK(first.options.complete_domain_coverage);

  const std::string report = first.render();
  PD_CHECK(report.find("synthetic fabric spines=2") != std::string::npos);
  PD_CHECK(report.find("leaves=4") != std::string::npos);
  PD_CHECK(report.find("paths=8") != std::string::npos);
  PD_CHECK(report.find("topology=g1") != std::string::npos);
  PD_CHECK(report.find("failure-domains=g1") != std::string::npos);
  PD_CHECK(report.find("coverage=COMPLETE") != std::string::npos);
  PD_CHECK(report.find("seed=4242") != std::string::npos);

  for (const SyntheticPath& path : first.paths) {
    PD_CHECK(path.path.valid());
    PD_CHECK_EQ(path.authority_generation.value(), std::uint64_t{1});
    PD_CHECK_EQ(path.label, path.path.str());
    PD_CHECK(first_evidence.has_path(path.path));
    PD_CHECK(first_evidence.is_authorized(path.path, path.authority_generation));
    const std::optional<PathAuthorityGeneration> current = first_evidence.current_generation(path.path);
    PD_REQUIRE(current.has_value());
    PD_CHECK_EQ(current->value(), std::uint64_t{1});
    const std::optional<PathComposition> composition = first_evidence.composition(path.path);
    PD_REQUIRE(composition.has_value());
    PD_CHECK(composition->path == path.path);
    PD_CHECK_EQ(composition->topology_generation.value(), std::uint64_t{1});
    PD_CHECK(!composition->links.empty());
    PD_CHECK(!composition->transit_nodes.empty());
    PD_CHECK(!composition->devices.empty());
    PD_CHECK(!composition->sources.empty());
    PD_CHECK(!composition->destinations.empty());
    PD_CHECK(composition->all_topology_complete());
    PD_CHECK(!composition->has_repeated_topology_elements());
  }
}

PD_TEST(seed_changes_coverage_but_not_shape) {
  pd_test::InMemoryEvidence base_evidence;
  pd_test::InMemoryEvidence other_evidence;
  const SyntheticFabric base = populate_synthetic_fabric(base_evidence, small_options(11, true));
  const SyntheticFabric other = populate_synthetic_fabric(other_evidence, small_options(22, true));

  // With complete coverage the seed carries no information: the fabric is a
  // pure function of the options.
  PD_CHECK(base.paths == other.paths);
  PD_CHECK(coverage_map(base_evidence, base) == coverage_map(other_evidence, other));
  PD_CHECK_EQ(base_evidence.render(), other_evidence.render());
  PD_CHECK(!(base.render() == other.render()));
  const std::string base_report = base.render();
  const std::string other_report = other.render();
  PD_CHECK_EQ(base_report.substr(0, base_report.find(" seed=")),
              other_report.substr(0, other_report.find(" seed=")));

  // With incomplete coverage the seed decides which entities are left ABSENT.
  pd_test::InMemoryEvidence seed_a_evidence;
  pd_test::InMemoryEvidence seed_b_evidence;
  pd_test::InMemoryEvidence seed_c_evidence;
  const SyntheticFabric seed_a = populate_synthetic_fabric(seed_a_evidence, small_options(101, false));
  const SyntheticFabric seed_b = populate_synthetic_fabric(seed_b_evidence, small_options(202, false));
  const SyntheticFabric seed_c = populate_synthetic_fabric(seed_c_evidence, small_options(303, false));
  PD_CHECK(seed_a.paths == seed_b.paths);
  PD_CHECK(seed_b.paths == seed_c.paths);
  PD_CHECK(seed_a.paths == base.paths);
  const std::vector<std::string> map_a = coverage_map(seed_a_evidence, seed_a);
  const std::vector<std::string> map_b = coverage_map(seed_b_evidence, seed_b);
  const std::vector<std::string> map_c = coverage_map(seed_c_evidence, seed_c);
  PD_CHECK_EQ(map_a.size(), map_b.size());
  // Each seed selects its own deterministic eighth of entities to leave ABSENT,
  // so the coverage maps genuinely differ between seeds while the path catalogue
  // stays identical.
  PD_CHECK(!(map_a == map_b));
  PD_CHECK(!(map_a == map_c));
  PD_CHECK(!(map_b == map_c));
  const auto count_suffix = [](const std::vector<std::string>& entries,
                               const std::string& suffix) {
    std::size_t count = 0;
    for (const std::string& entry : entries) {
      if (entry.size() >= suffix.size() &&
          entry.compare(entry.size() - suffix.size(), suffix.size(), suffix) == 0) {
        ++count;
      }
    }
    return count;
  };
  PD_CHECK(count_suffix(map_a, "=COMPLETE") > 0);
  PD_CHECK(count_suffix(map_a, "=ABSENT") + count_suffix(map_b, "=ABSENT") +
               count_suffix(map_c, "=ABSENT") >
           0);
  PD_CHECK(seed_a.render() != seed_b.render());
  PD_CHECK(seed_a.render().find("coverage=PARTIAL") != std::string::npos);
  PD_CHECK(seed_a.render().find("seed=101") != std::string::npos);
  PD_CHECK(seed_b.render().find("seed=202") != std::string::npos);

  // The same seed replays the same coverage exactly.
  pd_test::InMemoryEvidence replay_evidence;
  const SyntheticFabric replay = populate_synthetic_fabric(replay_evidence, small_options(101, false));
  PD_CHECK(replay.paths == seed_a.paths);
  PD_CHECK(coverage_map(replay_evidence, replay) == map_a);
  PD_CHECK_EQ(replay.render(), seed_a.render());
}

PD_TEST(complete_and_incomplete_coverage_modes) {
  pd_test::InMemoryEvidence complete_evidence;
  const SyntheticFabric complete =
      populate_synthetic_fabric(complete_evidence, small_options(7, true));
  PD_CHECK_EQ(count_coverage(complete_evidence, complete, EvidenceCoverage::COMPLETE) > 0, true);
  PD_CHECK_EQ(count_coverage(complete_evidence, complete, EvidenceCoverage::ABSENT), std::size_t{0});
  PD_CHECK_EQ(count_coverage(complete_evidence, complete, EvidenceCoverage::PARTIAL), std::size_t{0});

  pd_test::InMemoryEvidence partial_evidence;
  const SyntheticFabric partial =
      populate_synthetic_fabric(partial_evidence, small_options(7, false));
  const std::size_t absent = count_coverage(partial_evidence, partial, EvidenceCoverage::ABSENT);
  const std::size_t present = count_coverage(partial_evidence, partial, EvidenceCoverage::COMPLETE);
  // The incomplete mode leaves a deterministic minority ABSENT and the rest
  // COMPLETE: an evidence gap, not a fabric with no classification at all.
  PD_CHECK(absent > 0);
  PD_CHECK(present > 0);
  PD_CHECK(absent < present);
  PD_CHECK_EQ(count_coverage(partial_evidence, partial, EvidenceCoverage::PARTIAL), std::size_t{0});
  PD_CHECK(partial.render().find("coverage=PARTIAL") != std::string::npos);
  PD_CHECK(!partial.options.complete_domain_coverage);

  // Placement relations are authored alongside the correlated-failure relation:
  // an entity that lost coverage lost it for every relation it is classified in.
  const std::optional<PathComposition> composition = partial_evidence.composition(partial.paths.front().path);
  PD_REQUIRE(composition.has_value());
  bool saw_incomplete = false;
  bool saw_complete = false;
  for (const EntityRef& entity : entities_of(*composition)) {
    const EvidenceCoverage failure_domain =
        partial_evidence.domain_membership(entity, DomainRelation::FAILURE_DOMAIN).coverage;
    const EvidenceCoverage rack =
        partial_evidence.domain_membership(entity, DomainRelation::RACK).coverage;
    const EvidenceCoverage site =
        partial_evidence.domain_membership(entity, DomainRelation::SITE).coverage;
    PD_CHECK(rack == failure_domain);
    PD_CHECK(site == failure_domain);
    if (failure_domain == EvidenceCoverage::COMPLETE) {
      saw_complete = true;
      PD_CHECK(!partial_evidence.domain_membership(entity, DomainRelation::FAILURE_DOMAIN)
                    .domains.empty());
    } else {
      saw_incomplete = true;
      PD_CHECK(failure_domain == EvidenceCoverage::ABSENT);
    }
  }
  PD_CHECK(saw_complete || saw_incomplete);

  // Complete coverage classifies every entity of every path.
  const std::optional<PathComposition> complete_composition =
      complete_evidence.composition(complete.paths.front().path);
  PD_REQUIRE(complete_composition.has_value());
  for (const EntityRef& entity : entities_of(*complete_composition)) {
    PD_CHECK(complete_evidence.domain_membership(entity, DomainRelation::FAILURE_DOMAIN).coverage ==
             EvidenceCoverage::COMPLETE);
    PD_CHECK(!complete_evidence.domain_membership(entity, DomainRelation::RACK).domains.empty());
    PD_CHECK(!complete_evidence.domain_membership(entity, DomainRelation::SITE).domains.empty());
    PD_CHECK(!complete_evidence.domain_membership(entity, DomainRelation::POWER_DOMAIN).domains.empty());
  }
}

PD_TEST(deterministic_rng_streams_are_reproducible) {
  DeterministicRng first(1234);
  DeterministicRng second(1234);
  PD_CHECK_EQ(first.seed(), std::uint64_t{1234});
  PD_CHECK_EQ(second.seed(), std::uint64_t{1234});

  std::vector<std::uint64_t> left;
  std::vector<std::uint64_t> right;
  for (int i = 0; i < 32; ++i) {
    left.push_back(first.next_u64());
    right.push_back(second.next_u64());
  }
  PD_CHECK(left == right);
  PD_CHECK(first.seed() != std::uint64_t{1234});

  // Reseeding restores the exact stream, draw for draw.
  first.reseed(1234);
  PD_CHECK_EQ(first.seed(), std::uint64_t{1234});
  for (std::size_t i = 0; i < left.size(); ++i) {
    pd_test::check(first.next_u64() == left[i],
                   "reseeded stream diverged at draw " + std::to_string(i), __FILE__, __LINE__);
  }

  // A different seed produces a different stream.
  DeterministicRng other(4321);
  bool differs = false;
  for (int i = 0; i < 8; ++i) {
    if (!(other.next_u64() == left[static_cast<std::size_t>(i)])) {
      differs = true;
    }
  }
  PD_CHECK(differs);

  DeterministicRng bounded(99);
  const std::uint32_t bounds[6] = {1, 2, 3, 7, 64, 1000};
  for (std::uint32_t bound : bounds) {
    for (int i = 0; i < 16; ++i) {
      const std::uint32_t value = bounded.next_below(bound);
      pd_test::check(value < bound,
                     "next_below(" + std::to_string(bound) + ") produced " +
                         std::to_string(value),
                     __FILE__, __LINE__);
    }
  }
  PD_CHECK_EQ(bounded.next_below(0), std::uint32_t{0});
  std::size_t trues = 0;
  std::size_t falses = 0;
  for (int i = 0; i < 64; ++i) {
    if (bounded.next_bool()) {
      ++trues;
    } else {
      ++falses;
    }
  }
  PD_CHECK(trues > 0);
  PD_CHECK(falses > 0);
}

PD_TEST(synthetic_policy_validates) {
  const Limits limits;
  const DiversityPolicy all_pairs =
      synthetic_policy("dpol-synthetic-all", default_scope(), SetSemantics::ALL_PAIRS, 2);
  const PolicyValidation validation = validate_policy(all_pairs, limits);
  PD_CHECK(validation.ok());
  PD_CHECK_EQ(to_string(validation.status), std::string_view("VALID"));
  PD_CHECK_EQ(all_pairs.required_classes.size(), std::size_t{4});
  const std::vector<DiversityClass> expected = {
      DiversityClass::LINK_DISJOINT, DiversityClass::TRANSIT_NODE_DISJOINT,
      DiversityClass::DEVICE_DISJOINT, DiversityClass::FAILURE_DOMAIN_DISJOINT};
  PD_CHECK(all_pairs.required_classes == expected);
  PD_CHECK(all_pairs.endpoint_exemption == EndpointExemption::SHARED_SOURCE_AND_DESTINATION);
  PD_CHECK(all_pairs.semantics == SetSemantics::ALL_PAIRS);
  PD_CHECK(all_pairs.completeness == CompletenessRequirement::REQUIRE_COMPLETE_EVIDENCE);
  PD_CHECK(all_pairs.unknown_behavior == UnknownBehavior::REJECT_PROOF);
  PD_CHECK(all_pairs.require_path_authority_current);
  PD_CHECK(all_pairs.scope == default_scope());
  PD_CHECK_EQ(all_pairs.minimum_independent_paths, std::uint32_t{2});
  PD_CHECK_EQ(all_pairs.allowed_failure_domain_relations.size(), std::size_t{4});
  PD_CHECK(!all_pairs.allowed_failure_domain_relations.empty());
  PD_CHECK(all_pairs.semantic_digest() == all_pairs.semantic_digest());
  PD_CHECK(all_pairs.generation.is_set());
  PD_CHECK(!all_pairs.description.empty());

  const DiversityPolicy at_least_k =
      synthetic_policy("dpol-synthetic-k", default_scope(), SetSemantics::AT_LEAST_K_INDEPENDENT, 3);
  PD_CHECK(validate_policy(at_least_k, limits).ok());
  PD_CHECK(at_least_k.semantics == SetSemantics::AT_LEAST_K_INDEPENDENT);
  PD_CHECK_EQ(at_least_k.minimum_independent_paths, std::uint32_t{3});
  PD_CHECK(!(at_least_k.semantic_digest() == all_pairs.semantic_digest()));

  const DiversityPolicy fallback =
      synthetic_policy("not a valid identity", default_scope(), SetSemantics::ALL_PAIRS, 2);
  PD_CHECK_EQ(fallback.id.str(), std::string("dpol-synthetic"));
  PD_CHECK(validate_policy(fallback, limits).ok());

  Limits tight;
  tight.max_paths_per_proof = 2;
  tight.max_k_subset_paths = 2;
  tight.max_snapshot_paths = 2;
  PD_CHECK(tight.self_consistent());
  const PolicyValidation too_many = validate_policy(
      synthetic_policy("dpol-synthetic-k3", default_scope(), SetSemantics::AT_LEAST_K_INDEPENDENT, 3),
      tight);
  PD_CHECK(too_many.status == PolicyStatus::MINIMUM_EXCEEDS_PATH_BOUND);
  PD_CHECK(!too_many.ok());
  PD_CHECK(!too_many.detail.empty());
}

PD_TEST(generated_fabric_evaluates_deterministically) {
  pd_test::InMemoryEvidence evidence;
  const SyntheticFabric fabric =
      populate_synthetic_fabric(evidence, small_options(20260101, true));
  const DiversityPolicy policy =
      synthetic_policy("dpol-synthetic-eval", default_scope(), SetSemantics::ALL_PAIRS, 2);
  PD_CHECK(validate_policy(policy, Limits()).ok());

  ProofRequest request;
  request.policy = policy.id;
  request.policy_generation = policy.generation;
  const std::size_t wanted = 4;
  PD_REQUIRE(fabric.paths.size() >= wanted);
  for (std::size_t i = 0; i < wanted; ++i) {
    request.paths.push_back(
        PathRef{fabric.paths[i].path, fabric.paths[i].authority_generation});
  }
  PD_CHECK(request.canonicalize());

  EvaluationInputs inputs;
  inputs.authority = &evidence;
  inputs.structure = &evidence;
  inputs.domains = &evidence;
  const Limits limits;
  inputs.limits = &limits;
  const EvaluationResult first = evaluate_diversity(request, policy, inputs);
  const EvaluationResult second = evaluate_diversity(request, policy, inputs);
  PD_CHECK(first.outcome != ProofOutcome::MALFORMED);
  PD_CHECK(first.outcome != ProofOutcome::UNAUTHORIZED);
  PD_CHECK(first.outcome != ProofOutcome::RESOURCE_LIMIT);
  PD_CHECK(first.outcome == second.outcome);
  PD_CHECK_EQ(first.detail, second.detail);
  PD_CHECK(first.matrix == second.matrix);
  PD_CHECK(first.classes == second.classes);
  PD_CHECK(first.conflicts == second.conflicts);
  PD_CHECK(first.consulted_domains == second.consulted_domains);
  PD_CHECK_EQ(first.matrix.order.size(), wanted);
  PD_CHECK_EQ(first.matrix.cells.size(), std::size_t{6});
  PD_CHECK_EQ(first.classes.size(), policy.required_classes.size());
  PD_CHECK(!first.consulted_domains.empty());
  PD_CHECK(!has_duplicates(first.consulted_domains));
  PD_CHECK_EQ(first.observed_topology.value(), std::uint64_t{1});
  PD_CHECK_EQ(first.observed_failure_domain.value(), std::uint64_t{1});
  PD_CHECK(first.dependencies.paths.size() == wanted);
  PD_CHECK(!first.dependencies.topology_entities.empty());
  for (const PairwiseCell& cell : first.matrix.cells) {
    PD_CHECK(cell.left < cell.right);
    PD_CHECK_EQ(cell.classes.size(), policy.required_classes.size());
  }
}

PD_TEST_MAIN()
