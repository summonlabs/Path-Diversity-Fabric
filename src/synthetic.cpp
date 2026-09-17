// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include "path_diversity/synthetic.hpp"

#include <string>
#include <utility>
#include <vector>

#include "path_diversity/limits.hpp"

namespace path_diversity {

namespace {

std::string index_text(std::uint32_t value) { return std::to_string(value); }

std::vector<FailureDomainId> single_domain(const std::string& text) {
  std::vector<FailureDomainId> out;
  const auto parsed = FailureDomainId::try_parse(text);
  if (parsed.has_value()) {
    out.push_back(*parsed);
  }
  return out;
}

std::vector<SharedRiskGroupId> single_group(const std::string& text) {
  std::vector<SharedRiskGroupId> out;
  const auto parsed = SharedRiskGroupId::try_parse(text);
  if (parsed.has_value()) {
    out.push_back(*parsed);
  }
  return out;
}

struct Placement {
  std::uint32_t rack = 0;
  std::uint32_t pod = 0;
  std::uint32_t site = 0;
};

Placement placement_of(std::uint32_t device_index, const SyntheticFabricOptions& options) {
  Placement placement;
  placement.rack = options.racks == 0 ? 0 : device_index % options.racks;
  placement.pod = options.pods == 0 ? 0 : device_index % options.pods;
  placement.site = options.sites == 0 ? 0 : device_index % options.sites;
  return placement;
}

// Assigns the full authoritative classification of one entity. Placement
// relations are fabricated alongside the correlated-failure domain: nothing is
// inferred from a name, because the generator authors both.
void classify(InMemoryEvidence& evidence, const EntityRef& entity, const Placement& placement,
              const std::string& risk_group, EvidenceCoverage coverage) {
  evidence.set_domain_membership(entity, DomainRelation::FAILURE_DOMAIN, coverage,
                                 single_domain("fd-" + index_text(placement.rack)));
  evidence.set_domain_membership(entity, DomainRelation::RACK, coverage,
                                 single_domain("rack-" + index_text(placement.rack)));
  evidence.set_domain_membership(entity, DomainRelation::POD, coverage,
                                 single_domain("pod-" + index_text(placement.pod)));
  evidence.set_domain_membership(entity, DomainRelation::SITE, coverage,
                                 single_domain("site-" + index_text(placement.site)));
  evidence.set_domain_membership(entity, DomainRelation::POWER_DOMAIN, coverage,
                                 single_domain("pwr-" + index_text(placement.rack)));
  if (!risk_group.empty()) {
    evidence.set_srlg_membership(entity, coverage, single_group(risk_group));
  }
}

}  // namespace

DeterministicRng::DeterministicRng(std::uint64_t seed) noexcept : state_(seed) {}

void DeterministicRng::reseed(std::uint64_t seed) noexcept { state_ = seed; }

std::uint64_t DeterministicRng::seed() const noexcept { return state_; }

std::uint64_t DeterministicRng::next_u64() noexcept {
  // SplitMix64: a small, fully specified, platform-independent generator.
  state_ += 0x9e3779b97f4a7c15ULL;
  std::uint64_t z = state_;
  z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
  z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
  return z ^ (z >> 31);
}

std::uint32_t DeterministicRng::next_below(std::uint32_t bound) noexcept {
  if (bound == 0) {
    return 0;
  }
  return static_cast<std::uint32_t>(next_u64() % bound);
}

bool DeterministicRng::next_bool() noexcept { return (next_u64() & 1ULL) != 0ULL; }

std::string SyntheticFabric::render() const {
  std::string out = "synthetic fabric spines=" + std::to_string(options.spine_count);
  out += " leaves=" + std::to_string(options.leaf_count);
  out += " racks=" + std::to_string(options.racks);
  out += " pods=" + std::to_string(options.pods);
  out += " sites=" + std::to_string(options.sites);
  out += " paths=" + std::to_string(paths.size());
  out += " topology=g" + std::to_string(topology_generation.value());
  out += " failure-domains=g" + std::to_string(failure_domain_generation.value());
  out += options.complete_domain_coverage ? " coverage=COMPLETE" : " coverage=PARTIAL";
  out += " seed=" + std::to_string(options.seed);
  return out;
}

DiversityPolicy synthetic_policy(const std::string& id, ScopeId scope, SetSemantics semantics,
                                 std::uint32_t minimum_paths) {
  DiversityPolicy policy;
  const auto parsed = DiversityPolicyId::try_parse(id);
  policy.id = parsed.has_value() ? *parsed : DiversityPolicyId::parse("dpol-synthetic");
  policy.generation = DiversityPolicyGeneration::from_value(1);
  policy.scope = scope;
  policy.required_classes = {DiversityClass::LINK_DISJOINT,
                             DiversityClass::TRANSIT_NODE_DISJOINT,
                             DiversityClass::DEVICE_DISJOINT,
                             DiversityClass::FAILURE_DOMAIN_DISJOINT};
  policy.endpoint_exemption = EndpointExemption::SHARED_SOURCE_AND_DESTINATION;
  policy.minimum_independent_paths = minimum_paths;
  policy.semantics = semantics;
  policy.completeness = CompletenessRequirement::REQUIRE_COMPLETE_EVIDENCE;
  policy.unknown_behavior = UnknownBehavior::REJECT_PROOF;
  policy.allowed_failure_domain_relations = {DomainRelation::FAILURE_DOMAIN, DomainRelation::RACK,
                                             DomainRelation::POD, DomainRelation::SITE};
  policy.require_path_authority_current = true;
  policy.description = "synthetic policy " + id;
  policy.canonicalize();
  return policy;
}

SyntheticFabric populate_synthetic_fabric(InMemoryEvidence& evidence,
                                          const SyntheticFabricOptions& options) {
  SyntheticFabric fabric;
  fabric.options = options;
  evidence.set_topology_generation(TopologyGeneration::from_value(1));
  evidence.set_failure_domain_generation(FailureDomainGeneration::from_value(1));

  const std::uint32_t spines = options.spine_count == 0 ? 1 : options.spine_count;
  const std::uint32_t leaves = options.leaf_count < 2 ? 2 : options.leaf_count;
  // The incomplete mode removes classification from a deterministic eighth of
  // the entities and leaves the rest COMPLETE. Which entities lose coverage is a
  // pure function of the seed, so the same seed always produces the same
  // coverage map.
  DeterministicRng coverage_rng(options.seed ^ 0x5eed5eedULL);
  auto coverage_for = [&](std::uint32_t salt) {
    if (options.complete_domain_coverage) {
      return EvidenceCoverage::COMPLETE;
    }
    coverage_rng.reseed(options.seed ^ (0x9e3779b9ULL * (salt + 1)));
    return (coverage_rng.next_u64() % 8ULL) == 0ULL ? EvidenceCoverage::ABSENT
                                                    : EvidenceCoverage::COMPLETE;
  };

  for (std::uint32_t i = 0; i < leaves; ++i) {
    for (std::uint32_t offset = 1; offset <= options.paths_per_pair; ++offset) {
      const std::uint32_t destination = (i + offset) % leaves;
      const std::uint32_t spine = (i + offset) % spines;
      const std::string path_text = "path-syn-" + index_text(i) + "-" +
                                    index_text(destination) + "-" + index_text(offset);
      const auto path_id = PathId::try_parse(path_text);
      if (!path_id.has_value()) {
        continue;
      }
      PathComposition composition;
      composition.path = *path_id;
      composition.authority_generation = PathAuthorityGeneration::from_value(1);
      composition.topology_generation = TopologyGeneration::from_value(1);
      composition.sources = {NodeId::parse("host-" + index_text(i))};
      composition.destinations = {NodeId::parse("host-" + index_text(destination))};
      composition.transit_nodes = {NodeId::parse("leaf-" + index_text(i)),
                                   NodeId::parse("spine-" + index_text(spine)),
                                   NodeId::parse("leaf-" + index_text(destination))};
      composition.links = {LinkId::parse("link-host-" + index_text(i) + "-leaf-" + index_text(i)),
                           LinkId::parse("link-leaf-" + index_text(i) + "-spine-" +
                                         index_text(spine)),
                           LinkId::parse("link-spine-" + index_text(spine) + "-leaf-" +
                                         index_text(destination)),
                           LinkId::parse("link-leaf-" + index_text(destination) + "-host-" +
                                         index_text(destination))};
      composition.devices = {DeviceId::parse("leaf-" + index_text(i)),
                             DeviceId::parse("spine-" + index_text(spine)),
                             DeviceId::parse("leaf-" + index_text(destination))};
      composition.canonicalize();
      evidence.set_path(composition);

      const Placement source_placement = placement_of(i, options);
      const Placement destination_placement = placement_of(destination, options);
      const Placement spine_placement = placement_of(spines + spine, options);
      const std::string spine_group = "srlg-spine-" + index_text(spine);

      classify(evidence, EntityRef{EntityKind::ENDPOINT, "host-" + index_text(i)},
               source_placement, std::string(), coverage_for(i * 7U + 1U));
      classify(evidence, EntityRef{EntityKind::ENDPOINT, "host-" + index_text(destination)},
               destination_placement, std::string(), coverage_for(destination * 7U + 2U));
      classify(evidence, EntityRef{EntityKind::NODE, "leaf-" + index_text(i)}, source_placement,
               std::string(), coverage_for(i * 7U + 3U));
      classify(evidence, EntityRef{EntityKind::NODE, "spine-" + index_text(spine)},
               spine_placement, spine_group, coverage_for(spine * 7U + 4U));
      classify(evidence, EntityRef{EntityKind::NODE, "leaf-" + index_text(destination)},
               destination_placement, std::string(), coverage_for(destination * 7U + 5U));
      classify(evidence,
               EntityRef{EntityKind::LINK,
                         "link-host-" + index_text(i) + "-leaf-" + index_text(i)},
               source_placement, std::string(), coverage_for(i * 7U + 6U));
      classify(evidence,
               EntityRef{EntityKind::LINK, "link-leaf-" + index_text(i) + "-spine-" +
                                               index_text(spine)},
               source_placement, spine_group, coverage_for(i * 7U + 7U));
      classify(evidence,
               EntityRef{EntityKind::LINK, "link-spine-" + index_text(spine) + "-leaf-" +
                                               index_text(destination)},
               destination_placement, spine_group,
               coverage_for(destination * 7U + 8U));
      classify(evidence,
               EntityRef{EntityKind::LINK, "link-leaf-" + index_text(destination) + "-host-" +
                                               index_text(destination)},
               destination_placement, std::string(), coverage_for(destination * 7U + 9U));
      classify(evidence, EntityRef{EntityKind::DEVICE, "leaf-" + index_text(i)}, source_placement,
               std::string(), coverage_for(i * 7U + 10U));
      classify(evidence, EntityRef{EntityKind::DEVICE, "spine-" + index_text(spine)},
               spine_placement, spine_group, coverage_for(spine * 7U + 11U));
      classify(evidence, EntityRef{EntityKind::DEVICE, "leaf-" + index_text(destination)},
               destination_placement, std::string(), coverage_for(destination * 7U + 12U));

      SyntheticPath entry;
      entry.path = *path_id;
      entry.authority_generation = PathAuthorityGeneration::from_value(1);
      entry.label = path_text;
      fabric.paths.push_back(std::move(entry));
    }
  }
  return fabric;
}

}  // namespace path_diversity
