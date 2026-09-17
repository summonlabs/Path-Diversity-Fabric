// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.

// Cross-check of the production pairwise evaluator against the independent
// raw-set oracles in test_support.hpp. Every family builds randomized but
// seeded path pairs, computes the expected verdict straight from the raw
// composition values, and asserts that classify_pair reaches the same verdict
// and the same exact shared-resource set.

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "test_support.hpp"

namespace {

using namespace path_diversity;

constexpr std::uint32_t kPairsPerFamily = 220;

void expect(bool condition, const std::string& context) {
  if (!condition) {
    std::cout << "  context: " << context << "\n";
  }
  pd_test::check(condition, context, __FILE__, __LINE__);
}

// A fixed default keeps a failure reproducible forever; PD_ORACLE_SEED lets an
// operator replay a fresh seed without editing the suite.
std::uint64_t oracle_seed() {
  static const std::uint64_t seed = []() {
    const char* override = std::getenv("PD_ORACLE_SEED");
    if (override != nullptr && override[0] != '\0') {
      return static_cast<std::uint64_t>(std::strtoull(override, nullptr, 10));
    }
    return 20260101ULL;
  }();
  std::cout << "oracle seed=" << seed << "\n";
  return seed;
}

std::string case_context(std::uint64_t seed, const char* family, std::uint32_t index) {
  return std::string("ORACLE SEED=") + std::to_string(seed) + " family=" + family +
         " case=" + std::to_string(index);
}

std::string pick_name(DeterministicRng& rng, const char* prefix, std::uint32_t universe) {
  return std::string(prefix) + std::to_string(rng.next_below(universe));
}

void add_unique(std::vector<std::string>& into, const std::string& value) {
  for (const std::string& existing : into) {
    if (existing == value) {
      return;
    }
  }
  into.push_back(value);
}

void fill(std::vector<std::string>& into, DeterministicRng& rng, const char* prefix,
          std::uint32_t universe, std::uint32_t count) {
  for (std::uint32_t i = 0; i < count; ++i) {
    add_unique(into, pick_name(rng, prefix, universe));
  }
}

EvidenceCoverage random_coverage(DeterministicRng& rng) {
  const std::uint32_t draw = rng.next_below(10);
  if (draw == 0) {
    return EvidenceCoverage::PARTIAL;
  }
  if (draw == 1) {
    return EvidenceCoverage::ABSENT;
  }
  return EvidenceCoverage::COMPLETE;
}

PathComposition random_composition(DeterministicRng& rng, const std::string& tag) {
  PathComposition composition;
  composition.path = PathId::parse("path-" + tag);
  composition.authority_generation = PathAuthorityGeneration::from_value(1);
  composition.topology_generation = TopologyGeneration::from_value(1);
  std::vector<std::string> sources;
  std::vector<std::string> destinations;
  std::vector<std::string> transit;
  std::vector<std::string> links;
  std::vector<std::string> devices;
  // Endpoints draw from one shared universe so that source/destination sharing
  // and endpoint/transit overlap both occur.
  fill(sources, rng, "host-", 4, static_cast<std::uint32_t>(1 + rng.next_below(2)));
  fill(destinations, rng, "host-", 4, static_cast<std::uint32_t>(1 + rng.next_below(2)));
  fill(transit, rng, "node-", 6, rng.next_below(4));
  fill(links, rng, "link-", 6, rng.next_below(5));
  fill(devices, rng, "dev-", 5, rng.next_below(4));
  for (const std::string& name : sources) {
    composition.sources.push_back(NodeId::parse(name));
  }
  for (const std::string& name : destinations) {
    composition.destinations.push_back(NodeId::parse(name));
  }
  for (const std::string& name : transit) {
    composition.transit_nodes.push_back(NodeId::parse(name));
  }
  for (const std::string& name : links) {
    composition.links.push_back(LinkId::parse(name));
  }
  for (const std::string& name : devices) {
    composition.devices.push_back(DeviceId::parse(name));
  }
  composition.link_coverage = random_coverage(rng);
  composition.node_coverage = random_coverage(rng);
  composition.device_coverage = random_coverage(rng);
  composition.endpoint_coverage = random_coverage(rng);
  composition.canonicalize();
  return composition;
}

// Independent enumeration of the entities a path exposes. Written here rather
// than shared with the production path so the oracle cannot inherit a defect.
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

std::vector<std::string> domain_texts(const FailureDomainView& view,
                                      const PathComposition& composition, DomainRelation relation) {
  std::vector<std::string> out;
  for (const EntityRef& entity : entities_of(composition)) {
    for (const FailureDomainId& domain : view.domain_membership(entity, relation).domains) {
      out.push_back(domain.str());
    }
  }
  canonical_sort_unique(out);
  return out;
}

std::vector<std::string> group_texts(const FailureDomainView& view,
                                     const PathComposition& composition) {
  std::vector<std::string> out;
  for (const EntityRef& entity : entities_of(composition)) {
    for (const SharedRiskGroupId& group : view.srlg_membership(entity).groups) {
      out.push_back(group.str());
    }
  }
  canonical_sort_unique(out);
  return out;
}

bool domain_evidence_complete(const FailureDomainView& view, const PathComposition& composition,
                              DomainRelation relation) {
  for (const EntityRef& entity : entities_of(composition)) {
    if (view.domain_membership(entity, relation).coverage != EvidenceCoverage::COMPLETE) {
      return false;
    }
  }
  return true;
}

bool group_evidence_complete(const FailureDomainView& view, const PathComposition& composition) {
  for (const EntityRef& entity : entities_of(composition)) {
    if (view.srlg_membership(entity).coverage != EvidenceCoverage::COMPLETE) {
      return false;
    }
  }
  return true;
}

const ClassResult* find_class(const std::vector<ClassResult>& results, DiversityClass klass) {
  for (const ClassResult& result : results) {
    if (result.klass == klass) {
      return &result;
    }
  }
  return nullptr;
}

std::vector<std::string> reported_ids(const ClassResult& result) {
  std::vector<std::string> out;
  for (const SharedResource& conflict : result.shared) {
    out.push_back(conflict.id);
  }
  canonical_sort_unique(out);
  return out;
}

std::vector<std::string> minus(const std::vector<std::string>& values,
                               const std::vector<std::string>& removed) {
  std::vector<std::string> out;
  for (const std::string& value : values) {
    bool drop = false;
    for (const std::string& candidate : removed) {
      if (candidate == value) {
        drop = true;
        break;
      }
    }
    if (!drop) {
      out.push_back(value);
    }
  }
  return out;
}

// Compares an observed class verdict against the raw-set expectation.
void check_verdict(const ClassResult& result, bool has_shared, bool evidence_complete,
                   const std::string& where) {
  if (has_shared) {
    // An observed conflict is positive evidence and decides even when some
    // other required class is still incomplete.
    expect(result.outcome == ProofOutcome::NOT_DIVERSE, where + " missed a concrete conflict");
  } else if (evidence_complete) {
    expect(result.outcome == ProofOutcome::PROVEN_DIVERSE, where + " did not prove independence");
    expect(result.evidence_complete, where + " reported incomplete evidence");
  } else {
    expect(result.outcome == ProofOutcome::UNKNOWN_INCOMPLETE_EVIDENCE,
           where + " claimed a verdict from incomplete evidence");
    expect(!result.evidence_complete, where + " reported complete evidence");
  }
}

}  // namespace

PD_TEST(link_disjoint_oracle) {
  const std::uint64_t seed = oracle_seed();
  DeterministicRng rng(seed + 11);
  pd_test::InMemoryEvidence evidence;
  const Limits limits;
  const DiversityPolicy policy =
      pd_test::make_policy("dpol-oracle-link", {DiversityClass::LINK_DISJOINT},
                           EndpointExemption::SHARED_SOURCE_AND_DESTINATION, 2);
  EvaluationInputs inputs;
  inputs.authority = &evidence;
  inputs.structure = &evidence;
  inputs.domains = &evidence;
  inputs.limits = &limits;

  for (std::uint32_t index = 0; index < kPairsPerFamily; ++index) {
    const PathComposition left = random_composition(rng, "L" + std::to_string(index));
    const PathComposition right = random_composition(rng, "R" + std::to_string(index));
    const std::string where = case_context(seed, "link", index);
    const std::vector<std::string> shared =
        pd_test::oracle::intersection(pd_test::oracle::texts(left.links),
                                      pd_test::oracle::texts(right.links));
    const bool complete = left.link_coverage == EvidenceCoverage::COMPLETE &&
                          right.link_coverage == EvidenceCoverage::COMPLETE;
    expect(pd_test::oracle::link_disjoint(left, right) == shared.empty(), where + " oracle drift");

    const std::vector<ClassResult> results =
        classify_pair(left, right, policy, inputs, 16);
    const ClassResult* observed = find_class(results, DiversityClass::LINK_DISJOINT);
    expect(observed != nullptr, where + " produced no link verdict");
    if (observed == nullptr) {
      continue;
    }
    expect(observed->klass == DiversityClass::LINK_DISJOINT, where + " wrong class reported");
    expect(reported_ids(*observed) == shared, where + " reported a different shared link set");
    expect(observed->shared_total == shared.size(), where + " reported a different shared total");
    check_verdict(*observed, !shared.empty(), complete, where);
  }
}

PD_TEST(node_disjoint_oracle_every_exemption) {
  const std::uint64_t seed = oracle_seed();
  DeterministicRng rng(seed + 23);
  pd_test::InMemoryEvidence evidence;
  const Limits limits;
  EvaluationInputs inputs;
  inputs.authority = &evidence;
  inputs.structure = &evidence;
  inputs.domains = &evidence;
  inputs.limits = &limits;

  const EndpointExemption exemptions[5] = {
      EndpointExemption::NONE, EndpointExemption::SHARED_SOURCE_AND_DESTINATION,
      EndpointExemption::SHARED_SOURCE_ONLY, EndpointExemption::SHARED_DESTINATION_ONLY,
      EndpointExemption::ANY_ENDPOINT};
  for (const EndpointExemption exemption : exemptions) {
    const std::string family = std::string("node/") + std::string(to_string(exemption));
    const DiversityPolicy policy =
        pd_test::make_policy(std::string("dpol-oracle-node-") + std::string(to_string(exemption)),
                             {DiversityClass::TRANSIT_NODE_DISJOINT}, exemption, 2);
    for (std::uint32_t index = 0; index < kPairsPerFamily; ++index) {
      const PathComposition left = random_composition(rng, "L" + std::to_string(index));
      const PathComposition right = random_composition(rng, "R" + std::to_string(index));
      const std::string where = case_context(seed, family.c_str(), index);
      const std::vector<std::string> shared =
          pd_test::oracle::intersection(pd_test::oracle::all_nodes(left),
                                        pd_test::oracle::all_nodes(right));
      const std::vector<std::string> relevant =
          minus(shared, pd_test::oracle::exempt(left, right, exemption));
      const bool complete = left.node_coverage == EvidenceCoverage::COMPLETE &&
                            right.node_coverage == EvidenceCoverage::COMPLETE &&
                            left.endpoint_coverage == EvidenceCoverage::COMPLETE &&
                            right.endpoint_coverage == EvidenceCoverage::COMPLETE;
      expect(pd_test::oracle::node_disjoint(left, right, exemption) == relevant.empty(),
             where + " oracle drift");

      const std::vector<ClassResult> results = classify_pair(left, right, policy, inputs, 16);
      const ClassResult* observed = find_class(results, DiversityClass::TRANSIT_NODE_DISJOINT);
      expect(observed != nullptr, where + " produced no node verdict");
      if (observed == nullptr) {
        continue;
      }
      expect(reported_ids(*observed) == relevant, where + " reported a different shared node set");
      expect(observed->shared_total == relevant.size(), where + " reported a different total");
      check_verdict(*observed, !relevant.empty(), complete, where);
    }
  }
}

PD_TEST(device_disjoint_oracle) {
  const std::uint64_t seed = oracle_seed();
  DeterministicRng rng(seed + 37);
  pd_test::InMemoryEvidence evidence;
  const Limits limits;
  const DiversityPolicy policy =
      pd_test::make_policy("dpol-oracle-device", {DiversityClass::DEVICE_DISJOINT},
                           EndpointExemption::SHARED_SOURCE_AND_DESTINATION, 2);
  EvaluationInputs inputs;
  inputs.authority = &evidence;
  inputs.structure = &evidence;
  inputs.domains = &evidence;
  inputs.limits = &limits;

  for (std::uint32_t index = 0; index < kPairsPerFamily; ++index) {
    const PathComposition left = random_composition(rng, "L" + std::to_string(index));
    const PathComposition right = random_composition(rng, "R" + std::to_string(index));
    const std::string where = case_context(seed, "device", index);
    const std::vector<std::string> shared =
        pd_test::oracle::intersection(pd_test::oracle::texts(left.devices),
                                      pd_test::oracle::texts(right.devices));
    const bool complete = left.device_coverage == EvidenceCoverage::COMPLETE &&
                          right.device_coverage == EvidenceCoverage::COMPLETE;
    expect(pd_test::oracle::device_disjoint(left, right) == shared.empty(), where + " oracle drift");

    const std::vector<ClassResult> results = classify_pair(left, right, policy, inputs, 16);
    const ClassResult* observed = find_class(results, DiversityClass::DEVICE_DISJOINT);
    expect(observed != nullptr, where + " produced no device verdict");
    if (observed == nullptr) {
      continue;
    }
    expect(reported_ids(*observed) == shared, where + " reported a different shared device set");
    expect(observed->shared_total == shared.size(), where + " reported a different total");
    check_verdict(*observed, !shared.empty(), complete, where);
  }
}

PD_TEST(failure_domain_and_rack_oracle) {
  const std::uint64_t seed = oracle_seed();
  DeterministicRng rng(seed + 53);
  pd_test::InMemoryEvidence evidence;
  const Limits limits;
  DiversityPolicy failure_domain_policy =
      pd_test::make_policy("dpol-oracle-fd", {DiversityClass::FAILURE_DOMAIN_DISJOINT},
                           EndpointExemption::SHARED_SOURCE_AND_DESTINATION, 2);
  failure_domain_policy.allowed_failure_domain_relations = {DomainRelation::FAILURE_DOMAIN};
  const DiversityPolicy rack_policy =
      pd_test::make_policy("dpol-oracle-rack", {DiversityClass::RACK_DISJOINT},
                           EndpointExemption::SHARED_SOURCE_AND_DESTINATION, 2);
  EvaluationInputs inputs;
  inputs.authority = &evidence;
  inputs.structure = &evidence;
  inputs.domains = &evidence;
  inputs.limits = &limits;

  for (std::uint32_t index = 0; index < kPairsPerFamily; ++index) {
    const PathComposition left = random_composition(rng, "L" + std::to_string(index));
    const PathComposition right = random_composition(rng, "R" + std::to_string(index));
    for (const EntityRef& entity : entities_of(left)) {
      std::vector<FailureDomainId> domains;
      const std::uint32_t count = rng.next_below(3);
      for (std::uint32_t i = 0; i < count; ++i) {
        domains.push_back(FailureDomainId::parse("fd-" + std::to_string(rng.next_below(6))));
      }
      evidence.set_domain_membership(entity, DomainRelation::FAILURE_DOMAIN, random_coverage(rng),
                                     domains);
      std::vector<FailureDomainId> racks;
      if (rng.next_below(4) != 0) {
        racks.push_back(FailureDomainId::parse("rack-" + std::to_string(rng.next_below(3))));
      }
      evidence.set_domain_membership(entity, DomainRelation::RACK, random_coverage(rng), racks);
    }
    for (const EntityRef& entity : entities_of(right)) {
      std::vector<FailureDomainId> domains;
      const std::uint32_t count = rng.next_below(3);
      for (std::uint32_t i = 0; i < count; ++i) {
        domains.push_back(FailureDomainId::parse("fd-" + std::to_string(rng.next_below(6))));
      }
      evidence.set_domain_membership(entity, DomainRelation::FAILURE_DOMAIN, random_coverage(rng),
                                     domains);
      std::vector<FailureDomainId> racks;
      if (rng.next_below(4) != 0) {
        racks.push_back(FailureDomainId::parse("rack-" + std::to_string(rng.next_below(3))));
      }
      evidence.set_domain_membership(entity, DomainRelation::RACK, random_coverage(rng), racks);
    }

    struct Family {
      DomainRelation relation;
      DiversityClass klass;
      const DiversityPolicy* policy;
      const char* name;
    };
    const Family families[2] = {{DomainRelation::FAILURE_DOMAIN,
                                 DiversityClass::FAILURE_DOMAIN_DISJOINT, &failure_domain_policy,
                                 "failure-domain"},
                                {DomainRelation::RACK, DiversityClass::RACK_DISJOINT, &rack_policy,
                                 "rack"}};
    for (const Family& family : families) {
      const std::string where = case_context(seed, family.name, index);
      const std::vector<std::string> shared =
          pd_test::oracle::intersection(domain_texts(evidence, left, family.relation),
                                        domain_texts(evidence, right, family.relation));
      const bool complete =
          domain_evidence_complete(evidence, left, family.relation) &&
          domain_evidence_complete(evidence, right, family.relation);
      const std::vector<ClassResult> results =
          classify_pair(left, right, *family.policy, inputs, 16);
      const ClassResult* observed = find_class(results, family.klass);
      expect(observed != nullptr, where + " produced no verdict");
      if (observed == nullptr) {
        continue;
      }
      expect(reported_ids(*observed) == shared, where + " reported a different shared domain set");
      expect(observed->shared_total == shared.size(), where + " reported a different total");
      check_verdict(*observed, !shared.empty(), complete, where);
      if (!shared.empty()) {
        expect(observed->shared.front().relation == family.relation,
               where + " attributed the conflict to the wrong relation");
      }
    }
  }
}

PD_TEST(shared_risk_group_oracle) {
  const std::uint64_t seed = oracle_seed();
  DeterministicRng rng(seed + 71);
  pd_test::InMemoryEvidence evidence;
  const Limits limits;
  const DiversityPolicy policy =
      pd_test::make_policy("dpol-oracle-srlg", {DiversityClass::SHARED_RISK_GROUP_DISJOINT},
                           EndpointExemption::SHARED_SOURCE_AND_DESTINATION, 2);
  EvaluationInputs inputs;
  inputs.authority = &evidence;
  inputs.structure = &evidence;
  inputs.domains = &evidence;
  inputs.limits = &limits;

  for (std::uint32_t index = 0; index < kPairsPerFamily; ++index) {
    const PathComposition left = random_composition(rng, "L" + std::to_string(index));
    const PathComposition right = random_composition(rng, "R" + std::to_string(index));
    for (const EntityRef& entity : entities_of(left)) {
      std::vector<SharedRiskGroupId> groups;
      const std::uint32_t count = rng.next_below(3);
      for (std::uint32_t i = 0; i < count; ++i) {
        groups.push_back(SharedRiskGroupId::parse("srlg-" + std::to_string(rng.next_below(5))));
      }
      evidence.set_srlg_membership(entity, random_coverage(rng), groups);
    }
    for (const EntityRef& entity : entities_of(right)) {
      std::vector<SharedRiskGroupId> groups;
      const std::uint32_t count = rng.next_below(3);
      for (std::uint32_t i = 0; i < count; ++i) {
        groups.push_back(SharedRiskGroupId::parse("srlg-" + std::to_string(rng.next_below(5))));
      }
      evidence.set_srlg_membership(entity, random_coverage(rng), groups);
    }

    const std::string where = case_context(seed, "srlg", index);
    const std::vector<std::string> shared =
        pd_test::oracle::intersection(group_texts(evidence, left), group_texts(evidence, right));
    const bool complete = group_evidence_complete(evidence, left) &&
                          group_evidence_complete(evidence, right);
    const std::vector<ClassResult> results = classify_pair(left, right, policy, inputs, 16);
    const ClassResult* observed = find_class(results, DiversityClass::SHARED_RISK_GROUP_DISJOINT);
    expect(observed != nullptr, where + " produced no risk-group verdict");
    if (observed == nullptr) {
      continue;
    }
    expect(reported_ids(*observed) == shared, where + " reported a different shared group set");
    expect(observed->shared_total == shared.size(), where + " reported a different total");
    check_verdict(*observed, !shared.empty(), complete, where);
  }
}

PD_TEST(classify_pair_reports_every_required_class_in_policy_order) {
  pd_test::InMemoryEvidence evidence;
  const Limits limits;
  const std::vector<DiversityClass> required = {
      DiversityClass::SHARED_RISK_GROUP_DISJOINT, DiversityClass::DEVICE_DISJOINT,
      DiversityClass::LINK_DISJOINT, DiversityClass::TRANSIT_NODE_DISJOINT};
  const DiversityPolicy policy =
      pd_test::make_policy("dpol-oracle-order", required,
                           EndpointExemption::SHARED_SOURCE_AND_DESTINATION, 2);
  EvaluationInputs inputs;
  inputs.authority = &evidence;
  inputs.structure = &evidence;
  inputs.domains = &evidence;
  inputs.limits = &limits;

  const PathComposition left =
      pd_test::make_path("path-order-a", 1, {"node-1"}, {"link-1"}, {"dev-1"}, "host-a", "host-b");
  const PathComposition right =
      pd_test::make_path("path-order-b", 1, {"node-2"}, {"link-2"}, {"dev-2"}, "host-a", "host-c");

  // Required classes are reported first in canonical class order, then every
  // remaining defined class as an advisory.
  const std::vector<ClassResult> results = classify_pair(left, right, policy, inputs, 16);
  PD_CHECK_EQ(results.size(), std::size_t{8});
  PD_CHECK(results[0].klass == DiversityClass::LINK_DISJOINT);
  PD_CHECK(results[1].klass == DiversityClass::TRANSIT_NODE_DISJOINT);
  PD_CHECK(results[2].klass == DiversityClass::DEVICE_DISJOINT);
  PD_CHECK(results[3].klass == DiversityClass::SHARED_RISK_GROUP_DISJOINT);
  for (std::size_t i = 0; i < results.size(); ++i) {
    for (std::size_t j = i + 1; j < results.size(); ++j) {
      PD_CHECK(!(results[i].klass == results[j].klass));
    }
  }
  for (const ClassResult& result : results) {
    PD_CHECK(result.outcome != ProofOutcome::MALFORMED);
  }

  // The independent oracle agrees on each of the four structural classes here.
  const ClassResult* link = find_class(results, DiversityClass::LINK_DISJOINT);
  const ClassResult* node = find_class(results, DiversityClass::TRANSIT_NODE_DISJOINT);
  const ClassResult* device = find_class(results, DiversityClass::DEVICE_DISJOINT);
  PD_REQUIRE(link != nullptr);
  PD_REQUIRE(node != nullptr);
  PD_REQUIRE(device != nullptr);
  PD_CHECK(pd_test::oracle::link_disjoint(left, right) == link->proven());
  PD_CHECK(pd_test::oracle::device_disjoint(left, right) == device->proven());
  PD_CHECK(pd_test::oracle::node_disjoint(left, right,
                                          EndpointExemption::SHARED_SOURCE_AND_DESTINATION) ==
           node->proven());
}

PD_TEST(consulted_identities_are_canonical_and_unique) {
  pd_test::InMemoryEvidence evidence;
  const Limits limits;
  DiversityPolicy policy =
      pd_test::make_policy("dpol-oracle-consulted", {DiversityClass::FAILURE_DOMAIN_DISJOINT},
                           EndpointExemption::SHARED_SOURCE_AND_DESTINATION, 2);
  policy.allowed_failure_domain_relations = {DomainRelation::FAILURE_DOMAIN};
  EvaluationInputs inputs;
  inputs.authority = &evidence;
  inputs.structure = &evidence;
  inputs.domains = &evidence;
  inputs.limits = &limits;

  const PathComposition left =
      pd_test::make_path("path-c1", 1, {"node-1"}, {"link-1"}, {"dev-1"}, "host-a", "host-b");
  const PathComposition right =
      pd_test::make_path("path-c2", 1, {"node-2"}, {"link-2"}, {"dev-2"}, "host-a", "host-c");
  std::vector<FailureDomainId> shared_domains = {FailureDomainId::parse("fd-shared"),
                                                 FailureDomainId::parse("fd-extra")};
  for (const EntityRef& entity : entities_of(left)) {
    evidence.set_domain_membership(entity, DomainRelation::FAILURE_DOMAIN,
                                   EvidenceCoverage::COMPLETE, shared_domains);
    evidence.set_srlg_membership(entity, EvidenceCoverage::COMPLETE,
                                 {SharedRiskGroupId::parse("srlg-1")});
  }
  for (const EntityRef& entity : entities_of(right)) {
    evidence.set_domain_membership(entity, DomainRelation::FAILURE_DOMAIN,
                                   EvidenceCoverage::COMPLETE, shared_domains);
    evidence.set_srlg_membership(entity, EvidenceCoverage::COMPLETE,
                                 {SharedRiskGroupId::parse("srlg-1")});
  }

  std::vector<FailureDomainId> consulted_domains;
  std::vector<SharedRiskGroupId> consulted_groups;
  const std::vector<ClassResult> results = classify_pair(left, right, policy, inputs, 16,
                                                         &consulted_domains, &consulted_groups);
  PD_CHECK(!consulted_domains.empty());
  PD_CHECK(!consulted_groups.empty());
  // classify_pair reports every consultation in evaluation order; the exact
  // canonical identity set is the one the set-wise evaluator dedupes and sorts.
  std::vector<FailureDomainId> domain_set = consulted_domains;
  std::vector<SharedRiskGroupId> group_set = consulted_groups;
  canonical_sort_unique(domain_set);
  canonical_sort_unique(group_set);
  PD_CHECK_EQ(domain_set.size(), std::size_t{2});
  PD_CHECK_EQ(domain_set[0].str(), std::string("fd-extra"));
  PD_CHECK_EQ(domain_set[1].str(), std::string("fd-shared"));
  PD_CHECK_EQ(group_set.size(), std::size_t{1});
  PD_CHECK_EQ(group_set[0].str(), std::string("srlg-1"));
  const ClassResult* merged = find_class(results, DiversityClass::FAILURE_DOMAIN_DISJOINT);
  PD_REQUIRE(merged != nullptr);
  PD_CHECK(merged->outcome == ProofOutcome::NOT_DIVERSE);
  PD_CHECK(merged->evidence_complete);
  PD_CHECK_EQ(merged->shared_total, std::uint64_t{2});

  // The set-wise evaluator reports the same identities, canonical and unique.
  evidence.set_path(left);
  evidence.set_path(right);
  ProofRequest request;
  request.policy = policy.id;
  request.policy_generation = policy.generation;
  request.paths.push_back(PathRef{left.path, left.authority_generation});
  request.paths.push_back(PathRef{right.path, right.authority_generation});
  PD_CHECK(request.canonicalize());
  const EvaluationResult evaluation = evaluate_diversity(request, policy, inputs);
  PD_CHECK(evaluation.outcome == ProofOutcome::NOT_DIVERSE);
  PD_CHECK(evaluation.consulted_domains == domain_set);
  PD_CHECK(evaluation.consulted_risk_groups == group_set);
  PD_CHECK(!has_duplicates(evaluation.consulted_domains));
  PD_CHECK(evaluation.dependencies.topology_entities.size() >= std::size_t{6});
  PD_CHECK(evaluation.proven() == false);
}

PD_TEST(evaluate_diversity_agrees_with_the_oracle_for_every_family) {
  // The set-wise evaluator is the entry point a caller uses; for a two-path set
  // its aggregated per-class verdict must equal the raw-set oracle expectation
  // for every family at once.
  const std::uint64_t seed = oracle_seed();
  DeterministicRng rng(seed + 97);
  pd_test::InMemoryEvidence evidence;
  const Limits limits;
  EvaluationInputs inputs;
  inputs.authority = &evidence;
  inputs.structure = &evidence;
  inputs.domains = &evidence;
  inputs.limits = &limits;
  const EndpointExemption exemptions[5] = {
      EndpointExemption::NONE, EndpointExemption::SHARED_SOURCE_AND_DESTINATION,
      EndpointExemption::SHARED_SOURCE_ONLY, EndpointExemption::SHARED_DESTINATION_ONLY,
      EndpointExemption::ANY_ENDPOINT};

  struct Expectation {
    DiversityClass klass;
    bool conflict;
    bool complete;
  };

  for (std::uint32_t index = 0; index < kPairsPerFamily; ++index) {
    const PathComposition left = random_composition(rng, "L" + std::to_string(index));
    const PathComposition right = random_composition(rng, "R" + std::to_string(index));
    evidence.set_path(left);
    evidence.set_path(right);
    for (const PathComposition* composition : {&left, &right}) {
      for (const EntityRef& entity : entities_of(*composition)) {
        std::vector<FailureDomainId> domains;
        const std::uint32_t domain_count = rng.next_below(3);
        for (std::uint32_t i = 0; i < domain_count; ++i) {
          domains.push_back(FailureDomainId::parse("fd-" + std::to_string(rng.next_below(6))));
        }
        evidence.set_domain_membership(entity, DomainRelation::FAILURE_DOMAIN, random_coverage(rng),
                                       domains);
        std::vector<SharedRiskGroupId> groups;
        const std::uint32_t group_count = rng.next_below(3);
        for (std::uint32_t i = 0; i < group_count; ++i) {
          groups.push_back(SharedRiskGroupId::parse("srlg-" + std::to_string(rng.next_below(5))));
        }
        evidence.set_srlg_membership(entity, random_coverage(rng), groups);
      }
    }

    const EndpointExemption exemption = exemptions[rng.next_below(5)];
    DiversityPolicy policy =
        pd_test::make_policy("dpol-oracle-set",
                             {DiversityClass::LINK_DISJOINT, DiversityClass::TRANSIT_NODE_DISJOINT,
                              DiversityClass::DEVICE_DISJOINT,
                              DiversityClass::FAILURE_DOMAIN_DISJOINT},
                             exemption, 2);
    policy.allowed_failure_domain_relations = {DomainRelation::FAILURE_DOMAIN};
    policy.canonicalize();

    const std::string where = case_context(seed, "set", index);
    const std::vector<std::string> nodes =
        minus(pd_test::oracle::intersection(pd_test::oracle::all_nodes(left),
                                            pd_test::oracle::all_nodes(right)),
              pd_test::oracle::exempt(left, right, exemption));
    const std::vector<Expectation> expected = {
        {DiversityClass::LINK_DISJOINT,
         !pd_test::oracle::intersection(pd_test::oracle::texts(left.links),
                                        pd_test::oracle::texts(right.links))
              .empty(),
         left.link_coverage == EvidenceCoverage::COMPLETE &&
             right.link_coverage == EvidenceCoverage::COMPLETE},
        {DiversityClass::TRANSIT_NODE_DISJOINT, !nodes.empty(),
         left.node_coverage == EvidenceCoverage::COMPLETE &&
             right.node_coverage == EvidenceCoverage::COMPLETE &&
             left.endpoint_coverage == EvidenceCoverage::COMPLETE &&
             right.endpoint_coverage == EvidenceCoverage::COMPLETE},
        {DiversityClass::DEVICE_DISJOINT,
         !pd_test::oracle::intersection(pd_test::oracle::texts(left.devices),
                                        pd_test::oracle::texts(right.devices))
              .empty(),
         left.device_coverage == EvidenceCoverage::COMPLETE &&
             right.device_coverage == EvidenceCoverage::COMPLETE},
        {DiversityClass::FAILURE_DOMAIN_DISJOINT,
         !pd_test::oracle::intersection(domain_texts(evidence, left, DomainRelation::FAILURE_DOMAIN),
                                        domain_texts(evidence, right, DomainRelation::FAILURE_DOMAIN))
              .empty(),
         domain_evidence_complete(evidence, left, DomainRelation::FAILURE_DOMAIN) &&
             domain_evidence_complete(evidence, right, DomainRelation::FAILURE_DOMAIN)}};

    ProofRequest request;
    request.policy = policy.id;
    request.policy_generation = policy.generation;
    request.paths.push_back(PathRef{left.path, left.authority_generation});
    request.paths.push_back(PathRef{right.path, right.authority_generation});
    PD_CHECK(request.canonicalize());
    const EvaluationResult result = evaluate_diversity(request, policy, inputs);
    expect(result.outcome != ProofOutcome::MALFORMED, where + " was refused as malformed");
    expect(result.matrix.order.size() == 2, where + " did not build a two-path matrix");
    expect(result.matrix.cells.size() == 1, where + " did not build one pairwise cell");
    expect(result.classes.size() == expected.size(), where + " reported a different class count");
    if (result.classes.size() != expected.size()) {
      continue;
    }

    bool any_conflict = false;
    bool any_undecided = false;
    for (std::size_t i = 0; i < expected.size(); ++i) {
      const ClassResult& observed = result.classes[i];
      const Expectation& want = expected[i];
      expect(observed.klass == want.klass, where + " reported the classes out of canonical order");
      expect(observed.evidence_complete == want.complete,
             where + " disagreed about evidence completeness for " +
                 std::string(to_string(want.klass)));
      if (want.conflict) {
        expect(observed.outcome == ProofOutcome::NOT_DIVERSE,
               where + " missed the conflict in " + std::string(to_string(want.klass)));
        expect(observed.shared_total >= 1, where + " reported no shared resource");
      } else if (want.complete) {
        expect(observed.outcome == ProofOutcome::PROVEN_DIVERSE,
               where + " failed to prove " + std::string(to_string(want.klass)));
      } else {
        expect(observed.outcome == ProofOutcome::UNKNOWN_INCOMPLETE_EVIDENCE,
               where + " claimed a verdict for " + std::string(to_string(want.klass)) +
                   " from incomplete evidence");
      }
      any_conflict = any_conflict || want.conflict;
      any_undecided = any_undecided || (!want.conflict && !want.complete);
    }

    // Whole-set classification under REQUIRE_COMPLETE_EVIDENCE: a class that
    // could not be decided dominates, while an observed conflict still decides
    // its own class even when that class's remaining evidence is incomplete.
    if (any_undecided) {
      expect(result.outcome == ProofOutcome::UNKNOWN_INCOMPLETE_EVIDENCE,
             where + " did not report unknown despite incomplete required evidence");
    } else if (any_conflict) {
      expect(result.outcome == ProofOutcome::NOT_DIVERSE, where + " missed an observed conflict");
    } else {
      expect(result.outcome == ProofOutcome::PROVEN_DIVERSE, where + " did not prove the set");
    }
    expect(result.classes == result.matrix.cells.front().classes,
           where + " aggregated classes differ from the pairwise cell");
  }
}

PD_TEST_MAIN()
