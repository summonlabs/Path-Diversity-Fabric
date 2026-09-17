// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
// Mandatory boundary proofs and the deterministic-identity proofs.
//
// Every assertion here is about an exact, evidence-backed claim this runtime
// makes. Nothing in this file claims that a physical fabric was exercised.

#include "test_support.hpp"

using namespace path_diversity;
using pd_test::Fixture;
using pd_test::make_path;
using pd_test::make_policy;

namespace {

struct Scenario {
  Fixture fixture;
  PathComposition primary;
  PathComposition secondary;
  DiversityPolicyId policy;
};

// Two paths that share no link and no transit node but do share one
// authoritative failure domain. This is the shape of the mandatory proof.
void build_srlg_conflict_scenario(Scenario& scenario) {
  // The two paths have their own endpoints, their own transit nodes, their own
  // links and their own devices. The only thing they share is the authoritative
  // correlated-failure domain placed on one link of each.
  scenario.primary = make_path("path-p", 1, {"node-a1", "node-a2"}, {"la1", "la2"}, {"sw-a"},
                               "host-src-a", "host-dst-a");
  scenario.secondary = make_path("path-s", 1, {"node-b1", "node-b2"}, {"lb1", "lb2"}, {"sw-b"},
                                 "host-src-b", "host-dst-b");
  scenario.fixture.evidence.set_path(scenario.primary);
  scenario.fixture.evidence.set_path(scenario.secondary);

  // Every entity of the primary path sits in the alpha correlated-failure
  // domain and every entity of the secondary path in beta, so nothing is shared
  // by default. One link on each path additionally belongs to the authoritative
  // shared domain "rack-17": the paths remain link-disjoint and node-disjoint,
  // yet they are not independent.
  pd_test::classify_path(scenario.fixture.evidence, scenario.primary,
                         DomainRelation::FAILURE_DOMAIN, EvidenceCoverage::COMPLETE,
                         {"fd-alpha"});
  pd_test::classify_path(scenario.fixture.evidence, scenario.secondary,
                         DomainRelation::FAILURE_DOMAIN, EvidenceCoverage::COMPLETE,
                         {"fd-beta"});
  pd_test::classify_path(scenario.fixture.evidence, scenario.primary, DomainRelation::RACK,
                         EvidenceCoverage::COMPLETE, {"rack-1"});
  pd_test::classify_path(scenario.fixture.evidence, scenario.secondary, DomainRelation::RACK,
                         EvidenceCoverage::COMPLETE, {"rack-2"});
  scenario.fixture.evidence.set_domain_membership(
      EntityRef{EntityKind::LINK, "la2"}, DomainRelation::FAILURE_DOMAIN,
      EvidenceCoverage::COMPLETE, {FailureDomainId::parse("fd-alpha"),
                                   FailureDomainId::parse("rack-17")});
  scenario.fixture.evidence.set_domain_membership(
      EntityRef{EntityKind::LINK, "lb2"}, DomainRelation::FAILURE_DOMAIN,
      EvidenceCoverage::COMPLETE, {FailureDomainId::parse("fd-beta"),
                                   FailureDomainId::parse("rack-17")});
  scenario.fixture.evidence.set_domain_membership(
      EntityRef{EntityKind::LINK, "la2"}, DomainRelation::RACK, EvidenceCoverage::COMPLETE,
      {FailureDomainId::parse("rack-1")});
  scenario.fixture.evidence.set_domain_membership(
      EntityRef{EntityKind::LINK, "lb2"}, DomainRelation::RACK, EvidenceCoverage::COMPLETE,
      {FailureDomainId::parse("rack-2")});

  const DiversityPolicy policy =
      make_policy("dpol-srlg", {DiversityClass::LINK_DISJOINT,
                                DiversityClass::TRANSIT_NODE_DISJOINT,
                                DiversityClass::FAILURE_DOMAIN_DISJOINT},
                  EndpointExemption::SHARED_SOURCE_AND_DESTINATION, 2);
  scenario.policy = policy.id;
  const MutationResult published =
      scenario.fixture.runtime.publish_policy(policy, scenario.fixture.actor("publish-policy"));
  (void)published;
}

const ClassResult* find_class(const DiversityProof& proof, DiversityClass klass) {
  for (const ClassResult& result : proof.classes) {
    if (result.klass == klass) {
      return &result;
    }
  }
  return nullptr;
}

}  // namespace

// ---------------------------------------------------------------------------
// Mandatory proof: link-disjoint but SRLG-conflicting.
// ---------------------------------------------------------------------------
PD_TEST(mandatory_link_disjoint_srlg_conflict) {
  Scenario scenario;
  build_srlg_conflict_scenario(scenario);
  ProofRequest request;
  request.policy = scenario.policy;
  request.policy_generation = DiversityPolicyGeneration::from_value(1);
  request.paths.push_back(PathRef{scenario.primary.path, PathAuthorityGeneration::from_value(1)});
  request.paths.push_back(PathRef{scenario.secondary.path, PathAuthorityGeneration::from_value(1)});

  const MutationResult result =
      scenario.fixture.runtime.evaluate(request, scenario.fixture.actor("evaluate-1"));
  PD_REQUIRE(result.status == MutationStatus::APPLIED);
  PD_REQUIRE(result.has_proof);
  const DiversityProof& proof = result.proof;

  const ClassResult* link = find_class(proof, DiversityClass::LINK_DISJOINT);
  const ClassResult* node = find_class(proof, DiversityClass::TRANSIT_NODE_DISJOINT);
  const ClassResult* domain = find_class(proof, DiversityClass::FAILURE_DOMAIN_DISJOINT);
  PD_REQUIRE(link != nullptr);
  PD_REQUIRE(node != nullptr);
  PD_REQUIRE(domain != nullptr);

  PD_CHECK(link->outcome == ProofOutcome::PROVEN_DIVERSE);
  PD_CHECK(node->outcome == ProofOutcome::PROVEN_DIVERSE);
  PD_CHECK(domain->outcome == ProofOutcome::NOT_DIVERSE);
  PD_CHECK(proof.outcome == ProofOutcome::NOT_DIVERSE);
  PD_CHECK(proof.lifecycle == LifecycleState::CURRENT);
  PD_CHECK(proof.currentness == Currentness::CURRENT);
  PD_CHECK(link->evidence_complete);
  PD_CHECK(node->evidence_complete);

  // The exact shared domain is named, and nothing about a shared link or node
  // is invented.
  PD_CHECK_EQ(domain->shared.size(), std::size_t(1));
  PD_CHECK_EQ(domain->shared.front().id, std::string("rack-17"));
  PD_CHECK(domain->shared.front().kind == ConflictClass::SHARED_FAILURE_DOMAIN);

  // The oracle agrees: no shared link, no shared node beyond the endpoints, but
  // a shared authoritative domain.
  PD_CHECK(pd_test::oracle::link_disjoint(scenario.primary, scenario.secondary));
  PD_CHECK(pd_test::oracle::node_disjoint(scenario.primary, scenario.secondary,
                                          EndpointExemption::SHARED_SOURCE_AND_DESTINATION));
}

// The same shape, with the domain evidence removed: absence of an observed
// shared domain must never become a proof of independence.
PD_TEST(mandatory_incomplete_coverage_is_unknown) {
  Scenario scenario;
  build_srlg_conflict_scenario(scenario);
  // One relevant entity of the secondary path loses its classification.
  scenario.fixture.evidence.clear_entity(EntityRef{EntityKind::LINK, "lb2"});

  ProofRequest request;
  request.policy = scenario.policy;
  request.policy_generation = DiversityPolicyGeneration::from_value(1);
  request.paths.push_back(PathRef{scenario.primary.path, PathAuthorityGeneration::from_value(1)});
  request.paths.push_back(PathRef{scenario.secondary.path, PathAuthorityGeneration::from_value(1)});
  const MutationResult result =
      scenario.fixture.runtime.evaluate(request, scenario.fixture.actor("evaluate-unknown"));
  PD_REQUIRE(result.has_proof);
  PD_CHECK(result.proof.outcome == ProofOutcome::UNKNOWN_INCOMPLETE_EVIDENCE);
  PD_CHECK(result.proof.outcome != ProofOutcome::PROVEN_DIVERSE);

  const ClassResult* domain = find_class(result.proof, DiversityClass::FAILURE_DOMAIN_DISJOINT);
  PD_REQUIRE(domain != nullptr);
  PD_CHECK(domain->outcome == ProofOutcome::UNKNOWN_INCOMPLETE_EVIDENCE);
  PD_CHECK(!domain->evidence_complete);
  PD_CHECK(!domain->detail.empty());

  // Publish complete, independent evidence and revalidate: now it proves.
  pd_test::classify_path(scenario.fixture.evidence, scenario.secondary,
                         DomainRelation::FAILURE_DOMAIN, EvidenceCoverage::COMPLETE,
                         {"fd-beta"});
  pd_test::classify_path(scenario.fixture.evidence, scenario.secondary, DomainRelation::RACK,
                         EvidenceCoverage::COMPLETE, {"rack-2"});
  const MutationResult revalidated =
      scenario.fixture.runtime.revalidate(result.proof.id, scenario.fixture.actor("revalidate-1"));
  PD_REQUIRE(revalidated.has_proof);
  PD_CHECK(revalidated.proof.outcome == ProofOutcome::PROVEN_DIVERSE);
  PD_CHECK(revalidated.proof.generation.value() == result.proof.generation.value() + 1);
  PD_CHECK(revalidated.proof.lifecycle == LifecycleState::CURRENT);
}

// Sharing an endpoint is a shared failure domain when the policy requires
// failure-domain independence: the endpoint host is a single point of failure
// even though the endpoint exemption excuses it from node-disjointness. The two
// axes are genuinely separate and this test pins that.
PD_TEST(shared_endpoint_is_a_shared_failure_domain) {
  Fixture fixture;
  const PathComposition left = make_path("path-se1", 1, {"node-x"}, {"lx"}, {"sw-x"}, "ep-src",
                                         "ep-dst");
  const PathComposition right = make_path("path-se2", 1, {"node-y"}, {"ly"}, {"sw-y"}, "ep-src",
                                          "ep-dst");
  fixture.evidence.set_path(left);
  fixture.evidence.set_path(right);
  // Non-endpoint entities are independent; the shared endpoints carry one
  // correlated-failure domain.
  for (const EntityRef& entity : pd_test::entities_of(left)) {
    if (entity.kind == EntityKind::ENDPOINT) {
      continue;
    }
    fixture.evidence.set_domain_membership(entity, DomainRelation::FAILURE_DOMAIN,
                                           EvidenceCoverage::COMPLETE,
                                           {FailureDomainId::parse("fd-left")});
  }
  for (const EntityRef& entity : pd_test::entities_of(right)) {
    if (entity.kind == EntityKind::ENDPOINT) {
      continue;
    }
    fixture.evidence.set_domain_membership(entity, DomainRelation::FAILURE_DOMAIN,
                                           EvidenceCoverage::COMPLETE,
                                           {FailureDomainId::parse("fd-right")});
  }
  for (const char* endpoint : {"ep-src", "ep-dst"}) {
    fixture.evidence.set_domain_membership(EntityRef{EntityKind::ENDPOINT, endpoint},
                                           DomainRelation::FAILURE_DOMAIN,
                                           EvidenceCoverage::COMPLETE,
                                           {FailureDomainId::parse("fd-endpoint")});
  }
  const DiversityPolicy policy =
      make_policy("dpol-endpoint-domain",
                  {DiversityClass::TRANSIT_NODE_DISJOINT,
                   DiversityClass::FAILURE_DOMAIN_DISJOINT},
                  EndpointExemption::SHARED_SOURCE_AND_DESTINATION, 2);
  PD_REQUIRE(fixture.runtime.publish_policy(policy, fixture.actor("publish-se")).status ==
             MutationStatus::APPLIED);
  ProofRequest request;
  request.policy = policy.id;
  request.policy_generation = DiversityPolicyGeneration::from_value(1);
  request.paths.push_back(PathRef{left.path, PathAuthorityGeneration::from_value(1)});
  request.paths.push_back(PathRef{right.path, PathAuthorityGeneration::from_value(1)});
  const MutationResult result = fixture.runtime.evaluate(request, fixture.actor("eval-se"));
  PD_REQUIRE(result.has_proof);
  const ClassResult* node = find_class(result.proof, DiversityClass::TRANSIT_NODE_DISJOINT);
  const ClassResult* domain = find_class(result.proof, DiversityClass::FAILURE_DOMAIN_DISJOINT);
  PD_REQUIRE(node != nullptr);
  PD_REQUIRE(domain != nullptr);
  PD_CHECK(node->outcome == ProofOutcome::PROVEN_DIVERSE);
  PD_CHECK(domain->outcome == ProofOutcome::NOT_DIVERSE);
  PD_CHECK(result.proof.outcome == ProofOutcome::NOT_DIVERSE);
  bool saw_endpoint_domain = false;
  for (const SharedResource& conflict : domain->shared) {
    if (conflict.kind == ConflictClass::SHARED_FAILURE_DOMAIN && conflict.id == "fd-endpoint") {
      saw_endpoint_domain = true;
    }
  }
  PD_CHECK(saw_endpoint_domain);
}

// ---------------------------------------------------------------------------
// Endpoint exemption proof.
// ---------------------------------------------------------------------------
PD_TEST(endpoint_exemption_semantics) {
  Fixture fixture;
  const PathComposition left = make_path("path-e1", 1, {"node-x"}, {"lx"}, {"sw-x"}, "ep-src",
                                         "ep-dst");
  const PathComposition right = make_path("path-e2", 1, {"node-y"}, {"ly"}, {"sw-y"}, "ep-src",
                                          "ep-dst");
  fixture.evidence.set_path(left);
  fixture.evidence.set_path(right);
  pd_test::classify_path(fixture.evidence, left, DomainRelation::FAILURE_DOMAIN,
                         EvidenceCoverage::COMPLETE, {"fd-1"});
  pd_test::classify_path(fixture.evidence, right, DomainRelation::FAILURE_DOMAIN,
                         EvidenceCoverage::COMPLETE, {"fd-2"});

  pd_test::classify_path(fixture.evidence, left, DomainRelation::RACK, EvidenceCoverage::COMPLETE,
                         {"rack-1"});
  pd_test::classify_path(fixture.evidence, right, DomainRelation::RACK, EvidenceCoverage::COMPLETE,
                         {"rack-2"});

  const DiversityPolicy exempt =
      make_policy("dpol-exempt", {DiversityClass::TRANSIT_NODE_DISJOINT},
                  EndpointExemption::SHARED_SOURCE_AND_DESTINATION, 2);
  const DiversityPolicy strict = make_policy(
      "dpol-strict", {DiversityClass::TRANSIT_NODE_DISJOINT}, EndpointExemption::NONE, 2);
  PD_REQUIRE(fixture.runtime
                 .publish_policy(exempt, fixture.actor("publish-exempt"))
                 .status == MutationStatus::APPLIED);
  PD_REQUIRE(fixture.runtime
                 .publish_policy(strict, fixture.actor("publish-strict"))
                 .status == MutationStatus::APPLIED);

  ProofRequest request;
  request.paths.push_back(PathRef{left.path, PathAuthorityGeneration::from_value(1)});
  request.paths.push_back(PathRef{right.path, PathAuthorityGeneration::from_value(1)});

  request.policy = exempt.id;
  request.policy_generation = DiversityPolicyGeneration::from_value(1);
  const MutationResult with_exemption =
      fixture.runtime.evaluate(request, fixture.actor("eval-exempt"));
  PD_REQUIRE(with_exemption.has_proof);
  PD_CHECK(with_exemption.proof.outcome == ProofOutcome::PROVEN_DIVERSE);

  request.policy = strict.id;
  request.policy_generation = DiversityPolicyGeneration::from_value(1);
  const MutationResult without_exemption =
      fixture.runtime.evaluate(request, fixture.actor("eval-strict"));
  PD_REQUIRE(without_exemption.has_proof);
  PD_CHECK(without_exemption.proof.outcome == ProofOutcome::NOT_DIVERSE);
  const ClassResult* node =
      find_class(without_exemption.proof, DiversityClass::TRANSIT_NODE_DISJOINT);
  PD_REQUIRE(node != nullptr);
  PD_CHECK_EQ(node->shared.size(), std::size_t(2));
  std::vector<std::string> shared_ids;
  for (const SharedResource& conflict : node->shared) {
    shared_ids.push_back(conflict.id);
  }
  PD_CHECK_EQ(shared_ids[0], std::string("ep-dst"));
  PD_CHECK_EQ(shared_ids[1], std::string("ep-src"));

  // The digest of the two proofs differs: endpoint semantics are part of proof
  // identity, not an invisible evaluation detail.
  PD_CHECK(!(with_exemption.proof.semantic_digest == without_exemption.proof.semantic_digest));
}

// ---------------------------------------------------------------------------
// Insertion-order independence.
// ---------------------------------------------------------------------------
PD_TEST(insertion_order_independence) {
  Fixture fixture;
  std::vector<PathComposition> paths;
  for (int i = 0; i < 4; ++i) {
    const std::string suffix = std::to_string(i);
    PathComposition composition =
        make_path("path-perm-" + suffix, 1, {"node-" + suffix}, {"link-" + suffix},
                  {"sw-" + suffix}, "ep-src", "ep-dst");
    fixture.evidence.set_path(composition);
    pd_test::classify_path(fixture.evidence, composition, DomainRelation::FAILURE_DOMAIN,
                           EvidenceCoverage::COMPLETE, {"fd-perm"});
    pd_test::classify_path(fixture.evidence, composition, DomainRelation::RACK,
                           EvidenceCoverage::COMPLETE, {"rack-1"});
    paths.push_back(composition);
  }
  const DiversityPolicy policy =
      make_policy("dpol-perm", {DiversityClass::LINK_DISJOINT,
                                DiversityClass::TRANSIT_NODE_DISJOINT,
                                DiversityClass::FAILURE_DOMAIN_DISJOINT},
                  EndpointExemption::SHARED_SOURCE_AND_DESTINATION, 2);
  PD_REQUIRE(fixture.runtime.publish_policy(policy, fixture.actor("publish-perm")).status ==
             MutationStatus::APPLIED);

  // Permutations of four elements: the canonical order is fixed, so all of them
  // must produce one identical proof identity and one identical digest.
  const std::vector<std::vector<std::size_t>> permutations = {
      {0, 1, 2, 3}, {3, 2, 1, 0}, {1, 0, 3, 2}, {2, 3, 0, 1}, {0, 2, 1, 3}, {3, 0, 2, 1}};
  std::optional<DiversityProof> reference;
  for (const std::vector<std::size_t>& order : permutations) {
    ProofRequest request;
    request.policy = policy.id;
    request.policy_generation = DiversityPolicyGeneration::from_value(1);
    for (std::size_t index : order) {
      request.paths.push_back(
          PathRef{paths[index].path, PathAuthorityGeneration::from_value(1)});
    }
    const MutationResult result = fixture.runtime.evaluate(
        request, fixture.actor("perm-" + std::to_string(order[0]) + std::to_string(order[1])));
    PD_REQUIRE(result.has_proof);
    if (!reference.has_value()) {
      reference = result.proof;
      continue;
    }
    PD_CHECK_EQ(result.proof.id.str(), reference->id.str());
    PD_CHECK_EQ(result.proof.semantic_digest.hex(), reference->semantic_digest.hex());
    PD_CHECK_EQ(result.proof.outcome, reference->outcome);
    PD_CHECK_EQ(result.proof.matrix.order.size(), reference->matrix.order.size());
    for (std::size_t i = 0; i < result.proof.matrix.order.size(); ++i) {
      PD_CHECK_EQ(result.proof.matrix.order[i].str(), reference->matrix.order[i].str());
    }
    PD_CHECK_EQ(result.proof.conflicts.size(), reference->conflicts.size());
    for (std::size_t i = 0; i < result.proof.conflicts.size(); ++i) {
      PD_CHECK_EQ(result.proof.conflicts[i].id, reference->conflicts[i].id);
    }
  }
  PD_CHECK(reference.has_value());
}

// ---------------------------------------------------------------------------
// Deterministic primary reason precedence.
// ---------------------------------------------------------------------------
PD_TEST(primary_reason_precedence) {
  Fixture fixture;
  // Two paths that share a link, a transit node and one failure domain at the
  // same time. The correlated-failure relation must win the primary slot.
  PathComposition left =
      make_path("path-pre-1", 1, {"shared-node", "node-1"}, {"shared-link", "link-1"}, {"sw-1"},
                "ep-src", "ep-dst");
  const PathComposition right =
      make_path("path-pre-2", 1, {"shared-node", "node-2"}, {"shared-link", "link-2"}, {"sw-2"},
                "ep-src", "ep-dst");
  fixture.evidence.set_path(left);
  fixture.evidence.set_path(right);
  pd_test::classify_path(fixture.evidence, left, DomainRelation::FAILURE_DOMAIN,
                         EvidenceCoverage::COMPLETE, {"rack-17"});
  pd_test::classify_path(fixture.evidence, right, DomainRelation::FAILURE_DOMAIN,
                         EvidenceCoverage::COMPLETE, {"rack-17"});
  pd_test::classify_path(fixture.evidence, left, DomainRelation::RACK, EvidenceCoverage::COMPLETE,
                         {"rack-17"});
  pd_test::classify_path(fixture.evidence, right, DomainRelation::RACK, EvidenceCoverage::COMPLETE,
                         {"rack-17"});
  pd_test::classify_path(fixture.evidence, left, DomainRelation::POWER_DOMAIN,
                         EvidenceCoverage::COMPLETE, {"power-domain-2"});
  pd_test::classify_path(fixture.evidence, right, DomainRelation::POWER_DOMAIN,
                         EvidenceCoverage::COMPLETE, {"power-domain-2"});

  const DiversityPolicy policy =
      make_policy("dpol-precedence", {DiversityClass::LINK_DISJOINT,
                                      DiversityClass::TRANSIT_NODE_DISJOINT,
                                      DiversityClass::FAILURE_DOMAIN_DISJOINT},
                  EndpointExemption::SHARED_SOURCE_AND_DESTINATION, 2);
  PD_REQUIRE(fixture.runtime.publish_policy(policy, fixture.actor("publish-prec")).status ==
             MutationStatus::APPLIED);

  ProofRequest request;
  request.policy = policy.id;
  request.policy_generation = DiversityPolicyGeneration::from_value(1);
  request.paths.push_back(PathRef{left.path, PathAuthorityGeneration::from_value(1)});
  request.paths.push_back(PathRef{right.path, PathAuthorityGeneration::from_value(1)});
  const MutationResult result = fixture.runtime.evaluate(request, fixture.actor("eval-prec"));
  PD_REQUIRE(result.has_proof);
  PD_CHECK(result.proof.outcome == ProofOutcome::NOT_DIVERSE);
  PD_REQUIRE(!result.proof.conflicts.empty());
  PD_CHECK(result.proof.conflicts.front().kind == ConflictClass::SHARED_FAILURE_DOMAIN);
  PD_CHECK_EQ(result.proof.conflicts.front().id, std::string("rack-17"));

  // The pairwise cell carries the same primary reason.
  PD_REQUIRE(result.proof.matrix.cells.size() == 1);
  PD_REQUIRE(result.proof.matrix.cells.front().primary_conflict.has_value());
  PD_CHECK(result.proof.matrix.cells.front().primary_conflict->kind ==
           ConflictClass::SHARED_FAILURE_DOMAIN);

  // An explanation names the exact required class and the exact resource.
  const std::optional<Explanation> explanation = fixture.runtime.explain(result.proof.id);
  PD_REQUIRE(explanation.has_value());
  bool saw_failure_domain = false;
  bool saw_shared_link = false;
  for (const ExplanationEntry& entry : explanation->entries) {
    if (entry.kind == ExplanationKind::SHARED_DOMAIN && entry.subject == "rack-17") {
      saw_failure_domain = true;
    }
    if (entry.kind == ExplanationKind::SHARED_LINK && entry.subject == "shared-link") {
      saw_shared_link = true;
    }
  }
  PD_CHECK(saw_failure_domain);
  PD_CHECK(saw_shared_link);
}

// ---------------------------------------------------------------------------
// Conflict graph and pairwise matrix.
// ---------------------------------------------------------------------------
PD_TEST(conflict_graph_matches_matrix) {
  Fixture fixture;
  std::vector<PathComposition> paths;
  for (int i = 0; i < 4; ++i) {
    const std::string suffix = std::to_string(i);
    const std::string link = i < 2 ? "link-shared" : "link-" + suffix;
    PathComposition composition = make_path("path-graph-" + suffix, 1, {"node-" + suffix}, {link},
                                            {"sw-" + suffix}, "ep-src", "ep-dst");
    fixture.evidence.set_path(composition);
    pd_test::classify_path(fixture.evidence, composition, DomainRelation::FAILURE_DOMAIN,
                           EvidenceCoverage::COMPLETE, {"fd-" + suffix});
    paths.push_back(composition);
  }
  const DiversityPolicy policy = make_policy("dpol-graph", {DiversityClass::LINK_DISJOINT},
                                             EndpointExemption::SHARED_SOURCE_AND_DESTINATION, 2);
  PD_REQUIRE(fixture.runtime.publish_policy(policy, fixture.actor("publish-graph")).status ==
             MutationStatus::APPLIED);

  ProofRequest request;
  request.policy = policy.id;
  request.policy_generation = DiversityPolicyGeneration::from_value(1);
  for (const PathComposition& composition : paths) {
    request.paths.push_back(
        PathRef{composition.path, PathAuthorityGeneration::from_value(1)});
  }
  const MutationResult result = fixture.runtime.evaluate(request, fixture.actor("eval-graph"));
  PD_REQUIRE(result.has_proof);
  const std::optional<ConflictGraph> graph = fixture.runtime.conflict_graph(result.proof.id);
  PD_REQUIRE(graph.has_value());
  PD_CHECK_EQ(graph->path_count, std::uint32_t(4));
  PD_CHECK_EQ(graph->edge_count(), std::uint64_t(1));
  PD_CHECK(graph->edge(0, 1));
  PD_CHECK(!graph->edge(0, 2));
  PD_CHECK_EQ(graph->neighbours(0).size(), std::size_t(1));
}

PD_TEST_MAIN()
