// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.

// Structured explanations: why a pair is not independent, which exact shared
// resources exist, which evidence generation proves it, which required evidence
// is missing, why a proof is unknown or stale, which policy class was required
// and the exact witness subset. Rendering must be byte-identical across repeated
// calls and across permuted arrival order.

#include <cstdint>
#include <string>
#include <vector>

#include "test_support.hpp"

namespace {

using namespace path_diversity;

DiversityPolicy shared_policy(const char* id) {
  DiversityPolicy policy = pd_test::make_policy(
      id,
      {DiversityClass::LINK_DISJOINT, DiversityClass::TRANSIT_NODE_DISJOINT,
       DiversityClass::DEVICE_DISJOINT, DiversityClass::FAILURE_DOMAIN_DISJOINT},
      EndpointExemption::NONE, 2);
  policy.allowed_failure_domain_relations = {DomainRelation::FAILURE_DOMAIN};
  policy.canonicalize();
  return policy;
}

// Two paths that share a link, a device, a transit node (the common source, not
// exempt under NONE) and one failure domain.
void add_shared_paths(pd_test::InMemoryEvidence& evidence) {
  const PathComposition left = pd_test::make_path("path-a", 1, {"t1"}, {"l1", "l-shared"},
                                                  {"d1", "d-shared"}, "h1", "h2");
  const PathComposition right = pd_test::make_path("path-b", 1, {"t2"}, {"l2", "l-shared"},
                                                   {"d2", "d-shared"}, "h1", "h3");
  evidence.set_path(left);
  evidence.set_path(right);
  pd_test::classify_path(evidence, left, DomainRelation::FAILURE_DOMAIN, EvidenceCoverage::COMPLETE,
                         {"fd-1"});
  pd_test::classify_path(evidence, right, DomainRelation::FAILURE_DOMAIN, EvidenceCoverage::COMPLETE,
                         {"fd-1"});
}

void add_independent_paths(pd_test::InMemoryEvidence& evidence) {
  evidence.set_path(pd_test::make_path("path-a", 1, {"t1"}, {"l1"}, {"d1"}, "h1", "h2"));
  evidence.set_path(pd_test::make_path("path-b", 1, {"t2"}, {"l2"}, {"d2"}, "h1", "h3"));
  evidence.set_path(pd_test::make_path("path-c", 1, {"t3"}, {"l3"}, {"d3"}, "h1", "h4"));
}

ProofRequest request_of(const DiversityPolicy& policy, DiversityPolicyGeneration generation,
                        const std::vector<const char*>& order) {
  ProofRequest request;
  request.policy = policy.id;
  request.policy_generation = generation;
  for (const char* name : order) {
    request.paths.push_back(PathRef{PathId::parse(name), PathAuthorityGeneration::from_value(1)});
  }
  return request;
}

const ExplanationEntry* find_entry(const Explanation& explanation, ExplanationKind kind,
                                   const std::string& subject) {
  for (const ExplanationEntry& entry : explanation.entries) {
    if (entry.kind == kind && entry.subject == subject) {
      return &entry;
    }
  }
  return nullptr;
}

std::size_t count_kind(const Explanation& explanation, ExplanationKind kind) {
  std::size_t count = 0;
  for (const ExplanationEntry& entry : explanation.entries) {
    if (entry.kind == kind) {
      ++count;
    }
  }
  return count;
}

bool has_kind(const Explanation& explanation, ExplanationKind kind) {
  return count_kind(explanation, kind) != 0;
}

bool contains(const std::string& text, const std::string& needle) {
  return text.find(needle) != std::string::npos;
}

// A committed shared-resource scenario, optionally built from a permuted arrival
// order and optionally under tighter limits.
struct SharedScenario {
  explicit SharedScenario(bool reversed, Limits limits)
      : fixture(limits), policy(shared_policy("dpol-explain-shared")) {
    add_shared_paths(fixture.evidence);
    published = fixture.runtime.publish_policy(policy, fixture.actor("publish"));
    const std::vector<const char*> order =
        reversed ? std::vector<const char*>{"path-b", "path-a"}
                 : std::vector<const char*>{"path-a", "path-b"};
    committed = fixture.runtime.evaluate(
        request_of(policy, fixture.runtime.policy_generation(policy.id), order),
        fixture.actor("evaluate"));
  }

  pd_test::Fixture fixture;
  DiversityPolicy policy;
  MutationResult published;
  MutationResult committed;
};

}  // namespace

PD_TEST(explains_why_a_pair_is_not_independent) {
  SharedScenario scenario(false, Limits());
  PD_REQUIRE(scenario.committed.has_proof);
  const DiversityProof& proof = scenario.committed.proof;
  PD_CHECK(proof.outcome == ProofOutcome::NOT_DIVERSE);
  PD_CHECK(!proof.conflicts.empty());
  PD_CHECK(proof.conflicts.front().kind == ConflictClass::SHARED_FAILURE_DOMAIN);

  const std::optional<Explanation> explanation = scenario.fixture.runtime.explain(proof.id);
  PD_REQUIRE(explanation.has_value());
  PD_CHECK(explanation->proof == proof.id);
  PD_CHECK(explanation->generation == proof.generation);
  PD_CHECK(explanation->outcome == ProofOutcome::NOT_DIVERSE);
  PD_CHECK(!explanation->truncated);
  PD_CHECK_EQ(explanation->entries_total, static_cast<std::uint64_t>(explanation->entries.size()));
  PD_CHECK(!explanation->entries.empty());

  // Which policy class was required.
  PD_CHECK_EQ(count_kind(*explanation, ExplanationKind::POLICY), std::size_t{1});
  PD_CHECK_EQ(count_kind(*explanation, ExplanationKind::REQUIRED_CLASS),
              scenario.policy.required_classes.size());
  std::vector<DiversityClass> explained_classes;
  for (const ExplanationEntry& entry : explanation->entries) {
    if (entry.kind == ExplanationKind::REQUIRED_CLASS) {
      explained_classes.push_back(entry.klass);
    }
  }
  PD_CHECK(explained_classes == scenario.policy.required_classes);
  const ExplanationEntry* device_class =
      find_entry(*explanation, ExplanationKind::REQUIRED_CLASS, "DEVICE_DISJOINT");
  PD_REQUIRE(device_class != nullptr);
  PD_CHECK(device_class->outcome == ProofOutcome::NOT_DIVERSE);
  PD_CHECK(contains(device_class->detail, "evidence COMPLETE"));
  PD_CHECK(contains(device_class->detail, "d-shared"));

  // The endpoint semantics the proof was evaluated under are stated, not hidden.
  const ExplanationEntry* endpoints =
      find_entry(*explanation, ExplanationKind::ENDPOINT_SEMANTICS, "endpoint-exemption");
  PD_REQUIRE(endpoints != nullptr);
  PD_CHECK(contains(endpoints->detail, "ordinary nodes"));

  // Which exact shared resources, each with the class it belongs to.
  const ExplanationEntry* shared_link =
      find_entry(*explanation, ExplanationKind::SHARED_LINK, "l-shared");
  PD_REQUIRE(shared_link != nullptr);
  PD_CHECK(shared_link->outcome == ProofOutcome::NOT_DIVERSE);
  PD_CHECK(shared_link->paths == std::vector<std::uint32_t>({0, 1}));
  PD_CHECK(contains(shared_link->detail, "SHARED_LINK shared by 2 paths"));
  PD_CHECK(find_entry(*explanation, ExplanationKind::SHARED_DEVICE, "d-shared") != nullptr);
  PD_CHECK(find_entry(*explanation, ExplanationKind::SHARED_DOMAIN, "fd-1") != nullptr);
  PD_CHECK(find_entry(*explanation, ExplanationKind::SHARED_TRANSIT_NODE, "h1") != nullptr);
  for (const SharedResource& conflict : proof.conflicts) {
    bool found = false;
    for (const ExplanationEntry& entry : explanation->entries) {
      if (entry.subject == conflict.id && !entry.paths.empty()) {
        found = true;
        break;
      }
    }
    pd_test::check(found, std::string("no explanation entry for conflict ") + conflict.id, __FILE__,
                   __LINE__);
  }

  // Which evidence generation proves it: the exact dependency binding.
  const ExplanationEntry* generations =
      find_entry(*explanation, ExplanationKind::DEPENDENCY, "generations");
  PD_REQUIRE(generations != nullptr);
  PD_CHECK(contains(generations->detail, "policy=g1"));
  PD_CHECK(contains(generations->detail, "topology=g1"));
  PD_CHECK(contains(generations->detail, "failure-domains=g1"));
  PD_CHECK(contains(generations->detail, "epoch=g1"));
  const ExplanationEntry* path_dependency =
      find_entry(*explanation, ExplanationKind::DEPENDENCY, "path-a");
  PD_REQUIRE(path_dependency != nullptr);
  PD_CHECK_EQ(path_dependency->detail, std::string("Path Authority generation g1"));

  // The aggregate result and the conflict graph it rests on.
  const ExplanationEntry* result =
      find_entry(*explanation, ExplanationKind::PROOF_RESULT, proof.id.str() + "@g1");
  PD_REQUIRE(result != nullptr);
  PD_CHECK(result->outcome == ProofOutcome::NOT_DIVERSE);
  PD_CHECK_EQ(result->detail, proof.detail);
  const ExplanationEntry* graph =
      find_entry(*explanation, ExplanationKind::CONFLICT_GRAPH, "conflict-graph");
  PD_REQUIRE(graph != nullptr);
  PD_CHECK(contains(graph->detail, "2 vertices"));
  PD_CHECK(contains(graph->detail, "1 conflict edges"));
  PD_CHECK(contains(graph->detail, "independent set of size K"));
  PD_CHECK(!has_kind(*explanation, ExplanationKind::WITNESS));
}

PD_TEST(rendering_is_byte_identical_and_order_independent) {
  SharedScenario first(false, Limits());
  SharedScenario permuted(true, Limits());
  PD_REQUIRE(first.committed.has_proof);
  PD_REQUIRE(permuted.committed.has_proof);
  PD_CHECK(first.committed.proof.id == permuted.committed.proof.id);
  PD_CHECK_EQ(first.committed.proof.generation.value(), permuted.committed.proof.generation.value());

  const std::optional<Explanation> left = first.fixture.runtime.explain(first.committed.proof.id);
  const std::optional<Explanation> right =
      permuted.fixture.runtime.explain(permuted.committed.proof.id);
  PD_REQUIRE(left.has_value());
  PD_REQUIRE(right.has_value());
  PD_CHECK(left->entries == right->entries);
  PD_CHECK_EQ(render_explanation(*left), render_explanation(*right));
  PD_CHECK_EQ(left->render(), right->render());

  // Repeated calls on one runtime produce byte-identical output.
  const std::string once = render_explanation(*left);
  const std::string twice =
      render_explanation(*first.fixture.runtime.explain(first.committed.proof.id));
  PD_CHECK_EQ(once, twice);
  PD_CHECK(once.find("explanation dproof-") == std::size_t{0});
  PD_CHECK(contains(once, "outcome=NOT_DIVERSE"));
  PD_CHECK(contains(once, "[SHARED_LINK LINK_DISJOINT] l-shared"));
  PD_CHECK(contains(once, "[REQUIRED_CLASS DEVICE_DISJOINT]"));
  PD_CHECK(contains(once, "[ENDPOINT_SEMANTICS] endpoint-exemption"));

  // A permuted arrival order yields the same canonical matrix indices.
  const std::optional<Explanation> left_pair =
      first.fixture.runtime.explain_pair(first.committed.proof.id, 0, 1);
  const std::optional<Explanation> right_pair =
      permuted.fixture.runtime.explain_pair(permuted.committed.proof.id, 0, 1);
  PD_REQUIRE(left_pair.has_value());
  PD_REQUIRE(right_pair.has_value());
  PD_CHECK_EQ(render_explanation(*left_pair), render_explanation(*right_pair));
}

PD_TEST(explains_which_required_evidence_is_missing) {
  pd_test::Fixture fixture;
  PathComposition left = pd_test::make_path("path-a", 1, {"t1"}, {"l1"}, {"d1"}, "h1", "h2");
  left.link_coverage = EvidenceCoverage::PARTIAL;
  fixture.evidence.set_path(left);
  fixture.evidence.set_path(pd_test::make_path("path-b", 1, {"t2"}, {"l2"}, {"d2"}, "h1", "h3"));
  const DiversityPolicy policy =
      pd_test::make_policy("dpol-explain-unknown", {DiversityClass::LINK_DISJOINT},
                           EndpointExemption::SHARED_SOURCE_AND_DESTINATION, 2);
  PD_CHECK(fixture.runtime.publish_policy(policy, fixture.actor("publish")).status ==
           MutationStatus::APPLIED);
  const MutationResult committed = fixture.runtime.evaluate(
      request_of(policy, fixture.runtime.policy_generation(policy.id), {"path-a", "path-b"}),
      fixture.actor("evaluate"));
  PD_REQUIRE(committed.has_proof);
  PD_CHECK(committed.proof.outcome == ProofOutcome::UNKNOWN_INCOMPLETE_EVIDENCE);
  PD_CHECK(committed.proof.lifecycle == LifecycleState::CURRENT);
  PD_CHECK(committed.proof.currentness == Currentness::INCOMPLETE_EVIDENCE);

  const std::optional<Explanation> explanation = fixture.runtime.explain(committed.proof.id);
  PD_REQUIRE(explanation.has_value());
  PD_CHECK(explanation->outcome == ProofOutcome::UNKNOWN_INCOMPLETE_EVIDENCE);
  PD_CHECK(has_kind(*explanation, ExplanationKind::MISSING_EVIDENCE));
  const ExplanationEntry* missing =
      find_entry(*explanation, ExplanationKind::MISSING_EVIDENCE, "LINK_DISJOINT");
  PD_REQUIRE(missing != nullptr);
  PD_CHECK(missing->klass == DiversityClass::LINK_DISJOINT);
  PD_CHECK(missing->outcome == ProofOutcome::UNKNOWN_INCOMPLETE_EVIDENCE);
  PD_CHECK(contains(missing->detail, "coverage is not complete"));
  const ExplanationEntry* link_class =
      find_entry(*explanation, ExplanationKind::REQUIRED_CLASS, "LINK_DISJOINT");
  PD_REQUIRE(link_class != nullptr);
  PD_CHECK(contains(link_class->detail, "evidence INCOMPLETE"));
  PD_CHECK(!has_kind(*explanation, ExplanationKind::SHARED_LINK));
  PD_CHECK(contains(render_explanation(*explanation), "outcome=UNKNOWN_INCOMPLETE_EVIDENCE"));
}

PD_TEST(explains_the_exact_stale_generation) {
  pd_test::Fixture fixture;
  add_independent_paths(fixture.evidence);
  const DiversityPolicy policy =
      pd_test::make_policy("dpol-explain-stale", {DiversityClass::LINK_DISJOINT},
                           EndpointExemption::SHARED_SOURCE_AND_DESTINATION, 2);
  PD_CHECK(fixture.runtime.publish_policy(policy, fixture.actor("publish")).status ==
           MutationStatus::APPLIED);

  // Advancing the topology after the paths were composed leaves every
  // composition bound to the generation it was derived under.
  fixture.evidence.advance_topology_generation();
  const ProofRequest request =
      request_of(policy, fixture.runtime.policy_generation(policy.id), {"path-a", "path-b"});

  EvaluationInputs inputs;
  inputs.authority = &fixture.evidence;
  inputs.structure = &fixture.evidence;
  inputs.domains = &fixture.evidence;
  inputs.limits = &fixture.limits;
  const EvaluationResult precise = evaluate_diversity(request, policy, inputs);
  PD_CHECK(precise.outcome == ProofOutcome::STALE_TOPOLOGY);
  PD_CHECK_EQ(precise.observed_topology.value(), std::uint64_t{2});
  PD_CHECK_EQ(precise.observed_failure_domain.value(), std::uint64_t{1});
  PD_CHECK(contains(precise.detail, "topology generation 1"));
  PD_CHECK(contains(precise.detail, "generation 2"));
  PD_CHECK(contains(precise.detail, "path-a"));

  // The runtime records the refusal unchanged: nothing unusable becomes current,
  // and the exact reason survives.
  const MutationResult committed = fixture.runtime.evaluate(request, fixture.actor("evaluate"));
  PD_REQUIRE(committed.has_proof);
  PD_CHECK(committed.proof.outcome == ProofOutcome::STALE_TOPOLOGY);
  PD_CHECK(committed.proof.lifecycle == LifecycleState::CURRENT);
  PD_CHECK(committed.proof.currentness == Currentness::STALE_TOPOLOGY);
  PD_CHECK(!committed.proof.current());
  PD_CHECK_EQ(committed.proof.detail, precise.detail);

  const std::optional<Explanation> explanation = fixture.runtime.explain(committed.proof.id);
  PD_REQUIRE(explanation.has_value());
  PD_CHECK(explanation->outcome == ProofOutcome::STALE_TOPOLOGY);
  const ExplanationEntry* stale =
      find_entry(*explanation, ExplanationKind::STALE_GENERATION, "STALE_TOPOLOGY");
  PD_REQUIRE(stale != nullptr);
  PD_CHECK(stale->outcome == ProofOutcome::STALE_TOPOLOGY);
  PD_CHECK_EQ(stale->detail, precise.detail);
  PD_CHECK(contains(render_explanation(*explanation), "[STALE_GENERATION] STALE_TOPOLOGY"));
}

PD_TEST(explains_the_exact_witness_subset) {
  pd_test::Fixture fixture;
  add_independent_paths(fixture.evidence);
  const DiversityPolicy policy =
      pd_test::make_policy("dpol-explain-witness", {DiversityClass::LINK_DISJOINT},
                           EndpointExemption::SHARED_SOURCE_AND_DESTINATION, 3,
                           SetSemantics::AT_LEAST_K_INDEPENDENT);
  PD_CHECK(fixture.runtime.publish_policy(policy, fixture.actor("publish")).status ==
           MutationStatus::APPLIED);
  const MutationResult committed = fixture.runtime.evaluate(
      request_of(policy, fixture.runtime.policy_generation(policy.id),
                 {"path-a", "path-b", "path-c"}),
      fixture.actor("evaluate"));
  PD_REQUIRE(committed.has_proof);
  PD_CHECK(committed.proof.outcome == ProofOutcome::PROVEN_DIVERSE);
  const WitnessSubset& witness = committed.proof.witness;
  PD_CHECK(witness.present);
  PD_CHECK_EQ(witness.requested_k, std::uint32_t{3});
  PD_CHECK_EQ(witness.achieved, std::uint32_t{3});
  PD_CHECK(witness.maximum_exact);
  PD_CHECK(witness.indices == std::vector<std::uint32_t>({0, 1, 2}));
  PD_CHECK(verify_witness(committed.proof.matrix, witness.indices));
  PD_CHECK_EQ(witness.render(), std::string("witness k=3 achieved=3 exact indices=[0,1,2]"));

  const std::optional<Explanation> explanation = fixture.runtime.explain(committed.proof.id);
  PD_REQUIRE(explanation.has_value());
  const ExplanationEntry* explained =
      find_entry(*explanation, ExplanationKind::WITNESS, witness.render());
  PD_REQUIRE(explained != nullptr);
  PD_CHECK(contains(explained->detail, "requested K=3"));
  PD_CHECK(contains(explained->detail, "achieved=3"));
  PD_CHECK(contains(explained->detail, "exact maximum"));
  const std::optional<ConflictGraph> graph = fixture.runtime.conflict_graph(committed.proof.id);
  PD_REQUIRE(graph.has_value());
  PD_CHECK_EQ(graph->path_count, std::uint32_t{3});
  PD_CHECK_EQ(graph->edge_count(), std::uint64_t{0});
  PD_CHECK(graph->neighbours(0).empty());
}

PD_TEST(pair_explanation_names_the_exact_pair_and_its_shared_resources) {
  SharedScenario scenario(false, Limits());
  PD_REQUIRE(scenario.committed.has_proof);
  const DiversityProofId id = scenario.committed.proof.id;

  const std::optional<Explanation> pair = scenario.fixture.runtime.explain_pair(id, 0, 1);
  PD_REQUIRE(pair.has_value());
  PD_CHECK(pair->proof == id);
  PD_CHECK(pair->outcome == ProofOutcome::NOT_DIVERSE);
  const ExplanationEntry* result = find_entry(*pair, ExplanationKind::PAIR_RESULT, "pair 0,1");
  PD_REQUIRE(result != nullptr);
  PD_CHECK(result->outcome == ProofOutcome::NOT_DIVERSE);
  PD_CHECK(result->paths == std::vector<std::uint32_t>({0, 1}));
  PD_CHECK(contains(result->detail, "does not satisfy every required diversity class"));
  PD_CHECK_EQ(count_kind(*pair, ExplanationKind::REQUIRED_CLASS), std::size_t{4});
  const ExplanationEntry* shared = find_entry(*pair, ExplanationKind::SHARED_LINK, "l-shared");
  PD_REQUIRE(shared != nullptr);
  PD_CHECK(shared->klass == DiversityClass::LINK_DISJOINT);
  PD_CHECK(shared->paths == std::vector<std::uint32_t>({0, 1}));
  PD_CHECK(find_entry(*pair, ExplanationKind::SHARED_DEVICE, "d-shared") != nullptr);
  PD_CHECK(find_entry(*pair, ExplanationKind::SHARED_DOMAIN, "fd-1") != nullptr);
  PD_CHECK(!has_kind(*pair, ExplanationKind::MISSING_EVIDENCE));

  // The pair is symmetric: (0,1) and (1,0) are one cell.
  const std::optional<Explanation> reversed = scenario.fixture.runtime.explain_pair(id, 1, 0);
  PD_REQUIRE(reversed.has_value());
  PD_CHECK(reversed->entries == pair->entries);

  // A degenerate or out-of-range pair is reported, never guessed.
  const std::optional<Explanation> same = scenario.fixture.runtime.explain_pair(id, 1, 1);
  PD_REQUIRE(same.has_value());
  PD_CHECK_EQ(same->entries.size(), std::size_t{1});
  PD_CHECK(same->entries.front().kind == ExplanationKind::PAIR_RESULT);
  PD_CHECK(same->entries.front().outcome == ProofOutcome::MALFORMED);
  PD_CHECK(contains(same->entries.front().detail, "not a distinct pair"));
  const std::optional<Explanation> outside = scenario.fixture.runtime.explain_pair(id, 7, 9);
  PD_REQUIRE(outside.has_value());
  PD_CHECK_EQ(outside->entries.size(), std::size_t{1});
  PD_CHECK(outside->entries.front().detail == same->entries.front().detail);

  const DiversityProofId unknown_id =
      DiversityProofId::parse("dproof-00000000000000000000000000000000");
  PD_CHECK(!scenario.fixture.runtime.explain_pair(unknown_id, 0, 1).has_value());
  PD_CHECK(!scenario.fixture.runtime.explain(unknown_id).has_value());
}

PD_TEST(entries_are_bounded_by_max_explanation_entries) {
  Limits limits;
  limits.max_explanation_entries = 3;
  PD_CHECK(limits.self_consistent());
  SharedScenario scenario(false, limits);
  PD_REQUIRE(scenario.committed.has_proof);
  const std::optional<Explanation> bounded =
      scenario.fixture.runtime.explain(scenario.committed.proof.id);
  PD_REQUIRE(bounded.has_value());
  PD_CHECK(bounded->truncated);
  PD_CHECK_EQ(bounded->entries.size(), std::size_t{3});
  PD_CHECK(bounded->entries_total > static_cast<std::uint64_t>(bounded->entries.size()));

  // The same bound applies to the pure function and reports how much it dropped.
  const Explanation unbounded = explain_proof(scenario.committed.proof, Limits());
  PD_CHECK(!unbounded.truncated);
  const Explanation clipped = explain_proof(scenario.committed.proof, limits);
  PD_CHECK(clipped.truncated);
  PD_CHECK_EQ(clipped.entries.size(), std::size_t{3});
  PD_CHECK_EQ(clipped.entries_total, unbounded.entries_total);
  PD_CHECK(clipped.entries.front() == unbounded.entries.front());
  PD_CHECK(contains(render_explanation(clipped), "(truncated)"));

  Limits one;
  one.max_explanation_entries = 1;
  const Explanation single = explain_proof(scenario.committed.proof, one);
  PD_CHECK_EQ(single.entries.size(), std::size_t{1});
  PD_CHECK(single.entries.front().kind == ExplanationKind::POLICY);
}

PD_TEST_MAIN()
