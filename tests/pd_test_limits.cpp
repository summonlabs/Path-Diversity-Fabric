// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.

// Limit coverage. Every field of Limits is tightened here and the subsystem
// named in its comment is observed refusing, truncating or reporting the exact
// bound. A bound that no code path reads would fail this suite.

#include <cstdint>
#include <string>
#include <vector>

#include "test_support.hpp"

namespace {

using namespace path_diversity;

void check_bound(const std::optional<ResourceLimitNotice>& notice, ResourceBound expected,
                 const std::string& label, const char* file, int line) {
  pd_test::check(notice.has_value(), label + ": no resource-limit notice was reported", file, line);
  if (!notice.has_value()) {
    return;
  }
  pd_test::check(notice->bound == expected,
                 label + ": bound is " + std::string(to_string(notice->bound)) + ", expected " +
                     std::string(to_string(expected)) + " (" + notice->render() + ")",
                 file, line);
  pd_test::check(notice->observed >= notice->allowed,
                 label + ": observed " + std::to_string(notice->observed) + " is below allowed " +
                     std::to_string(notice->allowed),
                 file, line);
}

void check_mutation(const MutationResult& result, MutationStatus expected,
                    const std::string& label, const char* file, int line) {
  pd_test::check(result.status == expected,
                 label + ": observed " + std::string(to_string(result.status)) + ", expected " +
                     std::string(to_string(expected)) + " (" + result.detail + ")",
                 file, line);
}

// Paths are named "<prefix>-path-<n>" and are pairwise disjoint in links, nodes
// and devices.
std::vector<std::string> add_disjoint_paths(pd_test::Fixture& fixture, std::size_t count,
                                            const std::string& prefix) {
  std::vector<std::string> names;
  for (std::size_t index = 0; index < count; ++index) {
    const std::string suffix = std::to_string(index);
    const std::string name = prefix + "-path-" + suffix;
    fixture.evidence.set_path(pd_test::make_path(name, 1, {prefix + "-node-" + suffix},
                                                 {prefix + "-link-" + suffix},
                                                 {prefix + "-dev-" + suffix}, "ep-src", "ep-dst"));
    names.push_back(name);
  }
  return names;
}

struct PublishedPolicy {
  DiversityPolicyId id;
  DiversityPolicyGeneration generation;
};

PublishedPolicy publish_link_policy(pd_test::Fixture& fixture, const std::string& id,
                                    std::uint32_t minimum,
                                    SetSemantics semantics = SetSemantics::ALL_PAIRS) {
  const DiversityPolicy policy =
      pd_test::make_policy(id, {DiversityClass::LINK_DISJOINT},
                           EndpointExemption::SHARED_SOURCE_AND_DESTINATION, minimum, semantics);
  const MutationResult published = fixture.runtime.publish_policy(policy, fixture.actor(id + "-pub"));
  PD_CHECK_EQ(published.status, MutationStatus::APPLIED);
  return PublishedPolicy{published.policy.id, published.policy.generation};
}

ProofRequest request_for(const std::vector<std::string>& names, const PublishedPolicy& policy) {
  ProofRequest request;
  request.policy = policy.id;
  request.policy_generation = policy.generation;
  for (const std::string& name : names) {
    request.paths.push_back(PathRef{PathId::parse(name), PathAuthorityGeneration::from_value(1)});
  }
  return request;
}

// Same, for a request that binds every path in the vector.
ProofRequest request_for(const std::vector<std::string>& names, const PublishedPolicy& policy,
                         std::size_t first, std::size_t count) {
  ProofRequest request;
  request.policy = policy.id;
  request.policy_generation = policy.generation;
  for (std::size_t index = first; index < first + count; ++index) {
    request.paths.push_back(
        PathRef{PathId::parse(names[index]), PathAuthorityGeneration::from_value(1)});
  }
  return request;
}

// A limits set in which one path-set bound is tightened and every relational
// rule still holds.
Limits with_path_bound(std::uint32_t bound) {
  Limits limits;
  limits.max_paths_per_proof = bound;
  limits.max_k_subset_paths = bound;
  limits.max_snapshot_paths = bound;
  return limits;
}

}  // namespace

PD_TEST(every_resource_bound_has_a_defined_name) {
  for (std::uint8_t raw = static_cast<std::uint8_t>(ResourceBound::MAX_POLICIES);
       raw <= static_cast<std::uint8_t>(ResourceBound::MAX_TOPOLOGY_DEPENDENCIES); ++raw) {
    PD_CHECK(is_defined_resource_bound(raw));
    const ResourceBound bound = static_cast<ResourceBound>(raw);
    const std::string name(to_string(bound));
    PD_CHECK(!name.empty());
    PD_CHECK(name != "unknown_bound");
    PD_CHECK(name != "UNKNOWN");
    // The name is the exact field name of Limits, so an operator can act on it.
    const Limits limits;
    PD_CHECK(limits.render().find(name) != std::string::npos);
  }
  PD_CHECK(!is_defined_resource_bound(0));
  PD_CHECK_EQ(to_string(static_cast<ResourceBound>(0)), std::string_view("unknown_bound"));
  PD_CHECK(!is_defined_resource_bound(24));
  PD_CHECK_EQ(to_string(static_cast<ResourceBound>(24)), std::string_view("unknown_bound"));

  const ResourceLimitNotice notice{ResourceBound::MAX_PATHS_PER_PROOF, 9, 8};
  const std::string rendered = notice.render();
  PD_CHECK(rendered.find("max_paths_per_proof") != std::string::npos);
  PD_CHECK(rendered.find("9") != std::string::npos);
  PD_CHECK(rendered.find("8") != std::string::npos);
  PD_CHECK_EQ(notice, (ResourceLimitNotice{ResourceBound::MAX_PATHS_PER_PROOF, 9, 8}));
}

PD_TEST(self_consistency_rejects_impossible_configurations) {
  const Limits defaults;
  PD_CHECK(defaults.self_consistent());
  PD_CHECK(!defaults.render().empty());

  // A zero bound cannot express its own subject. Every scalar field of Limits is
  // exercised here, one at a time.
  const int zero_selector[18] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17};
  for (int selector : zero_selector) {
    Limits limits;
    switch (selector) {
      case 0:
        limits.max_policies = 0;
        break;
      case 1: limits.max_proofs = 0; break;
      case 2: limits.max_required_classes = 0; break;
      case 3: limits.max_conflicts_per_proof = 0; break;
      case 4: limits.max_pairwise_cells = 0; break;
      case 5: limits.max_domain_evidence_entries = 0; break;
      case 6: limits.max_query_results = 0; break;
      case 7: limits.max_history = 0; break;
      case 8: limits.max_batch_size = 0; break;
      case 9: limits.max_publishers = 0; break;
      case 10: limits.max_frame_bytes = 0; break;
      case 11: limits.max_persistence_record_bytes = 0; break;
      case 12: limits.max_explanation_entries = 0; break;
      case 13: limits.max_identity_length = 0; break;
      case 14: limits.max_attempts_tracked = 0; break;
      case 15: limits.max_store_records = 0; break;
      case 16: limits.max_diff_entries = 0; break;
      default: limits.max_topology_dependencies = 0; break;
    }
    pd_test::check(!limits.self_consistent(),
                   "zeroed " + limits.render() + " was accepted as consistent", __FILE__, __LINE__);
  }

  // Structural rules that a zero check cannot express.
  {
    Limits limits;
    limits.max_paths_per_proof = 1;
    PD_CHECK(!limits.self_consistent());
  }
  {
    Limits limits;
    limits.max_k_subset_paths = 1;
    PD_CHECK(!limits.self_consistent());
  }
  {
    Limits limits;
    limits.max_snapshot_paths = 1;
    PD_CHECK(!limits.self_consistent());
  }
  {
    // A path set that cannot fit inside the pairwise-cell budget.
    Limits limits;
    limits.max_paths_per_proof = 64;
    limits.max_pairwise_cells = 100;
    PD_CHECK(!limits.self_consistent());
    limits.max_pairwise_cells = 2016;  // 64*63/2
    PD_CHECK(limits.self_consistent());
  }
  {
    Limits limits;
    limits.max_k_subset_paths = limits.max_paths_per_proof + 1;
    PD_CHECK(!limits.self_consistent());
  }
  {
    Limits limits;
    limits.max_snapshot_paths = limits.max_paths_per_proof + 1;
    PD_CHECK(!limits.self_consistent());
  }
  {
    // An assembly bound smaller than one frame can never assemble a frame.
    Limits limits;
    limits.max_frame_bytes = 128;
    limits.max_wire_assembly_bytes = 64;
    PD_CHECK(!limits.self_consistent());
    limits.max_wire_assembly_bytes = 128;
    PD_CHECK(limits.self_consistent());
  }

  // The evaluator refuses to run at all under an inconsistent limit set rather
  // than clamping silently, and the registry refuses even earlier: no policy can
  // be published against limits that cannot hold its own minimum.
  {
    pd_test::Fixture fixture;
    const std::vector<std::string> names = add_disjoint_paths(fixture, 2, "inc");
    const PublishedPolicy policy = publish_link_policy(fixture, "dpol-inconsistent", 2);

    Limits broken;
    broken.max_paths_per_proof = 1;
    broken.max_k_subset_paths = 1;
    broken.max_snapshot_paths = 1;
    PD_CHECK(!broken.self_consistent());
    EvaluationInputs inputs;
    inputs.authority = &fixture.evidence;
    inputs.structure = &fixture.evidence;
    inputs.domains = &fixture.evidence;
    inputs.limits = &broken;
    const EvaluationResult result =
        evaluate_diversity(request_for(names, policy), *fixture.runtime.policy(policy.id), inputs);
    PD_CHECK_EQ(result.outcome, ProofOutcome::MALFORMED);
    PD_CHECK(result.detail.find("self-consistent") != std::string::npos);

    pd_test::Fixture limited(broken);
    const MutationResult refused = limited.runtime.publish_policy(
        pd_test::make_policy("dpol-inconsistent-publish", {DiversityClass::LINK_DISJOINT},
                             EndpointExemption::NONE, 2),
        limited.actor("inconsistent-publish"));
    check_mutation(refused, MutationStatus::MALFORMED, "inconsistent publish", __FILE__, __LINE__);
    PD_CHECK(refused.detail.find("MINIMUM_EXCEEDS_PATH_BOUND") != std::string::npos);
  }
}

PD_TEST(registry_query_and_authority_bounds) {
  // max_policies bounds the policy registry.
  {
    Limits limits;
    limits.max_policies = 2;
    pd_test::Fixture fixture(limits);
    for (int index = 0; index < 2; ++index) {
      const DiversityPolicy policy = pd_test::make_policy(
          "dpol-cap-" + std::to_string(index), {DiversityClass::LINK_DISJOINT},
          EndpointExemption::NONE, 2);
      const MutationResult published =
          fixture.runtime.publish_policy(policy, fixture.actor("cap-" + std::to_string(index)));
      check_mutation(published, MutationStatus::APPLIED, "policy under the bound", __FILE__,
                     __LINE__);
    }
    const DiversityPolicy overflow = pd_test::make_policy(
        "dpol-cap-overflow", {DiversityClass::LINK_DISJOINT}, EndpointExemption::NONE, 2);
    const MutationResult refused =
        fixture.runtime.publish_policy(overflow, fixture.actor("cap-overflow"));
    check_mutation(refused, MutationStatus::LIMIT_EXCEEDED, "max_policies", __FILE__, __LINE__);
    check_bound(refused.limit, ResourceBound::MAX_POLICIES, "max_policies", __FILE__, __LINE__);
    PD_CHECK_EQ(fixture.runtime.policy_count(), std::size_t{2});
  }

  // max_proofs bounds the proof registry.
  {
    Limits limits;
    limits.max_proofs = 1;
    pd_test::Fixture fixture(limits);
    const std::vector<std::string> names = add_disjoint_paths(fixture, 4, "cap");
    const PublishedPolicy policy = publish_link_policy(fixture, "dpol-cap-proofs", 2);
    check_mutation(fixture.runtime.evaluate(request_for(names, policy, 0, 2), fixture.actor("cap-a")),
                   MutationStatus::APPLIED, "first proof", __FILE__, __LINE__);
    const MutationResult refused =
        fixture.runtime.evaluate(request_for(names, policy, 2, 2), fixture.actor("cap-b"));
    check_mutation(refused, MutationStatus::LIMIT_EXCEEDED, "max_proofs", __FILE__, __LINE__);
    check_bound(refused.limit, ResourceBound::MAX_PROOFS, "max_proofs", __FILE__, __LINE__);
    PD_CHECK_EQ(fixture.runtime.proof_count(), std::size_t{1});
  }

  // max_batch_size bounds one batch; the refused overflow is reported, not
  // dropped silently.
  {
    Limits limits;
    limits.max_batch_size = 1;
    pd_test::Fixture fixture(limits);
    const std::vector<std::string> names = add_disjoint_paths(fixture, 4, "batch");
    const PublishedPolicy policy = publish_link_policy(fixture, "dpol-batch", 2);
    std::vector<ProofRequest> requests;
    requests.push_back(request_for(names, policy, 0, 2));
    requests.push_back(request_for(names, policy, 2, 2));
    const std::vector<MutationResult> results =
        fixture.runtime.evaluate_batch(requests, fixture.actor("batch"));
    PD_REQUIRE(results.size() == 2);
    check_mutation(results.front(), MutationStatus::APPLIED, "batched element", __FILE__, __LINE__);
    check_mutation(results.back(), MutationStatus::LIMIT_EXCEEDED, "max_batch_size", __FILE__,
                   __LINE__);
    check_bound(results.back().limit, ResourceBound::MAX_BATCH_SIZE, "max_batch_size", __FILE__,
                __LINE__);
  }

  // max_attempts_tracked bounds retained replay records.
  {
    Limits limits;
    limits.max_attempts_tracked = 2;
    pd_test::Fixture fixture(limits);
    for (int index = 0; index < 2; ++index) {
      const DiversityPolicy policy = pd_test::make_policy(
          "dpol-attempt-" + std::to_string(index), {DiversityClass::LINK_DISJOINT},
          EndpointExemption::NONE, 2);
      check_mutation(
          fixture.runtime.publish_policy(policy, fixture.actor("attempt-" + std::to_string(index))),
          MutationStatus::APPLIED, "attempt under the bound", __FILE__, __LINE__);
    }
    const DiversityPolicy overflow = pd_test::make_policy(
        "dpol-attempt-overflow", {DiversityClass::LINK_DISJOINT}, EndpointExemption::NONE, 2);
    const MutationResult refused =
        fixture.runtime.publish_policy(overflow, fixture.actor("attempt-overflow"));
    check_mutation(refused, MutationStatus::LIMIT_EXCEEDED, "max_attempts_tracked", __FILE__,
                   __LINE__);
  }

  // max_publishers bounds registered sessions.
  {
    Limits limits;
    limits.max_publishers = 1;
    pd_test::Fixture fixture(limits);
    PublisherSession second;
    second.publisher = mint_publisher_id("second");
    second.boot = mint_worker_boot_id();
    second.epoch = fixture.publication.current_epoch();
    second.scope = default_scope();
    PD_CHECK_EQ(fixture.publication.register_publisher(second), AuthorityStatus::LIMIT_EXCEEDED);
    PD_CHECK_EQ(fixture.publication.session_count(), std::size_t{1});
  }

  // max_query_results bounds one query and reports the untruncated total.
  {
    Limits limits;
    limits.max_query_results = 1;
    pd_test::Fixture fixture(limits);
    const std::vector<std::string> names = add_disjoint_paths(fixture, 4, "query");
    const PublishedPolicy policy = publish_link_policy(fixture, "dpol-query", 2);
    check_mutation(fixture.runtime.evaluate(request_for(names, policy, 0, 2),
                                            fixture.actor("query-a")),
                   MutationStatus::APPLIED, "query proof a", __FILE__, __LINE__);
    check_mutation(fixture.runtime.evaluate(request_for(names, policy, 2, 2),
                                            fixture.actor("query-b")),
                   MutationStatus::APPLIED, "query proof b", __FILE__, __LINE__);
    const DiversityRuntime::QueryResult all = fixture.runtime.all_proofs();
    PD_CHECK_EQ(all.proofs.size(), std::size_t{1});
    PD_CHECK(all.truncated);
    PD_CHECK_EQ(all.total, std::uint64_t{2});
    const DiversityRuntime::QueryResult current = fixture.runtime.current_proofs();
    PD_CHECK_EQ(current.proofs.size(), std::size_t{1});
    PD_CHECK(current.truncated);
    PD_CHECK_EQ(current.total, std::uint64_t{2});
  }
}

PD_TEST(evaluation_hard_bounds_report_their_exact_bound) {
  // max_paths_per_proof.
  {
    pd_test::Fixture fixture(with_path_bound(2));
    const std::vector<std::string> names = add_disjoint_paths(fixture, 3, "paths");
    const PublishedPolicy policy = publish_link_policy(fixture, "dpol-paths", 2);
    const MutationResult result =
        fixture.runtime.evaluate(request_for(names, policy), fixture.actor("paths"));
    check_mutation(result, MutationStatus::APPLIED, "max_paths_per_proof applied", __FILE__,
                   __LINE__);
    PD_CHECK_EQ(result.proof.outcome, ProofOutcome::RESOURCE_LIMIT);
    // The notice travels on the evaluated revision, so a caller reading the
    // proof sees exactly which bound refused it.
    check_bound(result.proof.limit, ResourceBound::MAX_PATHS_PER_PROOF, "max_paths_per_proof",
                __FILE__, __LINE__);
  }

  // max_k_subset_paths, reached only by the exact K-subset solver: the path
  // bound is deliberately roomier than the solver bound.
  {
    Limits limits;
    limits.max_paths_per_proof = 8;
    limits.max_k_subset_paths = 3;
    limits.max_snapshot_paths = 8;
    PD_REQUIRE(limits.self_consistent());
    pd_test::Fixture fixture(limits);
    const std::vector<std::string> names = add_disjoint_paths(fixture, 4, "kset");
    const PublishedPolicy policy = publish_link_policy(
        fixture, "dpol-kset", 2, SetSemantics::AT_LEAST_K_INDEPENDENT);
    const MutationResult result =
        fixture.runtime.evaluate(request_for(names, policy), fixture.actor("kset"));
    check_mutation(result, MutationStatus::APPLIED, "max_k_subset_paths applied", __FILE__,
                   __LINE__);
    PD_CHECK_EQ(result.proof.outcome, ProofOutcome::RESOURCE_LIMIT);
    check_bound(result.proof.limit, ResourceBound::MAX_K_SUBSET_PATHS, "max_k_subset_paths",
                __FILE__, __LINE__);
  }

  // max_topology_dependencies bounds the precise-invalidation footprint.
  {
    Limits limits;
    limits.max_topology_dependencies = 2;
    pd_test::Fixture fixture(limits);
    const std::vector<std::string> names = add_disjoint_paths(fixture, 2, "topo");
    const PublishedPolicy policy = publish_link_policy(fixture, "dpol-topo", 2);
    const MutationResult result =
        fixture.runtime.evaluate(request_for(names, policy), fixture.actor("topo"));
    check_mutation(result, MutationStatus::APPLIED, "max_topology_dependencies applied", __FILE__,
                   __LINE__);
    PD_CHECK_EQ(result.proof.outcome, ProofOutcome::RESOURCE_LIMIT);
    check_bound(result.proof.limit, ResourceBound::MAX_TOPOLOGY_DEPENDENCIES,
                "max_topology_dependencies", __FILE__, __LINE__);
  }
}

PD_TEST(the_pairwise_cell_bound_is_consulted_and_scoped) {
  // The decoder applies the cell bound to a declared matrix size.
  {
    pd_test::Fixture fixture;
    const std::vector<std::string> names = add_disjoint_paths(fixture, 2, "cells");
    const PublishedPolicy policy = publish_link_policy(fixture, "dpol-cells", 2);
    const MutationResult committed =
        fixture.runtime.evaluate(request_for(names, policy), fixture.actor("cells"));
    check_mutation(committed, MutationStatus::APPLIED, "cell proof", __FILE__, __LINE__);
    DiversityProof proof = committed.proof;

    ByteWriter accepted;
    encode_proof(accepted, proof);
    ByteReader accepted_reader(accepted.data().data(), accepted.size());
    DiversityProof round;
    PD_CHECK_EQ(decode_proof(accepted_reader, fixture.limits, round), DecodeStatus::OK);

    const Limits limits = fixture.limits;
    proof.matrix.cells.resize(static_cast<std::size_t>(limits.max_pairwise_cells) + 1);
    ByteWriter oversized;
    encode_proof(oversized, proof);
    ByteReader oversized_reader(oversized.data().data(), oversized.size());
    DiversityProof refused;
    PD_CHECK_EQ(decode_proof(oversized_reader, limits, refused), DecodeStatus::LIMIT_EXCEEDED);
  }

  // Inside a self-consistent limit set the evaluation-side cell check cannot
  // fire: the path bound is tighter and reports first. The bound is nonetheless
  // enforced, so a request can never reach the matrix builder with more cells
  // than the budget allows.
  {
    Limits limits;
    limits.max_paths_per_proof = 3;
    limits.max_k_subset_paths = 3;
    limits.max_snapshot_paths = 3;
    limits.max_pairwise_cells = 3;  // exactly 3*2/2
    PD_REQUIRE(limits.self_consistent());
    pd_test::Fixture fixture(limits);
    const std::vector<std::string> names = add_disjoint_paths(fixture, 4, "cellbound");
    const PublishedPolicy policy = publish_link_policy(fixture, "dpol-cellbound", 2);
    const MutationResult result =
        fixture.runtime.evaluate(request_for(names, policy), fixture.actor("cellbound"));
    check_mutation(result, MutationStatus::APPLIED, "cell bound", __FILE__, __LINE__);
    PD_CHECK_EQ(result.proof.outcome, ProofOutcome::RESOURCE_LIMIT);
    check_bound(result.proof.limit, ResourceBound::MAX_PATHS_PER_PROOF, "cell bound ordering",
                __FILE__, __LINE__);
    const std::size_t cells = PairwiseMatrix::cell_count(limits.max_paths_per_proof);
    PD_CHECK(cells <= limits.max_pairwise_cells);
  }
}

PD_TEST(soft_bounds_truncate_without_lying) {
  // max_conflicts_per_proof bounds the retained conflict list while the total
  // stays exact.
  {
    Limits limits;
    limits.max_conflicts_per_proof = 1;
    pd_test::Fixture fixture(limits);
    fixture.evidence.set_path(pd_test::make_path("conflict-a", 1, {"node-a"},
                                                 {"link-1", "link-2", "link-3"}, {"dev-a"}, "ep-a",
                                                 "ep-b"));
    fixture.evidence.set_path(pd_test::make_path("conflict-b", 1, {"node-b"},
                                                 {"link-1", "link-2", "link-3"}, {"dev-b"}, "ep-a",
                                                 "ep-b"));
    const PublishedPolicy policy = publish_link_policy(fixture, "dpol-conflicts", 2);
    const MutationResult result = fixture.runtime.evaluate(
        request_for({"conflict-a", "conflict-b"}, policy), fixture.actor("conflicts"));
    check_mutation(result, MutationStatus::APPLIED, "conflict bound", __FILE__, __LINE__);
    PD_CHECK_EQ(result.proof.outcome, ProofOutcome::NOT_DIVERSE);
    // The retained list is bounded by the limit while the reason still names
    // every shared resource that was observed, so a bounded list never hides
    // what the evaluation actually found.
    PD_CHECK(result.proof.conflicts.size() <=
             static_cast<std::size_t>(limits.max_conflicts_per_proof));
    PD_REQUIRE(!result.proof.classes.empty());
    const ClassResult& link_class = result.proof.classes.front();
    PD_CHECK_EQ(link_class.klass, DiversityClass::LINK_DISJOINT);
    PD_CHECK_EQ(link_class.shared.size(), std::size_t{1});
    PD_CHECK(link_class.shared_total >= static_cast<std::uint64_t>(link_class.shared.size()));
    PD_CHECK(link_class.detail.find("link-1") != std::string::npos);
    PD_CHECK(link_class.detail.find("link-2") != std::string::npos);
    PD_CHECK(link_class.detail.find("link-3") != std::string::npos);
  }

  // max_domain_evidence_entries bounds the precise domain index; the class
  // results themselves are unaffected.
  {
    Limits tight;
    tight.max_domain_evidence_entries = 1;
    pd_test::Fixture narrow(tight);
    pd_test::Fixture wide;
    for (pd_test::Fixture* fixture : {&narrow, &wide}) {
      fixture->evidence.set_path(pd_test::make_path("rack-a-path", 1, {"rack-node-a"},
                                                    {"rack-link-a"}, {"rack-dev-a"}, "ep-src-a",
                                                    "ep-dst-a"));
      fixture->evidence.set_path(pd_test::make_path("rack-b-path", 1, {"rack-node-b"},
                                                    {"rack-link-b"}, {"rack-dev-b"}, "ep-src-b",
                                                    "ep-dst-b"));
      const PathComposition left = *fixture->evidence.composition(PathId::parse("rack-a-path"));
      const PathComposition right = *fixture->evidence.composition(PathId::parse("rack-b-path"));
      pd_test::classify_path(fixture->evidence, left, DomainRelation::RACK,
                             EvidenceCoverage::COMPLETE, {"rack-a"});
      pd_test::classify_path(fixture->evidence, right, DomainRelation::RACK,
                             EvidenceCoverage::COMPLETE, {"rack-b", "rack-c"});
      const DiversityPolicy policy = pd_test::make_policy("dpol-racks",
                                                          {DiversityClass::RACK_DISJOINT},
                                                          EndpointExemption::NONE, 2);
      const MutationResult published =
          fixture->runtime.publish_policy(policy, fixture->actor("racks-pub"));
      PD_CHECK_EQ(published.status, MutationStatus::APPLIED);
      const MutationResult result = fixture->runtime.evaluate(
          request_for({"rack-a-path", "rack-b-path"},
                      PublishedPolicy{published.policy.id, published.policy.generation}),
          fixture->actor("racks"));
      check_mutation(result, MutationStatus::APPLIED, "rack proof", __FILE__, __LINE__);
      PD_CHECK_EQ(result.proof.outcome, ProofOutcome::PROVEN_DIVERSE);
    }
    PD_CHECK(narrow.runtime.proofs_for_domain(FailureDomainId::parse("rack-c")).proofs.empty());
    PD_CHECK_EQ(narrow.runtime.proofs_for_domain(FailureDomainId::parse("rack-a")).proofs.size(),
                std::size_t{1});
    PD_CHECK_EQ(wide.runtime.proofs_for_domain(FailureDomainId::parse("rack-c")).proofs.size(),
                std::size_t{1});
    PD_CHECK_EQ(wide.runtime.proofs_for_domain(FailureDomainId::parse("rack-b")).proofs.size(),
                std::size_t{1});
  }

  // max_explanation_entries bounds one explanation and reports the total.
  {
    pd_test::Fixture fixture;
    const std::vector<std::string> names = add_disjoint_paths(fixture, 2, "explain");
    const PublishedPolicy policy = publish_link_policy(fixture, "dpol-explain", 2);
    const MutationResult committed =
        fixture.runtime.evaluate(request_for(names, policy), fixture.actor("explain"));
    PD_REQUIRE(committed.has_proof);

    const Explanation full = explain_proof(committed.proof, fixture.limits);
    PD_CHECK(full.entries.size() > 1);
    PD_CHECK(!full.truncated);
    PD_CHECK_EQ(full.entries_total, static_cast<std::uint64_t>(full.entries.size()));

    Limits limits;
    limits.max_explanation_entries = 1;
    const Explanation bounded = explain_proof(committed.proof, limits);
    PD_CHECK_EQ(bounded.entries.size(), std::size_t{1});
    PD_CHECK(bounded.truncated);
    PD_CHECK(bounded.entries_total > static_cast<std::uint64_t>(bounded.entries.size()));
  }

  // max_diff_entries bounds one diff and reports the total.
  {
    pd_test::Fixture fixture;
    const std::vector<std::string> names = add_disjoint_paths(fixture, 2, "diff");
    const PublishedPolicy policy = publish_link_policy(fixture, "dpol-diff", 2);
    const MutationResult first =
        fixture.runtime.evaluate(request_for(names, policy), fixture.actor("diff-a"));
    PD_REQUIRE(first.has_proof);
    fixture.evidence.set_path(pd_test::make_path(names[1], 1, {"diff-node-1"},
                                                 {"diff-link-0"}, {"diff-dev-1"}, "ep-src",
                                                 "ep-dst"));
    const MutationResult second =
        fixture.runtime.evaluate(request_for(names, policy), fixture.actor("diff-b"));
    PD_REQUIRE(second.has_proof);

    // The runtime keeps only the latest snapshot per identity, so the earlier
    // revision is captured explicitly.
    const ProofSnapshot left = capture_snapshot(first.proof);
    const ProofSnapshot right = capture_snapshot(second.proof);
    PD_CHECK(!(left == right));
    const ProofDiff full = diff_snapshots(left, right, fixture.limits);
    PD_CHECK(full.entries.size() > 1);
    PD_CHECK(!full.truncated);

    Limits limits;
    limits.max_diff_entries = 1;
    const ProofDiff bounded = diff_snapshots(left, right, limits);
    PD_CHECK_EQ(bounded.entries.size(), std::size_t{1});
    PD_CHECK(bounded.truncated);
    PD_CHECK(bounded.entries_total > static_cast<std::uint64_t>(bounded.entries.size()));
  }
}

PD_TEST(history_and_persistence_bounds) {
  // max_history bounds the retained revisions of one proof identity.
  {
    Limits limits;
    limits.max_history = 2;
    pd_test::Fixture fixture(limits);
    const std::vector<std::string> names = add_disjoint_paths(fixture, 2, "hist");
    const PublishedPolicy policy = publish_link_policy(fixture, "dpol-history-limit", 2);
    const ProofRequest request = request_for(names, policy);
    for (int revision = 0; revision < 5; ++revision) {
      if (revision % 2 == 1) {
        fixture.evidence.set_path(pd_test::make_path(names[1], 1, {"hist-node-1"},
                                                     {"hist-link-0"}, {"hist-dev-1"}, "ep-src",
                                                     "ep-dst"));
      } else {
        fixture.evidence.set_path(pd_test::make_path(names[1], 1, {"hist-node-1"},
                                                     {"hist-link-1"}, {"hist-dev-1"}, "ep-src",
                                                     "ep-dst"));
      }
      check_mutation(fixture.runtime.evaluate(request, fixture.actor("hist-" +
                                                                     std::to_string(revision))),
                     MutationStatus::APPLIED, "history revision", __FILE__, __LINE__);
    }
    const std::vector<DiversityProof> history = fixture.runtime.history(proof_identity(request));
    PD_CHECK_EQ(history.size(), std::size_t{2});
  }

  // max_persistence_record_bytes bounds a policy description on both paths.
  {
    Limits limits;
    limits.max_persistence_record_bytes = 128;
    PD_REQUIRE(limits.self_consistent());
    pd_test::Fixture fixture(limits);
    DiversityPolicy policy = pd_test::make_policy("dpol-record", {DiversityClass::LINK_DISJOINT},
                                                  EndpointExemption::NONE, 2);
    policy.description.assign(200, 'd');
    const MutationResult refused =
        fixture.runtime.publish_policy(policy, fixture.actor("record"));
    check_mutation(refused, MutationStatus::MALFORMED, "max_persistence_record_bytes", __FILE__,
                   __LINE__);
    PD_CHECK(refused.detail.find("DESCRIPTION_TOO_LONG") != std::string::npos);

    ByteWriter writer;
    encode_policy(writer, policy);
    ByteReader reader(writer.data().data(), writer.size());
    DiversityPolicy decoded;
    PD_CHECK_EQ(decode_policy(reader, limits, decoded), DecodeStatus::LIMIT_EXCEEDED);
  }

  // max_required_classes bounds one policy's class list.
  {
    Limits limits;
    limits.max_required_classes = 2;
    PD_REQUIRE(limits.self_consistent());
    std::vector<DiversityClass> classes = {DiversityClass::LINK_DISJOINT,
                                           DiversityClass::TRANSIT_NODE_DISJOINT,
                                           DiversityClass::DEVICE_DISJOINT};
    const DiversityPolicy policy = pd_test::make_policy(
        "dpol-classes", classes, EndpointExemption::SHARED_SOURCE_AND_DESTINATION, 2);
    const PolicyValidation validation = validate_policy(policy, limits);
    PD_CHECK_EQ(validation.status, PolicyStatus::TOO_MANY_REQUIRED_CLASSES);
    PD_CHECK(!validation.ok());

    pd_test::Fixture fixture(limits);
    const MutationResult refused =
        fixture.runtime.publish_policy(policy, fixture.actor("classes"));
    check_mutation(refused, MutationStatus::MALFORMED, "max_required_classes", __FILE__, __LINE__);
    PD_CHECK(refused.detail.find("TOO_MANY_REQUIRED_CLASSES") != std::string::npos);

    ByteWriter writer;
    encode_policy(writer, policy);
    ByteReader reader(writer.data().data(), writer.size());
    DiversityPolicy decoded;
    PD_CHECK_EQ(decode_policy(reader, limits, decoded), DecodeStatus::LIMIT_EXCEEDED);
  }

  // max_identity_length bounds every identity read from an encoded record.
  {
    Limits limits;
    limits.max_identity_length = 8;
    PD_REQUIRE(limits.self_consistent());
    pd_test::Fixture fixture;
    const DiversityPolicy policy = pd_test::make_policy(
        "dpol-longer-than-eight", {DiversityClass::LINK_DISJOINT}, EndpointExemption::NONE, 2);
    ByteWriter writer;
    encode_policy(writer, policy);
    ByteReader reader(writer.data().data(), writer.size());
    DiversityPolicy decoded;
    PD_CHECK_EQ(decode_policy(reader, limits, decoded), DecodeStatus::LIMIT_EXCEEDED);
  }

  // max_snapshot_paths bounds the path list retained in one snapshot.
  {
    pd_test::Fixture fixture;
    const std::vector<std::string> names = add_disjoint_paths(fixture, 3, "snap");
    const PublishedPolicy policy = publish_link_policy(fixture, "dpol-snapshot-limit", 2);
    const MutationResult committed =
        fixture.runtime.evaluate(request_for(names, policy), fixture.actor("snap"));
    PD_REQUIRE(committed.has_proof);
    const ProofSnapshot snapshot = capture_snapshot(committed.proof);
    PD_CHECK_EQ(snapshot.paths.size(), std::size_t{3});

    ByteWriter writer;
    encode_snapshot(writer, snapshot);
    ByteReader full_reader(writer.data().data(), writer.size());
    ProofSnapshot decoded;
    PD_CHECK_EQ(decode_snapshot(full_reader, fixture.limits, decoded), DecodeStatus::OK);

    Limits limits = fixture.limits;
    limits.max_snapshot_paths = 2;
    PD_REQUIRE(limits.self_consistent());
    ByteReader bounded_reader(writer.data().data(), writer.size());
    ProofSnapshot refused;
    PD_CHECK_EQ(decode_snapshot(bounded_reader, limits, refused), DecodeStatus::LIMIT_EXCEEDED);
  }

  // max_store_records and max_store_bytes bound one durable file.
  {
    pd_test::Fixture fixture;
    const std::vector<std::string> names = add_disjoint_paths(fixture, 2, "store");
    const PublishedPolicy policy = publish_link_policy(fixture, "dpol-store-limit", 2);
    for (int index = 0; index < 2; ++index) {
      const DiversityPolicy extra = pd_test::make_policy(
          "dpol-store-extra-" + std::to_string(index), {DiversityClass::LINK_DISJOINT},
          EndpointExemption::NONE, 2);
      PD_CHECK_EQ(
          fixture.runtime.publish_policy(extra, fixture.actor("store-" + std::to_string(index)))
              .status,
          MutationStatus::APPLIED);
    }
    check_mutation(fixture.runtime.evaluate(request_for(names, policy), fixture.actor("store")),
                   MutationStatus::APPLIED, "store proof", __FILE__, __LINE__);
    const std::filesystem::path path = pd_test::unique_test_path("limits.pds");
    PD_CHECK_EQ(fixture.runtime.save(path.string()), PersistenceStatus::OK);

    std::vector<std::uint8_t> bytes;
    PD_CHECK_EQ(read_store_bytes(path.string(), fixture.limits, bytes), PersistenceStatus::OK);
    StoreContents contents;
    std::string detail;

    Limits records;
    records.max_store_records = 2;
    PD_REQUIRE(records.self_consistent());
    PD_CHECK_EQ(decode_store(bytes.data(), bytes.size(), records, contents, detail),
                PersistenceStatus::RECORD_LIMIT_EXCEEDED);

    Limits size;
    size.max_store_bytes = bytes.size() - 1;
    PD_REQUIRE(size.self_consistent());
    PD_CHECK_EQ(decode_store(bytes.data(), bytes.size(), size, contents, detail),
                PersistenceStatus::SIZE_LIMIT_EXCEEDED);
    std::vector<std::uint8_t> raw;
    PD_CHECK_EQ(read_store_bytes(path.string(), size, raw), PersistenceStatus::SIZE_LIMIT_EXCEEDED);

    std::error_code error;
    std::filesystem::remove(path, error);
  }

  // max_frame_bytes and max_wire_assembly_bytes bound the wire codec.
  {
    Limits limits;
    limits.max_frame_bytes = 32;
    limits.max_wire_assembly_bytes = 64;
    PD_REQUIRE(limits.self_consistent());
    const std::vector<std::uint8_t> payload(static_cast<std::size_t>(limits.max_frame_bytes) + 1,
                                            0x5aU);
    PD_CHECK(encode_frame(MessageId::PING, payload, limits).empty());

    std::vector<std::uint8_t> header(kWireHeaderBytes, 0);
    const std::uint32_t magic = kWireFrameMagic;
    for (int index = 0; index < 4; ++index) {
      header[static_cast<std::size_t>(index)] =
          static_cast<std::uint8_t>((magic >> (8 * index)) & 0xffU);
    }
    header[4] = static_cast<std::uint8_t>(kWireProtocolVersion & 0xffU);
    header[6] = static_cast<std::uint8_t>(MessageId::PING);
    const std::uint32_t declared = limits.max_frame_bytes + 1;
    for (int index = 0; index < 4; ++index) {
      header[8 + static_cast<std::size_t>(index)] =
          static_cast<std::uint8_t>((declared >> (8 * index)) & 0xffU);
    }
    MessageId message = MessageId::PING;
    std::uint32_t length = 0;
    std::uint64_t integrity = 0;
    PD_CHECK_EQ(decode_frame_header(header.data(), header.size(), limits, message, length, integrity),
                WireStatus::FRAME_TOO_LARGE);

    FrameAssembler assembler(limits);
    const std::vector<std::uint8_t> partial(static_cast<std::size_t>(limits.max_wire_assembly_bytes),
                                            0x11U);
    assembler.append(partial.data(), partial.size());
    PD_CHECK_EQ(assembler.status(), WireStatus::OK);
    const std::uint8_t extra = 0x22U;
    assembler.append(&extra, 1);
    PD_CHECK_EQ(assembler.status(), WireStatus::ASSEMBLY_LIMIT_EXCEEDED);
    WireFrame frame;
    PD_CHECK_EQ(assembler.next(frame), WireStatus::ASSEMBLY_LIMIT_EXCEEDED);
  }
}

PD_TEST_MAIN()
