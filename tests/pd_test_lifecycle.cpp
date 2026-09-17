// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.

// The full lifecycle transition table and the separation between lifecycle and
// currentness: every allowed transition succeeds, every disallowed transition
// is refused with ILLEGAL_TRANSITION, and the two terminal states never
// reactivate.

#include <cstdint>
#include <string>
#include <vector>

#include "test_support.hpp"

namespace {

using namespace path_diversity;

// A second, independent transcription of the declared rule. The production
// table is compared against this one for all 49 combinations.
bool expected_allowed(LifecycleState from, LifecycleState to) {
  if (from == to) {
    return true;
  }
  switch (from) {
    case LifecycleState::DECLARED:
      return to == LifecycleState::CURRENT || to == LifecycleState::REVALIDATION_REQUIRED ||
             to == LifecycleState::SUPERSEDED || to == LifecycleState::REVOKED ||
             to == LifecycleState::RETIRED;
    case LifecycleState::CURRENT:
      return to == LifecycleState::REVALIDATION_REQUIRED || to == LifecycleState::SUPERSEDED ||
             to == LifecycleState::REVOKED || to == LifecycleState::RETIRED ||
             to == LifecycleState::HISTORICAL;
    case LifecycleState::REVALIDATION_REQUIRED:
      return to == LifecycleState::CURRENT || to == LifecycleState::SUPERSEDED ||
             to == LifecycleState::REVOKED || to == LifecycleState::RETIRED ||
             to == LifecycleState::HISTORICAL;
    case LifecycleState::SUPERSEDED:
      return to == LifecycleState::CURRENT || to == LifecycleState::REVOKED ||
             to == LifecycleState::RETIRED || to == LifecycleState::HISTORICAL;
    case LifecycleState::HISTORICAL:
      return to == LifecycleState::CURRENT || to == LifecycleState::SUPERSEDED ||
             to == LifecycleState::REVOKED || to == LifecycleState::RETIRED;
    case LifecycleState::REVOKED:
    case LifecycleState::RETIRED:
      return false;
  }
  return false;
}

const LifecycleState kAllStates[7] = {LifecycleState::DECLARED,
                                      LifecycleState::CURRENT,
                                      LifecycleState::REVALIDATION_REQUIRED,
                                      LifecycleState::SUPERSEDED,
                                      LifecycleState::REVOKED,
                                      LifecycleState::RETIRED,
                                      LifecycleState::HISTORICAL};

void two_disjoint_paths(pd_test::InMemoryEvidence& evidence) {
  evidence.set_path(pd_test::make_path("path-a", 1, {"n1"}, {"l1"}, {"d1"}, "h1", "h2"));
  evidence.set_path(pd_test::make_path("path-b", 1, {"n2"}, {"l2"}, {"d2"}, "h1", "h3"));
}

DiversityPolicy simple_policy(const std::string& id) {
  return pd_test::make_policy(id, {DiversityClass::LINK_DISJOINT},
                              EndpointExemption::SHARED_SOURCE_AND_DESTINATION, 2);
}

ProofRequest simple_request(const DiversityPolicy& policy, DiversityPolicyGeneration generation) {
  ProofRequest request;
  request.policy = policy.id;
  request.policy_generation = generation;
  request.paths.push_back(PathRef{PathId::parse("path-a"), PathAuthorityGeneration::from_value(1)});
  request.paths.push_back(PathRef{PathId::parse("path-b"), PathAuthorityGeneration::from_value(1)});
  return request;
}

// A committed, CURRENT proof plus the runtime that owns it. The evidence must
// exist before the proof is evaluated, so the scenario is built in the body.
struct Scenario {
  explicit Scenario(const char* policy_id) : policy(simple_policy(policy_id)) {
    two_disjoint_paths(fixture.evidence);
    published = fixture.runtime.publish_policy(policy, fixture.actor("publish"));
    committed = fixture.runtime.evaluate(
        simple_request(policy, fixture.runtime.policy_generation(policy.id)),
        fixture.actor("evaluate"));
  }

  pd_test::Fixture fixture;
  DiversityPolicy policy;
  MutationResult published;
  MutationResult committed;
};

// A structure view that cannot resolve one composition, used to reach a
// MALFORMED evaluation that is still recorded as a DECLARED proof.
class HiddenComposition final : public PathStructureView {
 public:
  HiddenComposition(const PathStructureView& inner, const PathId& hidden)
      : inner_(inner), hidden_(hidden) {}

  TopologyGeneration topology_generation() const override { return inner_.topology_generation(); }

  std::optional<PathComposition> composition(const PathId& path) const override {
    if (path == hidden_) {
      return std::nullopt;
    }
    return inner_.composition(path);
  }

 private:
  const PathStructureView& inner_;
  PathId hidden_;
};

}  // namespace

PD_TEST(transition_table_matches_the_declared_rule) {
  std::size_t allowed = 0;
  for (LifecycleState from : kAllStates) {
    for (LifecycleState to : kAllStates) {
      const bool expected = expected_allowed(from, to);
      const bool observed = lifecycle_transition_allowed(from, to);
      pd_test::check(observed == expected,
                     std::string("transition ") + std::string(to_string(from)) + " -> " +
                         std::string(to_string(to)) + " observed " + (observed ? "allowed" : "refused"),
                     __FILE__, __LINE__);
      if (observed) {
        ++allowed;
      }
    }
  }
  // 7 identity transitions plus 23 distinct transitions.
  PD_CHECK_EQ(allowed, std::size_t{30});
  for (LifecycleState state : kAllStates) {
    PD_CHECK(lifecycle_transition_allowed(state, state));
  }
}

PD_TEST(terminal_states_are_terminal_and_publishability_is_exact) {
  for (LifecycleState state : kAllStates) {
    const bool terminal = lifecycle_is_terminal(state);
    PD_CHECK_EQ(terminal, state == LifecycleState::REVOKED || state == LifecycleState::RETIRED);
    if (terminal) {
      for (LifecycleState target : kAllStates) {
        if (target == state) {
          continue;
        }
        pd_test::check(!lifecycle_transition_allowed(state, target),
                       std::string("terminal ") + std::string(to_string(state)) + " reactivated to " +
                           std::string(to_string(target)),
                       __FILE__, __LINE__);
      }
    }
  }
  for (LifecycleState state : kAllStates) {
    PD_CHECK_EQ(lifecycle_is_publishable(state), state == LifecycleState::CURRENT);
  }
  PD_CHECK(lifecycle_is_publishable(LifecycleState::CURRENT));
  PD_CHECK(!lifecycle_is_publishable(LifecycleState::DECLARED));
  PD_CHECK(!lifecycle_is_publishable(LifecycleState::REVALIDATION_REQUIRED));
}

PD_TEST(currentness_for_outcome_mapping_is_total) {
  struct Mapping {
    ProofOutcome outcome;
    Currentness expected;
  };
  const Mapping mappings[11] = {
      {ProofOutcome::PROVEN_DIVERSE, Currentness::CURRENT},
      {ProofOutcome::NOT_DIVERSE, Currentness::CURRENT},
      {ProofOutcome::UNKNOWN_INCOMPLETE_EVIDENCE, Currentness::INCOMPLETE_EVIDENCE},
      {ProofOutcome::STALE_PATH_AUTHORITY, Currentness::STALE_PATH_AUTHORITY},
      {ProofOutcome::STALE_TOPOLOGY, Currentness::STALE_TOPOLOGY},
      {ProofOutcome::STALE_FAILURE_DOMAIN, Currentness::STALE_FAILURE_DOMAIN},
      {ProofOutcome::STALE_POLICY, Currentness::STALE_POLICY},
      {ProofOutcome::REVALIDATION_REQUIRED, Currentness::REVALIDATION_REQUIRED},
      // An unauthorized path is a Path Authority currentness problem; only an
      // observed boot fence produces FENCED_PUBLISHER.
      {ProofOutcome::UNAUTHORIZED, Currentness::STALE_PATH_AUTHORITY},
      {ProofOutcome::RESOURCE_LIMIT, Currentness::REVALIDATION_REQUIRED},
      {ProofOutcome::MALFORMED, Currentness::REVALIDATION_REQUIRED}};
  for (const Mapping& mapping : mappings) {
    const Currentness observed = currentness_for_outcome(mapping.outcome);
    pd_test::check(observed == mapping.expected,
                   std::string("outcome ") + std::string(to_string(mapping.outcome)) +
                       " mapped to " + std::string(to_string(observed)),
                   __FILE__, __LINE__);
  }
  PD_CHECK_EQ(to_string(currentness_for_stale_generation()), std::string_view("REVALIDATION_REQUIRED"));
  PD_CHECK(currentness_for_stale_generation() == Currentness::REVALIDATION_REQUIRED);
  for (std::uint8_t raw = 1; raw <= 9; ++raw) {
    const Currentness value = static_cast<Currentness>(raw);
    PD_CHECK(is_defined_currentness(raw));
    PD_CHECK_EQ(currentness_is_current(value), value == Currentness::CURRENT);
    const std::string_view text = to_string(value);
    PD_CHECK(!text.empty());
    PD_CHECK(text != std::string_view("UNKNOWN"));
  }
  PD_CHECK(!is_defined_currentness(0));
  PD_CHECK(!is_defined_currentness(10));
  PD_CHECK(!is_defined_currentness(255));
  PD_CHECK_EQ(to_string(Currentness::FENCED_PUBLISHER), std::string_view("FENCED_PUBLISHER"));
  PD_CHECK_EQ(to_string(Currentness::INCOMPLETE_EVIDENCE), std::string_view("INCOMPLETE_EVIDENCE"));
  for (std::uint8_t raw = 1; raw <= 7; ++raw) {
    PD_CHECK(is_defined_lifecycle_state(raw));
    PD_CHECK(to_string(static_cast<LifecycleState>(raw)) != std::string_view("UNKNOWN"));
  }
  PD_CHECK(!is_defined_lifecycle_state(0));
  PD_CHECK(!is_defined_lifecycle_state(8));
  PD_CHECK_EQ(to_string(LifecycleState::REVALIDATION_REQUIRED),
              std::string_view("REVALIDATION_REQUIRED"));
}

PD_TEST(committed_proof_is_current_and_publishable) {
  Scenario scenario("dpol-lifecycle-commit");
  PD_CHECK(scenario.published.status == MutationStatus::APPLIED);
  PD_CHECK(scenario.committed.status == MutationStatus::APPLIED);
  PD_REQUIRE(scenario.committed.has_proof);
  const DiversityProof& proof = scenario.committed.proof;
  PD_CHECK(proof.lifecycle == LifecycleState::CURRENT);
  PD_CHECK(proof.currentness == Currentness::CURRENT);
  PD_CHECK(proof.current());
  PD_CHECK(lifecycle_is_publishable(proof.lifecycle));
  PD_CHECK(proof.outcome == ProofOutcome::PROVEN_DIVERSE);
  PD_CHECK_EQ(proof.generation.value(), std::uint64_t{1});
  PD_CHECK(proof.provenance.publisher == scenario.fixture.publisher);
  PD_CHECK(proof.provenance.boot == scenario.fixture.boot);
  PD_CHECK(proof.provenance.epoch == scenario.fixture.publication.current_epoch());
  PD_CHECK(proof.dependencies.epoch == scenario.fixture.publication.current_epoch());
}

PD_TEST(every_reachable_allowed_transition_succeeds) {
  Scenario scenario("dpol-lifecycle-allowed");
  PD_REQUIRE(scenario.committed.has_proof);
  const DiversityProofId id = scenario.committed.proof.id;
  DiversityRuntime& runtime = scenario.fixture.runtime;

  // CURRENT -> HISTORICAL -> SUPERSEDED -> RETIRED.
  const MutationResult historical = runtime.mark_historical(id, scenario.fixture.actor("mh"), "audit");
  PD_CHECK(historical.status == MutationStatus::APPLIED);
  PD_CHECK(historical.proof.lifecycle == LifecycleState::HISTORICAL);
  PD_CHECK(historical.proof.currentness == Currentness::REVALIDATION_REQUIRED);
  PD_CHECK(!historical.proof.current());
  PD_CHECK(historical.proof.outcome == ProofOutcome::PROVEN_DIVERSE);

  const MutationResult superseded = runtime.supersede(id, scenario.fixture.actor("sup"));
  PD_CHECK(superseded.status == MutationStatus::APPLIED);
  PD_CHECK(superseded.proof.lifecycle == LifecycleState::SUPERSEDED);

  const MutationResult retired = runtime.retire(id, scenario.fixture.actor("ret"), "end of life");
  PD_CHECK(retired.status == MutationStatus::APPLIED);
  PD_CHECK(retired.proof.lifecycle == LifecycleState::RETIRED);
  PD_CHECK(lifecycle_is_terminal(retired.proof.lifecycle));

  // The full retained history is ordered oldest first and ends at the current
  // revision.
  const std::vector<DiversityProof> history = runtime.history(id);
  PD_CHECK_EQ(history.size(), std::size_t{3});
  PD_CHECK(history.front().lifecycle == LifecycleState::CURRENT);
  PD_CHECK(history.back().lifecycle == LifecycleState::SUPERSEDED);
}

PD_TEST(disallowed_transitions_are_refused_with_illegal_transition) {
  Scenario scenario("dpol-lifecycle-illegal");
  PD_REQUIRE(scenario.committed.has_proof);
  const DiversityProofId id = scenario.committed.proof.id;
  DiversityRuntime& runtime = scenario.fixture.runtime;

  const MutationResult revoked = runtime.revoke(id, scenario.fixture.actor("revoke"), "operator");
  PD_CHECK(revoked.status == MutationStatus::APPLIED);
  PD_CHECK(revoked.proof.lifecycle == LifecycleState::REVOKED);
  PD_CHECK(revoked.proof.currentness == Currentness::REVALIDATION_REQUIRED);
  PD_CHECK(revoked.proof.outcome == ProofOutcome::PROVEN_DIVERSE);

  const MutationResult retire_revoked = runtime.retire(id, scenario.fixture.actor("retire"), "no");
  PD_CHECK(retire_revoked.status == MutationStatus::ILLEGAL_TRANSITION);
  const MutationResult historical_revoked =
      runtime.mark_historical(id, scenario.fixture.actor("historical"), "no");
  PD_CHECK(historical_revoked.status == MutationStatus::ILLEGAL_TRANSITION);
  const MutationResult supersede_revoked = runtime.supersede(id, scenario.fixture.actor("supersede"));
  PD_CHECK(supersede_revoked.status == MutationStatus::ILLEGAL_TRANSITION);
  const MutationResult revalidate_revoked = runtime.revalidate(id, scenario.fixture.actor("reval"));
  PD_CHECK(revalidate_revoked.status == MutationStatus::ILLEGAL_TRANSITION);

  // Re-entering the same state is not a transition.
  const MutationResult revoked_again = runtime.revoke(id, scenario.fixture.actor("revoke-2"), "again");
  PD_CHECK(revoked_again.status == MutationStatus::UNCHANGED);
  PD_CHECK(revoked_again.proof.lifecycle == LifecycleState::REVOKED);

  // The refused transitions did not move the stored revision.
  const std::optional<DiversityProof> stored = runtime.proof(id);
  PD_REQUIRE(stored.has_value());
  PD_CHECK(stored->lifecycle == LifecycleState::REVOKED);
  PD_CHECK_EQ(runtime.history(id).size(), std::size_t{1});

  // An unknown proof identity is NOT_FOUND, never an implicit success.
  const MutationResult missing =
      runtime.revoke(DiversityProofId::parse("dproof-00000000000000000000000000000000"),
                     scenario.fixture.actor("missing"), "no");
  PD_CHECK(missing.status == MutationStatus::NOT_FOUND);
}

PD_TEST(refused_evaluations_keep_their_exact_reason) {
  pd_test::Fixture fixture;
  two_disjoint_paths(fixture.evidence);
  const DiversityPolicy policy = simple_policy("dpol-lifecycle-declared");
  const HiddenComposition structure(fixture.evidence, PathId::parse("path-b"));

  // The pure evaluator reports the refusal exactly and records what it observed,
  // so a caller comparing watermarks never mistakes an unread generation for a
  // moved one.
  EvaluationInputs inputs;
  inputs.authority = &fixture.evidence;
  inputs.structure = &structure;
  inputs.domains = &fixture.evidence;
  inputs.limits = &fixture.limits;
  const EvaluationResult precise =
      evaluate_diversity(simple_request(policy, DiversityPolicyGeneration::from_value(1)), policy,
                         inputs);
  PD_CHECK(precise.outcome == ProofOutcome::MALFORMED);
  PD_CHECK(precise.detail.find("no composition") != std::string::npos);
  PD_CHECK(precise.watermarks_observed);
  PD_CHECK_EQ(precise.observed_topology.value(), std::uint64_t{1});
  PD_CHECK_EQ(precise.observed_failure_domain.value(), std::uint64_t{1});

  // The runtime records the same refusal: an unusable evaluation is DECLARED, is
  // never current, and keeps the reason it was refused for.
  DiversityRuntime runtime(fixture.evidence, structure, fixture.evidence, fixture.publication,
                           fixture.limits);
  PD_CHECK(runtime.publish_policy(policy, fixture.actor("publish")).status ==
           MutationStatus::APPLIED);
  const MutationResult committed = runtime.evaluate(
      simple_request(policy, runtime.policy_generation(policy.id)), fixture.actor("evaluate"));
  PD_REQUIRE(committed.has_proof);
  PD_CHECK(committed.proof.outcome == ProofOutcome::MALFORMED);
  PD_CHECK(committed.proof.lifecycle == LifecycleState::DECLARED);
  PD_CHECK(committed.proof.currentness == Currentness::REVALIDATION_REQUIRED);
  PD_CHECK(committed.proof.detail.find("no composition") != std::string::npos);
  PD_CHECK(!committed.proof.current());
  PD_CHECK(!lifecycle_is_publishable(committed.proof.lifecycle));

  // DECLARED refuses the historical transition and accepts the table's own exits.
  const DiversityProofId id = committed.proof.id;
  PD_CHECK(runtime.mark_historical(id, fixture.actor("mh"), "no").status ==
           MutationStatus::ILLEGAL_TRANSITION);
  PD_CHECK(runtime.supersede(id, fixture.actor("supersede")).status == MutationStatus::APPLIED);
  PD_CHECK(runtime.supersede(id, fixture.actor("supersede-2")).status == MutationStatus::UNCHANGED);
  const MutationResult revoked = runtime.revoke(id, fixture.actor("revoke"), "operator");
  PD_CHECK(revoked.status == MutationStatus::APPLIED);
  PD_CHECK(revoked.proof.lifecycle == LifecycleState::REVOKED);
  PD_CHECK(revoked.proof.outcome == ProofOutcome::MALFORMED);
  PD_CHECK(runtime.retire(id, fixture.actor("retire"), "no").status ==
           MutationStatus::ILLEGAL_TRANSITION);
  PD_CHECK(runtime.mark_historical(id, fixture.actor("mh-2"), "no").status ==
           MutationStatus::ILLEGAL_TRANSITION);
}

PD_TEST(unauthorized_publication_is_declared_not_fenced) {
  pd_test::Fixture fixture;
  two_disjoint_paths(fixture.evidence);
  const DiversityPolicy policy = simple_policy("dpol-lifecycle-unauthorized");
  PD_CHECK(fixture.runtime.publish_policy(policy, fixture.actor("publish")).status ==
           MutationStatus::APPLIED);

  // Path Authority no longer authorizes one path: no proof may become current,
  // and the currentness cause is a Path Authority problem rather than a fence.
  fixture.evidence.revoke_path(PathId::parse("path-b"));
  const MutationResult committed = fixture.runtime.evaluate(
      simple_request(policy, fixture.runtime.policy_generation(policy.id)),
      fixture.actor("evaluate"));
  PD_REQUIRE(committed.has_proof);
  PD_CHECK(committed.proof.outcome == ProofOutcome::UNAUTHORIZED);
  PD_CHECK(committed.proof.lifecycle == LifecycleState::DECLARED);
  PD_CHECK(committed.proof.currentness == Currentness::STALE_PATH_AUTHORITY);
  PD_CHECK(committed.proof.detail.find("Path Authority") != std::string::npos);
  PD_CHECK(!committed.proof.current());
  PD_CHECK(!fixture.publication.is_fenced(fixture.boot));
  PD_CHECK_EQ(fixture.runtime.current_proofs().proofs.size(), std::size_t{0});
  PD_CHECK_EQ(fixture.runtime.all_proofs().proofs.size(), std::size_t{1});

  // Path Authority returning to the same generation does not resurrect it: the
  // stored revision stays DECLARED until a fresh evaluation says otherwise.
  const MutationResult revoked =
      fixture.runtime.revoke(committed.proof.id, fixture.actor("revoke"), "operator");
  PD_CHECK(revoked.status == MutationStatus::APPLIED);
  PD_CHECK(revoked.proof.lifecycle == LifecycleState::REVOKED);
  PD_CHECK(revoked.proof.currentness == Currentness::REVALIDATION_REQUIRED);
  PD_CHECK(revoked.proof.outcome == ProofOutcome::UNAUTHORIZED);
}

PD_TEST(currentness_is_a_separate_axis_from_lifecycle) {
  Scenario scenario("dpol-lifecycle-axis");
  PD_REQUIRE(scenario.committed.has_proof);
  const DiversityProof original = scenario.committed.proof;

  // A REVOKED proof can be perfectly accurate: lifecycle says what the operator
  // did, currentness says whether the proof still describes the world.
  DiversityProof revoked = original;
  revoked.lifecycle = LifecycleState::REVOKED;
  revoked.currentness = Currentness::CURRENT;
  PD_CHECK(!revoked.current());
  PD_CHECK(currentness_is_current(revoked.currentness));
  PD_CHECK(!lifecycle_is_publishable(revoked.lifecycle));
  PD_CHECK(revoked.outcome == ProofOutcome::PROVEN_DIVERSE);

  // A CURRENT proof can be stale, and a stale proof is not publishable as
  // current while its lifecycle still says CURRENT.
  DiversityProof stale = original;
  stale.lifecycle = LifecycleState::CURRENT;
  stale.currentness = Currentness::STALE_TOPOLOGY;
  PD_CHECK(!stale.current());
  PD_CHECK(!currentness_is_current(stale.currentness));
  PD_CHECK(lifecycle_is_publishable(stale.lifecycle));

  // Only the pair (CURRENT, CURRENT) is current.
  std::size_t current_combinations = 0;
  for (LifecycleState state : kAllStates) {
    for (std::uint8_t raw = 1; raw <= 9; ++raw) {
      DiversityProof candidate = original;
      candidate.lifecycle = state;
      candidate.currentness = static_cast<Currentness>(raw);
      const bool expected =
          state == LifecycleState::CURRENT && raw == static_cast<std::uint8_t>(Currentness::CURRENT);
      pd_test::check(candidate.current() == expected,
                     std::string("current() disagreed for ") + std::string(to_string(state)) + "/" +
                         std::string(to_string(candidate.currentness)),
                     __FILE__, __LINE__);
      if (candidate.current()) {
        ++current_combinations;
      }
    }
  }
  PD_CHECK_EQ(current_combinations, std::size_t{1});
}

PD_TEST(watermark_demotion_moves_lifecycle_and_currentness_together) {
  Scenario scenario("dpol-lifecycle-demote");
  PD_REQUIRE(scenario.committed.has_proof);
  const DiversityProofId id = scenario.committed.proof.id;
  DiversityRuntime& runtime = scenario.fixture.runtime;
  PD_CHECK(runtime.proof(id)->current());

  scenario.fixture.evidence.advance_topology_generation();
  const std::vector<DiversityProofId> demoted =
      runtime.demote_topology_generation(scenario.fixture.evidence.topology_generation());
  PD_CHECK_EQ(demoted.size(), std::size_t{1});
  if (!demoted.empty()) {
    PD_CHECK(demoted.front() == id);
  }
  const std::optional<DiversityProof> after = runtime.proof(id);
  PD_REQUIRE(after.has_value());
  PD_CHECK(after->lifecycle == LifecycleState::REVALIDATION_REQUIRED);
  PD_CHECK(after->currentness == Currentness::STALE_TOPOLOGY);
  PD_CHECK(!after->current());
  PD_CHECK(!lifecycle_is_publishable(after->lifecycle));

  // REVALIDATION_REQUIRED -> HISTORICAL is in the table.
  const MutationResult historical = runtime.mark_historical(id, scenario.fixture.actor("mh"), "audit");
  PD_CHECK(historical.status == MutationStatus::APPLIED);
  PD_CHECK(historical.proof.lifecycle == LifecycleState::HISTORICAL);
  const MutationResult retired = runtime.retire(id, scenario.fixture.actor("ret"), "done");
  PD_CHECK(retired.status == MutationStatus::APPLIED);
  PD_CHECK(retired.proof.lifecycle == LifecycleState::RETIRED);
  const MutationResult revoke_retired = runtime.revoke(id, scenario.fixture.actor("rev"), "no");
  PD_CHECK(revoke_retired.status == MutationStatus::ILLEGAL_TRANSITION);
}

PD_TEST_MAIN()
