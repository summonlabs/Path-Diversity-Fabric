// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.

// Publication authority: default deny, permanent boot fencing, epoch and scope
// enforcement, exact-replay idempotence, attempt conflicts, and the resource
// bounds that stop a registry from growing without limit.

#include <cstdint>
#include <string>
#include <vector>

#include "test_support.hpp"

namespace {

using namespace path_diversity;

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

PublisherSession make_session(const PublisherId& publisher, const WorkerBootId& boot,
                              CoordinatorEpoch epoch, const ScopeId& scope) {
  PublisherSession session;
  session.publisher = publisher;
  session.boot = boot;
  session.epoch = epoch;
  session.scope = scope;
  return session;
}

ActingAuthority make_authority(const PublisherId& publisher, const WorkerBootId& boot,
                               CoordinatorEpoch epoch, const ScopeId& scope,
                               const MutationAttemptId& attempt) {
  ActingAuthority authority;
  authority.epoch = epoch;
  authority.publisher = publisher;
  authority.boot = boot;
  authority.scope = scope;
  authority.attempt = attempt;
  return authority;
}

}  // namespace

PD_TEST(unregistered_boot_is_denied_by_default) {
  const Limits limits;
  PublicationAuthority publication(limits);
  const PublisherId publisher = mint_publisher_id("deny");
  const WorkerBootId boot = mint_worker_boot_id();
  const ActingAuthority authority =
      make_authority(publisher, boot, publication.current_epoch(), default_scope(),
                     MutationAttemptId::parse("attempt-deny"));

  PD_CHECK_EQ(publication.session_count(), std::size_t{0});
  PD_CHECK(publication.validate(authority) == AuthorityStatus::UNAUTHORIZED);
  PD_CHECK(publication.admit(authority, Digest::of("x", 1)) == AuthorityStatus::UNAUTHORIZED);
  PD_CHECK(!publication.is_fenced(boot));
  PD_CHECK(publication.fenced_boots().empty());

  // A malformed authority is MALFORMED, which is a different fact from
  // "connected but not authorized".
  ActingAuthority malformed = authority;
  malformed.attempt = MutationAttemptId();
  PD_CHECK(publication.validate(malformed) == AuthorityStatus::MALFORMED);
  malformed = authority;
  malformed.epoch = CoordinatorEpoch();
  PD_CHECK(publication.validate(malformed) == AuthorityStatus::MALFORMED);
  malformed = authority;
  malformed.publisher = PublisherId();
  PD_CHECK(publication.validate(malformed) == AuthorityStatus::MALFORMED);
  PD_CHECK(publication.register_publisher(PublisherSession()) == AuthorityStatus::MALFORMED);
  PD_CHECK(publication.fence_boot(WorkerBootId()) == AuthorityStatus::MALFORMED);
}

PD_TEST(fencing_is_permanent) {
  const Limits limits;
  PublicationAuthority publication(limits);
  const PublisherId publisher = mint_publisher_id("fence");
  const WorkerBootId boot = mint_worker_boot_id();
  const ActingAuthority authority =
      make_authority(publisher, boot, publication.current_epoch(), default_scope(),
                     MutationAttemptId::parse("attempt-fence"));

  PD_CHECK(publication.register_publisher(
               make_session(publisher, boot, publication.current_epoch(), default_scope())) ==
           AuthorityStatus::ACCEPTED);
  PD_CHECK(publication.validate(authority) == AuthorityStatus::ACCEPTED);

  PD_CHECK(publication.fence_boot(boot) == AuthorityStatus::ACCEPTED);
  PD_CHECK(publication.is_fenced(boot));
  PD_CHECK(publication.validate(authority) == AuthorityStatus::FENCED_PUBLISHER);
  PD_CHECK(publication.admit(authority, Digest::of("y", 1)) == AuthorityStatus::FENCED_PUBLISHER);
  PD_CHECK(publication.fence_boot(boot) == AuthorityStatus::ACCEPTED);
  PD_CHECK(publication.is_fenced(boot));
  PD_CHECK_EQ(publication.fenced_boots().size(), std::size_t{1});
  PD_CHECK(publication.fenced_boots().front() == boot);
  PD_CHECK(publication.register_publisher(
               make_session(publisher, boot, publication.current_epoch(), default_scope())) ==
           AuthorityStatus::FENCED_PUBLISHER);
  // The session survives as a fenced record: the fence is visible, not deleted.
  PD_CHECK_EQ(publication.session_count(), std::size_t{1});
  PD_CHECK(publication.render().find("FENCED") != std::string::npos);
}

PD_TEST(a_new_boot_permanently_fences_the_boot_it_replaces) {
  const Limits limits;
  PublicationAuthority publication(limits);
  const PublisherId publisher = mint_publisher_id("reincarnate");
  const PublisherId other_publisher = mint_publisher_id("other");
  const WorkerBootId first = mint_worker_boot_id();
  const WorkerBootId second = mint_worker_boot_id();
  const WorkerBootId third = mint_worker_boot_id();
  const CoordinatorEpoch epoch = publication.current_epoch();

  PD_CHECK(publication.register_publisher(make_session(publisher, first, epoch, default_scope())) ==
           AuthorityStatus::ACCEPTED);
  PD_CHECK(publication.register_publisher(make_session(publisher, second, epoch, default_scope())) ==
           AuthorityStatus::ACCEPTED);
  PD_CHECK(publication.is_fenced(first));
  PD_CHECK(!publication.is_fenced(second));
  PD_CHECK(publication.validate(make_authority(publisher, first, epoch, default_scope(),
                                               MutationAttemptId::parse("attempt-old"))) ==
           AuthorityStatus::FENCED_PUBLISHER);
  PD_CHECK(publication.validate(make_authority(publisher, second, epoch, default_scope(),
                                               MutationAttemptId::parse("attempt-new"))) ==
           AuthorityStatus::ACCEPTED);
  PD_CHECK(publication.register_publisher(make_session(publisher, first, epoch, default_scope())) ==
           AuthorityStatus::FENCED_PUBLISHER);

  // Registering a boot for a different publisher fences nothing.
  PD_CHECK(publication.register_publisher(
               make_session(other_publisher, third, epoch, default_scope())) ==
           AuthorityStatus::ACCEPTED);
  PD_CHECK(!publication.is_fenced(second));
  PD_CHECK(!publication.is_fenced(third));
  PD_CHECK_EQ(publication.session_count(), std::size_t{3});
}

PD_TEST(stale_epoch_and_scope_mismatch_are_refused) {
  const Limits limits;
  PublicationAuthority publication(limits);
  const PublisherId publisher = mint_publisher_id("epoch");
  const WorkerBootId boot = mint_worker_boot_id();
  const CoordinatorEpoch initial = publication.current_epoch();
  PD_CHECK(publication.register_publisher(make_session(publisher, boot, initial, default_scope())) ==
           AuthorityStatus::ACCEPTED);

  // Recovery moves the coordinator epoch forward, which is what makes an
  // otherwise well-formed older authority stale.
  const CoordinatorEpoch epoch = CoordinatorEpoch::from_value(10);
  PD_CHECK(publication.restore_epoch(CoordinatorEpoch()) == AuthorityStatus::MALFORMED);
  PD_CHECK(publication.restore_epoch(epoch) == AuthorityStatus::ACCEPTED);
  PD_CHECK_EQ(publication.current_epoch().value(), std::uint64_t{10});
  const CoordinatorEpoch older = CoordinatorEpoch::from_value(9);
  const CoordinatorEpoch newer = CoordinatorEpoch::from_value(11);
  PD_CHECK(publication.validate(make_authority(publisher, boot, older, default_scope(),
                                               MutationAttemptId::parse("attempt-old-epoch"))) ==
           AuthorityStatus::STALE_EPOCH);
  PD_CHECK(publication.admit(make_authority(publisher, boot, older, default_scope(),
                                            MutationAttemptId::parse("attempt-old-epoch")),
                             Digest::of("z", 1)) == AuthorityStatus::STALE_EPOCH);
  // An epoch that has not been restored yet is not a license to publish.
  PD_CHECK(publication.validate(make_authority(publisher, boot, newer, default_scope(),
                                               MutationAttemptId::parse("attempt-new-epoch"))) ==
           AuthorityStatus::STALE_EPOCH);
  PD_CHECK(publication.register_publisher(make_session(publisher, mint_worker_boot_id(), older,
                                                       default_scope())) ==
           AuthorityStatus::STALE_EPOCH);

  const ScopeId other_scope = ScopeId::parse("scope-other");
  PD_CHECK(publication.validate(make_authority(publisher, boot, epoch, other_scope,
                                               MutationAttemptId::parse("attempt-scope"))) ==
           AuthorityStatus::SCOPE_MISMATCH);
  PD_CHECK(publication.admit(make_authority(publisher, boot, epoch, other_scope,
                                            MutationAttemptId::parse("attempt-scope")),
                             Digest::of("z", 1)) == AuthorityStatus::SCOPE_MISMATCH);
  const PublisherId impostor = mint_publisher_id("impostor");
  PD_CHECK(publication.validate(make_authority(impostor, boot, epoch, default_scope(),
                                               MutationAttemptId::parse("attempt-impostor"))) ==
           AuthorityStatus::UNAUTHORIZED);

  // The epoch never moves backwards, and a later recovery always wins.
  PD_CHECK(publication.restore_epoch(CoordinatorEpoch::from_value(15)) == AuthorityStatus::ACCEPTED);
  PD_CHECK_EQ(publication.current_epoch().value(), std::uint64_t{15});
  PD_CHECK(publication.restore_epoch(epoch) == AuthorityStatus::STALE_EPOCH);
  PD_CHECK(publication.restore_epoch(CoordinatorEpoch::from_value(16)) == AuthorityStatus::ACCEPTED);
  PD_CHECK_EQ(publication.current_epoch().value(), std::uint64_t{16});
}

PD_TEST(exact_replay_is_idempotent_and_a_different_payload_conflicts) {
  const Limits limits;
  PublicationAuthority publication(limits);
  const PublisherId publisher = mint_publisher_id("replay");
  const WorkerBootId boot = mint_worker_boot_id();
  const CoordinatorEpoch epoch = publication.current_epoch();
  PD_CHECK(publication.register_publisher(make_session(publisher, boot, epoch, default_scope())) ==
           AuthorityStatus::ACCEPTED);

  const MutationAttemptId attempt = MutationAttemptId::parse("attempt-replay");
  const ActingAuthority authority =
      make_authority(publisher, boot, epoch, default_scope(), attempt);
  const Digest payload = Digest::of("payload-one", 11);
  const Digest other_payload = Digest::of("payload-two", 11);

  // validate() never records replay state, so it can be called repeatedly.
  PD_CHECK(publication.validate(authority) == AuthorityStatus::ACCEPTED);
  PD_CHECK(publication.validate(authority) == AuthorityStatus::ACCEPTED);
  PD_CHECK(publication.admit(authority, payload) == AuthorityStatus::ACCEPTED);
  PD_CHECK(publication.admit(authority, payload) == AuthorityStatus::IDEMPOTENT);
  PD_CHECK(publication.admit(authority, other_payload) == AuthorityStatus::ATTEMPT_CONFLICT);
  PD_CHECK(publication.admit(authority, payload) == AuthorityStatus::IDEMPOTENT);

  // A different attempt id is a different mutation.
  PD_CHECK(publication.admit(
               make_authority(publisher, boot, epoch, default_scope(),
                              MutationAttemptId::parse("attempt-replay-2")),
               payload) == AuthorityStatus::ACCEPTED);

  // A released attempt may be retried with different content.
  const MutationAttemptId retry = MutationAttemptId::parse("attempt-retry");
  PD_CHECK(publication.admit(
               make_authority(publisher, boot, epoch, default_scope(), retry), payload) ==
           AuthorityStatus::ACCEPTED);
  publication.forget_attempt(retry);
  PD_CHECK(publication.admit(
               make_authority(publisher, boot, epoch, default_scope(), retry), other_payload) ==
           AuthorityStatus::ACCEPTED);
  PD_CHECK(publication.render().find("attempts=3") != std::string::npos);
}

PD_TEST(max_publishers_and_max_attempts_are_enforced) {
  Limits limits;
  limits.max_publishers = 2;
  PublicationAuthority publication(limits);
  const CoordinatorEpoch epoch = publication.current_epoch();
  const WorkerBootId first = mint_worker_boot_id();
  const WorkerBootId second = mint_worker_boot_id();
  const WorkerBootId third = mint_worker_boot_id();

  PD_CHECK(publication.register_publisher(
               make_session(mint_publisher_id("p1"), first, epoch, default_scope())) ==
           AuthorityStatus::ACCEPTED);
  PD_CHECK(publication.register_publisher(
               make_session(mint_publisher_id("p2"), second, epoch, default_scope())) ==
           AuthorityStatus::ACCEPTED);
  PD_CHECK(publication.register_publisher(
               make_session(mint_publisher_id("p3"), third, epoch, default_scope())) ==
           AuthorityStatus::LIMIT_EXCEEDED);
  PD_CHECK_EQ(publication.session_count(), std::size_t{2});
  PD_CHECK(!publication.is_fenced(third));
  // Re-registering a boot that already holds a session does not consume another.
  PD_CHECK(publication.register_publisher(
               make_session(mint_publisher_id("p1"), first, epoch, default_scope())) ==
           AuthorityStatus::ACCEPTED);
  PD_CHECK_EQ(publication.session_count(), std::size_t{2});

  Limits attempt_limits;
  attempt_limits.max_attempts_tracked = 2;
  PublicationAuthority bounded(attempt_limits);
  const PublisherId publisher = mint_publisher_id("attempts");
  const WorkerBootId boot = mint_worker_boot_id();
  PD_CHECK(bounded.register_publisher(make_session(publisher, boot, bounded.current_epoch(),
                                                   default_scope())) == AuthorityStatus::ACCEPTED);
  PD_CHECK(bounded.admit(make_authority(publisher, boot, bounded.current_epoch(), default_scope(),
                                        MutationAttemptId::parse("a-1")),
                         Digest::of("1", 1)) == AuthorityStatus::ACCEPTED);
  PD_CHECK(bounded.admit(make_authority(publisher, boot, bounded.current_epoch(), default_scope(),
                                        MutationAttemptId::parse("a-2")),
                         Digest::of("2", 1)) == AuthorityStatus::ACCEPTED);
  PD_CHECK(bounded.admit(make_authority(publisher, boot, bounded.current_epoch(), default_scope(),
                                        MutationAttemptId::parse("a-3")),
                         Digest::of("3", 1)) == AuthorityStatus::LIMIT_EXCEEDED);
  // Replays of tracked attempts are still answered exactly.
  PD_CHECK(bounded.admit(make_authority(publisher, boot, bounded.current_epoch(), default_scope(),
                                        MutationAttemptId::parse("a-1")),
                         Digest::of("1", 1)) == AuthorityStatus::IDEMPOTENT);
  bounded.forget_attempt(MutationAttemptId::parse("a-1"));
  PD_CHECK(bounded.admit(make_authority(publisher, boot, bounded.current_epoch(), default_scope(),
                                        MutationAttemptId::parse("a-3")),
                         Digest::of("3", 1)) == AuthorityStatus::ACCEPTED);
}

PD_TEST(fresh_process_identity_is_per_call_unique) {
  const WorkerBootId first = mint_worker_boot_id();
  const WorkerBootId second = mint_worker_boot_id();
  PD_CHECK(first.valid());
  PD_CHECK(second.valid());
  PD_CHECK(!(first == second));
  PD_CHECK(first.str().rfind("boot-", 0) == std::size_t{0});
  PD_CHECK_EQ(WorkerBootId::type_name(), std::string_view("WorkerBootId"));

  const MutationAttemptId attempt_a = mint_mutation_attempt_id();
  const MutationAttemptId attempt_b = mint_mutation_attempt_id();
  PD_CHECK(attempt_a.valid());
  PD_CHECK(!(attempt_a == attempt_b));

  const PublisherId publisher_a = mint_publisher_id("label");
  const PublisherId publisher_b = mint_publisher_id("label");
  PD_CHECK(publisher_a.valid());
  PD_CHECK(!(publisher_a == publisher_b));
  PD_CHECK(publisher_a.str().rfind("pub-label-", 0) == std::size_t{0});
  PD_CHECK(mint_publisher_id("").valid());
}

PD_TEST(runtime_refuses_unregistered_scope_mismatched_and_fenced_mutations) {
  pd_test::Fixture fixture;
  two_disjoint_paths(fixture.evidence);
  const DiversityPolicy policy = simple_policy("dpol-authority-runtime");
  const ProofRequest request =
      simple_request(policy, DiversityPolicyGeneration::from_value(1));

  ActingAuthority unregistered = fixture.actor("unregistered");
  unregistered.boot = mint_worker_boot_id();
  PD_CHECK(fixture.runtime.publish_policy(policy, unregistered).status ==
           MutationStatus::UNAUTHORIZED);
  PD_CHECK(fixture.runtime.evaluate(request, unregistered).status == MutationStatus::UNAUTHORIZED);

  ActingAuthority foreign_scope = fixture.actor("scope");
  foreign_scope.scope = ScopeId::parse("scope-elsewhere");
  PD_CHECK(fixture.runtime.publish_policy(policy, foreign_scope).status ==
           MutationStatus::SCOPE_MISMATCH);

  ActingAuthority stale_epoch = fixture.actor("epoch");
  stale_epoch.epoch = CoordinatorEpoch::from_value(fixture.publication.current_epoch().value() + 3);
  PD_CHECK(fixture.runtime.publish_policy(policy, stale_epoch).status ==
           MutationStatus::STALE_EPOCH);

  ActingAuthority foreign_publisher = fixture.actor("publisher");
  foreign_publisher.publisher = mint_publisher_id("stranger");
  PD_CHECK(fixture.runtime.publish_policy(policy, foreign_publisher).status ==
           MutationStatus::UNAUTHORIZED);

  // The refusals left no state behind.
  PD_CHECK_EQ(fixture.runtime.policy_count(), std::size_t{0});
  PD_CHECK_EQ(fixture.runtime.proof_count(), std::size_t{0});

  PD_CHECK(fixture.runtime.publish_policy(policy, fixture.actor("publish")).status ==
           MutationStatus::APPLIED);
  PD_CHECK(fixture.publication.fence_boot(fixture.boot) == AuthorityStatus::ACCEPTED);
  PD_CHECK(fixture.runtime.evaluate(request, fixture.actor("fenced")).status ==
           MutationStatus::FENCED_PUBLISHER);
  PD_CHECK_EQ(fixture.runtime.proof_count(), std::size_t{0});
  PD_CHECK(fixture.runtime.stats().rejected_mutations >= std::uint64_t{5});
}

PD_TEST(runtime_exact_replay_is_idempotent_and_conflicts_are_detected) {
  pd_test::Fixture fixture;
  two_disjoint_paths(fixture.evidence);
  const DiversityPolicy policy = simple_policy("dpol-authority-replay");
  const ActingAuthority authority = fixture.actor("replay");

  const MutationResult published = fixture.runtime.publish_policy(policy, authority);
  PD_CHECK(published.status == MutationStatus::APPLIED);
  PD_CHECK(published.has_policy);
  const MutationResult replayed = fixture.runtime.publish_policy(policy, authority);
  PD_CHECK(replayed.status == MutationStatus::IDEMPOTENT);
  PD_CHECK(replayed.has_policy);
  PD_CHECK_EQ(replayed.policy.generation.value(), std::uint64_t{1});

  // The same attempt id with different content is a conflict, never a replay.
  DiversityPolicy changed = policy;
  changed.description = "different content under the same attempt identity";
  const MutationResult conflicted = fixture.runtime.publish_policy(changed, authority);
  PD_CHECK(conflicted.status == MutationStatus::ATTEMPT_CONFLICT);

  const ProofRequest request =
      simple_request(policy, fixture.runtime.policy_generation(policy.id));
  const ActingAuthority evaluation_authority = fixture.actor("evaluate");
  const MutationResult committed = fixture.runtime.evaluate(request, evaluation_authority);
  PD_CHECK(committed.status == MutationStatus::APPLIED);
  const MutationResult committed_again = fixture.runtime.evaluate(request, evaluation_authority);
  PD_CHECK(committed_again.status == MutationStatus::IDEMPOTENT);
  PD_CHECK(committed_again.has_proof);
  PD_CHECK(committed_again.proof.id == committed.proof.id);

  ProofRequest different = request;
  different.paths.pop_back();
  PD_CHECK(fixture.runtime.evaluate(different, evaluation_authority).status ==
           MutationStatus::ATTEMPT_CONFLICT);

  // A fresh identity re-evaluating the identical request is UNCHANGED: nothing
  // advanced because the semantic content did not change.
  const MutationResult unchanged = fixture.runtime.evaluate(request, fixture.actor("re-evaluate"));
  PD_CHECK(unchanged.status == MutationStatus::UNCHANGED);
  PD_CHECK_EQ(unchanged.proof.generation.value(), std::uint64_t{1});
  PD_CHECK(fixture.runtime.stats().idempotent_replays >= std::uint64_t{2});
}

PD_TEST(runtime_registry_limits_are_enforced_with_the_exact_bound) {
  Limits limits;
  limits.max_policies = 1;
  pd_test::Fixture fixture(limits);
  two_disjoint_paths(fixture.evidence);
  const DiversityPolicy first = simple_policy("dpol-limit-first");
  const DiversityPolicy second = simple_policy("dpol-limit-second");
  PD_CHECK(fixture.runtime.publish_policy(first, fixture.actor("p1")).status ==
           MutationStatus::APPLIED);
  const MutationResult limited = fixture.runtime.publish_policy(second, fixture.actor("p2"));
  PD_CHECK(limited.status == MutationStatus::LIMIT_EXCEEDED);
  PD_REQUIRE(limited.limit.has_value());
  PD_CHECK(limited.limit->bound == ResourceBound::MAX_POLICIES);
  PD_CHECK_EQ(limited.limit->observed, std::uint64_t{2});
  PD_CHECK_EQ(limited.limit->allowed, std::uint64_t{1});
  PD_CHECK_EQ(fixture.runtime.policy_count(), std::size_t{1});

  Limits proof_limits;
  proof_limits.max_proofs = 1;
  pd_test::Fixture proof_fixture(proof_limits);
  two_disjoint_paths(proof_fixture.evidence);
  const DiversityPolicy policy = simple_policy("dpol-limit-proof");
  PD_CHECK(proof_fixture.runtime.publish_policy(policy, proof_fixture.actor("publish")).status ==
           MutationStatus::APPLIED);
  const MutationResult first_proof = proof_fixture.runtime.evaluate(
      simple_request(policy, proof_fixture.runtime.policy_generation(policy.id)),
      proof_fixture.actor("e1"));
  PD_CHECK(first_proof.status == MutationStatus::APPLIED);
  ProofRequest other = simple_request(policy, proof_fixture.runtime.policy_generation(policy.id));
  other.paths[0].authority_generation = PathAuthorityGeneration::from_value(2);
  const MutationResult second_proof =
      proof_fixture.runtime.evaluate(other, proof_fixture.actor("e2"));
  PD_CHECK(second_proof.status == MutationStatus::LIMIT_EXCEEDED);
  PD_REQUIRE(second_proof.limit.has_value());
  PD_CHECK(second_proof.limit->bound == ResourceBound::MAX_PROOFS);
  PD_CHECK_EQ(proof_fixture.runtime.proof_count(), std::size_t{1});

  // The pure evaluator reports the same bound as a structured RESOURCE_LIMIT.
  Limits tiny;
  tiny.max_paths_per_proof = 2;
  tiny.max_k_subset_paths = 2;
  tiny.max_snapshot_paths = 2;
  PD_CHECK(tiny.self_consistent());
  pd_test::InMemoryEvidence evidence;
  evidence.set_path(pd_test::make_path("path-a", 1, {"n1"}, {"l1"}, {"d1"}, "h1", "h2"));
  evidence.set_path(pd_test::make_path("path-b", 1, {"n2"}, {"l2"}, {"d2"}, "h1", "h3"));
  evidence.set_path(pd_test::make_path("path-c", 1, {"n3"}, {"l3"}, {"d3"}, "h1", "h4"));
  EvaluationInputs inputs;
  inputs.authority = &evidence;
  inputs.structure = &evidence;
  inputs.domains = &evidence;
  inputs.limits = &tiny;
  ProofRequest oversized;
  oversized.policy = policy.id;
  oversized.policy_generation = policy.generation;
  oversized.paths.push_back(PathRef{PathId::parse("path-a"), PathAuthorityGeneration::from_value(1)});
  oversized.paths.push_back(PathRef{PathId::parse("path-b"), PathAuthorityGeneration::from_value(1)});
  oversized.paths.push_back(PathRef{PathId::parse("path-c"), PathAuthorityGeneration::from_value(1)});
  const EvaluationResult evaluation = evaluate_diversity(oversized, policy, inputs);
  PD_CHECK(evaluation.outcome == ProofOutcome::RESOURCE_LIMIT);
  PD_REQUIRE(evaluation.limit.has_value());
  PD_CHECK(evaluation.limit->bound == ResourceBound::MAX_PATHS_PER_PROOF);
  PD_CHECK_EQ(evaluation.limit->observed, std::uint64_t{3});
  PD_CHECK_EQ(evaluation.limit->allowed, std::uint64_t{2});
  PD_CHECK(!evaluation.proven());
}

PD_TEST_MAIN()
