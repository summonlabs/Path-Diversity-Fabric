// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.

// Snapshot identity and deterministic diffs: two captures of one proof state are
// byte-identical and share one SnapshotId, the proof identity a snapshot carries
// never moves with lifecycle while the revision identity does, every DiffKind is
// produced for the change it names, entry order is fixed, and the entry list is
// bounded by limits.max_diff_entries.

#include <cstdint>
#include <functional>
#include <iostream>
#include <string>
#include <vector>

#include "test_support.hpp"

namespace {

using namespace path_diversity;

void add_shared_paths(pd_test::InMemoryEvidence& evidence) {
  evidence.set_path(pd_test::make_path("path-a", 1, {"t1"}, {"l1", "l-shared"}, {"d1", "d-shared"},
                                       "h1", "h2"));
  evidence.set_path(pd_test::make_path("path-b", 1, {"t2"}, {"l2", "l-shared"}, {"d2", "d-shared"},
                                       "h1", "h3"));
}

void add_independent_paths(pd_test::InMemoryEvidence& evidence) {
  evidence.set_path(pd_test::make_path("path-a", 1, {"t1"}, {"l1"}, {"d1"}, "h1", "h2"));
  evidence.set_path(pd_test::make_path("path-b", 1, {"t2"}, {"l2"}, {"d2"}, "h1", "h3"));
}

DiversityPolicy two_class_policy(const char* id) {
  return pd_test::make_policy(id,
                              {DiversityClass::LINK_DISJOINT, DiversityClass::DEVICE_DISJOINT},
                              EndpointExemption::SHARED_SOURCE_AND_DESTINATION, 2);
}

DiversityPolicy link_policy(const char* id) {
  return pd_test::make_policy(id, {DiversityClass::LINK_DISJOINT},
                              EndpointExemption::SHARED_SOURCE_AND_DESTINATION, 2);
}

ProofRequest request_of(const DiversityPolicy& policy, DiversityPolicyGeneration generation) {
  ProofRequest request;
  request.policy = policy.id;
  request.policy_generation = generation;
  request.paths.push_back(PathRef{PathId::parse("path-a"), PathAuthorityGeneration::from_value(1)});
  request.paths.push_back(PathRef{PathId::parse("path-b"), PathAuthorityGeneration::from_value(1)});
  return request;
}

// A committed proof, either with two concrete conflicts or proven diverse.
struct Committed {
  explicit Committed(bool shared, Limits limits)
      : fixture(limits),
        policy(shared ? two_class_policy("dpol-snapshot-shared")
                      : link_policy("dpol-snapshot-proven")) {
    if (shared) {
      add_shared_paths(fixture.evidence);
    } else {
      add_independent_paths(fixture.evidence);
    }
    published = fixture.runtime.publish_policy(policy, fixture.actor("publish"));
    committed = fixture.runtime.evaluate(
        request_of(policy, fixture.runtime.policy_generation(policy.id)),
        fixture.actor("evaluate"));
  }

  pd_test::Fixture fixture;
  DiversityPolicy policy;
  MutationResult published;
  MutationResult committed;
};

ProofSnapshot with_change(const ProofSnapshot& base,
                          const std::function<void(ProofSnapshot&)>& change) {
  ProofSnapshot copy = base;
  change(copy);
  finalize_snapshot(copy);
  return copy;
}

bool has_kind(const ProofDiff& diff, DiffKind kind) {
  for (const DiffEntry& entry : diff.entries) {
    if (entry.kind == kind) {
      return true;
    }
  }
  return false;
}

std::vector<DiffKind> kinds_of(const ProofDiff& diff) {
  std::vector<DiffKind> kinds;
  for (const DiffEntry& entry : diff.entries) {
    kinds.push_back(entry.kind);
  }
  return kinds;
}

// Membership changes are directional; every other kind names the same change in
// both directions.
DiffKind reverse_of(DiffKind kind) {
  switch (kind) {
    case DiffKind::PATH_ADDED:
      return DiffKind::PATH_REMOVED;
    case DiffKind::PATH_REMOVED:
      return DiffKind::PATH_ADDED;
    case DiffKind::CONFLICT_APPEARED:
      return DiffKind::CONFLICT_DISAPPEARED;
    case DiffKind::CONFLICT_DISAPPEARED:
      return DiffKind::CONFLICT_APPEARED;
    default:
      return kind;
  }
}

const DiffEntry* first_of(const ProofDiff& diff, DiffKind kind) {
  for (const DiffEntry& entry : diff.entries) {
    if (entry.kind == kind) {
      return &entry;
    }
  }
  return nullptr;
}

void expect_kind(const ProofDiff& diff, DiffKind kind, const char* label) {
  if (!has_kind(diff, kind)) {
    std::cout << "  diff for " << label << " omitted " << to_string(kind) << "\n";
  }
  pd_test::check(has_kind(diff, kind),
                 std::string("diff for ") + label + " omitted " + std::string(to_string(kind)),
                 __FILE__, __LINE__);
}

}  // namespace

PD_TEST(capture_is_deterministic_and_content_addressed) {
  Committed scenario(true, Limits());
  PD_REQUIRE(scenario.committed.has_proof);
  const DiversityProof& proof = scenario.committed.proof;
  const ProofSnapshot first = capture_snapshot(proof);
  const ProofSnapshot second = capture_snapshot(proof);
  PD_CHECK(first == second);
  PD_CHECK(first.id == second.id);
  PD_CHECK(first.digest == second.digest);
  PD_CHECK(first.id.valid());
  PD_CHECK_EQ(first.id.str().rfind("dsnap-", 0), std::size_t{0});
  PD_CHECK(first.id == derived_snapshot_id(first.digest));
  PD_CHECK(first.proof == proof.id);
  PD_CHECK(first.generation == proof.generation);
  PD_CHECK(first.policy == proof.request.policy);
  PD_CHECK(first.policy_generation == proof.request.policy_generation);
  PD_CHECK(first.paths == proof.request.paths);
  PD_CHECK(first.outcome == proof.outcome);
  PD_CHECK(first.classes == proof.classes);
  PD_CHECK(first.conflicts == proof.conflicts);
  PD_CHECK(first.witness == proof.witness);
  PD_CHECK(first.dependencies == proof.dependencies);
  PD_CHECK(first.lifecycle == proof.lifecycle);
  PD_CHECK(first.currentness == proof.currentness);
  PD_CHECK(first.provenance == proof.provenance);
  PD_CHECK(snapshot_digest(first) == first.digest);

  // A tampered encoding is rewritten from content, never trusted.
  ProofSnapshot tampered = first;
  tampered.digest = Digest::of("tampered", 8);
  tampered.id = SnapshotId::parse("dsnap-deadbeef");
  finalize_snapshot(tampered);
  PD_CHECK(tampered == first);

  PD_CHECK(first.render() == second.render());
  PD_CHECK(first.render().find(first.id.str()) != std::string::npos);
  const std::optional<ProofSnapshot> stored = scenario.fixture.runtime.snapshot(proof.id);
  PD_REQUIRE(stored.has_value());
  PD_CHECK(*stored == first);
  PD_CHECK_EQ(scenario.fixture.runtime.snapshot_ids(proof.id).size(), std::size_t{1});
  PD_CHECK(scenario.fixture.runtime.snapshot_ids(proof.id).front() == first.id);
}

PD_TEST(snapshot_identity_covers_lifecycle_and_excludes_free_text) {
  Committed scenario(true, Limits());
  PD_REQUIRE(scenario.committed.has_proof);
  const ProofSnapshot base = capture_snapshot(scenario.committed.proof);

  // The proof identity a snapshot carries is stable across lifecycle changes.
  DiversityProof revoked = scenario.committed.proof;
  revoked.lifecycle = LifecycleState::REVOKED;
  const ProofSnapshot after_revoke = capture_snapshot(revoked);
  PD_CHECK(after_revoke.proof == base.proof);
  PD_CHECK(!(after_revoke.id == base.id));
  PD_CHECK(!(after_revoke.digest == base.digest));

  // The revision identity is not: lifecycle and currentness are documented
  // inputs of the snapshot digest.
  DiversityProof demoted = scenario.committed.proof;
  demoted.currentness = Currentness::STALE_TOPOLOGY;
  const ProofSnapshot after_demotion = capture_snapshot(demoted);
  PD_CHECK(after_demotion.proof == base.proof);
  PD_CHECK(!(after_demotion.id == base.id));

  // Excluded by construction: free-text detail, advisories, counters and the
  // pairwise matrix are not inputs to the snapshot digest.
  DiversityProof annotated = scenario.committed.proof;
  annotated.detail = "a different explanation of exactly the same result";
  annotated.conflicts_total += 5;
  annotated.advisories.clear();
  annotated.matrix.cells.clear();
  const ProofSnapshot after_annotation = capture_snapshot(annotated);
  PD_CHECK(after_annotation.id == base.id);
  PD_CHECK(after_annotation == base);
  PD_CHECK(after_annotation.render() == base.render());
}

PD_TEST(diff_reports_every_diff_kind_it_can_produce) {
  Committed scenario(true, Limits());
  PD_REQUIRE(scenario.committed.has_proof);
  const ProofSnapshot base = capture_snapshot(scenario.committed.proof);
  const Limits limits;
  PD_REQUIRE(!base.conflicts.empty());
  PD_REQUIRE(!base.classes.empty());

  const ProofDiff identical = diff_snapshots(base, base, limits);
  PD_CHECK(identical.empty());
  PD_CHECK(!identical.truncated);
  PD_CHECK_EQ(identical.entries_total, std::uint64_t{0});
  PD_CHECK_EQ(identical.left, base.id);
  PD_CHECK_EQ(identical.right, base.id);
  PD_CHECK(identical.render().find("(no differences)") != std::string::npos);

  struct Case {
    DiffKind kind;
    const char* label;
    std::function<void(ProofSnapshot&)> change;
  };
  const std::vector<Case> cases = {
      {DiffKind::PATH_ADDED, "path added",
       [](ProofSnapshot& s) {
         s.paths.push_back(
             PathRef{PathId::parse("path-z"), PathAuthorityGeneration::from_value(1)});
       }},
      {DiffKind::PATH_REMOVED, "path removed", [](ProofSnapshot& s) { s.paths.pop_back(); }},
      {DiffKind::POLICY_CHANGED, "policy changed",
       [](ProofSnapshot& s) { s.policy = DiversityPolicyId::parse("dpol-snapshot-other"); }},
      {DiffKind::POLICY_GENERATION_CHANGED, "policy generation changed",
       [](ProofSnapshot& s) { s.policy_generation = DiversityPolicyGeneration::from_value(2); }},
      {DiffKind::CONFLICT_APPEARED, "conflict appeared",
       [](ProofSnapshot& s) {
         SharedResource conflict;
         conflict.kind = ConflictClass::SHARED_LINK;
         conflict.relation = DomainRelation::FAILURE_DOMAIN;
         conflict.id = "l-appeared";
         conflict.paths = {0, 1};
         s.conflicts.push_back(conflict);
       }},
      {DiffKind::CONFLICT_DISAPPEARED, "conflict disappeared",
       [](ProofSnapshot& s) { s.conflicts.pop_back(); }},
      {DiffKind::EVIDENCE_COMPLETENESS_CHANGED, "completeness changed",
       [](ProofSnapshot& s) {
         s.classes.front().evidence_complete = !s.classes.front().evidence_complete;
       }},
      {DiffKind::CLASS_RESULT_CHANGED, "class result changed",
       [](ProofSnapshot& s) { s.classes.front().outcome = ProofOutcome::PROVEN_DIVERSE; }},
      {DiffKind::TOPOLOGY_GENERATION_CHANGED, "topology generation changed",
       [](ProofSnapshot& s) { s.dependencies.topology_generation = TopologyGeneration::from_value(3); }},
      {DiffKind::FAILURE_DOMAIN_GENERATION_CHANGED, "failure-domain generation changed",
       [](ProofSnapshot& s) {
         s.dependencies.failure_domain_generation = FailureDomainGeneration::from_value(3);
       }},
      {DiffKind::PATH_AUTHORITY_GENERATION_CHANGED, "path authority generation changed",
       [](ProofSnapshot& s) {
         s.paths.front().authority_generation = PathAuthorityGeneration::from_value(2);
       }},
      {DiffKind::EPOCH_CHANGED, "epoch changed",
       [](ProofSnapshot& s) { s.dependencies.epoch = CoordinatorEpoch::from_value(4); }},
      {DiffKind::PROOF_RESULT_CHANGED, "proof result changed",
       [](ProofSnapshot& s) { s.outcome = ProofOutcome::PROVEN_DIVERSE; }},
      {DiffKind::CURRENTNESS_CHANGED, "currentness changed",
       [](ProofSnapshot& s) { s.currentness = Currentness::STALE_EPOCH; }},
      {DiffKind::LIFECYCLE_CHANGED, "lifecycle changed",
       [](ProofSnapshot& s) { s.lifecycle = LifecycleState::RETIRED; }},
      {DiffKind::WITNESS_CHANGED, "witness changed",
       [](ProofSnapshot& s) {
         s.witness.present = true;
         s.witness.requested_k = 2;
         s.witness.achieved = 1;
         s.witness.maximum_exact = true;
         s.witness.indices = {0};
       }},
      {DiffKind::PROOF_GENERATION_CHANGED, "proof generation changed",
       [](ProofSnapshot& s) { s.generation = DiversityProofGeneration::from_value(2); }},
      {DiffKind::PROVENANCE_CHANGED, "provenance changed",
       [](ProofSnapshot& s) { s.provenance.publisher = PublisherId::parse("pub-snapshot-other"); }}};

  std::size_t visited = 0;
  for (const Case& item : cases) {
    const ProofSnapshot changed = with_change(base, item.change);
    pd_test::check(!(changed.id == base.id),
                   std::string("change for ") + item.label + " did not move the snapshot identity",
                   __FILE__, __LINE__);
    const ProofDiff diff = diff_snapshots(base, changed, limits);
    expect_kind(diff, item.kind, item.label);
    expect_kind(diff_snapshots(changed, base, limits), reverse_of(item.kind), item.label);
    pd_test::check(diff.left == base.id && diff.right == changed.id,
                   std::string("diff endpoints are wrong for ") + item.label, __FILE__, __LINE__);
    pd_test::check(!diff.truncated, std::string("diff truncated for ") + item.label, __FILE__,
                   __LINE__);
    pd_test::check(diff.entries_total == static_cast<std::uint64_t>(diff.entries.size()),
                   std::string("diff lost entries for ") + item.label, __FILE__, __LINE__);
    ++visited;
  }
  PD_CHECK_EQ(visited, std::size_t{18});
  PD_CHECK_EQ(kinds_of(identical).size(), std::size_t{0});
}

PD_TEST(diff_ordering_is_fixed_and_rendering_repeats) {
  Committed scenario(true, Limits());
  PD_REQUIRE(scenario.committed.has_proof);
  const ProofSnapshot base = capture_snapshot(scenario.committed.proof);
  const ProofSnapshot changed = with_change(base, [](ProofSnapshot& s) {
    s.policy = DiversityPolicyId::parse("dpol-snapshot-other");
    s.policy_generation = DiversityPolicyGeneration::from_value(2);
    s.dependencies.epoch = CoordinatorEpoch::from_value(3);
    s.outcome = ProofOutcome::PROVEN_DIVERSE;
    s.currentness = Currentness::STALE_EPOCH;
    s.lifecycle = LifecycleState::REVOKED;
    s.witness.present = true;
    s.witness.requested_k = 2;
    s.witness.achieved = 1;
    s.witness.indices = {0};
    s.provenance.publisher = PublisherId::parse("pub-snapshot-other");
  });
  const Limits limits;
  const ProofDiff diff = diff_snapshots(base, changed, limits);
  const std::vector<DiffKind> expected = {
      DiffKind::POLICY_CHANGED,       DiffKind::POLICY_GENERATION_CHANGED,
      DiffKind::EPOCH_CHANGED,        DiffKind::PROOF_RESULT_CHANGED,
      DiffKind::CURRENTNESS_CHANGED,  DiffKind::LIFECYCLE_CHANGED,
      DiffKind::WITNESS_CHANGED,      DiffKind::PROVENANCE_CHANGED};
  PD_CHECK(kinds_of(diff) == expected);
  PD_CHECK(!diff.truncated);
  PD_CHECK_EQ(diff.entries_total, static_cast<std::uint64_t>(expected.size()));
  PD_CHECK_EQ(diff.render(), diff_snapshots(base, changed, limits).render());
  PD_CHECK(diff.render().find(std::string(to_string(DiffKind::POLICY_CHANGED))) != std::string::npos);
  PD_CHECK(diff.entries.front().render().find("->") != std::string::npos);
  const DiffEntry* conflict_free = first_of(diff, DiffKind::CONFLICT_APPEARED);
  PD_CHECK(conflict_free == nullptr);
}

PD_TEST(runtime_diff_reports_changes_between_stored_revisions) {
  Committed scenario(false, Limits());
  PD_REQUIRE(scenario.committed.has_proof);
  const DiversityProofId id = scenario.committed.proof.id;
  PD_CHECK(scenario.committed.proof.outcome == ProofOutcome::PROVEN_DIVERSE);
  PD_CHECK_EQ(scenario.fixture.runtime.snapshot_ids(id).size(), std::size_t{1});

  // The topology view now serves a revised path-b that shares path-a's link.
  scenario.fixture.evidence.set_path(
      pd_test::make_path("path-b", 1, {"t2"}, {"l1"}, {"d2"}, "h1", "h3"));
  const MutationResult again = scenario.fixture.runtime.evaluate(
      request_of(scenario.policy, scenario.fixture.runtime.policy_generation(scenario.policy.id)),
      scenario.fixture.actor("re-evaluate"));
  PD_REQUIRE(again.has_proof);
  PD_CHECK(again.status == MutationStatus::APPLIED);
  PD_CHECK(again.proof.id == id);
  PD_CHECK(again.proof.outcome == ProofOutcome::NOT_DIVERSE);
  PD_CHECK_EQ(again.proof.generation.value(), std::uint64_t{2});
  const std::vector<SnapshotId> ids = scenario.fixture.runtime.snapshot_ids(id);
  PD_CHECK_EQ(ids.size(), std::size_t{2});
  PD_CHECK(!(ids[0] == ids[1]));

  const std::optional<ProofDiff> forward = scenario.fixture.runtime.diff(id, ids[0], ids[1]);
  PD_REQUIRE(forward.has_value());
  PD_CHECK(forward->left == ids[0]);
  PD_CHECK(forward->right == ids[1]);
  PD_CHECK(has_kind(*forward, DiffKind::CONFLICT_APPEARED));
  PD_CHECK(has_kind(*forward, DiffKind::PROOF_RESULT_CHANGED));
  PD_CHECK(has_kind(*forward, DiffKind::PROOF_GENERATION_CHANGED));
  const DiffEntry* appeared = first_of(*forward, DiffKind::CONFLICT_APPEARED);
  PD_REQUIRE(appeared != nullptr);
  PD_CHECK(appeared->subject.find("l1") != std::string::npos);
  PD_CHECK_EQ(appeared->before, std::string("-"));

  const std::optional<ProofDiff> backward = scenario.fixture.runtime.diff(id, ids[1], ids[0]);
  PD_REQUIRE(backward.has_value());
  PD_CHECK(has_kind(*backward, DiffKind::CONFLICT_DISAPPEARED));
  PD_CHECK(!has_kind(*backward, DiffKind::CONFLICT_APPEARED));
  const DiffEntry* forward_result = first_of(*forward, DiffKind::PROOF_RESULT_CHANGED);
  const DiffEntry* backward_result = first_of(*backward, DiffKind::PROOF_RESULT_CHANGED);
  PD_REQUIRE(forward_result != nullptr);
  PD_REQUIRE(backward_result != nullptr);
  PD_CHECK_EQ(forward_result->before, backward_result->after);
  PD_CHECK_EQ(forward_result->after, backward_result->before);
  PD_CHECK(forward->render() != backward->render());

  const DiversityProofId unknown_id =
      DiversityProofId::parse("dproof-00000000000000000000000000000000");
  const SnapshotId unknown_snapshot = SnapshotId::parse("dsnap-00000000000000000000000000000000");
  PD_CHECK(!scenario.fixture.runtime.diff(id, ids[0], unknown_snapshot).has_value());
  PD_CHECK(!scenario.fixture.runtime.diff(unknown_id, ids[0], ids[1]).has_value());
  PD_CHECK(!scenario.fixture.runtime.snapshot(unknown_id).has_value());
  PD_CHECK(scenario.fixture.runtime.snapshot_ids(unknown_id).empty());
}

PD_TEST(diff_truncation_respects_max_diff_entries) {
  Committed scenario(true, Limits());
  PD_REQUIRE(scenario.committed.has_proof);
  const ProofSnapshot base = capture_snapshot(scenario.committed.proof);
  const ProofSnapshot changed = with_change(base, [](ProofSnapshot& s) {
    s.policy = DiversityPolicyId::parse("dpol-snapshot-other");
    s.policy_generation = DiversityPolicyGeneration::from_value(2);
    s.outcome = ProofOutcome::PROVEN_DIVERSE;
    s.lifecycle = LifecycleState::REVOKED;
    s.currentness = Currentness::STALE_EPOCH;
    s.provenance.publisher = PublisherId::parse("pub-snapshot-other");
  });

  const Limits full;
  const ProofDiff complete = diff_snapshots(base, changed, full);
  PD_CHECK(!complete.truncated);
  PD_CHECK(complete.entries.size() > std::size_t{2});

  Limits bounded;
  bounded.max_diff_entries = 2;
  PD_CHECK(bounded.self_consistent());
  const ProofDiff clipped = diff_snapshots(base, changed, bounded);
  PD_CHECK(clipped.truncated);
  PD_CHECK_EQ(clipped.entries.size(), std::size_t{2});
  PD_CHECK_EQ(clipped.entries_total, complete.entries_total);
  PD_CHECK(clipped.entries.front() == complete.entries.front());
  PD_CHECK(clipped.render().find("(truncated)") != std::string::npos);
  PD_CHECK_EQ(clipped.render(), diff_snapshots(base, changed, bounded).render());

  Limits single;
  single.max_diff_entries = 1;
  const ProofDiff one = diff_snapshots(base, changed, single);
  PD_CHECK_EQ(one.entries.size(), std::size_t{1});
  PD_CHECK(one.truncated);
  PD_CHECK(one.entries.front() == complete.entries.front());
}

PD_TEST_MAIN()
