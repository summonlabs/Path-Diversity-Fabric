// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
// Invalidation, watermarks and mid-proof races.
//
// Every race in this file is made deterministic by a view that changes the
// fabric at an exactly known point inside the evaluation, so the proof does not
// depend on scheduling luck.

#include <atomic>
#include <memory>
#include <vector>

#include "test_support.hpp"

using namespace path_diversity;
using pd_test::Fixture;
using pd_test::make_path;
using pd_test::make_policy;

namespace {

const ClassResult* find_class(const DiversityProof& proof, DiversityClass klass) {
  for (const ClassResult& result : proof.classes) {
    if (result.klass == klass) {
      return &result;
    }
  }
  return nullptr;
}

// Wraps the in-memory evidence and, when armed, changes the fabric at a precise
// call inside an evaluation.
class MeddlingView : public PathAuthorityView, public PathStructureView, public FailureDomainView {
 public:
  explicit MeddlingView(InMemoryEvidence& inner) : inner_(inner) {}

  enum class Trigger { NONE, TOPOLOGY_MID_PROOF, DOMAIN_MID_PROOF, PATH_AUTHORITY_MID_PROOF };

  void arm(Trigger trigger, std::uint32_t after_calls) {
    trigger_ = trigger;
    remaining_ = after_calls;
    fired_ = false;
  }

  bool fired() const { return fired_; }

  // Transparent until the trigger fires: the change is applied and the new value
  // is returned, so a reader that checks afterwards sees a different world from
  // the one the evaluation started in.
  std::optional<PathAuthorityGeneration> current_generation(const PathId& path) const override {
    if (trigger_ == Trigger::PATH_AUTHORITY_MID_PROOF && !fired_ && remaining_ == 0) {
      fired_ = true;
      inner_.set_path_authority(path, PathAuthorityGeneration::from_value(2), true);
    } else {
      tick(Trigger::PATH_AUTHORITY_MID_PROOF);
    }
    return inner_.current_generation(path);
  }

  // Removed instrumentation hook.

  bool is_authorized(const PathId& path, PathAuthorityGeneration generation) const override {
    return inner_.is_authorized(path, generation);
  }

  TopologyGeneration topology_generation() const override {
    return inner_.topology_generation();
  }

  std::optional<PathComposition> composition(const PathId& path) const override {
    std::optional<PathComposition> value = inner_.composition(path);
    if (trigger_ == Trigger::TOPOLOGY_MID_PROOF && !fired_ && remaining_ == 0) {
      fired_ = true;
      inner_.advance_topology_generation();
      if (value.has_value()) {
        PathComposition moved = *value;
        moved.topology_generation = inner_.topology_generation();
        moved.links.push_back(LinkId::parse("link-changed-mid-proof"));
        moved.canonicalize();
        inner_.set_path(moved);
      }
    }
    tick(Trigger::TOPOLOGY_MID_PROOF);
    return value;
  }

  FailureDomainGeneration generation() const override {
    const FailureDomainGeneration value = inner_.generation();
    if (trigger_ == Trigger::DOMAIN_MID_PROOF && !fired_ && remaining_ == 0) {
      fired_ = true;
      inner_.advance_failure_domain_generation();
    }
    tick(Trigger::DOMAIN_MID_PROOF);
    return value;
  }

  DomainEvidence domain_membership(const EntityRef& entity,
                                   DomainRelation relation) const override {
    return inner_.domain_membership(entity, relation);
  }

  SrlgEvidence srlg_membership(const EntityRef& entity) const override {
    return inner_.srlg_membership(entity);
  }

 private:
  // Only reads of the armed evidence surface advance the count. Sharing one
  // counter across every surface would let an unrelated read consume the arm.
  void tick(Trigger owner) const {
    if (trigger_ == owner && !fired_ && remaining_ > 0) {
      --remaining_;
    }
  }

  InMemoryEvidence& inner_;
  mutable Trigger trigger_ = Trigger::NONE;
  mutable std::uint32_t remaining_ = 0;
  mutable bool fired_ = false;
};

struct Activation {
  std::unique_ptr<InMemoryEvidence> evidence;
  std::unique_ptr<MeddlingView> view;
  std::unique_ptr<PublicationAuthority> publication;
  std::unique_ptr<DiversityRuntime> runtime;
  PublisherId publisher;
  WorkerBootId boot;
  Limits limits;

  explicit Activation(Limits configured = Limits()) : limits(configured) {
    evidence.reset(new InMemoryEvidence());
    view.reset(new MeddlingView(*evidence));
    publication.reset(new PublicationAuthority(limits));
    runtime.reset(new DiversityRuntime(*view, *view, *view, *publication, limits));
    publisher = mint_publisher_id("meddler");
    boot = mint_worker_boot_id();
    PublisherSession session;
    session.publisher = publisher;
    session.boot = boot;
    session.epoch = publication->current_epoch();
    session.scope = default_scope();
    publication->register_publisher(session);
  }

  ActingAuthority actor(const std::string& label) {
    ActingAuthority authority;
    authority.epoch = publication->current_epoch();
    authority.publisher = publisher;
    authority.boot = boot;
    authority.scope = default_scope();
    authority.attempt = MutationAttemptId::parse("attempt-" + label);
    return authority;
  }
};

}  // namespace

// ---------------------------------------------------------------------------
// Topology invalidation.
// ---------------------------------------------------------------------------
PD_TEST(topology_change_invalidates_precisely) {
  Fixture fixture;
  const PathComposition changed = make_path("path-topo-a", 1, {"node-a"}, {"link-a"}, {"sw-a"},
                                            "ep-src", "ep-dst");
  const PathComposition unrelated = make_path("path-topo-b", 1, {"node-b"}, {"link-b"}, {"sw-b"},
                                              "ep-src", "ep-dst");
  const PathComposition also_unrelated = make_path("path-topo-c", 1, {"node-c"}, {"link-c"},
                                                   {"sw-c"}, "ep-src", "ep-dst");
  fixture.evidence.set_path(changed);
  fixture.evidence.set_path(unrelated);
  fixture.evidence.set_path(also_unrelated);
  for (const PathComposition* composition : {&changed, &unrelated, &also_unrelated}) {
    pd_test::classify_path(fixture.evidence, *composition, DomainRelation::FAILURE_DOMAIN,
                           EvidenceCoverage::COMPLETE, {composition->path.str() + "-fd"});
  }
  const DiversityPolicy policy =
      make_policy("dpol-topo", {DiversityClass::LINK_DISJOINT}, 
                  EndpointExemption::SHARED_SOURCE_AND_DESTINATION, 2);
  PD_REQUIRE(fixture.runtime.publish_policy(policy, fixture.actor("publish-topo")).status ==
             MutationStatus::APPLIED);

  auto evaluate_pair = [&](const std::string& first, const std::string& second,
                           const std::string& label) {
    ProofRequest request;
    request.policy = policy.id;
    request.policy_generation = DiversityPolicyGeneration::from_value(1);
    request.paths.push_back(PathRef{PathId::parse(first), PathAuthorityGeneration::from_value(1)});
    request.paths.push_back(PathRef{PathId::parse(second), PathAuthorityGeneration::from_value(1)});
    return fixture.runtime.evaluate(request, fixture.actor(label));
  };

  const MutationResult affected =
      evaluate_pair("path-topo-a", "path-topo-b", "topo-1");
  PD_REQUIRE(affected.has_proof);
  PD_CHECK(affected.proof.lifecycle == LifecycleState::CURRENT);
  PD_CHECK(affected.proof.currentness == Currentness::CURRENT);
  PD_CHECK_EQ(affected.proof.dependencies.topology_generation.value(), std::uint64_t(1));

  // A second proof binds a different exact path set, so it has its own identity
  // and its own dependency footprint.
  const MutationResult isolated = evaluate_pair("path-topo-b", "path-topo-c", "topo-2");
  PD_REQUIRE(isolated.has_proof);
  PD_CHECK(isolated.proof.current());
  PD_CHECK(!(isolated.proof.id == affected.proof.id));

  // Topology advances and one path's exact membership changes.
  fixture.evidence.advance_topology_generation();
  // A topology generation bump re-derives every path composition; only one of
  // them actually changes membership.
  for (const PathComposition* composition : {&changed, &unrelated, &also_unrelated}) {
    PathComposition rederived = *composition;
    rederived.topology_generation = fixture.evidence.topology_generation();
    if (composition->path == changed.path) {
      rederived.links.push_back(LinkId::parse("link-a2"));
    }
    rederived.canonicalize();
    fixture.evidence.set_path(rederived);
  }

  const std::vector<DiversityProofId> demoted = fixture.runtime.demote_topology_entities(
      {EntityRef{EntityKind::LINK, "link-a"}}, fixture.evidence.topology_generation());
  PD_CHECK_EQ(demoted.size(), std::size_t(1));
  PD_CHECK(demoted.front() == affected.proof.id);

  const std::optional<DiversityProof> after = fixture.runtime.proof(affected.proof.id);
  PD_REQUIRE(after.has_value());
  PD_CHECK(after->lifecycle == LifecycleState::REVALIDATION_REQUIRED);
  PD_CHECK(after->currentness == Currentness::STALE_TOPOLOGY);
  PD_CHECK(after->outcome == ProofOutcome::PROVEN_DIVERSE);

  // The unrelated proof is untouched: precise invalidation never degrades into
  // a global invalidation.
  const std::optional<DiversityProof> unrelated_after = fixture.runtime.proof(isolated.proof.id);
  PD_REQUIRE(unrelated_after.has_value());
  PD_CHECK(unrelated_after->current());
  PD_CHECK(unrelated_after->currentness == Currentness::CURRENT);

  const DiversityRuntime::QueryResult live = fixture.runtime.current_proofs();
  bool saw_unrelated = false;
  for (const DiversityProofId& id : live.proofs) {
    PD_CHECK(!(id == affected.proof.id));
    if (id == isolated.proof.id) {
      saw_unrelated = true;
    }
  }
  PD_CHECK(saw_unrelated);

  // Re-evaluating against the new topology produces a new revision that is
  // current again.
  const MutationResult revalidated =
      fixture.runtime.revalidate(affected.proof.id, fixture.actor("topo-revalidate"));
  PD_REQUIRE(revalidated.has_proof);
  PD_CHECK(revalidated.proof.lifecycle == LifecycleState::CURRENT);
  PD_CHECK_EQ(revalidated.proof.dependencies.topology_generation.value(), std::uint64_t(2));
  PD_CHECK(revalidated.proof.generation.value() > affected.proof.generation.value());
}

// ---------------------------------------------------------------------------
// Failure-domain reclassification.
// ---------------------------------------------------------------------------
PD_TEST(failure_domain_reclassification_demotes_immediately) {
  Fixture fixture;
  const PathComposition left = make_path("path-dom-a", 1, {"node-a"}, {"link-a"}, {"sw-a"},
                                         "ep-src-a", "ep-dst-a");
  const PathComposition right = make_path("path-dom-b", 1, {"node-b"}, {"link-b"}, {"sw-b"},
                                          "ep-src-b", "ep-dst-b");
  fixture.evidence.set_path(left);
  fixture.evidence.set_path(right);
  pd_test::classify_path(fixture.evidence, left, DomainRelation::FAILURE_DOMAIN,
                         EvidenceCoverage::COMPLETE, {"fd-a"});
  pd_test::classify_path(fixture.evidence, right, DomainRelation::FAILURE_DOMAIN,
                         EvidenceCoverage::COMPLETE, {"fd-b"});
  pd_test::classify_path_srlg(fixture.evidence, left, EvidenceCoverage::COMPLETE, {"srlg-a"});
  pd_test::classify_path_srlg(fixture.evidence, right, EvidenceCoverage::COMPLETE, {"srlg-b"});

  const DiversityPolicy policy = make_policy(
      "dpol-dom", {DiversityClass::LINK_DISJOINT, DiversityClass::SHARED_RISK_GROUP_DISJOINT},
      EndpointExemption::SHARED_SOURCE_AND_DESTINATION, 2);
  PD_REQUIRE(fixture.runtime.publish_policy(policy, fixture.actor("publish-dom")).status ==
             MutationStatus::APPLIED);

  ProofRequest request;
  request.policy = policy.id;
  request.policy_generation = DiversityPolicyGeneration::from_value(1);
  request.paths.push_back(PathRef{left.path, PathAuthorityGeneration::from_value(1)});
  request.paths.push_back(PathRef{right.path, PathAuthorityGeneration::from_value(1)});
  const MutationResult result = fixture.runtime.evaluate(request, fixture.actor("eval-dom"));
  PD_REQUIRE(result.has_proof);
  PD_CHECK(result.proof.outcome == ProofOutcome::PROVEN_DIVERSE);

  const std::optional<ProofSnapshot> historical = fixture.runtime.snapshot(result.proof.id);
  PD_REQUIRE(historical.has_value());
  PD_CHECK(historical->outcome == ProofOutcome::PROVEN_DIVERSE);

  // The registry publishes a new classification that places both paths under
  // one shared-risk group.
  fixture.evidence.advance_failure_domain_generation();
  pd_test::classify_path_srlg(fixture.evidence, left, EvidenceCoverage::COMPLETE, {"srlg-shared"});
  pd_test::classify_path_srlg(fixture.evidence, right, EvidenceCoverage::COMPLETE,
                              {"srlg-shared"});
  const std::vector<DiversityProofId> demoted =
      fixture.runtime.demote_failure_domain_generation(fixture.evidence.generation());
  PD_CHECK_EQ(demoted.size(), std::size_t(1));

  const std::optional<DiversityProof> after = fixture.runtime.proof(result.proof.id);
  PD_REQUIRE(after.has_value());
  PD_CHECK(after->currentness == Currentness::STALE_FAILURE_DOMAIN);
  PD_CHECK(after->lifecycle == LifecycleState::REVALIDATION_REQUIRED);
  PD_CHECK(!after->current());
  const DiversityRuntime::QueryResult live = fixture.runtime.current_proofs();
  PD_CHECK(live.proofs.empty());

  // The stale revision still says exactly what was true at the time, and its
  // immutable snapshot is retained.
  PD_CHECK(after->outcome == ProofOutcome::PROVEN_DIVERSE);
  const std::vector<SnapshotId> snapshots = fixture.runtime.snapshot_ids(result.proof.id);
  PD_CHECK(!snapshots.empty());
  PD_CHECK(snapshots.front() == historical->id);

  // Revalidation now reports the conflict.
  const MutationResult revalidated =
      fixture.runtime.revalidate(result.proof.id, fixture.actor("dom-revalidate"));
  PD_REQUIRE(revalidated.has_proof);
  PD_CHECK(revalidated.proof.outcome == ProofOutcome::NOT_DIVERSE);
  const ClassResult* srlg = find_class(revalidated.proof, DiversityClass::SHARED_RISK_GROUP_DISJOINT);
  PD_REQUIRE(srlg != nullptr);
  PD_CHECK(srlg->outcome == ProofOutcome::NOT_DIVERSE);

  // The superseded revision is retained as history and still carries the
  // verdict that was true when it was proven.
  const std::vector<DiversityProof> history = fixture.runtime.history(result.proof.id);
  PD_REQUIRE(!history.empty());
  PD_CHECK(history.front().outcome == ProofOutcome::PROVEN_DIVERSE);
  PD_CHECK(history.front().generation.value() < revalidated.proof.generation.value());
}

// ---------------------------------------------------------------------------
// Watermarks: a change during evaluation never becomes current.
// ---------------------------------------------------------------------------
PD_TEST(topology_change_mid_proof_is_not_current) {
  Activation activation;
  const PathComposition left = make_path("path-race-a", 1, {"node-a"}, {"link-a"}, {"sw-a"},
                                         "ep-src-a", "ep-dst-a");
  const PathComposition right = make_path("path-race-b", 1, {"node-b"}, {"link-b"}, {"sw-b"},
                                          "ep-src-b", "ep-dst-b");
  activation.evidence->set_path(left);
  activation.evidence->set_path(right);
  pd_test::classify_path(*activation.evidence, left, DomainRelation::FAILURE_DOMAIN,
                         EvidenceCoverage::COMPLETE, {"fd-a"});
  pd_test::classify_path(*activation.evidence, right, DomainRelation::FAILURE_DOMAIN,
                         EvidenceCoverage::COMPLETE, {"fd-b"});
  const DiversityPolicy policy =
      make_policy("dpol-race-topo", {DiversityClass::LINK_DISJOINT},
                  EndpointExemption::SHARED_SOURCE_AND_DESTINATION, 2);
  PD_REQUIRE(activation.runtime
                 ->publish_policy(policy, activation.actor("publish-race-topo"))
                 .status == MutationStatus::APPLIED);

  ProofRequest request;
  request.policy = policy.id;
  request.policy_generation = DiversityPolicyGeneration::from_value(1);
  request.paths.push_back(PathRef{left.path, PathAuthorityGeneration::from_value(1)});
  request.paths.push_back(PathRef{right.path, PathAuthorityGeneration::from_value(1)});

  activation.view->arm(MeddlingView::Trigger::TOPOLOGY_MID_PROOF, 1);
  const MutationResult result =
      activation.runtime->evaluate(request, activation.actor("race-topo"));
  PD_CHECK(activation.view->fired());
  PD_REQUIRE(result.has_proof);
  PD_CHECK(result.status == MutationStatus::REVALIDATION_REQUIRED);
  PD_CHECK(result.proof.outcome == ProofOutcome::REVALIDATION_REQUIRED);
  PD_CHECK(result.proof.lifecycle == LifecycleState::REVALIDATION_REQUIRED);
  PD_CHECK(!result.proof.current());
  PD_CHECK(activation.runtime->stats().watermark_rejections >= 1);
}

PD_TEST(failure_domain_change_mid_proof_is_not_current) {
  Activation activation;
  const PathComposition left = make_path("path-race-c", 1, {"node-a"}, {"link-a"}, {"sw-a"},
                                         "ep-src-a", "ep-dst-a");
  const PathComposition right = make_path("path-race-d", 1, {"node-b"}, {"link-b"}, {"sw-b"},
                                          "ep-src-b", "ep-dst-b");
  activation.evidence->set_path(left);
  activation.evidence->set_path(right);
  pd_test::classify_path(*activation.evidence, left, DomainRelation::FAILURE_DOMAIN,
                         EvidenceCoverage::COMPLETE, {"fd-a"});
  pd_test::classify_path(*activation.evidence, right, DomainRelation::FAILURE_DOMAIN,
                         EvidenceCoverage::COMPLETE, {"fd-b"});
  const DiversityPolicy policy =
      make_policy("dpol-race-dom", {DiversityClass::FAILURE_DOMAIN_DISJOINT},
                  EndpointExemption::SHARED_SOURCE_AND_DESTINATION, 2);
  PD_REQUIRE(activation.runtime->publish_policy(policy, activation.actor("publish-race-dom")).status ==
             MutationStatus::APPLIED);

  ProofRequest request;
  request.policy = policy.id;
  request.policy_generation = DiversityPolicyGeneration::from_value(1);
  request.paths.push_back(PathRef{left.path, PathAuthorityGeneration::from_value(1)});
  request.paths.push_back(PathRef{right.path, PathAuthorityGeneration::from_value(1)});

  activation.view->arm(MeddlingView::Trigger::DOMAIN_MID_PROOF, 0);
  const MutationResult result = activation.runtime->evaluate(request, activation.actor("race-dom"));
  PD_CHECK(activation.view->fired());
  PD_REQUIRE(result.has_proof);
  PD_CHECK(result.proof.outcome == ProofOutcome::REVALIDATION_REQUIRED);
  PD_CHECK(!result.proof.current());
}

PD_TEST(path_authority_change_mid_proof_is_not_current) {
  Activation activation;
  const PathComposition left = make_path("path-race-e", 1, {"node-a"}, {"link-a"}, {"sw-a"},
                                         "ep-src-a", "ep-dst-a");
  const PathComposition right = make_path("path-race-f", 1, {"node-b"}, {"link-b"}, {"sw-b"},
                                          "ep-src-b", "ep-dst-b");
  activation.evidence->set_path(left);
  activation.evidence->set_path(right);
  pd_test::classify_path(*activation.evidence, left, DomainRelation::FAILURE_DOMAIN,
                         EvidenceCoverage::COMPLETE, {"fd-a"});
  pd_test::classify_path(*activation.evidence, right, DomainRelation::FAILURE_DOMAIN,
                         EvidenceCoverage::COMPLETE, {"fd-b"});
  const DiversityPolicy policy =
      make_policy("dpol-race-pa", {DiversityClass::LINK_DISJOINT},
                  EndpointExemption::SHARED_SOURCE_AND_DESTINATION, 2);
  PD_REQUIRE(activation.runtime->publish_policy(policy, activation.actor("publish-race-pa")).status ==
             MutationStatus::APPLIED);

  ProofRequest request;
  request.policy = policy.id;
  request.policy_generation = DiversityPolicyGeneration::from_value(1);
  request.paths.push_back(PathRef{left.path, PathAuthorityGeneration::from_value(1)});
  request.paths.push_back(PathRef{right.path, PathAuthorityGeneration::from_value(1)});

  // Two Path Authority reads happen during the evaluation; the change lands on
  // the re-observation the runtime performs after evaluation.
  activation.view->arm(MeddlingView::Trigger::PATH_AUTHORITY_MID_PROOF, 2);
  const MutationResult result = activation.runtime->evaluate(request, activation.actor("race-pa"));
  PD_CHECK(activation.view->fired());
  PD_REQUIRE(result.has_proof);
  PD_CHECK(result.proof.outcome == ProofOutcome::REVALIDATION_REQUIRED);
  PD_CHECK(!result.proof.current());
}

// ---------------------------------------------------------------------------
// Stale Path Authority and policy watermarks on the refresh path.
// ---------------------------------------------------------------------------
PD_TEST(refresh_currentness_demotes_only_stale_proofs) {
  Fixture fixture;
  const PathComposition left = make_path("path-ref-a", 1, {"node-a"}, {"link-a"}, {"sw-a"},
                                         "ep-src", "ep-dst");
  const PathComposition right = make_path("path-ref-b", 1, {"node-b"}, {"link-b"}, {"sw-b"},
                                          "ep-src", "ep-dst");
  const PathComposition third = make_path("path-ref-c", 1, {"node-c"}, {"link-c"}, {"sw-c"},
                                          "ep-src", "ep-dst");
  for (const PathComposition* composition : {&left, &right, &third}) {
    fixture.evidence.set_path(*composition);
    pd_test::classify_path(fixture.evidence, *composition, DomainRelation::FAILURE_DOMAIN,
                           EvidenceCoverage::COMPLETE, {composition->path.str() + "-fd"});
  }
  const DiversityPolicy policy =
      make_policy("dpol-refresh", {DiversityClass::LINK_DISJOINT},
                  EndpointExemption::SHARED_SOURCE_AND_DESTINATION, 2);
  PD_REQUIRE(fixture.runtime.publish_policy(policy, fixture.actor("publish-refresh")).status ==
             MutationStatus::APPLIED);

  auto evaluate_pair = [&](const PathId& first, const PathId& second, const std::string& label) {
    ProofRequest request;
    request.policy = policy.id;
    request.policy_generation = DiversityPolicyGeneration::from_value(1);
    request.paths.push_back(PathRef{first, PathAuthorityGeneration::from_value(1)});
    request.paths.push_back(PathRef{second, PathAuthorityGeneration::from_value(1)});
    return fixture.runtime.evaluate(request, fixture.actor(label));
  };
  const MutationResult touched = evaluate_pair(left.path, right.path, "refresh-1");
  const MutationResult untouched = evaluate_pair(right.path, third.path, "refresh-2");
  PD_REQUIRE(touched.has_proof);
  PD_REQUIRE(untouched.has_proof);

  // Path Authority advances for the left path only.
  fixture.evidence.set_path_authority(left.path, PathAuthorityGeneration::from_value(2), true);
  const std::vector<DiversityProofId> demoted = fixture.runtime.refresh_currentness();
  PD_CHECK_EQ(demoted.size(), std::size_t(1));
  PD_CHECK(demoted.front() == touched.proof.id);

  const std::optional<DiversityProof> untouched_after = fixture.runtime.proof(untouched.proof.id);
  PD_REQUIRE(untouched_after.has_value());
  PD_CHECK(untouched_after->current());
  PD_CHECK(untouched_after->currentness == Currentness::CURRENT);

  // An evaluation that still binds the stale generation is refused outright.
  ProofRequest stale;
  stale.policy = policy.id;
  stale.policy_generation = DiversityPolicyGeneration::from_value(1);
  stale.paths.push_back(PathRef{left.path, PathAuthorityGeneration::from_value(1)});
  stale.paths.push_back(PathRef{right.path, PathAuthorityGeneration::from_value(1)});
  const MutationResult refused =
      fixture.runtime.evaluate(stale, fixture.actor("refresh-stale"));
  PD_CHECK(refused.status == MutationStatus::GENERATION_CONFLICT ||
           (refused.has_proof && refused.proof.outcome == ProofOutcome::STALE_PATH_AUTHORITY));
}

PD_TEST(policy_generation_change_demotes_dependents) {
  Fixture fixture;
  const PathComposition left = make_path("path-pol-a", 1, {"node-a"}, {"link-a"}, {"sw-a"},
                                         "ep-src", "ep-dst");
  const PathComposition right = make_path("path-pol-b", 1, {"node-b"}, {"link-b"}, {"sw-b"},
                                          "ep-src", "ep-dst");
  fixture.evidence.set_path(left);
  fixture.evidence.set_path(right);
  pd_test::classify_path(fixture.evidence, left, DomainRelation::FAILURE_DOMAIN,
                         EvidenceCoverage::COMPLETE, {"fd-a"});
  pd_test::classify_path(fixture.evidence, right, DomainRelation::FAILURE_DOMAIN,
                         EvidenceCoverage::COMPLETE, {"fd-b"});
  DiversityPolicy policy = make_policy("dpol-policy-change", {DiversityClass::LINK_DISJOINT},
                                       EndpointExemption::SHARED_SOURCE_AND_DESTINATION, 2);
  PD_REQUIRE(fixture.runtime.publish_policy(policy, fixture.actor("publish-policy-1")).status ==
             MutationStatus::APPLIED);

  ProofRequest request;
  request.policy = policy.id;
  request.policy_generation = DiversityPolicyGeneration::from_value(1);
  request.paths.push_back(PathRef{left.path, PathAuthorityGeneration::from_value(1)});
  request.paths.push_back(PathRef{right.path, PathAuthorityGeneration::from_value(1)});
  const MutationResult result = fixture.runtime.evaluate(request, fixture.actor("eval-policy-1"));
  PD_REQUIRE(result.has_proof);
  PD_CHECK(result.proof.current());

  ActingAuthority publish = fixture.actor("publish-policy-2");
  publish.expected_policy_generation = DiversityPolicyGeneration::from_value(1);
  PD_REQUIRE(fixture.runtime.publish_policy(policy, publish).status == MutationStatus::APPLIED);
  PD_CHECK_EQ(fixture.runtime.policy_generation(policy.id).value(), std::uint64_t(2));

  const std::vector<DiversityProofId> demoted =
      fixture.runtime.demote_policy(policy.id, DiversityPolicyGeneration::from_value(2));
  PD_CHECK_EQ(demoted.size(), std::size_t(1));
  const std::optional<DiversityProof> after = fixture.runtime.proof(result.proof.id);
  PD_REQUIRE(after.has_value());
  PD_CHECK(after->currentness == Currentness::STALE_POLICY);
  PD_CHECK(!after->current());
}

PD_TEST_MAIN()
