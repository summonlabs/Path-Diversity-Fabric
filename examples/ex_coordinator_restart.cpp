// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.

// Coordinator restart. A runtime is persisted, a brand-new PublicationAuthority
// and DiversityRuntime load the store, the coordinator epoch advances, and the
// pre-restart epoch is refused while the historical proof data survives intact.

#include <filesystem>
#include <optional>

#include "example_support.hpp"

namespace {

using namespace example;

std::vector<PathComposition> disjoint_paths() {
  std::vector<PathComposition> paths;
  paths.push_back(make_path("path-a", "node-a1", "node-d1", {"node-b"}, {"link-a1b", "link-bd1"}));
  paths.push_back(make_path("path-b", "node-a2", "node-d2", {"node-c"}, {"link-a2c", "link-cd2"}));
  return paths;
}

}  // namespace

int main() {
  Reporter report("ex_coordinator_restart");
  Harness harness;

  const std::vector<PathComposition> paths = disjoint_paths();
  for (const PathComposition& composition : paths) {
    harness.evidence.set_path(composition);
  }

  PolicySpec spec;
  spec.id = "pol-restart";
  spec.classes = {DiversityClass::LINK_DISJOINT, DiversityClass::TRANSIT_NODE_DISJOINT,
                  DiversityClass::FAILURE_DOMAIN_DISJOINT};
  spec.relations = {DomainRelation::FAILURE_DOMAIN};
  const MutationResult published = harness.publish(spec, "publish-policy");
  report.check_name(published.status, "APPLIED", "the policy was published");
  if (!published.has_policy) {
    return report.finish();
  }
  classify_path(harness.evidence, paths[0], DomainRelation::FAILURE_DOMAIN,
                EvidenceCoverage::COMPLETE, {"fd-alpha"});
  classify_path(harness.evidence, paths[1], DomainRelation::FAILURE_DOMAIN,
                EvidenceCoverage::COMPLETE, {"fd-beta"});

  const ProofRequest request = harness.request(published.policy.id, paths);
  const MutationResult committed = harness.runtime.evaluate(request, harness.authority("prove"));
  report.check_name(committed.status, "APPLIED", "the proof committed before the restart");
  if (!committed.has_proof) {
    return report.finish();
  }
  const DiversityProof original = committed.proof;
  const std::string original_digest = original.semantic_digest.hex();
  report.field("proof", original.id.str() + "@g" + std::to_string(original.generation.value()));
  report.field("bound epoch", "g" + std::to_string(original.dependencies.epoch.value()));

  const std::string store = scratch_path("ex-coordinator-restart.store");
  report.check_name(harness.runtime.save(store), "OK", "the runtime was written durably");
  std::error_code error;
  const std::uintmax_t bytes = std::filesystem::file_size(store, error);
  report.check(!error, "the durable store exists");
  report.field("store bytes", bytes);

  // A brand-new coordinator process: fresh evidence views, fresh authority,
  // fresh runtime, nothing carried over in memory.
  InMemoryEvidence restarted_evidence;
  for (const PathComposition& composition : paths) {
    restarted_evidence.set_path(composition);
  }
  classify_path(restarted_evidence, paths[0], DomainRelation::FAILURE_DOMAIN,
                EvidenceCoverage::COMPLETE, {"fd-alpha"});
  classify_path(restarted_evidence, paths[1], DomainRelation::FAILURE_DOMAIN,
                EvidenceCoverage::COMPLETE, {"fd-beta"});
  PublicationAuthority restarted_publication;
  DiversityRuntime restarted(restarted_evidence, restarted_evidence, restarted_evidence,
                             restarted_publication);
  report.check_equal(restarted.proof_count(), std::size_t{0}, "the fresh runtime starts empty");
  report.check_name(restarted.load(store), "OK", "the store loaded into the fresh runtime");
  report.check_equal(restarted_publication.current_epoch().value(), std::uint64_t{1},
                     "the coordinator epoch was restored from the store");

  const std::optional<DiversityProof> survived = restarted.proof(original.id);
  report.check(survived.has_value(), "the historical proof survived the restart");
  report.check_equal(restarted.proof_count(), std::size_t{1}, "the proof registry was restored");
  report.check_equal(restarted.policy_count(), std::size_t{1}, "the policy registry was restored");
  report.check(restarted.policy(original.request.policy).has_value(),
               "the policy the proof binds was restored");
  report.check(restarted.snapshot(original.id).has_value(),
               "an immutable snapshot of the restored proof is available");
  if (!survived.has_value()) {
    return report.finish();
  }
  report.field("restored proof", survived->id.str() + "@g" +
                                     std::to_string(survived->generation.value()));
  report.field("restored outcome", std::string(to_string(survived->outcome)));
  report.check_name(survived->outcome, "PROVEN_DIVERSE", "the restored result is unchanged");
  report.check_equal(survived->semantic_digest.hex(), original_digest,
                     "the restored proof keeps its semantic identity");
  report.check(survived->request == original.request, "the restored request is identical");
  report.check_equal(survived->generation.value(), original.generation.value(),
                     "the restored revision is identical");
  report.check_equal(survived->dependencies.epoch.value(), std::uint64_t{1},
                     "the restored revision binds the pre-restart epoch");
  report.check_name(survived->lifecycle, "CURRENT", "the restored revision is still CURRENT");

  // A restarted coordinator always comes back strictly higher.
  report.check_name(restarted_publication.restore_epoch(CoordinatorEpoch::from_value(2)),
                    "ACCEPTED", "the coordinator advanced to epoch 2");
  report.check_equal(restarted_publication.current_epoch().value(), std::uint64_t{2},
                     "epoch 2 is the current epoch");
  const WorkerBootId fresh_boot = mint_worker_boot_id();
  report.check_name(restarted_publication.register_publisher(
                        publisher_session(harness.publisher, fresh_boot,
                                          CoordinatorEpoch::from_value(2))),
                    "ACCEPTED", "a fresh worker boot registered at epoch 2");

  ActingAuthority stale;
  stale.epoch = CoordinatorEpoch::from_value(1);
  stale.publisher = harness.publisher;
  stale.boot = harness.boot;
  stale.scope = default_scope();
  stale.attempt = MutationAttemptId::parse("attempt-stale-epoch");
  const MutationResult refused = restarted.evaluate(request, stale);
  report.check_name(refused.status, "STALE_EPOCH", "the pre-restart epoch is refused");
  const std::optional<DiversityProof> after_refusal = restarted.proof(original.id);
  report.check(after_refusal.has_value() && after_refusal->generation.value() == 1,
               "the refused mutation left the stored revision untouched");

  ActingAuthority current;
  current.epoch = CoordinatorEpoch::from_value(2);
  current.publisher = harness.publisher;
  current.boot = fresh_boot;
  current.scope = default_scope();
  current.attempt = MutationAttemptId::parse("attempt-current-epoch");
  const MutationResult reproved = restarted.evaluate(request, current);
  report.check_name(reproved.status, "APPLIED", "the current epoch re-proved the same request");
  if (!reproved.has_proof) {
    return report.finish();
  }
  report.field("reproved outcome", std::string(to_string(reproved.proof.outcome)));
  report.check_name(reproved.proof.outcome, "PROVEN_DIVERSE",
                    "the restored policy still proves the same set");
  report.check_equal(reproved.proof.dependencies.epoch.value(), std::uint64_t{2},
                     "the new revision binds epoch 2");
  report.check_equal(reproved.proof.generation.value(), std::uint64_t{2},
                     "the revision advanced past the restored one");
  report.check_equal(restarted.current_proofs().total, std::uint64_t{1},
                     "one proof is current after the restart");

  return report.finish();
}
