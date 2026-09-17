// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.

// Worker reincarnation. A publisher boot publishes a policy and a proof, is
// fenced, and is then refused forever: re-registration fails, authority
// validation fails and every mutation it attempts is refused. A fresh boot of
// the same publisher registers and publishes normally, and only the fenced
// boot's publication is demoted.

#include "example_support.hpp"

namespace {

using namespace example;

std::vector<PathComposition> disjoint_paths() {
  std::vector<PathComposition> paths;
  paths.push_back(make_path("path-a", "node-a1", "node-d1", {"node-b"}, {"link-a1b", "link-bd1"}));
  paths.push_back(make_path("path-b", "node-a2", "node-d2", {"node-c"}, {"link-a2c", "link-cd2"}));
  return paths;
}

PolicySpec link_policy(const std::string& id) {
  PolicySpec spec;
  spec.id = id;
  spec.classes = {DiversityClass::LINK_DISJOINT};
  return spec;
}

}  // namespace

int main() {
  Reporter report("ex_worker_reincarnation");
  Harness harness;

  const WorkerBootId first_boot = harness.boot;
  const CoordinatorEpoch epoch = harness.publication.current_epoch();
  report.check_equal(harness.publication.session_count(), std::size_t{1},
                     "one publisher session is registered");

  const MutationResult published = harness.publish(link_policy("pol-boot-1"), "publish-boot-1");
  report.check_name(published.status, "APPLIED", "the first boot published a policy");
  if (!published.has_policy) {
    return report.finish();
  }
  const std::vector<PathComposition> paths = disjoint_paths();
  for (const PathComposition& composition : paths) {
    harness.evidence.set_path(composition);
  }
  const ProofRequest request = harness.request(published.policy.id, paths);
  const MutationResult committed =
      harness.runtime.evaluate(request, harness.authority("prove-boot-1"));
  report.check_name(committed.status, "APPLIED", "the first boot committed a proof");
  if (!committed.has_proof) {
    return report.finish();
  }
  const DiversityProofId first_proof = committed.proof.id;
  report.field("proof 1", first_proof.str() + "@g" +
                              std::to_string(committed.proof.generation.value()));

  report.check_name(harness.publication.fence_boot(first_boot), "ACCEPTED",
                    "the first boot was fenced");
  report.check(harness.publication.is_fenced(first_boot), "the fence is recorded");
  report.check_name(harness.publication.register_publisher(
                        publisher_session(harness.publisher, first_boot, epoch)),
                    "FENCED_PUBLISHER",
                    "a fenced boot is refused registration permanently");
  report.check_name(harness.publication.validate(harness.authority("validate-boot-1")),
                    "FENCED_PUBLISHER", "a fenced boot fails authority validation");
  const MutationResult refused =
      harness.runtime.evaluate(request, harness.authority("boot-1-after-fence"));
  report.check_name(refused.status, "FENCED_PUBLISHER",
                    "a fenced boot cannot mutate the runtime");

  const WorkerBootId second_boot = mint_worker_boot_id();
  report.check(second_boot != first_boot, "the fresh boot identity is distinct");
  report.check_name(harness.publication.register_publisher(
                        publisher_session(harness.publisher, second_boot, epoch)),
                    "ACCEPTED", "the fresh boot registered");
  report.check(!harness.publication.is_fenced(second_boot), "the fresh boot is not fenced");

  ActingAuthority acting;
  acting.epoch = epoch;
  acting.publisher = harness.publisher;
  acting.boot = second_boot;
  acting.scope = default_scope();
  acting.attempt = MutationAttemptId::parse("attempt-boot-2-policy");
  const MutationResult republished =
      harness.runtime.publish_policy(build_policy(link_policy("pol-boot-2")), acting);
  report.check_name(republished.status, "APPLIED",
                    "the fresh boot publishes under the same publisher");
  if (!republished.has_policy) {
    return report.finish();
  }

  ActingAuthority prover = acting;
  prover.attempt = MutationAttemptId::parse("attempt-boot-2-proof");
  const ProofRequest second_request = harness.request(republished.policy.id, paths);
  const MutationResult second_proof = harness.runtime.evaluate(second_request, prover);
  report.check_name(second_proof.status, "APPLIED", "the fresh boot committed a proof");
  if (!second_proof.has_proof) {
    return report.finish();
  }
  report.field("proof 2", second_proof.proof.id.str() + "@g" +
                              std::to_string(second_proof.proof.generation.value()));

  const std::vector<DiversityProofId> demoted = harness.runtime.demote_boot(first_boot);
  report.check_equal(demoted.size(), std::size_t{1},
                     "only the fenced boot's publication is demoted");
  if (!demoted.empty()) {
    report.check_equal(demoted.front(), first_proof,
                       "the demoted proof is the one the fenced boot committed");
  }
  const std::optional<DiversityProof> stale = harness.runtime.proof(first_proof);
  report.check(stale.has_value(), "the fenced boot's proof is still stored");
  if (stale.has_value()) {
    report.field("proof 1 currentness", std::string(to_string(stale->currentness)));
    report.check_name(stale->lifecycle, "REVALIDATION_REQUIRED",
                      "the fenced boot's proof demoted");
    report.check_name(stale->currentness, "FENCED_PUBLISHER",
                      "the demotion names the fenced publisher");
  }
  const std::optional<DiversityProof> live = harness.runtime.proof(second_proof.proof.id);
  report.check(live.has_value() && live->current(),
               "the fresh boot's proof is untouched by the demotion");
  report.check_equal(harness.runtime.current_proofs().total, std::uint64_t{1},
                     "exactly one proof remains current");

  return report.finish();
}
