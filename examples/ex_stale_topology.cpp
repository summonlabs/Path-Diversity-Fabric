// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.

// A current proof bound to topology generation 7. When the topology authority
// advances, the proof is demoted to REVALIDATION_REQUIRED with the exact stale
// cause while its last evaluation result stays available for audit; a
// revalidation under the new topology restores CURRENT at a new revision.

#include "example_support.hpp"

namespace {

using namespace example;

std::vector<PathComposition> paths_at(std::uint64_t topology_generation) {
  std::vector<PathComposition> paths;
  paths.push_back(make_path("path-a", "node-a1", "node-d1", {"node-b"}, {"link-a1b", "link-bd1"},
                            topology_generation));
  paths.push_back(make_path("path-b", "node-a2", "node-d2", {"node-c"}, {"link-a2c", "link-cd2"},
                            topology_generation));
  return paths;
}

}  // namespace

int main() {
  Reporter report("ex_stale_topology");
  Harness harness;
  harness.evidence.set_topology_generation(TopologyGeneration::from_value(7));

  const std::vector<PathComposition> paths = paths_at(7);
  for (const PathComposition& composition : paths) {
    harness.evidence.set_path(composition);
  }

  PolicySpec spec;
  spec.id = "pol-stale-topology";
  spec.classes = {DiversityClass::LINK_DISJOINT, DiversityClass::TRANSIT_NODE_DISJOINT};
  const MutationResult published = harness.publish(spec, "publish-policy");
  report.check_name(published.status, "APPLIED", "the policy was published");
  if (!published.has_policy) {
    return report.finish();
  }

  const ProofRequest request = harness.request(published.policy.id, paths);
  const MutationResult committed = harness.runtime.evaluate(request, harness.authority("prove"));
  report.check_name(committed.status, "APPLIED", "the proof committed");
  if (!committed.has_proof) {
    return report.finish();
  }

  const DiversityProof& proof = committed.proof;
  report.field("proof", proof.id.str() + "@g" + std::to_string(proof.generation.value()));
  report.field("outcome", std::string(to_string(proof.outcome)));
  report.field("bound topology", "g" +
                                     std::to_string(proof.dependencies.topology_generation.value()));
  report.check_name(proof.outcome, "PROVEN_DIVERSE", "the proof is proven under topology 7");
  report.check(proof.current(), "the proof is current under topology 7");
  report.check_equal(proof.dependencies.topology_generation.value(), std::uint64_t{7},
                     "the proof binds topology generation 7");

  harness.evidence.advance_topology_generation();
  report.check_equal(harness.evidence.topology_generation().value(), std::uint64_t{8},
                     "the topology authority advanced to generation 8");
  const std::vector<DiversityProofId> demoted =
      harness.runtime.demote_topology_generation(TopologyGeneration::from_value(8));
  report.check_equal(demoted.size(), std::size_t{1}, "exactly one proof was demoted");
  if (!demoted.empty()) {
    report.check_equal(demoted.front(), proof.id, "the demoted proof is the one bound to g7");
  }

  const std::optional<DiversityProof> stale = harness.runtime.proof(proof.id);
  report.check(stale.has_value(), "the proof is still stored after demotion");
  if (!stale.has_value()) {
    return report.finish();
  }
  report.field("demoted lifecycle", std::string(to_string(stale->lifecycle)));
  report.field("demoted currentness", std::string(to_string(stale->currentness)));
  report.field("demoted detail", stale->detail);
  report.check_name(stale->lifecycle, "REVALIDATION_REQUIRED",
                    "the proof demoted to REVALIDATION_REQUIRED");
  report.check_name(stale->currentness, "STALE_TOPOLOGY", "the exact stale cause is recorded");
  report.check(!stale->current(), "a demoted proof is not current");
  report.check_name(stale->outcome, "PROVEN_DIVERSE",
                    "the last evaluation result is retained for audit");
  report.check_equal(stale->generation.value(), std::uint64_t{1},
                     "a demotion does not mint a new revision");
  report.check_equal(harness.runtime.current_proofs().total, std::uint64_t{0},
                     "no proof is current after the topology advanced");

  const std::vector<PathComposition> moved = paths_at(8);
  for (const PathComposition& composition : moved) {
    harness.evidence.set_path(composition);
  }
  const MutationResult revalidated =
      harness.runtime.revalidate(proof.id, harness.authority("revalidate-at-g8"));
  report.check_name(revalidated.status, "APPLIED", "revalidation committed a new revision");
  if (!revalidated.has_proof) {
    return report.finish();
  }
  report.field("revalidated outcome", std::string(to_string(revalidated.proof.outcome)));
  report.field("revalidated bound topology",
               "g" + std::to_string(revalidated.proof.dependencies.topology_generation.value()));
  report.check_name(revalidated.proof.outcome, "PROVEN_DIVERSE",
                    "the same set is proven under topology 8");
  report.check_name(revalidated.proof.lifecycle, "CURRENT", "the proof is CURRENT again");
  report.check(revalidated.proof.current(), "the revalidated proof is current");
  report.check_equal(revalidated.proof.dependencies.topology_generation.value(), std::uint64_t{8},
                     "the new revision binds topology generation 8");
  report.check_equal(revalidated.proof.generation.value(), std::uint64_t{2},
                     "the revision advanced to generation 2");
  report.check_equal(harness.runtime.current_proofs().total, std::uint64_t{1},
                     "the proof is current again");

  return report.finish();
}
