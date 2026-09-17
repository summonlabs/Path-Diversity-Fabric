// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.

// AT_LEAST_K_INDEPENDENT with K=3 over five paths. Three of the five paths
// share one link, so no subset of four mutually independent paths exists and
// the exact maximum is three. The runtime prints the witness it verified and
// the achieved maximum instead of reducing the question to one pair.

#include "example_support.hpp"

namespace {

using namespace example;

std::vector<PathComposition> five_paths() {
  std::vector<PathComposition> paths;
  paths.push_back(make_path("path-a", "node-a1", "node-d1", {"node-b"}, {"link-a1b", "link-shared"}));
  paths.push_back(make_path("path-b", "node-a2", "node-d2", {"node-c"}, {"link-a2c", "link-shared"}));
  paths.push_back(make_path("path-c", "node-a3", "node-d3", {"node-e"}, {"link-a3e", "link-shared"}));
  paths.push_back(make_path("path-d", "node-a4", "node-d4", {"node-f"}, {"link-a4f", "link-fd4"}));
  paths.push_back(make_path("path-e", "node-a5", "node-d5", {"node-g"}, {"link-a5g", "link-gd5"}));
  return paths;
}

PolicySpec k_policy(std::uint32_t k) {
  PolicySpec spec;
  spec.id = "pol-at-least-" + std::to_string(k);
  spec.classes = {DiversityClass::LINK_DISJOINT};
  spec.semantics = SetSemantics::AT_LEAST_K_INDEPENDENT;
  spec.minimum_paths = k;
  return spec;
}

}  // namespace

int main() {
  Reporter report("ex_k_independent_subset");
  Harness harness;

  const std::vector<PathComposition> paths = five_paths();
  for (const PathComposition& composition : paths) {
    harness.evidence.set_path(composition);
  }

  const MutationResult published = harness.publish(k_policy(3), "publish-k3");
  report.check_name(published.status, "APPLIED", "the K=3 policy was published");
  if (!published.has_policy) {
    return report.finish();
  }

  const ProofRequest request = harness.request(published.policy.id, paths);
  const MutationResult committed = harness.runtime.evaluate(request, harness.authority("prove-k3"));
  report.check_name(committed.status, "APPLIED", "the K=3 proof committed");
  if (!committed.has_proof) {
    return report.finish();
  }

  const DiversityProof& proof = committed.proof;
  report.field("proof", proof.id.str() + "@g" + std::to_string(proof.generation.value()));
  report.field("outcome", std::string(to_string(proof.outcome)));
  report.field("witness", proof.witness.render());
  report.field("detail", proof.detail);
  const ConflictGraph graph = build_conflict_graph(proof.matrix);
  report.field("conflict graph",
               std::to_string(graph.path_count) + " vertices " +
                   std::to_string(graph.edge_count()) + " edges");

  report.check_name(proof.outcome, "PROVEN_DIVERSE", "a witness of three paths exists");
  report.check_equal(proof.witness.present, true, "the witness is reported for AT_LEAST_K");
  report.check_equal(proof.witness.requested_k, std::uint32_t{3}, "the requested K is 3");
  report.check_equal(proof.witness.achieved, std::uint32_t{3},
                     "the achieved maximum is exactly 3");
  report.check_equal(proof.witness.maximum_exact, true,
                     "the maximum was computed exactly, not estimated");
  report.check(proof.witness.indices == std::vector<std::uint32_t>({0, 3, 4}),
               "the witness is the lexicographically smallest maximum subset [0,3,4]");
  report.check(verify_witness(proof.matrix, proof.witness.indices),
               "the witness is independently verified against the matrix");
  report.check_equal(graph.edge_count(), std::uint64_t{3},
                     "the three shared-link paths form a triangle of conflicts");
  report.check(proof.detail.find("[0,3,4]") != std::string::npos,
               "the proof detail names the witness subset");

  const std::optional<WitnessSubset> maximum =
      maximum_independent_subset(proof.matrix, 3, harness.runtime.limits());
  report.check(maximum.has_value(), "the exact maximum subset is computable for five paths");
  if (maximum.has_value()) {
    report.check_equal(maximum->achieved, std::uint32_t{3}, "the exact maximum is 3");
    report.check(maximum->indices == std::vector<std::uint32_t>({0, 3, 4}),
                 "the exact maximum matches the proof witness");
  }

  // The same five paths under K=4: no negative claim without an exact maximum.
  const MutationResult published_four = harness.publish(k_policy(4), "publish-k4");
  report.check_name(published_four.status, "APPLIED", "the K=4 policy was published");
  if (!published_four.has_policy) {
    return report.finish();
  }
  const ProofRequest request_four = harness.request(published_four.policy.id, paths);
  const MutationResult refused =
      harness.runtime.evaluate(request_four, harness.authority("prove-k4"));
  report.check_name(refused.status, "APPLIED", "the K=4 evaluation completed");
  if (!refused.has_proof) {
    return report.finish();
  }
  report.field("k4 outcome", std::string(to_string(refused.proof.outcome)));
  report.field("k4 witness", refused.proof.witness.render());
  report.field("k4 detail", refused.proof.detail);
  report.check_name(refused.proof.outcome, "NOT_DIVERSE",
                    "K=4 is NOT_DIVERSE because the exact maximum is 3");
  report.check_equal(refused.proof.witness.achieved, std::uint32_t{3},
                     "the K=4 proof reports the same achieved maximum");

  return report.finish();
}
