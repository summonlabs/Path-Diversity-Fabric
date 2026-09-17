// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.

// Two paths between one endpoint pair that share no link: the runtime proves
// LINK_DISJOINT. The same policy is then evaluated against a composition that
// does share one link, so the positive result is shown not to be vacuous.

#include "example_support.hpp"

namespace {

using namespace example;

std::vector<PathComposition> primary_paths() {
  std::vector<PathComposition> paths;
  paths.push_back(make_path("path-a", "node-a", "node-d", {"node-b"}, {"link-ab", "link-bd"}));
  paths.push_back(make_path("path-b", "node-a", "node-d", {"node-c"}, {"link-ac", "link-cd"}));
  return paths;
}

const ClassResult* class_result(const EvaluationResult& result, DiversityClass klass) {
  for (const ClassResult& candidate : result.classes) {
    if (candidate.klass == klass) {
      return &candidate;
    }
  }
  return nullptr;
}

}  // namespace

int main() {
  Reporter report("ex_link_disjoint");
  Harness harness;

  const std::vector<PathComposition> paths = primary_paths();
  for (const PathComposition& composition : paths) {
    harness.evidence.set_path(composition);
  }

  PolicySpec spec;
  spec.id = "pol-link-disjoint";
  spec.classes = {DiversityClass::LINK_DISJOINT};
  const MutationResult published = harness.publish(spec, "publish-policy");
  report.check_name(published.status, "APPLIED", "the link-disjoint policy was published");
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
  report.field("paths", proof.request.paths[0].render() + " and " + proof.request.paths[1].render());
  report.field("outcome", std::string(to_string(proof.outcome)));
  for (const ClassResult& result : proof.classes) {
    report.field(std::string(to_string(result.klass)),
                 std::string(to_string(result.outcome)) + " evidence=" +
                     (result.evidence_complete ? "COMPLETE" : "INCOMPLETE") +
                     " shared=" + std::to_string(result.shared_total));
  }
  report.field("conflicts", std::to_string(proof.conflicts_total));

  report.check_name(proof.outcome, "PROVEN_DIVERSE", "LINK_DISJOINT over both paths is proven");
  report.check_name(proof.lifecycle, "CURRENT", "the committed proof is CURRENT");
  report.check(proof.current(), "the proof is current under its bound generations");
  report.check_equal(proof.classes.size(), std::size_t{1}, "exactly one class was required");
  report.check_equal(proof.classes[0].evidence_complete, true, "link evidence is complete");
  report.check_equal(proof.classes[0].shared_total, std::uint64_t{0}, "no link is shared");
  report.check_equal(proof.conflicts_total, std::uint64_t{0}, "the proof lists no conflict");
  const PairwiseCell* cell = proof.matrix.at(0, 1);
  report.check(cell != nullptr && cell->independent, "the pair is independent in the matrix");
  report.check_equal(harness.runtime.current_proofs().total, std::uint64_t{1},
                     "one proof is current");

  const std::optional<DiversityPolicy> stored = harness.runtime.policy(published.policy.id);
  if (!stored.has_value()) {
    report.check(false, "the published policy is retrievable");
    return report.finish();
  }

  // Negative control: identical structure except that path-b reuses link-bd.
  std::vector<PathComposition> altered_paths = paths;
  altered_paths[1].links.push_back(LinkId::parse("link-bd"));
  altered_paths[1].canonicalize();
  InMemoryEvidence altered;
  for (const PathComposition& composition : altered_paths) {
    altered.set_path(composition);
  }
  const Limits limits;
  const EvaluationInputs inputs{&altered, &altered, &altered, &limits};
  const EvaluationResult control = evaluate_diversity(request, *stored, inputs);
  report.field("control outcome", std::string(to_string(control.outcome)));
  report.check_name(control.outcome, "NOT_DIVERSE", "the negative control is NOT_DIVERSE");
  const ClassResult* control_class =
      class_result(control, DiversityClass::LINK_DISJOINT);
  report.check(control_class != nullptr, "the control evaluated LINK_DISJOINT");
  if (control_class != nullptr) {
    report.check_name(control_class->outcome, "NOT_DIVERSE",
                      "the control link class reports a conflict");
    report.check_equal(control_class->shared_total, std::uint64_t{1},
                       "the control shared exactly one link");
  }
  report.check(!control.conflicts.empty(), "the control names the shared resource");
  if (!control.conflicts.empty()) {
    report.field("control primary conflict", control.conflicts.front().render());
    report.check_equal(control.conflicts.front().id, std::string("link-bd"),
                       "the control names the exact shared link");
  }

  return report.finish();
}
