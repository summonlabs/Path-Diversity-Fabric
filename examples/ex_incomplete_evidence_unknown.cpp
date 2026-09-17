// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.

// Absence of evidence is not evidence of absence. No shared domain is known
// here, but one relevant entity has no failure-domain classification at all,
// so the proof is UNKNOWN_INCOMPLETE_EVIDENCE rather than PROVEN_DIVERSE. Once
// the authority publishes complete independent evidence, revalidation proves
// the set without a new request identity.

#include "example_support.hpp"

namespace {

using namespace example;

std::vector<PathComposition> unclassified_paths() {
  std::vector<PathComposition> paths;
  paths.push_back(make_path("path-a", "node-a1", "node-d1", {"node-b"}, {"link-a1b", "link-bd1"}));
  paths.push_back(make_path("path-b", "node-a2", "node-d2", {"node-c"}, {"link-a2c", "link-cd2"}));
  return paths;
}

const ClassResult* class_result(const DiversityProof& proof, DiversityClass klass) {
  for (const ClassResult& candidate : proof.classes) {
    if (candidate.klass == klass) {
      return &candidate;
    }
  }
  return nullptr;
}

void report_classes(Reporter& report, const DiversityProof& proof) {
  for (const ClassResult& result : proof.classes) {
    report.field(std::string(to_string(result.klass)),
                 std::string(to_string(result.outcome)) + " evidence=" +
                     (result.evidence_complete ? "COMPLETE" : "INCOMPLETE") +
                     " shared=" + std::to_string(result.shared_total));
  }
}

}  // namespace

int main() {
  Reporter report("ex_incomplete_evidence_unknown");
  Harness harness;

  const std::vector<PathComposition> paths = unclassified_paths();
  for (const PathComposition& composition : paths) {
    harness.evidence.set_path(composition);
  }
  classify_path(harness.evidence, paths[0], DomainRelation::FAILURE_DOMAIN,
                EvidenceCoverage::COMPLETE, {"fd-alpha"});
  classify_path(harness.evidence, paths[1], DomainRelation::FAILURE_DOMAIN,
                EvidenceCoverage::COMPLETE, {"fd-beta"});
  // The authority holds no classification at all for this transit node.
  harness.evidence.clear_entity(EntityRef{EntityKind::NODE, "node-c"});

  PolicySpec spec;
  spec.id = "pol-complete-evidence";
  spec.classes = {DiversityClass::LINK_DISJOINT, DiversityClass::TRANSIT_NODE_DISJOINT,
                  DiversityClass::FAILURE_DOMAIN_DISJOINT};
  spec.relations = {DomainRelation::FAILURE_DOMAIN};
  const MutationResult published = harness.publish(spec, "publish-policy");
  report.check_name(published.status, "APPLIED", "the policy was published");
  if (!published.has_policy) {
    return report.finish();
  }

  const ProofRequest request = harness.request(published.policy.id, paths);
  const MutationResult committed = harness.runtime.evaluate(request, harness.authority("prove"));
  report.check_name(committed.status, "APPLIED", "the evaluation completed and committed");
  if (!committed.has_proof) {
    return report.finish();
  }

  const DiversityProof& unknown = committed.proof;
  report.field("proof", unknown.id.str() + "@g" + std::to_string(unknown.generation.value()));
  report.field("outcome", std::string(to_string(unknown.outcome)));
  report.field("detail", unknown.detail);
  report_classes(report, unknown);

  const ClassResult* links = class_result(unknown, DiversityClass::LINK_DISJOINT);
  const ClassResult* nodes = class_result(unknown, DiversityClass::TRANSIT_NODE_DISJOINT);
  const ClassResult* domains =
      class_result(unknown, DiversityClass::FAILURE_DOMAIN_DISJOINT);
  report.check(links != nullptr && nodes != nullptr && domains != nullptr,
               "all three required classes were evaluated");
  if (links == nullptr || nodes == nullptr || domains == nullptr) {
    return report.finish();
  }

  report.check_name(unknown.outcome, "UNKNOWN_INCOMPLETE_EVIDENCE",
                    "missing classification yields UNKNOWN_INCOMPLETE_EVIDENCE");
  report.check_name(domains->outcome, "UNKNOWN_INCOMPLETE_EVIDENCE",
                    "FAILURE_DOMAIN_DISJOINT cannot be proven from absent evidence");
  report.check_equal(domains->evidence_complete, false,
                     "the class records that its evidence is incomplete");
  report.check(domains->detail.find("NODE node-c") != std::string::npos,
               "the class detail names the entity with no classification");
  report.check(domains->detail.find("ABSENT") != std::string::npos,
               "the class detail states that coverage is ABSENT");
  report.check_name(links->outcome, "PROVEN_DIVERSE", "LINK_DISJOINT is still proven");
  report.check_name(nodes->outcome, "PROVEN_DIVERSE", "TRANSIT_NODE_DISJOINT is still proven");
  report.check_equal(unknown.conflicts_total, std::uint64_t{0},
                     "no shared resource was observed");
  report.check_name(unknown.currentness, "INCOMPLETE_EVIDENCE",
                    "the committed revision is explicitly not current");
  report.check(!unknown.current(), "an incomplete proof is not current");

  // The authority now classifies the outstanding entity completely.
  harness.evidence.set_domain_membership(EntityRef{EntityKind::NODE, "node-c"},
                                         DomainRelation::FAILURE_DOMAIN,
                                         EvidenceCoverage::COMPLETE,
                                         parse_domains("fd-beta"));
  const MutationResult revalidated =
      harness.runtime.revalidate(unknown.id, harness.authority("revalidate"));
  report.check_name(revalidated.status, "APPLIED", "revalidation committed a new revision");
  if (!revalidated.has_proof) {
    return report.finish();
  }
  report.field("revalidated outcome", std::string(to_string(revalidated.proof.outcome)));
  report_classes(report, revalidated.proof);
  report.check_name(revalidated.proof.outcome, "PROVEN_DIVERSE",
                    "complete independent evidence proves the set");
  report.check_equal(revalidated.proof.generation.value(), std::uint64_t{2},
                     "the proof identity is stable and its revision advanced");
  report.check_equal(revalidated.proof.id, unknown.id,
                     "revalidation kept the same proof identity");
  report.check(revalidated.proof.current(), "the revalidated revision is current");
  report.check_equal(revalidated.proof.conflicts_total, std::uint64_t{0},
                     "no conflict is reported after revalidation");

  return report.finish();
}
