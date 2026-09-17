// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.

// A mandatory failure-domain proof. The two paths share no link and no transit
// node, so LINK_DISJOINT and TRANSIT_NODE_DISJOINT are proven, yet one
// authoritative failure domain carries both: FAILURE_DOMAIN_DISJOINT is
// NOT_DIVERSE and the overall proof is NOT_DIVERSE, because this policy demands
// failure-domain independence and a proven conflict decides it.
//
// The paths deliberately use distinct endpoints: two paths that share an
// endpoint share that endpoint's failure domain, which is a real correlation
// and not an artifact of this scenario.

#include "example_support.hpp"

namespace {

using namespace example;

std::vector<PathComposition> correlated_paths() {
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

}  // namespace

int main() {
  Reporter report("ex_shared_risk_group_conflict");
  Harness harness;

  const std::vector<PathComposition> paths = correlated_paths();
  for (const PathComposition& composition : paths) {
    harness.evidence.set_path(composition);
  }

  // Every structural element is fully classified; only one failure domain is
  // shared, by one link of each path.
  classify_path(harness.evidence, paths[0], DomainRelation::FAILURE_DOMAIN,
                EvidenceCoverage::COMPLETE, {"fd-alpha"});
  classify_path(harness.evidence, paths[1], DomainRelation::FAILURE_DOMAIN,
                EvidenceCoverage::COMPLETE, {"fd-beta"});
  harness.evidence.set_domain_membership(EntityRef{EntityKind::LINK, "link-bd1"},
                                         DomainRelation::FAILURE_DOMAIN,
                                         EvidenceCoverage::COMPLETE, parse_domains("fd-shared"));
  harness.evidence.set_domain_membership(EntityRef{EntityKind::LINK, "link-cd2"},
                                         DomainRelation::FAILURE_DOMAIN,
                                         EvidenceCoverage::COMPLETE, parse_domains("fd-shared"));

  PolicySpec spec;
  spec.id = "pol-mandatory-failure-domain";
  spec.classes = {DiversityClass::LINK_DISJOINT, DiversityClass::TRANSIT_NODE_DISJOINT,
                  DiversityClass::FAILURE_DOMAIN_DISJOINT};
  spec.relations = {DomainRelation::FAILURE_DOMAIN};
  const MutationResult published = harness.publish(spec, "publish-policy");
  report.check_name(published.status, "APPLIED", "the mandatory policy was published");
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
  for (const ClassResult& result : proof.classes) {
    report.field(std::string(to_string(result.klass)),
                 std::string(to_string(result.outcome)) + " evidence=" +
                     (result.evidence_complete ? "COMPLETE" : "INCOMPLETE") +
                     " shared=" + std::to_string(result.shared_total));
  }
  for (const SharedResource& conflict : proof.conflicts) {
    report.field("conflict", conflict.render());
  }

  const ClassResult* links = class_result(proof, DiversityClass::LINK_DISJOINT);
  const ClassResult* nodes = class_result(proof, DiversityClass::TRANSIT_NODE_DISJOINT);
  const ClassResult* domains = class_result(proof, DiversityClass::FAILURE_DOMAIN_DISJOINT);
  report.check(links != nullptr && nodes != nullptr && domains != nullptr,
               "all three required classes were evaluated");
  if (links == nullptr || nodes == nullptr || domains == nullptr) {
    return report.finish();
  }

  report.check_name(links->outcome, "PROVEN_DIVERSE", "LINK_DISJOINT is proven");
  report.check_name(nodes->outcome, "PROVEN_DIVERSE", "TRANSIT_NODE_DISJOINT is proven");
  report.check_name(domains->outcome, "NOT_DIVERSE", "FAILURE_DOMAIN_DISJOINT is NOT_DIVERSE");
  report.check_name(proof.outcome, "NOT_DIVERSE",
                    "the overall proof is NOT_DIVERSE under the mandatory policy");
  report.check_equal(domains->shared_total, std::uint64_t{1},
                     "exactly one failure domain is shared");
  report.check(!proof.conflicts.empty(), "the proof names the shared resource");
  if (!proof.conflicts.empty()) {
    const SharedResource& primary = proof.conflicts.front();
    report.field("primary conflict", primary.render());
    report.check_name(primary.kind, "SHARED_FAILURE_DOMAIN",
                      "the primary reason is a shared failure domain");
    report.check_equal(primary.relation == DomainRelation::FAILURE_DOMAIN, true,
                       "the conflict names the authoritative relation");
    report.check_equal(primary.id, std::string("fd-shared"),
                       "the conflict names the exact shared domain");
    report.check_equal(primary.paths.size(), std::size_t{2},
                       "the conflict is attributed to both paths");
  }
  for (const SharedResource& conflict : proof.conflicts) {
    report.check(!(conflict.kind == ConflictClass::SHARED_LINK) &&
                     !(conflict.kind == ConflictClass::SHARED_TRANSIT_NODE),
                 "no link or transit-node conflict is reported");
  }
  report.check(proof.conflicts_total == proof.conflicts.size(),
               "the reported conflict list is complete");

  return report.finish();
}
