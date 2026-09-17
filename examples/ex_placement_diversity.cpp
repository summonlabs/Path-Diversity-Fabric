// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.

// Placement diversity from authoritative rack, pod and site evidence. Both
// paths are fully classified and differ in pod and site, but one transit node
// of the second path is placed in the first path's rack, so RACK_DISJOINT is
// NOT_DIVERSE and the explanation names the exact shared rack.

#include "example_support.hpp"

namespace {

using namespace example;

std::vector<PathComposition> placed_paths() {
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
  Reporter report("ex_placement_diversity");
  Harness harness;

  const std::vector<PathComposition> paths = placed_paths();
  for (const PathComposition& composition : paths) {
    harness.evidence.set_path(composition);
  }

  classify_path(harness.evidence, paths[0], DomainRelation::RACK, EvidenceCoverage::COMPLETE,
                {"rack-07"});
  classify_path(harness.evidence, paths[0], DomainRelation::POD, EvidenceCoverage::COMPLETE,
                {"pod-2"});
  classify_path(harness.evidence, paths[0], DomainRelation::SITE, EvidenceCoverage::COMPLETE,
                {"site-east"});
  classify_path(harness.evidence, paths[1], DomainRelation::RACK, EvidenceCoverage::COMPLETE,
                {"rack-09"});
  classify_path(harness.evidence, paths[1], DomainRelation::POD, EvidenceCoverage::COMPLETE,
                {"pod-3"});
  classify_path(harness.evidence, paths[1], DomainRelation::SITE, EvidenceCoverage::COMPLETE,
                {"site-west"});
  // Authoritative placement of the second path's transit node: same rack as the
  // whole first path, which no structural comparison could have detected.
  harness.evidence.set_domain_membership(EntityRef{EntityKind::NODE, "node-c"},
                                         DomainRelation::RACK, EvidenceCoverage::COMPLETE,
                                         parse_domains("rack-07"));

  PolicySpec spec;
  spec.id = "pol-placement";
  spec.classes = {DiversityClass::RACK_DISJOINT, DiversityClass::POD_DISJOINT,
                  DiversityClass::SITE_DISJOINT};
  spec.relations = {DomainRelation::RACK, DomainRelation::POD, DomainRelation::SITE};
  const MutationResult published = harness.publish(spec, "publish-policy");
  report.check_name(published.status, "APPLIED", "the placement policy was published");
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
                 std::string(to_string(result.outcome)) + " shared=" +
                     std::to_string(result.shared_total) + " detail=" + result.detail);
  }

  const ClassResult* racks = class_result(proof, DiversityClass::RACK_DISJOINT);
  const ClassResult* pods = class_result(proof, DiversityClass::POD_DISJOINT);
  const ClassResult* sites = class_result(proof, DiversityClass::SITE_DISJOINT);
  report.check(racks != nullptr && pods != nullptr && sites != nullptr,
               "all three placement classes were evaluated");
  if (racks == nullptr || pods == nullptr || sites == nullptr) {
    return report.finish();
  }

  report.check_name(racks->outcome, "NOT_DIVERSE", "RACK_DISJOINT is NOT_DIVERSE");
  report.check_name(pods->outcome, "PROVEN_DIVERSE", "POD_DISJOINT is proven");
  report.check_name(sites->outcome, "PROVEN_DIVERSE", "SITE_DISJOINT is proven");
  report.check_name(proof.outcome, "NOT_DIVERSE",
                    "the rack conflict demotes the whole proof");
  report.check_equal(racks->detail, std::string("shared RACK domains: rack-07"),
                     "the class detail names the shared rack");
  report.check(!proof.conflicts.empty(), "the proof names the shared resource");
  if (!proof.conflicts.empty()) {
    report.field("primary conflict", proof.conflicts.front().render());
    report.check_name(proof.conflicts.front().kind, "SHARED_RACK",
                      "the primary reason is a shared rack");
    report.check_equal(proof.conflicts.front().id, std::string("rack-07"),
                       "the primary reason names rack-07");
  }

  const std::optional<Explanation> explanation = harness.runtime.explain(proof.id);
  report.check(explanation.has_value(), "the runtime explains the committed proof");
  bool named_rack = false;
  if (explanation.has_value()) {
    report.field("explanation outcome", std::string(to_string(explanation->outcome)));
    for (const ExplanationEntry& entry : explanation->entries) {
      if (entry.kind == ExplanationKind::SHARED_DOMAIN && entry.subject == "rack-07") {
        named_rack = true;
        report.field("explanation entry", entry.render());
      }
    }
  }
  report.check(named_rack, "the explanation names the exact shared rack");

  return report.finish();
}
