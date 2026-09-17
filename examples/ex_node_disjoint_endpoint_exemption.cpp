// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.

// Two paths that share only their source and destination endpoints. Endpoint
// semantics are policy content, so one topology yields two different answers:
// with the exemption the pair passes transit-node diversity, without it the
// pair fails and the runtime names the two shared nodes.

#include "example_support.hpp"

namespace {

using namespace example;

std::vector<PathComposition> shared_endpoint_paths() {
  std::vector<PathComposition> paths;
  paths.push_back(make_path("path-a", "node-a", "node-d", {"node-b"}, {"link-ab", "link-bd"}));
  paths.push_back(make_path("path-b", "node-a", "node-d", {"node-c"}, {"link-ac", "link-cd"}));
  return paths;
}

EvaluationResult run(const std::vector<PathComposition>& paths, InMemoryEvidence& evidence,
                     EndpointExemption exemption, const Limits& limits) {
  PolicySpec spec;
  spec.id = "pol-endpoint-exemption";
  spec.classes = {DiversityClass::LINK_DISJOINT, DiversityClass::TRANSIT_NODE_DISJOINT};
  spec.exemption = exemption;
  ProofRequest request;
  request.policy = DiversityPolicyId::parse(spec.id);
  request.policy_generation = DiversityPolicyGeneration::from_value(1);
  for (const PathComposition& composition : paths) {
    request.paths.push_back(PathRef{composition.path, composition.authority_generation});
  }
  (void)request.canonicalize();
  const EvaluationInputs inputs{&evidence, &evidence, &evidence, &limits};
  return evaluate_diversity(request, build_policy(spec), inputs);
}

const ClassResult* class_result(const EvaluationResult& result, DiversityClass klass) {
  for (const ClassResult& candidate : result.classes) {
    if (candidate.klass == klass) {
      return &candidate;
    }
  }
  return nullptr;
}

std::string shared_ids(const ClassResult& result) {
  std::string out;
  for (const SharedResource& conflict : result.shared) {
    out += out.empty() ? "" : ",";
    out += conflict.id;
  }
  return out;
}

}  // namespace

int main() {
  Reporter report("ex_node_disjoint_endpoint_exemption");
  const std::vector<PathComposition> paths = shared_endpoint_paths();
  InMemoryEvidence evidence;
  for (const PathComposition& composition : paths) {
    evidence.set_path(composition);
  }
  const Limits limits;

  const EvaluationResult exempted =
      run(paths, evidence, EndpointExemption::SHARED_SOURCE_AND_DESTINATION, limits);
  const EvaluationResult strict = run(paths, evidence, EndpointExemption::NONE, limits);

  const ClassResult* exempted_nodes =
      class_result(exempted, DiversityClass::TRANSIT_NODE_DISJOINT);
  const ClassResult* strict_nodes = class_result(strict, DiversityClass::TRANSIT_NODE_DISJOINT);
  const ClassResult* exempted_links = class_result(exempted, DiversityClass::LINK_DISJOINT);
  const ClassResult* strict_links = class_result(strict, DiversityClass::LINK_DISJOINT);
  if (exempted_nodes == nullptr || strict_nodes == nullptr || exempted_links == nullptr ||
      strict_links == nullptr) {
    report.check(false, "both policies evaluated both required classes");
    return report.finish();
  }

  report.note("endpoint exemption SHARED_SOURCE_AND_DESTINATION");
  report.field("outcome", std::string(to_string(exempted.outcome)));
  report.field("TRANSIT_NODE_DISJOINT",
               std::string(to_string(exempted_nodes->outcome)) + " shared=" +
                   std::to_string(exempted_nodes->shared_total));
  report.note("endpoint exemption NONE");
  report.field("outcome", std::string(to_string(strict.outcome)));
  report.field("TRANSIT_NODE_DISJOINT",
               std::string(to_string(strict_nodes->outcome)) + " shared=[" +
                   shared_ids(*strict_nodes) + "]");
  report.field("endpoint semantics detail", strict_nodes->detail);

  report.check_name(exempted.outcome, "PROVEN_DIVERSE",
                    "shared endpoints pass transit-node diversity when exempted");
  report.check_name(exempted_nodes->outcome, "PROVEN_DIVERSE",
                    "the exempted pair is transit-node disjoint");
  report.check_name(strict.outcome, "NOT_DIVERSE",
                    "ordinary endpoints fail transit-node diversity");
  report.check_name(strict_nodes->outcome, "NOT_DIVERSE",
                    "the strict pair reports a shared transit node");
  report.check_equal(strict_nodes->shared_total, std::uint64_t{2},
                     "exactly the source and the destination are shared");
  report.check_equal(shared_ids(*strict_nodes), std::string("node-a,node-d"),
                     "the shared nodes are named exactly");
  report.check_name(exempted_links->outcome, "PROVEN_DIVERSE",
                    "the link class is proven under both exemptions");
  report.check_name(strict_links->outcome, "PROVEN_DIVERSE",
                    "the link class is unaffected by endpoint semantics");
  report.check_equal(exempted_nodes->evidence_complete, true,
                     "node and endpoint coverage is complete");

  return report.finish();
}
