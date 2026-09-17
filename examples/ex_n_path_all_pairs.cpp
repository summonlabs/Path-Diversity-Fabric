// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.

// Four paths under ALL_PAIRS semantics: every pair of the canonical order must
// satisfy every required class, so one transit node shared by two of the four
// paths decides the whole set. The deterministic pairwise matrix and the
// primary conflict are printed in full.

#include "example_support.hpp"

namespace {

using namespace example;

std::vector<PathComposition> four_paths() {
  std::vector<PathComposition> paths;
  paths.push_back(make_path("path-a", "node-a1", "node-d1", {"node-b"}, {"link-a1b", "link-bd1"}));
  paths.push_back(make_path("path-b", "node-a2", "node-d2", {"node-x"}, {"link-a2x", "link-xd2"}));
  paths.push_back(make_path("path-c", "node-a3", "node-d3", {"node-x"}, {"link-a3x", "link-xd3"}));
  paths.push_back(make_path("path-d", "node-a4", "node-d4", {"node-y"}, {"link-a4y", "link-yd4"}));
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

bool expected_pair(std::size_t index, bool independent, const PairwiseCell& cell) {
  return cell.independent == independent && index < 6;
}

}  // namespace

int main() {
  Reporter report("ex_n_path_all_pairs");
  Harness harness;

  const std::vector<PathComposition> paths = four_paths();
  for (const PathComposition& composition : paths) {
    harness.evidence.set_path(composition);
  }

  PolicySpec spec;
  spec.id = "pol-all-pairs";
  spec.classes = {DiversityClass::LINK_DISJOINT, DiversityClass::TRANSIT_NODE_DISJOINT};
  spec.semantics = SetSemantics::ALL_PAIRS;
  const MutationResult published = harness.publish(spec, "publish-policy");
  report.check_name(published.status, "APPLIED", "the all-pairs policy was published");
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
  report.field("detail", proof.detail);

  report.note("canonical order and pairwise matrix (- independent, X conflicting)");
  for (std::size_t i = 0; i < proof.matrix.order.size(); ++i) {
    report.field("path[" + std::to_string(i) + "]", proof.matrix.order[i].str());
  }
  for (std::size_t i = 0; i < proof.matrix.order.size(); ++i) {
    std::string row;
    for (std::size_t j = 0; j < proof.matrix.order.size(); ++j) {
      if (i == j) {
        row += " -";
        continue;
      }
      const PairwiseCell* cell = proof.matrix.at(static_cast<std::uint32_t>(i),
                                                 static_cast<std::uint32_t>(j));
      row += (cell != nullptr && cell->independent) ? " =" : " X";
    }
    report.field("row[" + std::to_string(i) + "]", row);
  }
  for (const PairwiseCell& cell : proof.matrix.cells) {
    std::string line = "[" + std::to_string(cell.left) + "," + std::to_string(cell.right) +
                       "] independent=" + (cell.independent ? "yes" : "no") +
                       " evidence=" + (cell.evidence_complete ? "COMPLETE" : "INCOMPLETE");
    if (cell.primary_conflict.has_value()) {
      line += " primary=" + cell.primary_conflict->render();
    }
    report.note(line);
  }

  const std::vector<bool> expected = {true, true, true, false, true, true};
  report.check_equal(proof.matrix.order.size(), std::size_t{4},
                     "the matrix covers the four canonical paths");
  report.check_equal(proof.matrix.cells.size(), std::size_t{6},
                     "the matrix holds all six unordered pairs");
  bool matrix_matches = proof.matrix.cells.size() == expected.size();
  for (std::size_t i = 0; i < expected.size() && i < proof.matrix.cells.size(); ++i) {
    matrix_matches = matrix_matches && expected_pair(i, expected[i], proof.matrix.cells[i]);
  }
  report.check(matrix_matches,
               "exactly one pair conflicts, and it is the pair (1,2) sharing node-x");
  report.check_name(proof.outcome, "NOT_DIVERSE",
                    "one conflicting pair decides the ALL_PAIRS proof");

  const ClassResult* links = class_result(proof, DiversityClass::LINK_DISJOINT);
  const ClassResult* nodes = class_result(proof, DiversityClass::TRANSIT_NODE_DISJOINT);
  report.check(links != nullptr && nodes != nullptr, "both required classes were evaluated");
  if (links != nullptr && nodes != nullptr) {
    report.check_name(links->outcome, "PROVEN_DIVERSE", "every pair is link disjoint");
    report.check_name(nodes->outcome, "NOT_DIVERSE", "transit-node diversity fails once");
    report.check_equal(nodes->shared_total, std::uint64_t{1},
                       "exactly one shared transit node is reported");
  }

  const PairwiseCell* conflicting = proof.matrix.at(1, 2);
  report.check(conflicting != nullptr && !conflicting->independent,
               "the matrix marks the pair (1,2) as conflicting");
  if (conflicting != nullptr && conflicting->primary_conflict.has_value()) {
    report.field("primary conflict", conflicting->primary_conflict->render());
  }
  report.check(!proof.conflicts.empty(), "the proof names the primary conflict");
  if (!proof.conflicts.empty()) {
    const SharedResource& primary = proof.conflicts.front();
    report.field("proof primary conflict", primary.render());
    report.check_name(primary.kind, "SHARED_TRANSIT_NODE",
                      "the primary reason is a shared transit node");
    report.check_equal(primary.id, std::string("node-x"),
                       "the primary reason names node-x");
    report.check(primary.paths == std::vector<std::uint32_t>({1, 2}),
                 "the primary reason is attributed to paths 1 and 2");
  }
  report.check_equal(proof.conflicts_total, std::uint64_t{1},
                     "the complete conflict list holds one entry");

  const ConflictGraph graph = build_conflict_graph(proof.matrix);
  report.check_equal(graph.path_count, std::uint32_t{4}, "the conflict graph has four vertices");
  report.check_equal(graph.edge_count(), std::uint64_t{1}, "the conflict graph has one edge");
  report.check(graph.neighbours(1) == std::vector<std::uint32_t>({2}),
               "vertex 1 conflicts with vertex 2 only");

  return report.finish();
}
