// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
// Set-wise K-independent diversity: exactness, witness determinism and the
// explicit computational bound. Every brute-force check in this file is written
// independently of the production solver.

#include <set>
#include <vector>

#include "test_support.hpp"

using namespace path_diversity;
using pd_test::Fixture;
using pd_test::make_path;
using pd_test::make_policy;

namespace {

// An independent, deliberately naive maximum-independent-set search over the
// pairwise matrix. It shares no code with the production solver.
std::vector<std::uint32_t> brute_force_maximum(const PairwiseMatrix& matrix) {
  const std::size_t n = matrix.order.size();
  std::vector<std::uint32_t> best;
  const std::uint64_t total = 1ULL << n;
  for (std::uint64_t mask = 1; mask < total; ++mask) {
    std::vector<std::uint32_t> candidate;
    bool ok = true;
    for (std::uint32_t i = 0; i < n && ok; ++i) {
      if (((mask >> i) & 1ULL) == 0ULL) {
        continue;
      }
      for (std::uint32_t chosen : candidate) {
        const PairwiseCell* cell = matrix.at(i, chosen);
        if (cell == nullptr || !cell->independent) {
          ok = false;
          break;
        }
      }
      candidate.push_back(i);
    }
    if (ok && candidate.size() > best.size()) {
      best = candidate;
    }
  }
  return best;
}

struct Graph {
  std::vector<PathComposition> paths;
  DiversityPolicy policy;
  ProofRequest request;
};

// Builds n paths whose conflict graph is exactly the supplied edge set. An edge
// is realised by sharing one link; no edge is realised by anything else.
Graph build_graph_fixture(Fixture& fixture, std::size_t n,
                          const std::vector<std::pair<std::size_t, std::size_t>>& edges) {
  Graph graph;
  for (std::size_t i = 0; i < n; ++i) {
    const std::string suffix = std::to_string(i);
    std::vector<std::string> links;
    links.push_back("link-own-" + suffix);
    for (const auto& edge : edges) {
      if (edge.first == i || edge.second == i) {
        // Both ends of an edge must carry the same link identity, which is what
        // makes the intended conflict real.
        const std::size_t low = edge.first < edge.second ? edge.first : edge.second;
        const std::size_t high = edge.first < edge.second ? edge.second : edge.first;
        links.push_back("link-shared-" + std::to_string(low) + "-" + std::to_string(high));
      }
    }
    PathComposition composition = make_path("path-k-" + suffix, 1, {"node-" + suffix}, links,
                                            {"sw-" + suffix}, "ep-src", "ep-dst");
    fixture.evidence.set_path(composition);
    pd_test::classify_path(fixture.evidence, composition, DomainRelation::FAILURE_DOMAIN,
                           EvidenceCoverage::COMPLETE, {"fd-" + suffix});
    graph.paths.push_back(composition);
  }
  graph.policy = make_policy("dpol-kset", {DiversityClass::LINK_DISJOINT},
                             EndpointExemption::SHARED_SOURCE_AND_DESTINATION, 3,
                             SetSemantics::AT_LEAST_K_INDEPENDENT);
  for (const PathComposition& composition : graph.paths) {
    graph.request.paths.push_back(
        PathRef{composition.path, PathAuthorityGeneration::from_value(1)});
  }
  graph.request.policy = graph.policy.id;
  graph.request.policy_generation = DiversityPolicyGeneration::from_value(1);
  graph.request.canonicalize();
  return graph;
}

}  // namespace

PD_TEST(k_subset_exactness_against_independent_brute_force) {
  // Four conflict shapes with known exact maxima.
  struct Case {
    std::size_t n;
    std::vector<std::pair<std::size_t, std::size_t>> edges;
    std::size_t expected_maximum;
  };
  const std::vector<Case> cases = {
      {4, {}, 4},
      {4, {{0, 1}}, 3},
      {4, {{0, 1}, {1, 2}, {2, 3}, {0, 3}}, 2},
      {5, {{0, 1}, {0, 2}, {0, 3}, {0, 4}}, 4},
      {5, {{0, 1}, {2, 3}}, 3},
      {6, {{0, 1}, {1, 2}, {2, 0}, {3, 4}, {4, 5}, {5, 3}}, 2},
  };
  for (const Case& test_case : cases) {
    Fixture fixture;
    Graph graph = build_graph_fixture(fixture, test_case.n, test_case.edges);
    PD_REQUIRE(fixture.runtime.publish_policy(graph.policy, fixture.actor("publish-kset")).status ==
               MutationStatus::APPLIED);
    const MutationResult result = fixture.runtime.evaluate(graph.request, fixture.actor("eval-kset"));
    PD_REQUIRE(result.has_proof);
    PD_REQUIRE(result.proof.witness.present);

    const std::vector<std::uint32_t> reference = brute_force_maximum(result.proof.matrix);
    PD_CHECK_EQ(static_cast<std::size_t>(result.proof.witness.achieved), reference.size());
    PD_CHECK_EQ(reference.size(), test_case.expected_maximum);
    PD_CHECK(result.proof.witness.maximum_exact);
    PD_CHECK(verify_witness(result.proof.matrix, result.proof.witness.indices));

    // The witness must be exactly the brute-force set: both searches select the
    // lexicographically smallest maximum independent set.
    PD_CHECK_EQ(result.proof.witness.indices.size(), reference.size());
    for (std::size_t i = 0; i < reference.size() && i < result.proof.witness.indices.size(); ++i) {
      PD_CHECK_EQ(result.proof.witness.indices[i], reference[i]);
    }

    if (reference.size() >= 3) {
      PD_CHECK(result.proof.outcome == ProofOutcome::PROVEN_DIVERSE);
    } else if (reference.size() == 2) {
      PD_CHECK(result.proof.outcome == ProofOutcome::NOT_DIVERSE);
    }
  }
}

PD_TEST(k_subset_per_pair_semantics_are_not_collapsed) {
  // Path 0 conflicts with everything; paths 1, 2 and 3 are mutually
  // independent. A policy that never looks past the first path would answer
  // "not diverse"; the exact answer is "three independent paths exist".
  Fixture fixture;
  Graph graph = build_graph_fixture(fixture, 4, {{0, 1}, {0, 2}, {0, 3}});
  PD_REQUIRE(fixture.runtime.publish_policy(graph.policy, fixture.actor("publish-pair")).status ==
             MutationStatus::APPLIED);
  const MutationResult result = fixture.runtime.evaluate(graph.request, fixture.actor("eval-pair"));
  PD_REQUIRE(result.has_proof);
  PD_CHECK(result.proof.outcome == ProofOutcome::PROVEN_DIVERSE);
  PD_CHECK_EQ(result.proof.witness.achieved, std::uint32_t(3));
  PD_CHECK_EQ(result.proof.witness.indices.size(), std::size_t(3));
  PD_CHECK_EQ(result.proof.witness.indices[0], std::uint32_t(1));
  PD_CHECK_EQ(result.proof.witness.indices[1], std::uint32_t(2));
  PD_CHECK_EQ(result.proof.witness.indices[2], std::uint32_t(3));

  // The pairwise matrix still reports the conflict against path 0 honestly.
  PD_CHECK_EQ(result.proof.matrix.cells.size(), std::size_t(6));
  const PairwiseCell* conflict_cell = result.proof.matrix.at(0, 1);
  PD_REQUIRE(conflict_cell != nullptr);
  PD_CHECK(!conflict_cell->independent);
}

PD_TEST(k_subset_bound_is_explicit_not_heuristic) {
  Fixture fixture;
  Limits tight = fixture.limits;
  tight.max_k_subset_paths = 3;
  tight.max_paths_per_proof = 8;
  tight.max_snapshot_paths = 8;
  tight.max_pairwise_cells = 256;
  Fixture small(tight);
  Graph graph = build_graph_fixture(small, 5, {});
  PD_REQUIRE(small.runtime.publish_policy(graph.policy, small.actor("publish-bound")).status ==
             MutationStatus::APPLIED);
  const MutationResult result = small.runtime.evaluate(graph.request, small.actor("eval-bound"));
  PD_REQUIRE(result.has_proof);
  PD_CHECK(result.proof.outcome == ProofOutcome::RESOURCE_LIMIT);
  PD_REQUIRE(result.proof.limit.has_value());
  PD_CHECK(result.proof.limit->bound == ResourceBound::MAX_K_SUBSET_PATHS);
  PD_CHECK_EQ(result.proof.limit->observed, std::uint64_t(5));
  PD_CHECK_EQ(result.proof.limit->allowed, std::uint64_t(3));
}

PD_TEST(witness_is_order_independent) {
  Fixture fixture;
  Graph graph = build_graph_fixture(fixture, 6, {{0, 1}, {2, 3}});
  PD_REQUIRE(fixture.runtime.publish_policy(graph.policy, fixture.actor("publish-order")).status ==
             MutationStatus::APPLIED);
  std::vector<std::uint32_t> reference;
  const std::vector<std::vector<std::size_t>> orders = {{0, 1, 2, 3, 4, 5},
                                                        {5, 4, 3, 2, 1, 0},
                                                        {2, 0, 4, 1, 5, 3}};
  for (const std::vector<std::size_t>& order : orders) {
    ProofRequest request;
    request.policy = graph.policy.id;
    request.policy_generation = DiversityPolicyGeneration::from_value(1);
    for (std::size_t index : order) {
      request.paths.push_back(
          PathRef{graph.paths[index].path, PathAuthorityGeneration::from_value(1)});
    }
    const MutationResult result =
        fixture.runtime.evaluate(request, fixture.actor("order-" + std::to_string(order[0])));
    PD_REQUIRE(result.has_proof);
    if (reference.empty()) {
      reference = result.proof.witness.indices;
      PD_CHECK_EQ(reference.size(), std::size_t(4));
      continue;
    }
    PD_CHECK_EQ(result.proof.witness.indices.size(), reference.size());
    for (std::size_t i = 0; i < reference.size(); ++i) {
      PD_CHECK_EQ(result.proof.witness.indices[i], reference[i]);
    }
  }
}

PD_TEST(witness_verification_rejects_non_independent_subset) {
  Fixture fixture;
  Graph graph = build_graph_fixture(fixture, 3, {{0, 1}});
  PD_REQUIRE(fixture.runtime.publish_policy(graph.policy, fixture.actor("publish-verify")).status ==
             MutationStatus::APPLIED);
  const MutationResult result =
      fixture.runtime.evaluate(graph.request, fixture.actor("eval-verify"));
  PD_REQUIRE(result.has_proof);
  PD_CHECK(verify_witness(result.proof.matrix, {1, 2}));
  PD_CHECK(!verify_witness(result.proof.matrix, {0, 1}));
  PD_CHECK(!verify_witness(result.proof.matrix, {0, 0}));
  PD_CHECK(!verify_witness(result.proof.matrix, {0, 9}));

  const std::optional<WitnessSubset> computed =
      maximum_independent_subset(result.proof.matrix, 2, fixture.limits);
  PD_REQUIRE(computed.has_value());
  PD_CHECK_EQ(computed->achieved, std::uint32_t(2));
  PD_CHECK(computed->maximum_exact);
  PD_CHECK(maximum_independent_subset(result.proof.matrix, 2, fixture.limits).has_value());
  Limits unbounded = fixture.limits;
  unbounded.max_k_subset_paths = 1;
  PD_CHECK(!maximum_independent_subset(result.proof.matrix, 2, unbounded).has_value());
}

PD_TEST_MAIN()
