// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

// Internal, non-installed helpers shared between the pairwise classifier and
// the set-wise aggregator. Nothing here is part of the public API and nothing
// here is reachable through the installed package.

#include <cstdint>
#include <vector>

#include "path_diversity/evaluate.hpp"

namespace path_diversity {
namespace internal {

bool is_required(const DiversityPolicy& policy, DiversityClass klass);
bool cell_has_conflict(const PairwiseCell& cell);
bool cell_fully_proven(const PairwiseCell& cell);

// Adjacency over the canonical path order. known_conflict_only selects between
// "the pair is not proven independent" (the conservative graph, where an
// incomplete pair is an edge) and "the pair has an observed conflict".
ConflictGraph graph_from_matrix(const PairwiseMatrix& matrix, bool known_conflict_only);

std::vector<std::uint32_t> mis_witness(const ConflictGraph& graph);
std::vector<std::uint32_t> mis_exhaustive(const ConflictGraph& graph);
std::vector<std::uint32_t> sorted_indices_of(const std::vector<std::uint32_t>& witness);

void aggregate_class(const std::vector<const ClassResult*>& sources, DiversityClass klass,
                     ClassResult& out, std::uint32_t max_shared);
std::vector<const ClassResult*> gather(const std::vector<PairwiseCell>& cells,
                                       DiversityClass klass);
void remap_cell(std::vector<ClassResult>& classes, std::uint32_t left, std::uint32_t right);

}  // namespace internal
}  // namespace path_diversity
