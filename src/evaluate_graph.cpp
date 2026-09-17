// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include <algorithm>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "path_diversity/evaluate.hpp"

#include "evaluate_internal.hpp"

namespace path_diversity {

namespace internal {

bool is_required(const DiversityPolicy& policy, DiversityClass klass) {
  for (DiversityClass required : policy.required_classes) {
    if (required == klass) {
      return true;
    }
  }
  return false;
}

void remap_conflict(SharedResource& conflict, std::uint32_t left, std::uint32_t right) {
  conflict.paths.clear();
  conflict.paths.push_back(left);
  conflict.paths.push_back(right);
}

void remap_cell(std::vector<ClassResult>& classes, std::uint32_t left, std::uint32_t right) {
  for (ClassResult& result : classes) {
    for (SharedResource& conflict : result.shared) {
      remap_conflict(conflict, left, right);
    }
    canonical_conflict_order(result.shared);
  }
}

bool cell_has_conflict(const PairwiseCell& cell) {
  for (const ClassResult& result : cell.classes) {
    if (result.outcome == ProofOutcome::NOT_DIVERSE) {
      return true;
    }
  }
  return false;
}

bool cell_fully_proven(const PairwiseCell& cell) {
  for (const ClassResult& result : cell.classes) {
    if (result.outcome != ProofOutcome::PROVEN_DIVERSE || !result.evidence_complete) {
      return false;
    }
  }
  return true;
}

// ---------------------------------------------------------------------------
// Maximum independent set.
//
// The cardinality function is exact and memoized; the witness is reconstructed
// greedily in ascending vertex order, which yields the lexicographically
// smallest maximum independent set and is therefore independent of any
// iteration order inside the recursion.
// ---------------------------------------------------------------------------
std::uint32_t mis_cardinality(const ConflictGraph& graph, std::uint64_t candidates,
                              std::unordered_map<std::uint64_t, std::uint32_t>& memo) {
  if (candidates == 0) {
    return 0;
  }
  const auto found = memo.find(candidates);
  if (found != memo.end()) {
    return found->second;
  }
  // Branch on the lowest-indexed candidate.
  std::uint32_t vertex = 0;
  while (((candidates >> vertex) & 1ULL) == 0ULL) {
    ++vertex;
  }
  const std::uint64_t without = candidates & ~(1ULL << vertex);
  std::uint64_t neighbours = 0;
  for (std::uint32_t other = 0; other < graph.path_count; ++other) {
    if (graph.edge(vertex, other)) {
      neighbours |= (1ULL << other);
    }
  }
  const std::uint64_t with = candidates & ~neighbours & ~(1ULL << vertex);
  const std::uint32_t excluded = mis_cardinality(graph, without, memo);
  const std::uint32_t included = 1U + mis_cardinality(graph, with, memo);
  const std::uint32_t best = included > excluded ? included : excluded;
  memo.emplace(candidates, best);
  return best;
}

std::vector<std::uint32_t> mis_witness(const ConflictGraph& graph) {
  std::unordered_map<std::uint64_t, std::uint32_t> memo;
  const std::uint64_t all = (graph.path_count >= 64)
                                ? ~0ULL
                                : ((1ULL << graph.path_count) - 1ULL);
  std::vector<std::uint32_t> witness;
  std::uint64_t candidates = all;
  while (candidates != 0) {
    bool took = false;
    for (std::uint32_t vertex = 0; vertex < graph.path_count; ++vertex) {
      if (((candidates >> vertex) & 1ULL) == 0ULL) {
        continue;
      }
      std::uint64_t neighbours = 0;
      for (std::uint32_t other = 0; other < graph.path_count; ++other) {
        if (graph.edge(vertex, other)) {
          neighbours |= (1ULL << other);
        }
      }
      const std::uint64_t rest = candidates & ~neighbours & ~(1ULL << vertex);
      if (1U + mis_cardinality(graph, rest, memo) == mis_cardinality(graph, candidates, memo)) {
        witness.push_back(vertex);
        candidates = rest;
        took = true;
        break;
      }
    }
    if (!took) {
      break;
    }
  }
  return witness;
}

// Independent brute-force maximum, used to cross-check the branch-and-bound
// result for path sets small enough to enumerate exhaustively.
std::vector<std::uint32_t> mis_exhaustive(const ConflictGraph& graph) {
  const std::uint32_t n = graph.path_count;
  std::vector<std::uint32_t> best;
  const std::uint64_t limit = 1ULL << n;
  for (std::uint64_t mask = 1; mask < limit; ++mask) {
    std::vector<std::uint32_t> candidate;
    bool independent = true;
    for (std::uint32_t i = 0; i < n && independent; ++i) {
      if (((mask >> i) & 1ULL) == 0ULL) {
        continue;
      }
      for (std::uint32_t chosen : candidate) {
        if (graph.edge(i, chosen)) {
          independent = false;
          break;
        }
      }
      candidate.push_back(i);
    }
    if (!independent) {
      continue;
    }
    if (candidate.size() > best.size()) {
      best = candidate;
    }
  }
  return best;
}

ConflictGraph graph_from_matrix(const PairwiseMatrix& matrix, bool known_conflict_only) {
  ConflictGraph graph;
  graph.path_count = static_cast<std::uint32_t>(matrix.order.size());
  graph.adjacent.assign(static_cast<std::size_t>(graph.path_count) * graph.path_count, 0);
  for (std::uint32_t i = 0; i < graph.path_count; ++i) {
    for (std::uint32_t j = i + 1; j < graph.path_count; ++j) {
      const PairwiseCell* cell = matrix.at(i, j);
      if (cell == nullptr) {
        continue;
      }
      const bool conflict = known_conflict_only ? cell_has_conflict(*cell) : !cell->independent;
      if (conflict) {
        graph.adjacent[static_cast<std::size_t>(i) * graph.path_count + j] = 1;
        graph.adjacent[static_cast<std::size_t>(j) * graph.path_count + i] = 1;
      }
    }
  }
  return graph;
}

std::vector<std::uint32_t> sorted_indices_of(const std::vector<std::uint32_t>& witness) {
  std::vector<std::uint32_t> out = witness;
  std::sort(out.begin(), out.end());
  return out;
}

void aggregate_class(const std::vector<const ClassResult*>& sources, DiversityClass klass,
                     ClassResult& out, std::uint32_t max_shared) {
  out.klass = klass;
  out.outcome = ProofOutcome::PROVEN_DIVERSE;
  out.evidence_complete = true;
  for (const ClassResult* source : sources) {
    if (source == nullptr) {
      continue;
    }
    if (!source->evidence_complete) {
      out.evidence_complete = false;
      if (out.detail.empty()) {
        out.detail = source->detail;
      }
    }
    // The reported total is the sum of what each pair actually observed, not the
    // number of entries that survived the bound: a bounded list must never
    // understate how much was shared.
    out.shared_total += source->shared_total;
    for (const SharedResource& conflict : source->shared) {
      if (out.shared.size() < max_shared) {
        out.shared.push_back(conflict);
      }
    }
    if (source->outcome == ProofOutcome::NOT_DIVERSE) {
      out.outcome = ProofOutcome::NOT_DIVERSE;
      if (out.detail.empty()) {
        out.detail = source->detail;
      }
    } else if (source->outcome == ProofOutcome::UNKNOWN_INCOMPLETE_EVIDENCE &&
               out.outcome != ProofOutcome::NOT_DIVERSE) {
      out.outcome = ProofOutcome::UNKNOWN_INCOMPLETE_EVIDENCE;
      if (out.detail.empty()) {
        out.detail = source->detail;
      }
    }
  }
  canonical_conflict_order(out.shared);
}

std::vector<const ClassResult*> gather(const std::vector<PairwiseCell>& cells, DiversityClass klass) {
  std::vector<const ClassResult*> out;
  for (const PairwiseCell& cell : cells) {
    for (const ClassResult& result : cell.classes) {
      if (result.klass == klass) {
        out.push_back(&result);
        break;
      }
    }
  }
  return out;
}

}  // namespace internal

using internal::graph_from_matrix;
using internal::mis_exhaustive;
using internal::mis_witness;
using internal::sorted_indices_of;

bool ConflictGraph::edge(std::uint32_t i, std::uint32_t j) const noexcept {
  if (i >= path_count || j >= path_count) {
    return false;
  }
  return adjacent[static_cast<std::size_t>(i) * path_count + j] != 0;
}

std::uint64_t ConflictGraph::edge_count() const noexcept {
  std::uint64_t count = 0;
  for (std::uint32_t i = 0; i < path_count; ++i) {
    for (std::uint32_t j = i + 1; j < path_count; ++j) {
      if (edge(i, j)) {
        ++count;
      }
    }
  }
  return count;
}

std::vector<std::uint32_t> ConflictGraph::neighbours(std::uint32_t vertex) const {
  std::vector<std::uint32_t> out;
  for (std::uint32_t other = 0; other < path_count; ++other) {
    if (edge(vertex, other)) {
      out.push_back(other);
    }
  }
  return out;
}

ConflictGraph build_conflict_graph(const PairwiseMatrix& matrix) {
  ConflictGraph graph;
  graph.path_count = static_cast<std::uint32_t>(matrix.order.size());
  graph.adjacent.assign(static_cast<std::size_t>(graph.path_count) * graph.path_count, 0);
  for (std::uint32_t i = 0; i < graph.path_count; ++i) {
    for (std::uint32_t j = 0; j < graph.path_count; ++j) {
      if (i == j) {
        continue;
      }
      const PairwiseCell* cell = matrix.at(i, j);
      if (cell != nullptr && !cell->independent) {
        graph.adjacent[static_cast<std::size_t>(i) * graph.path_count + j] = 1;
      }
    }
  }
  return graph;
}

bool verify_witness(const PairwiseMatrix& matrix, const std::vector<std::uint32_t>& indices) noexcept {
  for (std::size_t i = 0; i < indices.size(); ++i) {
    if (indices[i] >= matrix.order.size()) {
      return false;
    }
    for (std::size_t j = i + 1; j < indices.size(); ++j) {
      if (indices[i] == indices[j]) {
        return false;
      }
      const PairwiseCell* cell = matrix.at(indices[i], indices[j]);
      if (cell == nullptr || !cell->independent || !cell->evidence_complete) {
        return false;
      }
    }
  }
  return true;
}

std::optional<WitnessSubset> maximum_independent_subset(const PairwiseMatrix& matrix,
                                                        std::uint32_t requested_k,
                                                        const Limits& limits) {
  const std::size_t path_count = matrix.order.size();
  if (path_count > limits.max_k_subset_paths || path_count > 32) {
    // No heuristic is substituted: a caller that needs an answer for a larger
    // set must supply stronger semantics rather than receive a guess.
    return std::nullopt;
  }
  const ConflictGraph graph = graph_from_matrix(matrix, false);
  std::vector<std::uint32_t> witness = sorted_indices_of(mis_witness(graph));
  bool exact = true;
  if (path_count <= 16) {
    const std::vector<std::uint32_t> brute = sorted_indices_of(mis_exhaustive(graph));
    if (brute.size() != witness.size()) {
      // The two independent computations disagree: report the larger and mark
      // the result as not proven exact rather than silently trusting one.
      exact = false;
      if (brute.size() > witness.size()) {
        witness = brute;
      }
    }
  }
  WitnessSubset subset;
  subset.present = true;
  subset.requested_k = requested_k;
  subset.indices = witness;
  subset.achieved = static_cast<std::uint32_t>(witness.size());
  subset.maximum_exact = exact;
  return subset;
}

}  // namespace path_diversity
