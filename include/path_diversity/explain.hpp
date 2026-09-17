// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "path_diversity/export.hpp"
#include "path_diversity/ids.hpp"
#include "path_diversity/limits.hpp"
#include "path_diversity/outcome.hpp"
#include "path_diversity/proof.hpp"

namespace path_diversity {

// Structured explanations. Every entry names the exact subject it is about and
// the exact class it belongs to, so an operator dashboard, a CLI and a test can
// all consume the same structure and the same deterministic rendering.
enum class ExplanationKind : std::uint8_t {
  POLICY = 1,
  REQUIRED_CLASS = 2,
  ENDPOINT_SEMANTICS = 3,
  SHARED_LINK = 4,
  SHARED_TRANSIT_NODE = 5,
  SHARED_DEVICE = 6,
  SHARED_DOMAIN = 7,
  SHARED_RISK_GROUP = 8,
  MISSING_EVIDENCE = 9,
  STALE_GENERATION = 10,
  PROOF_RESULT = 11,
  WITNESS = 12,
  CONFLICT_GRAPH = 13,
  PAIR_RESULT = 14,
  RESOURCE_LIMIT = 15,
  DEPENDENCY = 16,
};

PATH_DIVERSITY_API std::string_view to_string(ExplanationKind value) noexcept;
PATH_DIVERSITY_API bool is_defined_explanation_kind(std::uint8_t raw) noexcept;

struct PATH_DIVERSITY_API ExplanationEntry {
  ExplanationKind kind = ExplanationKind::PROOF_RESULT;
  DiversityClass klass = DiversityClass::LINK_DISJOINT;
  ProofOutcome outcome = ProofOutcome::MALFORMED;
  // Canonical identity of what the entry is about: a link, a node, a device, a
  // domain, a generation, a path index range or a policy class.
  std::string subject;
  std::string detail;
  // Canonical indices into the proof path order, ascending.
  std::vector<std::uint32_t> paths;
  friend bool operator==(const ExplanationEntry&, const ExplanationEntry&) = default;
  std::string render() const;
};

struct PATH_DIVERSITY_API Explanation {
  DiversityProofId proof;
  DiversityProofGeneration generation;
  ProofOutcome outcome = ProofOutcome::MALFORMED;
  std::vector<ExplanationEntry> entries;
  bool truncated = false;
  std::uint64_t entries_total = 0;
  friend bool operator==(const Explanation&, const Explanation&) = default;
  std::string render() const;
};

// Full explanation of a proof: required classes, endpoint semantics, every
// shared resource with the evidence generation that proves it, the exact
// missing evidence when the outcome is UNKNOWN, the exact stale generation when
// the outcome is a staleness outcome, and the exact witness subset.
PATH_DIVERSITY_API Explanation explain_proof(const DiversityProof& proof, const Limits& limits);

// Focused explanation of one canonical pair.
PATH_DIVERSITY_API Explanation explain_pair(const DiversityProof& proof, std::uint32_t left,
                                            std::uint32_t right, const Limits& limits);

// Deterministic rendering shared by the CLI, the examples and the tests.
PATH_DIVERSITY_API std::string render_explanation(const Explanation& explanation);

}  // namespace path_diversity
