// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "path_diversity/export.hpp"
#include "path_diversity/limits.hpp"
#include "path_diversity/policy.hpp"
#include "path_diversity/proof.hpp"

namespace path_diversity {

// Result of a registry mutation or of a proof commit. This type is shared by the
// in-process runtime and the distributed protocol, so a remote caller and a
// local caller observe exactly the same taxonomy of outcomes.
enum class MutationStatus : std::uint8_t {
  APPLIED = 1,
  // The exact replay of an already-applied attempt. Nothing advanced.
  IDEMPOTENT = 2,
  // An exact revalidation whose inputs and result were unchanged: the proof
  // stays at its current generation and nothing advances.
  UNCHANGED = 3,
  UNAUTHORIZED = 4,
  FENCED_PUBLISHER = 5,
  STALE_EPOCH = 6,
  SCOPE_MISMATCH = 7,
  GENERATION_CONFLICT = 8,
  ATTEMPT_CONFLICT = 9,
  LIMIT_EXCEEDED = 10,
  MALFORMED = 11,
  NOT_FOUND = 12,
  ILLEGAL_TRANSITION = 13,
  // The evaluation completed, but its dependency watermarks moved while it ran,
  // so the result was not allowed to become CURRENT.
  REVALIDATION_REQUIRED = 14,
};

PATH_DIVERSITY_API std::string_view to_string(MutationStatus value) noexcept;
PATH_DIVERSITY_API bool is_defined_mutation_status(std::uint8_t raw) noexcept;
PATH_DIVERSITY_API bool mutation_status_is_success(MutationStatus value) noexcept;

struct PATH_DIVERSITY_API MutationResult {
  MutationStatus status = MutationStatus::MALFORMED;
  std::string detail;
  std::optional<ResourceLimitNotice> limit;
  // Populated for policy publication and for proof evaluation/commit.
  DiversityPolicy policy;
  DiversityProof proof;
  bool has_policy = false;
  bool has_proof = false;

  bool ok() const noexcept { return mutation_status_is_success(status); }
  std::string render() const;
};

}  // namespace path_diversity
