// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

#include <cstdint>
#include <string_view>

#include "path_diversity/export.hpp"
#include "path_diversity/outcome.hpp"

namespace path_diversity {

// Lifecycle is what the operator did to a proof. Currentness is whether the
// proof still describes the world. They are separate axes and are never merged:
// a CURRENT proof can be stale, and a REVOKED proof can be perfectly accurate.
enum class LifecycleState : std::uint8_t {
  DECLARED = 1,
  CURRENT = 2,
  REVALIDATION_REQUIRED = 3,
  SUPERSEDED = 4,
  REVOKED = 5,
  RETIRED = 6,
  HISTORICAL = 7,
};

PATH_DIVERSITY_API std::string_view to_string(LifecycleState value) noexcept;
PATH_DIVERSITY_API bool is_defined_lifecycle_state(std::uint8_t raw) noexcept;

// The explicit transition table. Any transition not listed is rejected; a
// retired proof can never reactivate.
PATH_DIVERSITY_API bool lifecycle_transition_allowed(LifecycleState from, LifecycleState to) noexcept;
// RETIRED and REVOKED are terminal: no transition leaves them.
PATH_DIVERSITY_API bool lifecycle_is_terminal(LifecycleState value) noexcept;
// A proof in one of these states may be published as authoritative.
PATH_DIVERSITY_API bool lifecycle_is_publishable(LifecycleState value) noexcept;

enum class Currentness : std::uint8_t {
  CURRENT = 1,
  STALE_PATH_AUTHORITY = 2,
  STALE_TOPOLOGY = 3,
  STALE_FAILURE_DOMAIN = 4,
  STALE_POLICY = 5,
  STALE_EPOCH = 6,
  FENCED_PUBLISHER = 7,
  INCOMPLETE_EVIDENCE = 8,
  REVALIDATION_REQUIRED = 9,
};

PATH_DIVERSITY_API std::string_view to_string(Currentness value) noexcept;
PATH_DIVERSITY_API bool is_defined_currentness(std::uint8_t raw) noexcept;
PATH_DIVERSITY_API bool currentness_is_current(Currentness value) noexcept;
// Maps a stale/demoting evaluation outcome onto the exact currentness cause.
PATH_DIVERSITY_API Currentness currentness_for_outcome(ProofOutcome outcome) noexcept;
PATH_DIVERSITY_API Currentness currentness_for_stale_generation() noexcept;

}  // namespace path_diversity
