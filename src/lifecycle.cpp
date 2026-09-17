// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include "path_diversity/lifecycle.hpp"

#include "path_diversity/outcome.hpp"

namespace path_diversity {

std::string_view to_string(LifecycleState value) noexcept {
  switch (value) {
    case LifecycleState::DECLARED:
      return "DECLARED";
    case LifecycleState::CURRENT:
      return "CURRENT";
    case LifecycleState::REVALIDATION_REQUIRED:
      return "REVALIDATION_REQUIRED";
    case LifecycleState::SUPERSEDED:
      return "SUPERSEDED";
    case LifecycleState::REVOKED:
      return "REVOKED";
    case LifecycleState::RETIRED:
      return "RETIRED";
    case LifecycleState::HISTORICAL:
      return "HISTORICAL";
  }
  return "UNKNOWN";
}

bool is_defined_lifecycle_state(std::uint8_t raw) noexcept {
  return raw >= static_cast<std::uint8_t>(LifecycleState::DECLARED) &&
         raw <= static_cast<std::uint8_t>(LifecycleState::HISTORICAL);
}

// Explicit transition table. Anything not listed here is refused, and a
// terminal state never transitions anywhere: a retired proof cannot reactivate.
bool lifecycle_transition_allowed(LifecycleState from, LifecycleState to) noexcept {
  if (from == to) {
    // Re-entering the same state is not a transition; the runtime reports it as
    // UNCHANGED rather than as an illegal transition.
    return true;
  }
  switch (from) {
    case LifecycleState::DECLARED:
      return to == LifecycleState::CURRENT || to == LifecycleState::REVALIDATION_REQUIRED ||
             to == LifecycleState::REVOKED || to == LifecycleState::RETIRED ||
             to == LifecycleState::SUPERSEDED;
    case LifecycleState::CURRENT:
      return to == LifecycleState::REVALIDATION_REQUIRED || to == LifecycleState::SUPERSEDED ||
             to == LifecycleState::REVOKED || to == LifecycleState::RETIRED ||
             to == LifecycleState::HISTORICAL;
    case LifecycleState::REVALIDATION_REQUIRED:
      return to == LifecycleState::CURRENT || to == LifecycleState::SUPERSEDED ||
             to == LifecycleState::REVOKED || to == LifecycleState::RETIRED ||
             to == LifecycleState::HISTORICAL;
    case LifecycleState::SUPERSEDED:
      return to == LifecycleState::CURRENT || to == LifecycleState::REVOKED ||
             to == LifecycleState::RETIRED || to == LifecycleState::HISTORICAL;
    case LifecycleState::HISTORICAL:
      return to == LifecycleState::CURRENT || to == LifecycleState::SUPERSEDED ||
             to == LifecycleState::REVOKED || to == LifecycleState::RETIRED;
    case LifecycleState::REVOKED:
      return false;
    case LifecycleState::RETIRED:
      return false;
  }
  return false;
}

bool lifecycle_is_terminal(LifecycleState value) noexcept {
  return value == LifecycleState::REVOKED || value == LifecycleState::RETIRED;
}

bool lifecycle_is_publishable(LifecycleState value) noexcept {
  return value == LifecycleState::CURRENT;
}

std::string_view to_string(Currentness value) noexcept {
  switch (value) {
    case Currentness::CURRENT:
      return "CURRENT";
    case Currentness::STALE_PATH_AUTHORITY:
      return "STALE_PATH_AUTHORITY";
    case Currentness::STALE_TOPOLOGY:
      return "STALE_TOPOLOGY";
    case Currentness::STALE_FAILURE_DOMAIN:
      return "STALE_FAILURE_DOMAIN";
    case Currentness::STALE_POLICY:
      return "STALE_POLICY";
    case Currentness::STALE_EPOCH:
      return "STALE_EPOCH";
    case Currentness::FENCED_PUBLISHER:
      return "FENCED_PUBLISHER";
    case Currentness::INCOMPLETE_EVIDENCE:
      return "INCOMPLETE_EVIDENCE";
    case Currentness::REVALIDATION_REQUIRED:
      return "REVALIDATION_REQUIRED";
  }
  return "UNKNOWN";
}

bool is_defined_currentness(std::uint8_t raw) noexcept {
  return raw >= static_cast<std::uint8_t>(Currentness::CURRENT) &&
         raw <= static_cast<std::uint8_t>(Currentness::REVALIDATION_REQUIRED);
}

bool currentness_is_current(Currentness value) noexcept { return value == Currentness::CURRENT; }

Currentness currentness_for_outcome(ProofOutcome outcome) noexcept {
  switch (outcome) {
    case ProofOutcome::PROVEN_DIVERSE:
    case ProofOutcome::NOT_DIVERSE:
      return Currentness::CURRENT;
    case ProofOutcome::STALE_PATH_AUTHORITY:
      return Currentness::STALE_PATH_AUTHORITY;
    case ProofOutcome::STALE_TOPOLOGY:
      return Currentness::STALE_TOPOLOGY;
    case ProofOutcome::STALE_FAILURE_DOMAIN:
      return Currentness::STALE_FAILURE_DOMAIN;
    case ProofOutcome::STALE_POLICY:
      return Currentness::STALE_POLICY;
    case ProofOutcome::UNKNOWN_INCOMPLETE_EVIDENCE:
      return Currentness::INCOMPLETE_EVIDENCE;
    case ProofOutcome::REVALIDATION_REQUIRED:
      return Currentness::REVALIDATION_REQUIRED;
    case ProofOutcome::UNAUTHORIZED:
      // An unauthorized path is a Path Authority currentness problem; only an
      // observed boot fence produces FENCED_PUBLISHER.
      return Currentness::STALE_PATH_AUTHORITY;
    case ProofOutcome::RESOURCE_LIMIT:
    case ProofOutcome::MALFORMED:
      return Currentness::REVALIDATION_REQUIRED;
  }
  return Currentness::REVALIDATION_REQUIRED;
}

Currentness currentness_for_stale_generation() noexcept {
  return Currentness::REVALIDATION_REQUIRED;
}

}  // namespace path_diversity
