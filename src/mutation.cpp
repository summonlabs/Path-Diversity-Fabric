// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include "path_diversity/mutation.hpp"

namespace path_diversity {

std::string_view to_string(MutationStatus value) noexcept {
  switch (value) {
    case MutationStatus::APPLIED:
      return "APPLIED";
    case MutationStatus::IDEMPOTENT:
      return "IDEMPOTENT";
    case MutationStatus::UNCHANGED:
      return "UNCHANGED";
    case MutationStatus::UNAUTHORIZED:
      return "UNAUTHORIZED";
    case MutationStatus::FENCED_PUBLISHER:
      return "FENCED_PUBLISHER";
    case MutationStatus::STALE_EPOCH:
      return "STALE_EPOCH";
    case MutationStatus::SCOPE_MISMATCH:
      return "SCOPE_MISMATCH";
    case MutationStatus::GENERATION_CONFLICT:
      return "GENERATION_CONFLICT";
    case MutationStatus::ATTEMPT_CONFLICT:
      return "ATTEMPT_CONFLICT";
    case MutationStatus::LIMIT_EXCEEDED:
      return "LIMIT_EXCEEDED";
    case MutationStatus::MALFORMED:
      return "MALFORMED";
    case MutationStatus::NOT_FOUND:
      return "NOT_FOUND";
    case MutationStatus::ILLEGAL_TRANSITION:
      return "ILLEGAL_TRANSITION";
    case MutationStatus::REVALIDATION_REQUIRED:
      return "REVALIDATION_REQUIRED";
  }
  return "UNKNOWN";
}

bool is_defined_mutation_status(std::uint8_t raw) noexcept {
  return raw >= static_cast<std::uint8_t>(MutationStatus::APPLIED) &&
         raw <= static_cast<std::uint8_t>(MutationStatus::REVALIDATION_REQUIRED);
}

bool mutation_status_is_success(MutationStatus value) noexcept {
  return value == MutationStatus::APPLIED || value == MutationStatus::IDEMPOTENT ||
         value == MutationStatus::UNCHANGED;
}

std::string MutationResult::render() const {
  std::string out = std::string(to_string(status));
  if (!detail.empty()) {
    out += ": ";
    out += detail;
  }
  if (limit.has_value()) {
    out += " [";
    out += limit->render();
    out += "]";
  }
  if (has_proof) {
    out += " proof=";
    out += proof.id.str();
    out += "@g";
    out += std::to_string(proof.generation.value());
    out += " outcome=";
    out += std::string(to_string(proof.outcome));
    out += " lifecycle=";
    out += std::string(to_string(proof.lifecycle));
    out += " currentness=";
    out += std::string(to_string(proof.currentness));
  }
  if (has_policy) {
    out += " policy=";
    out += policy.render();
  }
  return out;
}

}  // namespace path_diversity
