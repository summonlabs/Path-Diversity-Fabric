// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "path_diversity/canonical.hpp"
#include "path_diversity/digest.hpp"
#include "path_diversity/diversity_class.hpp"
#include "path_diversity/export.hpp"
#include "path_diversity/ids.hpp"
#include "path_diversity/limits.hpp"

namespace path_diversity {

// How source/destination sharing is treated by TRANSIT_NODE_DISJOINT and by the
// device/domain classes that include endpoint entities. Endpoint semantics are
// never hidden in an ad hoc special case: they are policy, they are versioned
// with the policy, and they are part of the proof digest.
enum class EndpointExemption : std::uint8_t {
  NONE = 1,                      // endpoints are ordinary nodes; sharing fails
  SHARED_SOURCE_AND_DESTINATION = 2,
  SHARED_SOURCE_ONLY = 3,
  SHARED_DESTINATION_ONLY = 4,
  ANY_ENDPOINT = 5,
};

PATH_DIVERSITY_API std::string_view to_string(EndpointExemption value) noexcept;
PATH_DIVERSITY_API std::optional<EndpointExemption> endpoint_exemption_from_string(
    std::string_view text) noexcept;
PATH_DIVERSITY_API bool is_defined_endpoint_exemption(std::uint8_t raw) noexcept;

// Set-wise semantics. ALL_PAIRS means every ordered pair of the canonical path
// set must satisfy every required class. AT_LEAST_K_INDEPENDENT means a subset
// of at least K mutually independent paths must exist. N-path diversity is
// never silently reduced to "P1 differs from everyone".
enum class SetSemantics : std::uint8_t {
  ALL_PAIRS = 1,
  AT_LEAST_K_INDEPENDENT = 2,
};

PATH_DIVERSITY_API std::string_view to_string(SetSemantics value) noexcept;
PATH_DIVERSITY_API std::optional<SetSemantics> set_semantics_from_string(
    std::string_view text) noexcept;
PATH_DIVERSITY_API bool is_defined_set_semantics(std::uint8_t raw) noexcept;

// How a policy combines incomplete evidence with an observed conflict.
//
// Neither option can ever produce PROVEN_DIVERSE from incomplete evidence:
// absence of evidence is not evidence of disjointness.
enum class CompletenessRequirement : std::uint8_t {
  // Conservative: any required class whose evidence is incomplete for any path
  // of the set yields UNKNOWN_INCOMPLETE_EVIDENCE, even when another required
  // class already shows a concrete shared resource.
  REQUIRE_COMPLETE_EVIDENCE = 1,
  // A conflict that was actually observed is positive evidence and decides
  // NOT_DIVERSE even while some other required class is still incomplete.
  // Incomplete evidence without an observed conflict still yields
  // UNKNOWN_INCOMPLETE_EVIDENCE.
  PROVEN_CONFLICT_DECISIVE = 2,
};

PATH_DIVERSITY_API std::string_view to_string(CompletenessRequirement value) noexcept;
PATH_DIVERSITY_API std::optional<CompletenessRequirement> completeness_requirement_from_string(
    std::string_view text) noexcept;
PATH_DIVERSITY_API bool is_defined_completeness_requirement(std::uint8_t raw) noexcept;

// What an incomplete-evidence evaluation produces. Neither option can ever
// produce PROVEN_DIVERSE: absence of evidence is not evidence of disjointness.
enum class UnknownBehavior : std::uint8_t {
  REJECT_PROOF = 1,             // UNKNOWN_INCOMPLETE_EVIDENCE
  DEMOTE_TO_REVALIDATION = 2,   // REVALIDATION_REQUIRED
};

PATH_DIVERSITY_API std::string_view to_string(UnknownBehavior value) noexcept;
PATH_DIVERSITY_API std::optional<UnknownBehavior> unknown_behavior_from_string(
    std::string_view text) noexcept;
PATH_DIVERSITY_API bool is_defined_unknown_behavior(std::uint8_t raw) noexcept;

// An explicit, versioned, authority-bound diversity policy.
struct PATH_DIVERSITY_API DiversityPolicy {
  DiversityPolicyId id;
  DiversityPolicyGeneration generation;
  ScopeId scope;
  std::vector<DiversityClass> required_classes;
  EndpointExemption endpoint_exemption = EndpointExemption::SHARED_SOURCE_AND_DESTINATION;
  std::uint32_t minimum_independent_paths = 2;
  SetSemantics semantics = SetSemantics::ALL_PAIRS;
  CompletenessRequirement completeness = CompletenessRequirement::REQUIRE_COMPLETE_EVIDENCE;
  UnknownBehavior unknown_behavior = UnknownBehavior::REJECT_PROOF;
  // Relations consulted by FAILURE_DOMAIN_DISJOINT. Must be non-empty whenever
  // that class is required: "no shared domain observed" is only meaningful
  // against a declared relation set.
  std::vector<DomainRelation> allowed_failure_domain_relations;
  bool require_path_authority_current = true;
  std::string description;

  void canonicalize();
  Digest semantic_digest() const;
  friend bool operator==(const DiversityPolicy&, const DiversityPolicy&) = default;
  std::string render() const;
};

enum class PolicyStatus : std::uint8_t {
  VALID = 0,
  INVALID_IDENTITY,
  UNSET_GENERATION,
  NO_REQUIRED_CLASSES,
  TOO_MANY_REQUIRED_CLASSES,
  DUPLICATE_REQUIRED_CLASS,
  UNKNOWN_REQUIRED_CLASS,
  INVALID_MINIMUM_INDEPENDENT_PATHS,
  MINIMUM_EXCEEDS_PATH_BOUND,
  UNKNOWN_DOMAIN_RELATION,
  DUPLICATE_DOMAIN_RELATION,
  MISSING_DOMAIN_RELATIONS,
  DESCRIPTION_TOO_LONG,
  INVALID_SCOPE,
};

PATH_DIVERSITY_API std::string_view to_string(PolicyStatus status) noexcept;

struct PATH_DIVERSITY_API PolicyValidation {
  PolicyStatus status = PolicyStatus::VALID;
  std::string detail;
  bool ok() const noexcept { return status == PolicyStatus::VALID; }
};

PATH_DIVERSITY_API PolicyValidation validate_policy(const DiversityPolicy& policy,
                                                    const Limits& limits);

// Canonical policy id derived from canonical content: "dpol-<hex>".
PATH_DIVERSITY_API DiversityPolicyId derived_policy_id(const Digest& digest);

}  // namespace path_diversity
