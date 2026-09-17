// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

#include "path_diversity/domain.hpp"
#include "path_diversity/export.hpp"

namespace path_diversity {

// Only explicit, evidence-backed classes exist. No class is ever inferred from
// another: a link-disjoint pair may still share a rack, a switch chassis, a
// conduit, a power domain or a shared-risk group, and this runtime says so
// rather than collapsing the classes.
enum class DiversityClass : std::uint8_t {
  LINK_DISJOINT = 1,
  TRANSIT_NODE_DISJOINT = 2,
  DEVICE_DISJOINT = 3,
  RACK_DISJOINT = 4,
  POD_DISJOINT = 5,
  SITE_DISJOINT = 6,
  FAILURE_DOMAIN_DISJOINT = 7,
  SHARED_RISK_GROUP_DISJOINT = 8,
};

PATH_DIVERSITY_API std::string_view to_string(DiversityClass value) noexcept;
PATH_DIVERSITY_API std::optional<DiversityClass> diversity_class_from_string(
    std::string_view text) noexcept;
PATH_DIVERSITY_API bool is_defined_diversity_class(std::uint8_t raw) noexcept;

// The authoritative relation classes a diversity class is evaluated against.
// An empty result means the class is not domain-based; a class whose relation
// list is empty at policy time is a policy defect, not a silent pass.
PATH_DIVERSITY_API std::vector<DomainRelation> required_domain_relations(
    DiversityClass value) noexcept;

// True when the class consults Failure Domain Registry membership under exactly
// these relations.
PATH_DIVERSITY_API bool is_domain_backed(DiversityClass value) noexcept;

}  // namespace path_diversity
