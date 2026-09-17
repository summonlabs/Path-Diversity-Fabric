// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include "path_diversity/domain.hpp"

#include <algorithm>
#include <string>

#include "path_diversity/diversity_class.hpp"

namespace path_diversity {

namespace {

template <class Container>
bool has_repeats_sorted(const Container& values) {
  for (std::size_t i = 1; i < values.size(); ++i) {
    if (values[i] == values[i - 1]) {
      return true;
    }
  }
  return false;
}

}  // namespace

// ---------------------------------------------------------------------------
// Entity kinds
// ---------------------------------------------------------------------------
std::string_view to_string(EntityKind value) noexcept {
  switch (value) {
    case EntityKind::ENDPOINT:
      return "ENDPOINT";
    case EntityKind::NODE:
      return "NODE";
    case EntityKind::LINK:
      return "LINK";
    case EntityKind::DEVICE:
      return "DEVICE";
  }
  return "UNKNOWN";
}

bool is_defined_entity_kind(std::uint8_t raw) noexcept {
  return raw >= static_cast<std::uint8_t>(EntityKind::ENDPOINT) &&
         raw <= static_cast<std::uint8_t>(EntityKind::DEVICE);
}

std::strong_ordering operator<=>(const EntityRef& lhs, const EntityRef& rhs) {
  if (lhs.kind != rhs.kind) {
    return lhs.kind < rhs.kind ? std::strong_ordering::less : std::strong_ordering::greater;
  }
  return lhs.id < rhs.id ? std::strong_ordering::less
                         : (lhs.id == rhs.id ? std::strong_ordering::equal
                                             : std::strong_ordering::greater);
}

std::string EntityRef::render() const {
  std::string out(to_string(kind));
  out += " ";
  out += id;
  return out;
}

void EntityRef::encode(ByteWriter& writer) const {
  writer.u8(static_cast<std::uint8_t>(kind));
  writer.text(id);
}

// ---------------------------------------------------------------------------
// Domain relations and coverage
// ---------------------------------------------------------------------------
std::string_view to_string(DomainRelation value) noexcept {
  switch (value) {
    case DomainRelation::FAILURE_DOMAIN:
      return "FAILURE_DOMAIN";
    case DomainRelation::RACK:
      return "RACK";
    case DomainRelation::POD:
      return "POD";
    case DomainRelation::SITE:
      return "SITE";
    case DomainRelation::POWER_DOMAIN:
      return "POWER_DOMAIN";
    case DomainRelation::CONDUIT:
      return "CONDUIT";
    case DomainRelation::COOLING:
      return "COOLING";
  }
  return "UNKNOWN";
}

std::string_view domain_relation_name(DomainRelation value) noexcept { return to_string(value); }

bool is_defined_domain_relation(std::uint8_t raw) noexcept {
  return raw >= static_cast<std::uint8_t>(DomainRelation::FAILURE_DOMAIN) &&
         raw <= static_cast<std::uint8_t>(DomainRelation::COOLING);
}

std::string_view to_string(EvidenceCoverage value) noexcept {
  switch (value) {
    case EvidenceCoverage::COMPLETE:
      return "COMPLETE";
    case EvidenceCoverage::PARTIAL:
      return "PARTIAL";
    case EvidenceCoverage::ABSENT:
      return "ABSENT";
  }
  return "UNKNOWN";
}

bool is_defined_coverage(std::uint8_t raw) noexcept {
  return raw >= static_cast<std::uint8_t>(EvidenceCoverage::COMPLETE) &&
         raw <= static_cast<std::uint8_t>(EvidenceCoverage::ABSENT);
}

void DomainEvidence::canonicalize() {
  canonical_sort_unique(domains);
}

void SrlgEvidence::canonicalize() { canonical_sort_unique(groups); }

// ---------------------------------------------------------------------------
// Diversity classes
// ---------------------------------------------------------------------------
std::string_view to_string(DiversityClass value) noexcept {
  switch (value) {
    case DiversityClass::LINK_DISJOINT:
      return "LINK_DISJOINT";
    case DiversityClass::TRANSIT_NODE_DISJOINT:
      return "TRANSIT_NODE_DISJOINT";
    case DiversityClass::DEVICE_DISJOINT:
      return "DEVICE_DISJOINT";
    case DiversityClass::RACK_DISJOINT:
      return "RACK_DISJOINT";
    case DiversityClass::POD_DISJOINT:
      return "POD_DISJOINT";
    case DiversityClass::SITE_DISJOINT:
      return "SITE_DISJOINT";
    case DiversityClass::FAILURE_DOMAIN_DISJOINT:
      return "FAILURE_DOMAIN_DISJOINT";
    case DiversityClass::SHARED_RISK_GROUP_DISJOINT:
      return "SHARED_RISK_GROUP_DISJOINT";
  }
  return "UNKNOWN";
}

bool is_defined_diversity_class(std::uint8_t raw) noexcept {
  return raw >= static_cast<std::uint8_t>(DiversityClass::LINK_DISJOINT) &&
         raw <= static_cast<std::uint8_t>(DiversityClass::SHARED_RISK_GROUP_DISJOINT);
}

std::optional<DiversityClass> diversity_class_from_string(std::string_view text) noexcept {
  for (std::uint8_t raw = static_cast<std::uint8_t>(DiversityClass::LINK_DISJOINT);
       raw <= static_cast<std::uint8_t>(DiversityClass::SHARED_RISK_GROUP_DISJOINT); ++raw) {
    const DiversityClass candidate = static_cast<DiversityClass>(raw);
    if (to_string(candidate) == text) {
      return candidate;
    }
  }
  return std::nullopt;
}

std::vector<DomainRelation> required_domain_relations(DiversityClass value) noexcept {
  switch (value) {
    case DiversityClass::LINK_DISJOINT:
    case DiversityClass::TRANSIT_NODE_DISJOINT:
    case DiversityClass::DEVICE_DISJOINT:
    case DiversityClass::SHARED_RISK_GROUP_DISJOINT:
      return {};
    case DiversityClass::RACK_DISJOINT:
      return {DomainRelation::RACK};
    case DiversityClass::POD_DISJOINT:
      return {DomainRelation::POD};
    case DiversityClass::SITE_DISJOINT:
      return {DomainRelation::SITE};
    case DiversityClass::FAILURE_DOMAIN_DISJOINT:
      // Supplied by the policy: the relation set is declared, never assumed.
      return {};
  }
  return {};
}

bool is_domain_backed(DiversityClass value) noexcept {
  switch (value) {
    case DiversityClass::RACK_DISJOINT:
    case DiversityClass::POD_DISJOINT:
    case DiversityClass::SITE_DISJOINT:
    case DiversityClass::FAILURE_DOMAIN_DISJOINT:
      return true;
    case DiversityClass::LINK_DISJOINT:
    case DiversityClass::TRANSIT_NODE_DISJOINT:
    case DiversityClass::DEVICE_DISJOINT:
    case DiversityClass::SHARED_RISK_GROUP_DISJOINT:
      return false;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Path composition
// ---------------------------------------------------------------------------
bool PathComposition::all_topology_complete() const noexcept {
  return link_coverage == EvidenceCoverage::COMPLETE &&
         node_coverage == EvidenceCoverage::COMPLETE &&
         device_coverage == EvidenceCoverage::COMPLETE &&
         endpoint_coverage == EvidenceCoverage::COMPLETE;
}

void PathComposition::canonicalize() {
  std::sort(sources.begin(), sources.end());
  std::sort(destinations.begin(), destinations.end());
  std::sort(transit_nodes.begin(), transit_nodes.end());
  std::sort(links.begin(), links.end());
  std::sort(devices.begin(), devices.end());
}

bool PathComposition::has_repeated_topology_elements() const noexcept {
  return has_repeats_sorted(sources) || has_repeats_sorted(destinations) ||
         has_repeats_sorted(transit_nodes) || has_repeats_sorted(links) ||
         has_repeats_sorted(devices);
}

}  // namespace path_diversity
