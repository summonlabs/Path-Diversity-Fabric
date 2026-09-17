// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "path_diversity/canonical.hpp"
#include "path_diversity/export.hpp"
#include "path_diversity/ids.hpp"

namespace path_diversity {

// ---------------------------------------------------------------------------
// The kinds of structural entity a path can traverse. These are consumed
// verbatim from authoritative identity; Path Diversity Fabric never mints one.
// ---------------------------------------------------------------------------
enum class EntityKind : std::uint8_t {
  ENDPOINT = 1,
  NODE = 2,
  LINK = 3,
  DEVICE = 4,
};

PATH_DIVERSITY_API std::string_view to_string(EntityKind value) noexcept;
PATH_DIVERSITY_API bool is_defined_entity_kind(std::uint8_t raw) noexcept;

// A typed reference to one authoritative structural entity.
struct PATH_DIVERSITY_API EntityRef {
  EntityKind kind = EntityKind::LINK;
  std::string id;

  friend bool operator==(const EntityRef&, const EntityRef&) = default;
  friend std::strong_ordering operator<=>(const EntityRef& lhs, const EntityRef& rhs);
  std::string render() const;
  void encode(ByteWriter& writer) const;
};

// ---------------------------------------------------------------------------
// Correlated-failure relations. Failure Domain Registry owns classification and
// coverage; this runtime only consumes it. A relation class is never inferred
// from a name, from a rack label, or from another relation class.
// ---------------------------------------------------------------------------
enum class DomainRelation : std::uint8_t {
  FAILURE_DOMAIN = 1,  // authoritative correlated-failure grouping
  RACK = 2,
  POD = 3,
  SITE = 4,
  POWER_DOMAIN = 5,
  CONDUIT = 6,
  COOLING = 7,
};

PATH_DIVERSITY_API std::string_view to_string(DomainRelation value) noexcept;
PATH_DIVERSITY_API bool is_defined_domain_relation(std::uint8_t raw) noexcept;
PATH_DIVERSITY_API std::string_view domain_relation_name(DomainRelation value) noexcept;

// Coverage is a first-class fact, not a default. ABSENT always means "the
// authority holds no classification for this entity under this relation", and
// never means "this entity is known to belong to no domain".
enum class EvidenceCoverage : std::uint8_t {
  COMPLETE = 1,  // the authority asserts the full membership set
  PARTIAL = 2,   // the authority holds some, but not demonstrably all, membership
  ABSENT = 3,    // the authority holds no classification for this entity
};

PATH_DIVERSITY_API std::string_view to_string(EvidenceCoverage value) noexcept;
PATH_DIVERSITY_API bool is_defined_coverage(std::uint8_t raw) noexcept;

// Domain membership evidence for one entity under one relation class.
struct PATH_DIVERSITY_API DomainEvidence {
  EvidenceCoverage coverage = EvidenceCoverage::ABSENT;
  FailureDomainGeneration generation;
  std::vector<FailureDomainId> domains;

  bool complete() const noexcept { return coverage == EvidenceCoverage::COMPLETE; }
  friend bool operator==(const DomainEvidence&, const DomainEvidence&) = default;
  void canonicalize();
};

// Shared-risk-group (SRLG) membership evidence for one entity.
struct PATH_DIVERSITY_API SrlgEvidence {
  EvidenceCoverage coverage = EvidenceCoverage::ABSENT;
  FailureDomainGeneration generation;
  std::vector<SharedRiskGroupId> groups;

  bool complete() const noexcept { return coverage == EvidenceCoverage::COMPLETE; }
  friend bool operator==(const SrlgEvidence&, const SrlgEvidence&) = default;
  void canonicalize();
};

// ---------------------------------------------------------------------------
// Authoritative path composition. Fabric Topology plus Fabric Registry own the
// structure; Path Diversity Fabric reads it and never derives it.
// ---------------------------------------------------------------------------
struct PATH_DIVERSITY_API PathComposition {
  PathId path;
  PathAuthorityGeneration authority_generation;
  TopologyGeneration topology_generation;

  // Ordered source and destination endpoint nodes. Primary/secondary paths
  // normally share these; endpoint sharing is an explicit policy decision and
  // never an implicit exemption.
  std::vector<NodeId> sources;
  std::vector<NodeId> destinations;
  // Ordered transit nodes: everything the path traverses that is neither a
  // source nor a destination.
  std::vector<NodeId> transit_nodes;
  // Ordered links.
  std::vector<LinkId> links;
  // Ordered devices carrying those links and nodes. Ports on different links
  // do not imply different devices; this set is the authoritative device
  // identity set, not a per-port projection.
  std::vector<DeviceId> devices;

  // Per-set evidence coverage. "The topology returned three links" and "the
  // topology returned every link of this path" are different facts.
  EvidenceCoverage link_coverage = EvidenceCoverage::COMPLETE;
  EvidenceCoverage node_coverage = EvidenceCoverage::COMPLETE;
  EvidenceCoverage device_coverage = EvidenceCoverage::COMPLETE;
  EvidenceCoverage endpoint_coverage = EvidenceCoverage::COMPLETE;

  bool all_topology_complete() const noexcept;

  // Canonical form: every set is sorted ascending. Duplicates are deliberately
  // preserved so that a repeated structural element stays detectable instead of
  // being silently normalized into a valid path; has_repeated_topology_elements
  // reports them and the evaluator rejects the path as MALFORMED.
  void canonicalize();
  bool has_repeated_topology_elements() const noexcept;
  friend bool operator==(const PathComposition&, const PathComposition&) = default;
};

}  // namespace path_diversity
