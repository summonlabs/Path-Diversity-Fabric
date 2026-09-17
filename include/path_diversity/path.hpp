// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

#include <compare>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "path_diversity/canonical.hpp"
#include "path_diversity/digest.hpp"
#include "path_diversity/domain.hpp"
#include "path_diversity/export.hpp"
#include "path_diversity/ids.hpp"

namespace path_diversity {

// One exact path at one exact Path Authority generation. Path Diversity Fabric
// never overrides Path Authority: a path whose bound generation is no longer
// the current authorized generation cannot participate in a current proof.
struct PATH_DIVERSITY_API PathRef {
  PathId path;
  PathAuthorityGeneration authority_generation;

  friend bool operator==(const PathRef&, const PathRef&) = default;
  friend std::strong_ordering operator<=>(const PathRef& lhs, const PathRef& rhs);
  std::string render() const;
};

// ---------------------------------------------------------------------------
// Evidence views. Every view is borrowed, must outlive the runtime, may be
// called concurrently, and must be internally synchronised. No view call ever
// runs while the runtime holds its state lock.
// ---------------------------------------------------------------------------

// Path Authority, consumed verbatim.
class PATH_DIVERSITY_API PathAuthorityView {
 public:
  virtual ~PathAuthorityView();

  // Current authorized generation for a path, or nullopt when Path Authority
  // holds no authorized path with this identity.
  virtual std::optional<PathAuthorityGeneration> current_generation(const PathId& path) const = 0;

  // True only when the exact pair (path, generation) is currently authorized.
  virtual bool is_authorized(const PathId& path, PathAuthorityGeneration generation) const = 0;
};

// Fabric Topology plus Fabric Registry structure, consumed verbatim.
class PATH_DIVERSITY_API PathStructureView {
 public:
  virtual ~PathStructureView();

  // The topology generation the view is serving.
  virtual TopologyGeneration topology_generation() const = 0;

  // Exact composition of a path under the topology generation the view serves.
  // nullopt means the structure is not known to this view at all.
  virtual std::optional<PathComposition> composition(const PathId& path) const = 0;
};

// Failure Domain Registry classification, consumed verbatim.
class PATH_DIVERSITY_API FailureDomainView {
 public:
  virtual ~FailureDomainView();

  virtual FailureDomainGeneration generation() const = 0;

  // Authoritative correlated-failure membership of one entity under one
  // relation class. An entity with no classification returns ABSENT coverage
  // rather than an empty COMPLETE set.
  virtual DomainEvidence domain_membership(const EntityRef& entity,
                                           DomainRelation relation) const = 0;

  // Authoritative shared-risk-group membership of one entity.
  virtual SrlgEvidence srlg_membership(const EntityRef& entity) const = 0;
};

// Deterministic digest of a canonical path set: the identity-bearing content of
// a proof request, independent of the order paths arrived in.
PATH_DIVERSITY_API Digest path_set_digest(const std::vector<PathRef>& canonical_paths);
PATH_DIVERSITY_API PathSetId path_set_id(const std::vector<PathRef>& canonical_paths);

// Canonical ordering: by path identity, then by authority generation. Applying
// this to any permutation yields the same sequence, so proof identity, pairwise
// matrix order, conflict ordering, witness selection and digests are all
// independent of arrival order.
PATH_DIVERSITY_API void canonical_path_order(std::vector<PathRef>& paths);
PATH_DIVERSITY_API bool has_duplicate_paths(const std::vector<PathRef>& paths) noexcept;

}  // namespace path_diversity
