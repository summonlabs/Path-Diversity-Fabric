// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "path_diversity/domain.hpp"
#include "path_diversity/export.hpp"
#include "path_diversity/ids.hpp"
#include "path_diversity/path.hpp"

namespace path_diversity {

// A concrete, thread-safe in-memory implementation of the three evidence views.
//
// It exists so that tests, examples, the CLI and the synthetic population
// generator have an implementation to run against, and so that an embedding
// product has a worked reference for the exact semantics each view must obey.
// It is NOT an authority: it stores whatever it is told and never derives,
// guesses or infers a failure domain, a device identity or a placement.
class PATH_DIVERSITY_API InMemoryEvidence : public PathAuthorityView,
                                            public PathStructureView,
                                            public FailureDomainView {
 public:
  InMemoryEvidence();
  ~InMemoryEvidence() override;

  InMemoryEvidence(const InMemoryEvidence&) = delete;
  InMemoryEvidence& operator=(const InMemoryEvidence&) = delete;

  // --- Path Authority surface -------------------------------------------
  std::optional<PathAuthorityGeneration> current_generation(const PathId& path) const override;
  bool is_authorized(const PathId& path, PathAuthorityGeneration generation) const override;

  // --- Fabric Topology surface ------------------------------------------
  TopologyGeneration topology_generation() const override;
  std::optional<PathComposition> composition(const PathId& path) const override;

  // --- Failure Domain Registry surface ----------------------------------
  FailureDomainGeneration generation() const override;
  DomainEvidence domain_membership(const EntityRef& entity, DomainRelation relation) const override;
  SrlgEvidence srlg_membership(const EntityRef& entity) const override;

  // --- Mutation (test/example/reference use) -----------------------------
  void set_topology_generation(TopologyGeneration generation);
  void advance_topology_generation();
  void set_failure_domain_generation(FailureDomainGeneration generation);
  void advance_failure_domain_generation();

  // Publishes the exact composition. The current authorized generation for the
  // path becomes composition.authority_generation.
  void set_path(PathComposition composition);
  // Advances Path Authority for an existing path without touching topology.
  void set_path_authority(const PathId& path, PathAuthorityGeneration generation,
                          bool authorized);
  // Removes the path from Path Authority entirely: it is no longer authorized
  // at any generation.
  void revoke_path(const PathId& path);
  bool has_path(const PathId& path) const;

  void set_domain_membership(const EntityRef& entity, DomainRelation relation,
                             EvidenceCoverage coverage, std::vector<FailureDomainId> domains);
  void set_srlg_membership(const EntityRef& entity, EvidenceCoverage coverage,
                           std::vector<SharedRiskGroupId> groups);
  void clear_entity(const EntityRef& entity);

  // Test helper: replace every membership with the same relation/coverage for a
  // whole path's entities, so a scenario can be built in one call.
  void assign_path_entities(const PathId& path, DomainRelation relation,
                            EvidenceCoverage coverage, std::vector<FailureDomainId> domains);
  void assign_path_entities_srlg(const PathId& path, EvidenceCoverage coverage,
                                 std::vector<SharedRiskGroupId> groups);

  std::size_t path_count() const;
  std::size_t membership_count() const;
  // Deterministic dump used by diagnostics and by the CLI.
  std::string render() const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace path_diversity
