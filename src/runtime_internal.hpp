// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

// Internal state definition of DiversityRuntime, shared by the runtime
// translation units. Nothing here is installed or reachable from the public
// package surface.

#include <map>
#include <mutex>
#include <set>
#include <vector>

#include "path_diversity/runtime.hpp"

namespace path_diversity {

struct DiversityRuntime::ProofRecord {
  DiversityProof current;
  std::vector<DiversityProof> history;
  std::vector<ProofSnapshot> snapshots;
};

struct DiversityRuntime::Impl {
  Impl(const PathAuthorityView& authority_view, const PathStructureView& structure_view,
       const FailureDomainView& domains_view, PublicationAuthority& publication_authority,
       Limits configured)
      : authority(&authority_view),
        structure(&structure_view),
        domains(&domains_view),
        publication(&publication_authority),
        limits(configured) {}

  const PathAuthorityView* authority;
  const PathStructureView* structure;
  const FailureDomainView* domains;
  PublicationAuthority* publication;
  Limits limits;

  mutable std::mutex mutex;
  std::map<DiversityPolicyId, DiversityPolicy> policies;
  std::map<DiversityProofId, ProofRecord> proofs;
  std::map<PathId, std::set<DiversityProofId>> by_path;
  std::map<FailureDomainId, std::set<DiversityProofId>> by_domain;
  std::map<SharedRiskGroupId, std::set<DiversityProofId>> by_risk_group;
  std::map<EntityRef, std::set<DiversityProofId>> by_entity;
  std::map<DiversityPolicyId, std::set<DiversityProofId>> by_policy;
  std::map<WorkerBootId, std::set<DiversityProofId>> by_boot;
  std::map<TopologyGeneration, std::set<DiversityProofId>> by_topology_generation;
  std::map<FailureDomainGeneration, std::set<DiversityProofId>> by_failure_domain_generation;
  RuntimeStats stats;
};

}  // namespace path_diversity
