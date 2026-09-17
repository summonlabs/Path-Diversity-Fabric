// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "path_diversity/authority.hpp"
#include "path_diversity/digest.hpp"
#include "path_diversity/evaluate.hpp"
#include "path_diversity/evidence.hpp"
#include "path_diversity/explain.hpp"
#include "path_diversity/export.hpp"
#include "path_diversity/ids.hpp"
#include "path_diversity/limits.hpp"
#include "path_diversity/mutation.hpp"
#include "path_diversity/path.hpp"
#include "path_diversity/persistence.hpp"
#include "path_diversity/policy.hpp"
#include "path_diversity/proof.hpp"
#include "path_diversity/snapshot.hpp"

namespace path_diversity {

// Diagnostic counters. Explicitly excluded from every digest: they are
// observations about this process, not facts about the fabric.
struct PATH_DIVERSITY_API RuntimeStats {
  std::uint64_t evaluations = 0;
  std::uint64_t commits = 0;
  std::uint64_t unchanged_revalidations = 0;
  std::uint64_t idempotent_replays = 0;
  std::uint64_t rejected_mutations = 0;
  std::uint64_t watermark_rejections = 0;
  std::uint64_t invalidations = 0;
  std::uint64_t demotions = 0;
  friend bool operator==(const RuntimeStats&, const RuntimeStats&) = default;
};

// The runtime. Owns policy publication authority, the proof registry, precise
// reverse indexes and conservative recovery.
//
// Concurrency contract: the state mutex is never held across a call into an
// evidence view, a persistence write or a network operation. Evaluation is
// two-phase: snapshot dependencies, evaluate outside the lock, reacquire, verify
// generations and watermarks, then commit only if still current.
class PATH_DIVERSITY_API DiversityRuntime {
 public:
  DiversityRuntime(const PathAuthorityView& authority, const PathStructureView& structure,
                   const FailureDomainView& domains, PublicationAuthority& publication,
                   Limits limits = {});
  ~DiversityRuntime();

  DiversityRuntime(const DiversityRuntime&) = delete;
  DiversityRuntime& operator=(const DiversityRuntime&) = delete;

  const Limits& limits() const noexcept;

  // --- Policy registry ---------------------------------------------------
  MutationResult publish_policy(const DiversityPolicy& policy, const ActingAuthority& authority);
  std::optional<DiversityPolicy> policy(const DiversityPolicyId& id) const;
  DiversityPolicyGeneration policy_generation(const DiversityPolicyId& id) const;
  std::vector<DiversityPolicyId> policies() const;
  std::size_t policy_count() const;

  // --- Evaluation and commit --------------------------------------------
  // Full pipeline. On APPLIED the request was evaluated against one evidence
  // snapshot and committed as CURRENT; on IDEMPOTENT nothing advanced; on
  // REVALIDATION_REQUIRED the evaluation ran but a watermark moved underneath
  // it and the committed revision is explicitly not current.
  MutationResult evaluate(const ProofRequest& request, const ActingAuthority& authority);

  // Re-evaluates an existing proof against current evidence. If nothing changed
  // the generation does not advance and the status is UNCHANGED.
  MutationResult revalidate(const DiversityProofId& id, const ActingAuthority& authority);

  // Evaluates a bounded batch. Each element is an independent two-phase
  // evaluation; a failure in one element does not abort the others.
  std::vector<MutationResult> evaluate_batch(const std::vector<ProofRequest>& requests,
                                             const ActingAuthority& authority);

  std::optional<DiversityProof> proof(const DiversityProofId& id) const;
  // Bounded retained revisions, oldest first, current revision last.
  std::vector<DiversityProof> history(const DiversityProofId& id) const;
  std::size_t proof_count() const;

  // --- Publication authority surface --------------------------------------
  // The coordinator registers a worker session through these calls. A worker
  // that has connected but has not been registered here is not authorized.
  AuthorityStatus register_publisher(const PublisherSession& session);
  // Permanently fences a boot and demotes every live publication attributed to
  // it. Returns the demoted proof identities.
  std::vector<DiversityProofId> fence_boot(const WorkerBootId& boot);

  // --- Lifecycle ---------------------------------------------------------
  MutationResult revoke(const DiversityProofId& id, const ActingAuthority& authority,
                        std::string reason);
  MutationResult retire(const DiversityProofId& id, const ActingAuthority& authority,
                        std::string reason);
  MutationResult mark_historical(const DiversityProofId& id, const ActingAuthority& authority,
                                 std::string reason);
  MutationResult supersede(const DiversityProofId& id, const ActingAuthority& authority);

  // --- Invalidation (precise wherever precise indexing is feasible) ------
  // Demotes exactly the proofs whose recorded dependency footprint intersects
  // the supplied entities. Unrelated proofs are untouched.
  std::vector<DiversityProofId> demote_topology_entities(const std::vector<EntityRef>& entities,
                                                         TopologyGeneration generation);
  // Watermark demotion used when the topology authority cannot attribute a
  // generation change to specific entities.
  std::vector<DiversityProofId> demote_topology_generation(TopologyGeneration generation);
  std::vector<DiversityProofId> demote_failure_domain_generation(FailureDomainGeneration generation);
  std::vector<DiversityProofId> demote_domains(const std::vector<FailureDomainId>& domains,
                                               FailureDomainGeneration generation);
  std::vector<DiversityProofId> demote_path(const PathId& path);
  std::vector<DiversityProofId> demote_policy(const DiversityPolicyId& policy,
                                              DiversityPolicyGeneration generation);
  // Demotes every live publication attributed to a fenced worker boot.
  std::vector<DiversityProofId> demote_boot(const WorkerBootId& boot);
  // Re-checks Path Authority currentness and policy currentness for every proof
  // and demotes exactly the ones that no longer hold.
  std::vector<DiversityProofId> refresh_currentness();

  // --- Queries (bounded by limits.max_query_results) ---------------------
  struct QueryResult {
    std::vector<DiversityProofId> proofs;
    bool truncated = false;
    std::uint64_t total = 0;
  };
  QueryResult proofs_for_path(const PathId& path) const;
  QueryResult proofs_for_domain(const FailureDomainId& domain) const;
  QueryResult proofs_for_entity(const EntityRef& entity) const;
  QueryResult proofs_for_policy(const DiversityPolicyId& policy) const;
  QueryResult proofs_for_boot(const WorkerBootId& boot) const;
  QueryResult current_proofs() const;
  QueryResult all_proofs() const;

  // --- Snapshots, diffs, explanations ------------------------------------
  std::optional<ProofSnapshot> snapshot(const DiversityProofId& id) const;
  std::optional<ProofDiff> diff(const DiversityProofId& id, const SnapshotId& left,
                                const SnapshotId& right) const;
  // Snapshot history retained per proof identity, oldest first.
  std::vector<SnapshotId> snapshot_ids(const DiversityProofId& id) const;
  std::optional<Explanation> explain(const DiversityProofId& id) const;
  std::optional<Explanation> explain_pair(const DiversityProofId& id, std::uint32_t left,
                                          std::uint32_t right) const;
  std::optional<ConflictGraph> conflict_graph(const DiversityProofId& id) const;

  // --- Persistence -------------------------------------------------------
  // A mutation that requires durability is acknowledged only after the durable
  // write succeeded. save() never returns OK for a store that was not fully
  // written and atomically replaced.
  PersistenceStatus save(const std::string& path) const;
  // Conservative recovery: a store that cannot be fully validated is refused
  // and the runtime keeps exactly the state it had.
  PersistenceStatus load(const std::string& path);

  RuntimeStats stats() const;
  // Deterministic diagnostic dump: counters, registries and index sizes.
  std::string render() const;

 private:
  struct ProofRecord;
  struct Impl;
  // Shared lifecycle transition used by revoke/retire/mark_historical/supersede.
  // Every transition is authority-checked, table-checked and never bypasses the
  // explicit transition table.
  MutationResult apply_lifecycle(const DiversityProofId& id, const ActingAuthority& authority,
                                 LifecycleState target, std::string reason);

  std::unique_ptr<Impl> impl_;
};

}  // namespace path_diversity