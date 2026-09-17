// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "path_diversity/canonical.hpp"
#include "path_diversity/digest.hpp"
#include "path_diversity/export.hpp"
#include "path_diversity/ids.hpp"
#include "path_diversity/lifecycle.hpp"
#include "path_diversity/limits.hpp"
#include "path_diversity/outcome.hpp"
#include "path_diversity/path.hpp"
#include "path_diversity/policy.hpp"

namespace path_diversity {

// Exact Path Authority generation bound to one path inside one proof.
struct PATH_DIVERSITY_API PathAuthorityBinding {
  PathId path;
  PathAuthorityGeneration generation;
  friend bool operator==(const PathAuthorityBinding&, const PathAuthorityBinding&) = default;
};

// Exact dependency generations a proof was evaluated against. A change to any of
// them invalidates precisely the proofs that bound it, and nothing else.
struct PATH_DIVERSITY_API DependencyBinding {
  DiversityPolicyGeneration policy_generation;
  TopologyGeneration topology_generation;
  FailureDomainGeneration failure_domain_generation;
  CoordinatorEpoch epoch;
  // Canonical path order, one entry per path.
  std::vector<PathAuthorityBinding> paths;
  // Exact structural entities consulted while proving this set, canonical
  // sorted and unique. Used for precise topology invalidation: a change to one
  // link demotes only the proofs that actually read that link.
  std::vector<EntityRef> topology_entities;
  // Endpoint-exemption semantics the proof was evaluated under. It is part of
  // the semantic digest, so two proofs that differ only in whether shared
  // endpoints are exempt are different proofs.
  EndpointExemption endpoint_exemption = EndpointExemption::SHARED_SOURCE_AND_DESTINATION;

  friend bool operator==(const DependencyBinding&, const DependencyBinding&) = default;
};

// Who published a proof and under which authority.
struct PATH_DIVERSITY_API Provenance {
  CoordinatorEpoch epoch;
  PublisherId publisher;
  WorkerBootId boot;
  MutationAttemptId attempt;
  friend bool operator==(const Provenance&, const Provenance&) = default;
};

// A proof request binds an exact canonical path set plus exact generations.
// Duplicate paths are rejected unless a future policy explicitly gives
// duplicates semantics; 1.0.0 rejects them.
struct PATH_DIVERSITY_API ProofRequest {
  DiversityPolicyId policy;
  DiversityPolicyGeneration policy_generation;
  std::vector<PathRef> paths;

  // Canonicalizes path order in place. Returns false when the request contains
  // duplicate path identities.
  bool canonicalize();
  Digest digest() const;
  PathSetId path_set() const;
  friend bool operator==(const ProofRequest&, const ProofRequest&) = default;
};

struct PATH_DIVERSITY_API DiversityProof {
  DiversityProofId id;
  DiversityProofGeneration generation;
  // Canonical path order.
  ProofRequest request;
  Digest request_digest;
  Digest semantic_digest;

  ProofOutcome outcome = ProofOutcome::MALFORMED;
  std::string detail;
  // Present exactly when the outcome is RESOURCE_LIMIT.
  std::optional<ResourceLimitNotice> limit;

  // One entry per required class, in canonical class order.
  std::vector<ClassResult> classes;
  // Classes evaluated but not required by the policy. Reported, never used to
  // assert independence.
  std::vector<ClassResult> advisories;

  // Bounded, canonically ordered complete conflict list across required
  // classes; primary_conflict is its first element when non-empty.
  std::vector<SharedResource> conflicts;
  std::uint64_t conflicts_total = 0;

  PairwiseMatrix matrix;
  WitnessSubset witness;
  DependencyBinding dependencies;
  Provenance provenance;

  LifecycleState lifecycle = LifecycleState::DECLARED;
  Currentness currentness = Currentness::REVALIDATION_REQUIRED;

  bool current() const noexcept {
    return lifecycle == LifecycleState::CURRENT && currentness_is_current(currentness);
  }
  friend bool operator==(const DiversityProof&, const DiversityProof&) = default;
};

// Immutable identity of the semantic content of a proof: canonical path set,
// policy content, exact relevant generations, proof result and canonical
// conflict evidence. Timestamps, thread ids, sockets, memory addresses, arrival
// order and diagnostic counters are excluded by construction -- none of them is
// an input to this function.
PATH_DIVERSITY_API Digest proof_semantic_digest(const DiversityProof& proof);

// Stable request identity, separate from the immutable proof revision: the same
// request re-evaluated after an evidence change keeps its DiversityProofId and
// advances DiversityProofGeneration.
PATH_DIVERSITY_API DiversityProofId proof_identity(const ProofRequest& canonical_request);

}  // namespace path_diversity
