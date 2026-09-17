// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include "path_diversity/export.hpp"
#include "path_diversity/strong_id.hpp"

namespace path_diversity {

// ---------------------------------------------------------------------------
// Identity tags. Each tag is a distinct C++ type, so cross-domain assignment
// does not compile and cross-domain decoding is impossible by construction.
// Path Diversity Fabric creates no infrastructure identities: every identifier
// below is either minted by this runtime's own authority or consumed verbatim
// from the authority named in its comment.
// ---------------------------------------------------------------------------
#define PATH_DIVERSITY_DEFINE_ID_TAG(TagName, DisplayName)                     \
  struct TagName {                                                            \
    static constexpr std::string_view name() noexcept { return DisplayName; }  \
  }

// Minted by Path Diversity Fabric.
PATH_DIVERSITY_DEFINE_ID_TAG(DiversityPolicyIdTag, "DiversityPolicyId");
PATH_DIVERSITY_DEFINE_ID_TAG(DiversityProofIdTag, "DiversityProofId");
PATH_DIVERSITY_DEFINE_ID_TAG(PathSetIdTag, "PathSetId");
PATH_DIVERSITY_DEFINE_ID_TAG(SnapshotIdTag, "SnapshotId");
PATH_DIVERSITY_DEFINE_ID_TAG(WorkerBootIdTag, "WorkerBootId");
PATH_DIVERSITY_DEFINE_ID_TAG(MutationAttemptIdTag, "MutationAttemptId");
PATH_DIVERSITY_DEFINE_ID_TAG(PublisherIdTag, "PublisherId");

// Consumed from upstream authorities (Path Authority, Fabric Topology, Fabric
// Registry, Failure Domain Registry, Fabric Epoch). Never minted here.
PATH_DIVERSITY_DEFINE_ID_TAG(PathIdTag, "PathId");
PATH_DIVERSITY_DEFINE_ID_TAG(ScopeIdTag, "ScopeId");
PATH_DIVERSITY_DEFINE_ID_TAG(LinkIdTag, "LinkId");
PATH_DIVERSITY_DEFINE_ID_TAG(NodeIdTag, "NodeId");
PATH_DIVERSITY_DEFINE_ID_TAG(DeviceIdTag, "DeviceId");
PATH_DIVERSITY_DEFINE_ID_TAG(EndpointIdTag, "EndpointId");
PATH_DIVERSITY_DEFINE_ID_TAG(FailureDomainIdTag, "FailureDomainId");
PATH_DIVERSITY_DEFINE_ID_TAG(SharedRiskGroupIdTag, "SharedRiskGroupId");

// Generation tags.
PATH_DIVERSITY_DEFINE_ID_TAG(DiversityPolicyGenerationTag, "DiversityPolicyGeneration");
PATH_DIVERSITY_DEFINE_ID_TAG(DiversityProofGenerationTag, "DiversityProofGeneration");
PATH_DIVERSITY_DEFINE_ID_TAG(PathAuthorityGenerationTag, "PathAuthorityGeneration");
PATH_DIVERSITY_DEFINE_ID_TAG(TopologyGenerationTag, "TopologyGeneration");
PATH_DIVERSITY_DEFINE_ID_TAG(FailureDomainGenerationTag, "FailureDomainGeneration");
PATH_DIVERSITY_DEFINE_ID_TAG(CoordinatorEpochTag, "CoordinatorEpoch");

#undef PATH_DIVERSITY_DEFINE_ID_TAG

using DiversityPolicyId = StringId<DiversityPolicyIdTag, 96>;
using DiversityProofId = StringId<DiversityProofIdTag, 96>;
using PathSetId = StringId<PathSetIdTag, 96>;
using SnapshotId = StringId<SnapshotIdTag, 96>;
using WorkerBootId = StringId<WorkerBootIdTag, 64>;
using MutationAttemptId = StringId<MutationAttemptIdTag, 96>;
using PublisherId = StringId<PublisherIdTag, 64>;

using PathId = StringId<PathIdTag, 96>;
using ScopeId = StringId<ScopeIdTag, 64>;
using LinkId = StringId<LinkIdTag, 128>;
using NodeId = StringId<NodeIdTag, 128>;
using DeviceId = StringId<DeviceIdTag, 128>;
using EndpointId = StringId<EndpointIdTag, 128>;
using FailureDomainId = StringId<FailureDomainIdTag, 128>;
using SharedRiskGroupId = StringId<SharedRiskGroupIdTag, 128>;

using DiversityPolicyGeneration = Generation<DiversityPolicyGenerationTag>;
using DiversityProofGeneration = Generation<DiversityProofGenerationTag>;
using PathAuthorityGeneration = Generation<PathAuthorityGenerationTag>;
using TopologyGeneration = Generation<TopologyGenerationTag>;
using FailureDomainGeneration = Generation<FailureDomainGenerationTag>;
using CoordinatorEpoch = Generation<CoordinatorEpochTag>;

// A path-set identity derived from canonical content: "pset-" plus the leading
// 128 bits of the canonical path-set digest. Deterministic across processes.
class Digest;
PATH_DIVERSITY_API PathSetId derived_path_set_id(const Digest& digest);
PATH_DIVERSITY_API DiversityProofId derived_proof_id(const Digest& request_digest);
PATH_DIVERSITY_API SnapshotId derived_snapshot_id(const Digest& digest);
PATH_DIVERSITY_API ScopeId default_scope() noexcept;

}  // namespace path_diversity
