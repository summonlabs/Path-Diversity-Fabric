// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include <algorithm>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "path_diversity/runtime.hpp"

#include "runtime_internal.hpp"

namespace path_diversity {

namespace {

MutationResult make_result(MutationStatus status, std::string detail) {
  MutationResult result;
  result.status = status;
  result.detail = std::move(detail);
  return result;
}

MutationResult authority_result(AuthorityStatus status, std::string detail) {
  MutationStatus mapped = MutationStatus::UNAUTHORIZED;
  switch (status) {
    case AuthorityStatus::FENCED_PUBLISHER:
      mapped = MutationStatus::FENCED_PUBLISHER;
      break;
    case AuthorityStatus::STALE_EPOCH:
      mapped = MutationStatus::STALE_EPOCH;
      break;
    case AuthorityStatus::SCOPE_MISMATCH:
      mapped = MutationStatus::SCOPE_MISMATCH;
      break;
    case AuthorityStatus::ATTEMPT_CONFLICT:
      mapped = MutationStatus::ATTEMPT_CONFLICT;
      break;
    case AuthorityStatus::LIMIT_EXCEEDED:
      mapped = MutationStatus::LIMIT_EXCEEDED;
      break;
    case AuthorityStatus::GENERATION_CONFLICT:
      mapped = MutationStatus::GENERATION_CONFLICT;
      break;
    default:
      mapped = MutationStatus::UNAUTHORIZED;
      break;
  }
  return make_result(mapped, std::move(detail));
}

bool is_current(const DiversityProof& proof) {
  return proof.lifecycle == LifecycleState::CURRENT &&
         currentness_is_current(proof.currentness);
}

}  // namespace

// ---------------------------------------------------------------------------
// Lifecycle transitions
// ---------------------------------------------------------------------------
MutationResult DiversityRuntime::apply_lifecycle(const DiversityProofId& id,
                                                 const ActingAuthority& authority,
                                                 LifecycleState target, std::string reason) {
  DiversityPolicyGeneration no_policy_generation;
  (void)no_policy_generation;
  const Digest payload = Digest::of((id.str() + "|" + std::string(to_string(target))).data(),
                                    id.str().size() + 1 + std::string(to_string(target)).size());
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const AuthorityStatus admitted = impl_->publication->admit(authority, payload);
  if (admitted == AuthorityStatus::IDEMPOTENT) {
    const auto existing = impl_->proofs.find(id);
    if (existing != impl_->proofs.end() && existing->second.current.lifecycle == target) {
      MutationResult result = make_result(MutationStatus::IDEMPOTENT,
                                          "lifecycle transition replayed exactly");
      result.proof = existing->second.current;
      result.has_proof = true;
      return result;
    }
  }
  if (!authority_status_is_success(admitted)) {
    ++impl_->stats.rejected_mutations;
    return authority_result(admitted, std::string("lifecycle transition refused: ") +
                                          std::string(to_string(admitted)));
  }
  const auto found = impl_->proofs.find(id);
  if (found == impl_->proofs.end()) {
    impl_->publication->forget_attempt(authority.attempt);
    return make_result(MutationStatus::NOT_FOUND, "no proof is stored under this identity");
  }
  DiversityProof& current = found->second.current;
  if (!lifecycle_transition_allowed(current.lifecycle, target)) {
    impl_->publication->forget_attempt(authority.attempt);
    return make_result(MutationStatus::ILLEGAL_TRANSITION,
                       std::string("transition from ") +
                           std::string(to_string(current.lifecycle)) + " to " +
                           std::string(to_string(target)) + " is not in the transition table");
  }
  if (current.lifecycle == target) {
    ++impl_->stats.unchanged_revalidations;
    MutationResult result = make_result(MutationStatus::UNCHANGED,
                                        "proof is already in the requested lifecycle state");
    result.proof = current;
    result.has_proof = true;
    return result;
  }
  found->second.history.push_back(current);
  if (found->second.history.size() > impl_->limits.max_history) {
    found->second.history.erase(found->second.history.begin());
  }
  current.lifecycle = target;
  current.detail = reason;
  if (target != LifecycleState::CURRENT) {
    current.currentness = Currentness::REVALIDATION_REQUIRED;
  }
  ++impl_->stats.commits;
  MutationResult result = make_result(MutationStatus::APPLIED, std::move(reason));
  result.proof = current;
  result.has_proof = true;
  return result;
}

MutationResult DiversityRuntime::revoke(const DiversityProofId& id,
                                        const ActingAuthority& authority, std::string reason) {
  return apply_lifecycle(id, authority, LifecycleState::REVOKED, std::move(reason));
}

MutationResult DiversityRuntime::retire(const DiversityProofId& id,
                                        const ActingAuthority& authority, std::string reason) {
  return apply_lifecycle(id, authority, LifecycleState::RETIRED, std::move(reason));
}

MutationResult DiversityRuntime::mark_historical(const DiversityProofId& id,
                                                 const ActingAuthority& authority,
                                                 std::string reason) {
  return apply_lifecycle(id, authority, LifecycleState::HISTORICAL, std::move(reason));
}

MutationResult DiversityRuntime::supersede(const DiversityProofId& id,
                                           const ActingAuthority& authority) {
  return apply_lifecycle(id, authority, LifecycleState::SUPERSEDED,
                         "superseded by an explicit operator decision");
}

// ---------------------------------------------------------------------------
// Publication authority surface
// ---------------------------------------------------------------------------
AuthorityStatus DiversityRuntime::register_publisher(const PublisherSession& session) {
  return impl_->publication->register_publisher(session);
}

std::vector<DiversityProofId> DiversityRuntime::fence_boot(const WorkerBootId& boot) {
  impl_->publication->fence_boot(boot);
  return demote_boot(boot);
}

// ---------------------------------------------------------------------------
// Precise invalidation
// ---------------------------------------------------------------------------
std::vector<DiversityProofId> DiversityRuntime::demote_topology_entities(
    const std::vector<EntityRef>& entities, TopologyGeneration generation) {
  std::vector<DiversityProofId> affected;
  std::lock_guard<std::mutex> guard(impl_->mutex);
  std::set<DiversityProofId> candidates;
  for (const EntityRef& entity : entities) {
    const auto found = impl_->by_entity.find(entity);
    if (found == impl_->by_entity.end()) {
      continue;
    }
    candidates.insert(found->second.begin(), found->second.end());
  }
  for (const DiversityProofId& id : candidates) {
    auto record = impl_->proofs.find(id);
    if (record == impl_->proofs.end()) {
      continue;
    }
    DiversityProof& current = record->second.current;
    if (!is_current(current)) {
      continue;
    }
    if (!(current.dependencies.topology_generation < generation)) {
      continue;
    }
    current.lifecycle = LifecycleState::REVALIDATION_REQUIRED;
    current.currentness = Currentness::STALE_TOPOLOGY;
    current.detail = "topology changed for an entity this proof depends on";
    ++impl_->stats.demotions;
    affected.push_back(id);
  }
  ++impl_->stats.invalidations;
  std::sort(affected.begin(), affected.end());
  return affected;
}

std::vector<DiversityProofId> DiversityRuntime::demote_topology_generation(
    TopologyGeneration generation) {
  std::vector<DiversityProofId> affected;
  std::lock_guard<std::mutex> guard(impl_->mutex);
  for (auto entry = impl_->by_topology_generation.begin();
       entry != impl_->by_topology_generation.end();) {
    if (!(entry->first < generation)) {
      ++entry;
      continue;
    }
    for (const DiversityProofId& id : entry->second) {
      auto record = impl_->proofs.find(id);
      if (record == impl_->proofs.end() || !is_current(record->second.current)) {
        continue;
      }
      record->second.current.lifecycle = LifecycleState::REVALIDATION_REQUIRED;
      record->second.current.currentness = Currentness::STALE_TOPOLOGY;
      record->second.current.detail =
          "topology advanced past the generation this proof was evaluated against";
      ++impl_->stats.demotions;
      affected.push_back(id);
    }
    entry = impl_->by_topology_generation.erase(entry);
  }
  ++impl_->stats.invalidations;
  std::sort(affected.begin(), affected.end());
  return affected;
}

std::vector<DiversityProofId> DiversityRuntime::demote_failure_domain_generation(
    FailureDomainGeneration generation) {
  std::vector<DiversityProofId> affected;
  std::lock_guard<std::mutex> guard(impl_->mutex);
  for (auto entry = impl_->by_failure_domain_generation.begin();
       entry != impl_->by_failure_domain_generation.end();) {
    if (!(entry->first < generation)) {
      ++entry;
      continue;
    }
    for (const DiversityProofId& id : entry->second) {
      auto record = impl_->proofs.find(id);
      if (record == impl_->proofs.end() || !is_current(record->second.current)) {
        continue;
      }
      record->second.current.lifecycle = LifecycleState::REVALIDATION_REQUIRED;
      record->second.current.currentness = Currentness::STALE_FAILURE_DOMAIN;
      record->second.current.detail =
          "failure-domain classification advanced past the generation this proof bound";
      ++impl_->stats.demotions;
      affected.push_back(id);
    }
    entry = impl_->by_failure_domain_generation.erase(entry);
  }
  ++impl_->stats.invalidations;
  std::sort(affected.begin(), affected.end());
  return affected;
}

std::vector<DiversityProofId> DiversityRuntime::demote_domains(
    const std::vector<FailureDomainId>& domains, FailureDomainGeneration generation) {
  std::vector<DiversityProofId> affected;
  std::lock_guard<std::mutex> guard(impl_->mutex);
  std::set<DiversityProofId> candidates;
  for (const FailureDomainId& domain : domains) {
    const auto found = impl_->by_domain.find(domain);
    if (found != impl_->by_domain.end()) {
      candidates.insert(found->second.begin(), found->second.end());
    }
  }
  for (const DiversityProofId& id : candidates) {
    auto record = impl_->proofs.find(id);
    if (record == impl_->proofs.end() || !is_current(record->second.current)) {
      continue;
    }
    DiversityProof& current = record->second.current;
    if (!(current.dependencies.failure_domain_generation < generation)) {
      continue;
    }
    current.lifecycle = LifecycleState::REVALIDATION_REQUIRED;
    current.currentness = Currentness::STALE_FAILURE_DOMAIN;
    current.detail = "failure-domain membership changed for a domain this proof consulted";
    ++impl_->stats.demotions;
    affected.push_back(id);
  }
  ++impl_->stats.invalidations;
  std::sort(affected.begin(), affected.end());
  return affected;
}

std::vector<DiversityProofId> DiversityRuntime::demote_path(const PathId& path) {
  std::vector<DiversityProofId> affected;
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const auto found = impl_->by_path.find(path);
  if (found == impl_->by_path.end()) {
    ++impl_->stats.invalidations;
    return affected;
  }
  for (const DiversityProofId& id : found->second) {
    auto record = impl_->proofs.find(id);
    if (record == impl_->proofs.end() || !is_current(record->second.current)) {
      continue;
    }
    record->second.current.lifecycle = LifecycleState::REVALIDATION_REQUIRED;
    record->second.current.currentness = Currentness::STALE_PATH_AUTHORITY;
    record->second.current.detail =
        "Path Authority changed for a path this proof binds; revalidation is required";
    ++impl_->stats.demotions;
    affected.push_back(id);
  }
  ++impl_->stats.invalidations;
  std::sort(affected.begin(), affected.end());
  return affected;
}

std::vector<DiversityProofId> DiversityRuntime::demote_policy(
    const DiversityPolicyId& policy, DiversityPolicyGeneration generation) {
  std::vector<DiversityProofId> affected;
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const auto found = impl_->by_policy.find(policy);
  if (found == impl_->by_policy.end()) {
    ++impl_->stats.invalidations;
    return affected;
  }
  for (const DiversityProofId& id : found->second) {
    auto record = impl_->proofs.find(id);
    if (record == impl_->proofs.end() || !is_current(record->second.current)) {
      continue;
    }
    DiversityProof& current = record->second.current;
    if (!(current.dependencies.policy_generation < generation)) {
      continue;
    }
    current.lifecycle = LifecycleState::REVALIDATION_REQUIRED;
    current.currentness = Currentness::STALE_POLICY;
    current.detail = "the policy advanced past the generation this proof was evaluated against";
    ++impl_->stats.demotions;
    affected.push_back(id);
  }
  ++impl_->stats.invalidations;
  std::sort(affected.begin(), affected.end());
  return affected;
}

std::vector<DiversityProofId> DiversityRuntime::demote_boot(const WorkerBootId& boot) {
  std::vector<DiversityProofId> affected;
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const auto found = impl_->by_boot.find(boot);
  if (found == impl_->by_boot.end()) {
    ++impl_->stats.invalidations;
    return affected;
  }
  for (const DiversityProofId& id : found->second) {
    auto record = impl_->proofs.find(id);
    if (record == impl_->proofs.end() || !is_current(record->second.current)) {
      continue;
    }
    record->second.current.lifecycle = LifecycleState::REVALIDATION_REQUIRED;
    record->second.current.currentness = Currentness::FENCED_PUBLISHER;
    record->second.current.detail =
        "the publishing worker boot was fenced; live authority for this proof is gone";
    ++impl_->stats.demotions;
    affected.push_back(id);
  }
  ++impl_->stats.invalidations;
  std::sort(affected.begin(), affected.end());
  return affected;
}

std::vector<DiversityProofId> DiversityRuntime::refresh_currentness() {
  // Phase 1: collect the exact dependency questions under the lock.
  struct Question {
    DiversityProofId id;
    PathId path;
    PathAuthorityGeneration bound;
  };
  std::vector<Question> questions;
  std::vector<DiversityProofId> live;
  std::map<DiversityPolicyId, std::vector<DiversityProofId>> by_policy;
  {
    std::lock_guard<std::mutex> guard(impl_->mutex);
    for (const auto& entry : impl_->proofs) {
      if (!is_current(entry.second.current)) {
        continue;
      }
      live.push_back(entry.first);
      by_policy[entry.second.current.request.policy].push_back(entry.first);
      for (const PathAuthorityBinding& binding : entry.second.current.dependencies.paths) {
        questions.push_back(Question{entry.first, binding.path, binding.generation});
      }
    }
  }

  // Phase 2: ask the evidence views outside every lock.
  std::set<DiversityProofId> stale_paths;
  for (const Question& question : questions) {
    const std::optional<PathAuthorityGeneration> current =
        impl_->authority->current_generation(question.path);
    if (!current.has_value() || *current != question.bound ||
        !impl_->authority->is_authorized(question.path, question.bound)) {
      stale_paths.insert(question.id);
    }
  }
  std::set<DiversityProofId> stale_policies;
  for (const auto& entry : by_policy) {
    const DiversityPolicyGeneration published = policy_generation(entry.first);
    for (const DiversityProofId& id : entry.second) {
      std::optional<DiversityProof> stored = proof(id);
      if (!stored.has_value()) {
        continue;
      }
      if (!(stored->dependencies.policy_generation == published)) {
        stale_policies.insert(id);
      }
    }
  }

  // Phase 3: apply the demotions under the lock, re-checking currentness.
  std::vector<DiversityProofId> affected;
  {
    std::lock_guard<std::mutex> guard(impl_->mutex);
    for (const DiversityProofId& id : live) {
      auto record = impl_->proofs.find(id);
      if (record == impl_->proofs.end() || !is_current(record->second.current)) {
        continue;
      }
      if (stale_policies.find(id) != stale_policies.end()) {
        record->second.current.lifecycle = LifecycleState::REVALIDATION_REQUIRED;
        record->second.current.currentness = Currentness::STALE_POLICY;
        record->second.current.detail = "the policy generation moved past this proof";
        affected.push_back(id);
        ++impl_->stats.demotions;
        continue;
      }
      if (stale_paths.find(id) != stale_paths.end()) {
        record->second.current.lifecycle = LifecycleState::REVALIDATION_REQUIRED;
        record->second.current.currentness = Currentness::STALE_PATH_AUTHORITY;
        record->second.current.detail = "Path Authority moved past this proof binding";
        affected.push_back(id);
        ++impl_->stats.demotions;
      }
    }
    ++impl_->stats.invalidations;
  }
  std::sort(affected.begin(), affected.end());
  return affected;
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------
namespace {

DiversityRuntime::QueryResult bounded_result(const std::set<DiversityProofId>& source,
                                             std::uint32_t max_results) {
  DiversityRuntime::QueryResult result;
  result.total = source.size();
  for (const DiversityProofId& id : source) {
    if (result.proofs.size() >= max_results) {
      result.truncated = true;
      break;
    }
    result.proofs.push_back(id);
  }
  return result;
}

}  // namespace

DiversityRuntime::QueryResult DiversityRuntime::proofs_for_path(const PathId& path) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const auto found = impl_->by_path.find(path);
  if (found == impl_->by_path.end()) {
    return QueryResult();
  }
  return bounded_result(found->second, impl_->limits.max_query_results);
}

DiversityRuntime::QueryResult DiversityRuntime::proofs_for_domain(
    const FailureDomainId& domain) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const auto found = impl_->by_domain.find(domain);
  if (found == impl_->by_domain.end()) {
    return QueryResult();
  }
  return bounded_result(found->second, impl_->limits.max_query_results);
}

DiversityRuntime::QueryResult DiversityRuntime::proofs_for_entity(const EntityRef& entity) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const auto found = impl_->by_entity.find(entity);
  if (found == impl_->by_entity.end()) {
    return QueryResult();
  }
  return bounded_result(found->second, impl_->limits.max_query_results);
}

DiversityRuntime::QueryResult DiversityRuntime::proofs_for_policy(
    const DiversityPolicyId& policy) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const auto found = impl_->by_policy.find(policy);
  if (found == impl_->by_policy.end()) {
    return QueryResult();
  }
  return bounded_result(found->second, impl_->limits.max_query_results);
}

DiversityRuntime::QueryResult DiversityRuntime::proofs_for_boot(const WorkerBootId& boot) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const auto found = impl_->by_boot.find(boot);
  if (found == impl_->by_boot.end()) {
    return QueryResult();
  }
  return bounded_result(found->second, impl_->limits.max_query_results);
}

DiversityRuntime::QueryResult DiversityRuntime::current_proofs() const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  std::set<DiversityProofId> live;
  for (const auto& entry : impl_->proofs) {
    if (is_current(entry.second.current)) {
      live.insert(entry.first);
    }
  }
  return bounded_result(live, impl_->limits.max_query_results);
}

DiversityRuntime::QueryResult DiversityRuntime::all_proofs() const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  std::set<DiversityProofId> all;
  for (const auto& entry : impl_->proofs) {
    all.insert(entry.first);
  }
  return bounded_result(all, impl_->limits.max_query_results);
}

}  // namespace path_diversity
