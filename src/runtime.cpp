// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include "path_diversity/runtime.hpp"

#include <algorithm>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "path_diversity/version.hpp"

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
  MutationStatus mapped = MutationStatus::MALFORMED;
  switch (status) {
    case AuthorityStatus::UNAUTHORIZED:
      mapped = MutationStatus::UNAUTHORIZED;
      break;
    case AuthorityStatus::FENCED_PUBLISHER:
      mapped = MutationStatus::FENCED_PUBLISHER;
      break;
    case AuthorityStatus::STALE_EPOCH:
      mapped = MutationStatus::STALE_EPOCH;
      break;
    case AuthorityStatus::SCOPE_MISMATCH:
      mapped = MutationStatus::SCOPE_MISMATCH;
      break;
    case AuthorityStatus::GENERATION_CONFLICT:
      mapped = MutationStatus::GENERATION_CONFLICT;
      break;
    case AuthorityStatus::ATTEMPT_CONFLICT:
      mapped = MutationStatus::ATTEMPT_CONFLICT;
      break;
    case AuthorityStatus::LIMIT_EXCEEDED:
      mapped = MutationStatus::LIMIT_EXCEEDED;
      break;
    case AuthorityStatus::IDEMPOTENT:
      mapped = MutationStatus::IDEMPOTENT;
      break;
    default:
      mapped = MutationStatus::UNAUTHORIZED;
      break;
  }
  return make_result(mapped, std::move(detail));
}

}  // namespace

DiversityRuntime::DiversityRuntime(const PathAuthorityView& authority,
                                   const PathStructureView& structure,
                                   const FailureDomainView& domains,
                                   PublicationAuthority& publication, Limits limits)
    : impl_(new Impl(authority, structure, domains, publication, limits)) {}

DiversityRuntime::~DiversityRuntime() = default;

const Limits& DiversityRuntime::limits() const noexcept { return impl_->limits; }

MutationResult DiversityRuntime::publish_policy(const DiversityPolicy& policy,
                                                const ActingAuthority& authority) {
  DiversityPolicy canonical = policy;
  canonical.canonicalize();
  const PolicyValidation validation = validate_policy(canonical, impl_->limits);
  if (!validation.ok()) {
    return make_result(MutationStatus::MALFORMED,
                       std::string("policy rejected: ") + std::string(to_string(validation.status)) +
                           " (" + validation.detail + ")");
  }
  const Digest payload = canonical.semantic_digest();

  std::lock_guard<std::mutex> guard(impl_->mutex);
  const AuthorityStatus admitted = impl_->publication->admit(authority, payload);
  if (admitted == AuthorityStatus::IDEMPOTENT) {
    ++impl_->stats.idempotent_replays;
    const auto existing = impl_->policies.find(canonical.id);
    if (existing != impl_->policies.end() &&
        existing->second.generation == canonical.generation) {
      MutationResult result = make_result(MutationStatus::IDEMPOTENT,
                                          "policy publication replayed exactly");
      result.policy = existing->second;
      result.has_policy = true;
      return result;
    }
    return make_result(MutationStatus::IDEMPOTENT, "policy publication replayed exactly");
  }
  if (!authority_status_is_success(admitted)) {
    ++impl_->stats.rejected_mutations;
    return authority_result(admitted, std::string("policy publication refused: ") +
                                          std::string(to_string(admitted)));
  }

  const auto existing = impl_->policies.find(canonical.id);
  const DiversityPolicyGeneration expected =
      existing == impl_->policies.end() ? DiversityPolicyGeneration()
                                        : existing->second.generation;
  if (authority.expected_policy_generation != expected) {
    impl_->publication->forget_attempt(authority.attempt);
    ++impl_->stats.rejected_mutations;
    return make_result(MutationStatus::GENERATION_CONFLICT,
                       "expected policy generation does not match the published generation");
  }
  if (existing == impl_->policies.end() &&
      impl_->policies.size() >= impl_->limits.max_policies) {
    impl_->publication->forget_attempt(authority.attempt);
    ++impl_->stats.rejected_mutations;
    MutationResult result = make_result(MutationStatus::LIMIT_EXCEEDED,
                                        "policy registry is full");
    ResourceLimitNotice notice;
    notice.bound = ResourceBound::MAX_POLICIES;
    notice.observed = impl_->policies.size() + 1;
    notice.allowed = impl_->limits.max_policies;
    result.limit = notice;
    return result;
  }
  {
    // Generations never decrease and never wrap.
    DiversityPolicyGeneration next = DiversityPolicyGeneration::from_value(1);
    if (existing != impl_->policies.end()) {
      if (!DiversityPolicyGeneration::can_advance(existing->second.generation.value())) {
        impl_->publication->forget_attempt(authority.attempt);
        return make_result(MutationStatus::GENERATION_CONFLICT,
                           "policy generation space is exhausted; it never wraps");
      }
      next = existing->second.generation.next();
    }
    canonical.generation = next;
  }
  impl_->policies[canonical.id] = canonical;
  MutationResult result = make_result(MutationStatus::APPLIED, "policy published");
  result.policy = canonical;
  result.has_policy = true;
  return result;
}

std::optional<DiversityPolicy> DiversityRuntime::policy(const DiversityPolicyId& id) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const auto found = impl_->policies.find(id);
  if (found == impl_->policies.end()) {
    return std::nullopt;
  }
  return found->second;
}

DiversityPolicyGeneration DiversityRuntime::policy_generation(const DiversityPolicyId& id) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const auto found = impl_->policies.find(id);
  if (found == impl_->policies.end()) {
    return DiversityPolicyGeneration();
  }
  return found->second.generation;
}

std::vector<DiversityPolicyId> DiversityRuntime::policies() const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  std::vector<DiversityPolicyId> out;
  out.reserve(impl_->policies.size());
  for (const auto& entry : impl_->policies) {
    out.push_back(entry.first);
  }
  return out;
}

std::size_t DiversityRuntime::policy_count() const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->policies.size();
}

MutationResult DiversityRuntime::evaluate(const ProofRequest& request,
                                          const ActingAuthority& authority) {
  ProofRequest canonical = request;
  if (!canonical.canonicalize()) {
    return make_result(MutationStatus::MALFORMED,
                       "proof set contains a duplicate path identity");
  }
  const Digest payload = canonical.digest();

  // --- Phase 1: authority and policy snapshot under the lock ---------------
  DiversityPolicy policy_copy;
  {
    std::lock_guard<std::mutex> guard(impl_->mutex);
    const AuthorityStatus admitted = impl_->publication->admit(authority, payload);
    if (admitted == AuthorityStatus::IDEMPOTENT) {
      ++impl_->stats.idempotent_replays;
      const DiversityProofId identity = proof_identity(canonical);
      const auto existing = impl_->proofs.find(identity);
      if (existing != impl_->proofs.end()) {
        MutationResult result = make_result(MutationStatus::IDEMPOTENT,
                                            "proof request replayed exactly");
        result.proof = existing->second.current;
        result.has_proof = true;
        return result;
      }
      return make_result(MutationStatus::IDEMPOTENT, "proof request replayed exactly");
    }
    if (!authority_status_is_success(admitted)) {
      ++impl_->stats.rejected_mutations;
      return authority_result(admitted, std::string("proof refused: ") +
                                            std::string(to_string(admitted)));
    }
    const auto found = impl_->policies.find(canonical.policy);
    if (found == impl_->policies.end()) {
      impl_->publication->forget_attempt(authority.attempt);
      ++impl_->stats.rejected_mutations;
      return make_result(MutationStatus::NOT_FOUND,
                         "no policy is published under this identity");
    }
    if (found->second.generation != canonical.policy_generation) {
      impl_->publication->forget_attempt(authority.attempt);
      ++impl_->stats.rejected_mutations;
      return make_result(MutationStatus::GENERATION_CONFLICT,
                         "request binds policy generation " +
                             std::to_string(canonical.policy_generation.value()) +
                             " but the published generation is " +
                             std::to_string(found->second.generation.value()));
    }
    policy_copy = found->second;
    // The counter is advanced under the state lock: phase two runs without any
    // lock, and an unsynchronised increment would lose updates whenever two
    // evaluations overlap.
    ++impl_->stats.evaluations;
  }

  // --- Phase 2: evaluation outside every lock ------------------------------
  EvaluationInputs inputs;
  inputs.authority = impl_->authority;
  inputs.structure = impl_->structure;
  inputs.domains = impl_->domains;
  inputs.limits = &impl_->limits;
  EvaluationResult evaluation = evaluate_diversity(canonical, policy_copy, inputs);

  const TopologyGeneration topology_after = impl_->structure->topology_generation();
  const FailureDomainGeneration domains_after = impl_->domains->generation();
  // Path Authority is re-observed as well: a path whose authorization moved
  // while the proof was being evaluated cannot be part of a current proof.
  bool authority_drift = false;
  std::string authority_drift_detail;
  if (policy_copy.require_path_authority_current) {
    for (const PathAuthorityBinding& binding : evaluation.dependencies.paths) {
      const std::optional<PathAuthorityGeneration> current =
          impl_->authority->current_generation(binding.path);
      if (!current.has_value() || *current != binding.generation ||
          !impl_->authority->is_authorized(binding.path, binding.generation)) {
        authority_drift = true;
        authority_drift_detail = "Path Authority moved for path " + binding.path.str() +
                                 " while the proof was being evaluated";
        break;
      }
    }
  }

  // --- Phase 3: watermark verification and commit --------------------------
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const auto policy_now = impl_->policies.find(canonical.policy);
  if (policy_now == impl_->policies.end() ||
      policy_now->second.generation != policy_copy.generation) {
    impl_->publication->forget_attempt(authority.attempt);
    ++impl_->stats.rejected_mutations;
    return make_result(MutationStatus::GENERATION_CONFLICT,
                       "the policy changed while the proof was being evaluated");
  }
  if (impl_->publication->current_epoch() != authority.epoch) {
    impl_->publication->forget_attempt(authority.attempt);
    ++impl_->stats.rejected_mutations;
    return make_result(MutationStatus::STALE_EPOCH,
                       "the coordinator epoch advanced while the proof was being evaluated");
  }
  if (impl_->publication->is_fenced(authority.boot)) {
    impl_->publication->forget_attempt(authority.attempt);
    ++impl_->stats.rejected_mutations;
    return make_result(MutationStatus::FENCED_PUBLISHER,
                       "the publishing boot was fenced while the proof was being evaluated");
  }

  // When the evaluation itself already reported that a path binding is stale,
  // that precise outcome is preserved: a generic watermark demotion would lose
  // the exact reason.
  if (authority_drift && (evaluation.outcome == ProofOutcome::STALE_PATH_AUTHORITY ||
                          evaluation.outcome == ProofOutcome::UNAUTHORIZED)) {
    authority_drift = false;
  }
  const bool watermark_drift =
      evaluation.watermarks_observed &&
      (topology_after != evaluation.observed_topology ||
       domains_after != evaluation.observed_failure_domain || authority_drift);
  MutationResult result;
  if (watermark_drift) {
    // A late result is never allowed to become current. The revision is still
    // recorded so the demotion is auditable.
    ++impl_->stats.watermark_rejections;
    evaluation.outcome = ProofOutcome::REVALIDATION_REQUIRED;
    evaluation.detail = authority_drift
                           ? authority_drift_detail +
                                 "; the late result is not current"
                           : "dependency watermarks moved while the proof was being evaluated "
                             "(topology " +
                                 std::to_string(evaluation.observed_topology.value()) + " -> " +
                                 std::to_string(topology_after.value()) + ", failure domains " +
                                 std::to_string(evaluation.observed_failure_domain.value()) +
                                 " -> " + std::to_string(domains_after.value()) +
                                 "); the late result is not current";
    result = make_result(MutationStatus::REVALIDATION_REQUIRED, evaluation.detail);
  } else {
    result = make_result(MutationStatus::APPLIED, "proof committed");
  }

  const DiversityProofId identity = proof_identity(canonical);
  auto record = impl_->proofs.find(identity);
  if (record == impl_->proofs.end()) {
    if (impl_->proofs.size() >= impl_->limits.max_proofs) {
      impl_->publication->forget_attempt(authority.attempt);
      ++impl_->stats.rejected_mutations;
      MutationResult limited = make_result(MutationStatus::LIMIT_EXCEEDED,
                                           "proof registry is full");
      ResourceLimitNotice notice;
      notice.bound = ResourceBound::MAX_PROOFS;
      notice.observed = impl_->proofs.size() + 1;
      notice.allowed = impl_->limits.max_proofs;
      limited.limit = notice;
      return limited;
    }
    record = impl_->proofs.emplace(identity, ProofRecord()).first;
  }
  if (authority.expected_proof_generation.is_set() &&
      authority.expected_proof_generation != record->second.current.generation) {
    impl_->publication->forget_attempt(authority.attempt);
    ++impl_->stats.rejected_mutations;
    return make_result(MutationStatus::GENERATION_CONFLICT,
                       "expected proof generation does not match the stored generation");
  }

  DiversityProof proof;
  proof.id = identity;
  proof.request = canonical;
  proof.request_digest = payload;
  proof.outcome = evaluation.outcome;
  proof.detail = evaluation.detail;
  proof.limit = evaluation.limit;
  proof.classes = evaluation.classes;
  proof.advisories = evaluation.advisories;
  proof.conflicts = evaluation.conflicts;
  proof.conflicts_total = evaluation.conflicts_total;
  proof.matrix = evaluation.matrix;
  proof.witness = evaluation.witness;
  proof.dependencies = evaluation.dependencies;
  proof.dependencies.epoch = authority.epoch;
  proof.provenance.epoch = authority.epoch;
  proof.provenance.publisher = authority.publisher;
  proof.provenance.boot = authority.boot;
  proof.provenance.attempt = authority.attempt;
  proof.lifecycle = evaluation.outcome == ProofOutcome::REVALIDATION_REQUIRED
                        ? LifecycleState::REVALIDATION_REQUIRED
                        : LifecycleState::CURRENT;
  proof.currentness = currentness_for_outcome(evaluation.outcome);
  if (evaluation.outcome == ProofOutcome::MALFORMED ||
      evaluation.outcome == ProofOutcome::RESOURCE_LIMIT ||
      evaluation.outcome == ProofOutcome::UNAUTHORIZED) {
    proof.lifecycle = LifecycleState::DECLARED;
  }

  // Immutable revision identity: the generation advances only when the semantic
  // content changes.
  {
    const bool existing_valid = record->second.current.id.valid();
    DiversityProofGeneration next = DiversityProofGeneration::from_value(1);
    if (existing_valid) {
      if (!DiversityProofGeneration::can_advance(record->second.current.generation.value())) {
        impl_->publication->forget_attempt(authority.attempt);
        return make_result(MutationStatus::GENERATION_CONFLICT,
                           "proof generation space is exhausted; it never wraps");
      }
      next = record->second.current.generation.next();
    }
    proof.generation = next;
  }
  proof.semantic_digest = proof_semantic_digest(proof);

  // A drifted revision is never reported as UNCHANGED: the drift itself is a
  // fact worth recording even when the semantic content came out the same.
  const bool unchanged = !watermark_drift && record->second.current.id.valid() &&
                         record->second.current.semantic_digest == proof.semantic_digest;
  if (unchanged) {
    ++impl_->stats.unchanged_revalidations;
    MutationResult same = make_result(MutationStatus::UNCHANGED,
                                      "revalidation produced an identical proof revision");
    same.proof = record->second.current;
    same.has_proof = true;
    return same;
  }

  if (record->second.current.id.valid()) {
    if (record->second.history.size() >= impl_->limits.max_history) {
      record->second.history.erase(record->second.history.begin());
    }
    record->second.history.push_back(record->second.current);
  }
  record->second.current = proof;
  if (record->second.snapshots.size() >= impl_->limits.max_history) {
    record->second.snapshots.erase(record->second.snapshots.begin());
  }
  record->second.snapshots.push_back(capture_snapshot(proof));

  for (const PathRef& reference : proof.request.paths) {
    impl_->by_path[reference.path].insert(identity);
  }
  for (const FailureDomainId& domain : evaluation.consulted_domains) {
    impl_->by_domain[domain].insert(identity);
  }
  for (const SharedRiskGroupId& group : evaluation.consulted_risk_groups) {
    impl_->by_risk_group[group].insert(identity);
  }
  for (const EntityRef& entity : proof.dependencies.topology_entities) {
    impl_->by_entity[entity].insert(identity);
  }
  impl_->by_policy[proof.request.policy].insert(identity);
  impl_->by_boot[proof.provenance.boot].insert(identity);
  impl_->by_topology_generation[proof.dependencies.topology_generation].insert(identity);
  impl_->by_failure_domain_generation[proof.dependencies.failure_domain_generation].insert(identity);

  ++impl_->stats.commits;
  result.proof = proof;
  result.has_proof = true;
  return result;
}

MutationResult DiversityRuntime::revalidate(const DiversityProofId& id,
                                            const ActingAuthority& authority) {
  std::optional<ProofRequest> request;
  {
    std::lock_guard<std::mutex> guard(impl_->mutex);
    const auto found = impl_->proofs.find(id);
    if (found == impl_->proofs.end()) {
      return make_result(MutationStatus::NOT_FOUND, "no proof is stored under this identity");
    }
    if (lifecycle_is_terminal(found->second.current.lifecycle)) {
      return make_result(MutationStatus::ILLEGAL_TRANSITION,
                         "a revoked or retired proof is never revalidated");
    }
    request = found->second.current.request;
  }
  return evaluate(*request, authority);
}

std::vector<MutationResult> DiversityRuntime::evaluate_batch(
    const std::vector<ProofRequest>& requests, const ActingAuthority& authority) {
  std::vector<MutationResult> results;
  const std::size_t bound = std::min<std::size_t>(requests.size(), impl_->limits.max_batch_size);
  results.reserve(bound);
  for (std::size_t i = 0; i < bound; ++i) {
    ActingAuthority per_request = authority;
    per_request.attempt = MutationAttemptId::parse(
        authority.attempt.str() + "-" + std::to_string(i));
    results.push_back(evaluate(requests[i], per_request));
  }
  if (requests.size() > bound) {
    MutationResult limited = make_result(MutationStatus::LIMIT_EXCEEDED,
                                         "batch exceeded max_batch_size");
    ResourceLimitNotice notice;
    notice.bound = ResourceBound::MAX_BATCH_SIZE;
    notice.observed = requests.size();
    notice.allowed = impl_->limits.max_batch_size;
    limited.limit = notice;
    results.push_back(limited);
  }
  return results;
}

std::optional<DiversityProof> DiversityRuntime::proof(const DiversityProofId& id) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const auto found = impl_->proofs.find(id);
  if (found == impl_->proofs.end()) {
    return std::nullopt;
  }
  return found->second.current;
}

std::vector<DiversityProof> DiversityRuntime::history(const DiversityProofId& id) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const auto found = impl_->proofs.find(id);
  if (found == impl_->proofs.end()) {
    return {};
  }
  return found->second.history;
}

std::size_t DiversityRuntime::proof_count() const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->proofs.size();
}

}  // namespace path_diversity