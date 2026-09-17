// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "path_diversity/canonical.hpp"
#include "path_diversity/digest.hpp"
#include "path_diversity/export.hpp"
#include "path_diversity/ids.hpp"
#include "path_diversity/limits.hpp"

namespace path_diversity {

// Every authoritative mutation binds CoordinatorEpoch + PublisherId +
// WorkerBootId + scope + expected generation + MutationAttemptId.
//
// Default deny: an authority that has not been registered is unauthorized, a
// boot that has been fenced stays fenced forever, and an epoch below the
// coordinator current epoch is rejected. Being connected is not being
// authorized.
struct PATH_DIVERSITY_API ActingAuthority {
  CoordinatorEpoch epoch;
  PublisherId publisher;
  WorkerBootId boot;
  ScopeId scope;
  MutationAttemptId attempt;
  // Optimistic-concurrency expectation. Unset means "no policy or proof with
  // this identity may already exist".
  DiversityPolicyGeneration expected_policy_generation;
  DiversityProofGeneration expected_proof_generation;

  friend bool operator==(const ActingAuthority&, const ActingAuthority&) = default;
};

enum class AuthorityStatus : std::uint8_t {
  ACCEPTED = 1,
  // The exact same MutationAttemptId with the exact same payload: the mutation
  // already happened. Nothing advances.
  IDEMPOTENT = 2,
  UNAUTHORIZED = 3,
  FENCED_PUBLISHER = 4,
  STALE_EPOCH = 5,
  SCOPE_MISMATCH = 6,
  GENERATION_CONFLICT = 7,
  // The same MutationAttemptId arrived with a different payload.
  ATTEMPT_CONFLICT = 8,
  LIMIT_EXCEEDED = 9,
  MALFORMED = 10,
};

PATH_DIVERSITY_API std::string_view to_string(AuthorityStatus value) noexcept;
PATH_DIVERSITY_API bool is_defined_authority_status(std::uint8_t raw) noexcept;
PATH_DIVERSITY_API bool authority_status_is_success(AuthorityStatus value) noexcept;
PATH_DIVERSITY_API bool authority_status_needs_demotion(AuthorityStatus value) noexcept;

// A publisher session registered with the coordinator.
struct PATH_DIVERSITY_API PublisherSession {
  PublisherId publisher;
  WorkerBootId boot;
  CoordinatorEpoch epoch;
  ScopeId scope;
  bool fenced = false;
  friend bool operator==(const PublisherSession&, const PublisherSession&) = default;
  std::string render() const;
};

// The distributed publication authority: epoch monotonicity, publisher session
// registration, permanent boot fencing and attempt replay detection.
class PATH_DIVERSITY_API PublicationAuthority {
 public:
  explicit PublicationAuthority(const Limits& limits = {});
  ~PublicationAuthority();

  PublicationAuthority(const PublicationAuthority&) = delete;
  PublicationAuthority& operator=(const PublicationAuthority&) = delete;

  // Recovery entry point: restores the coordinator epoch from durable state.
  // The epoch may only move forward; a lower epoch is refused.
  AuthorityStatus restore_epoch(CoordinatorEpoch epoch);
  CoordinatorEpoch current_epoch() const;

  // A fresh process must present a fresh WorkerBootId. Registering a boot that
  // has been fenced is refused permanently.
  AuthorityStatus register_publisher(const PublisherSession& session);
  AuthorityStatus fence_boot(const WorkerBootId& boot);
  bool is_fenced(const WorkerBootId& boot) const;

  // Validates an authority without mutating replay state.
  AuthorityStatus validate(const ActingAuthority& authority) const;

  // Validates and records the attempt. The payload digest is the digest of the
  // exact mutation content: the same attempt id with a different payload is a
  // conflict, and the same attempt id with the same payload is IDEMPOTENT.
  AuthorityStatus admit(const ActingAuthority& authority, const Digest& payload_digest);
  // Releases a reserved attempt after a failed commit so the caller can retry
  // with the same id.
  void forget_attempt(const MutationAttemptId& attempt);

  // Demotes every live publication attributed to a boot. Called when a worker
  // is detected dead.
  std::vector<WorkerBootId> fenced_boots() const;
  std::size_t session_count() const;
  std::string render() const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

// Fresh, process-unique worker boot identity. Two calls in one process never
// agree; it carries no randomness contract and no cryptographic meaning.
PATH_DIVERSITY_API WorkerBootId mint_worker_boot_id();
PATH_DIVERSITY_API PublisherId mint_publisher_id(std::string_view label);
PATH_DIVERSITY_API MutationAttemptId mint_mutation_attempt_id();

}  // namespace path_diversity
