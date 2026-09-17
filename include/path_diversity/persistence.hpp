// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "path_diversity/authority.hpp"
#include "path_diversity/canonical.hpp"
#include "path_diversity/digest.hpp"
#include "path_diversity/export.hpp"
#include "path_diversity/ids.hpp"
#include "path_diversity/limits.hpp"
#include "path_diversity/policy.hpp"
#include "path_diversity/proof.hpp"
#include "path_diversity/snapshot.hpp"

namespace path_diversity {

// Every rejection reason a durable store can produce. A corrupt file is never
// silently repaired, never partially applied and never acknowledged as a
// successful load.
enum class PersistenceStatus : std::uint8_t {
  OK = 1,
  EMPTY_FILE = 2,
  MALFORMED_MAGIC = 3,
  UNSUPPORTED_VERSION = 4,
  TRUNCATED = 5,
  INTEGRITY_FAILURE = 6,
  TRAILING_BYTES = 7,
  RECORD_LIMIT_EXCEEDED = 8,
  SIZE_LIMIT_EXCEEDED = 9,
  DUPLICATE_PATH = 10,
  MALFORMED_IDENTITY = 11,
  INVALID_ENUM = 12,
  IMPOSSIBLE_GENERATION = 13,
  MATRIX_DIMENSION_MISMATCH = 14,
  UNKNOWN_REFERENCE = 15,
  INCOMPLETE_EVIDENCE_CLAIM = 16,
  INVALID_WITNESS = 17,
  ABSURD_COUNT = 18,
  ARITHMETIC_OVERFLOW = 19,
  IO_FAILURE = 20,
  ATOMIC_REPLACE_FAILURE = 21,
  LIMIT_EXCEEDED = 22,
  INTERNAL_INCONSISTENCY = 23,
};

PATH_DIVERSITY_API std::string_view to_string(PersistenceStatus value) noexcept;
PATH_DIVERSITY_API bool is_defined_persistence_status(std::uint8_t raw) noexcept;

// The specific semantic corruption a record decoder detected, carried alongside
// the generic DecodeStatus. A decoder that recognised exactly what was wrong
// records it here; a decoder that only knows the bytes are unusable leaves the
// reason unset and the caller stays conservative. This is what keeps a
// duplicate-path store from being reported as an unclassified internal failure.
struct PATH_DIVERSITY_API DecodeFailure {
  PersistenceStatus status = PersistenceStatus::OK;

  bool classified() const noexcept { return status != PersistenceStatus::OK; }
  void classify(PersistenceStatus value) noexcept { status = value; }
};

// Maps a decoder outcome onto a public persistence status. An unclassified
// structural failure stays conservatively INTERNAL_INCONSISTENCY; a classified
// one keeps its exact reason.
PATH_DIVERSITY_API PersistenceStatus persistence_status_for(DecodeStatus status,
                                                            const DecodeFailure& failure) noexcept;

// One durable record of an admitted mutation attempt, so replay detection
// survives a restart.
struct PATH_DIVERSITY_API MutationAttemptRecord {
  MutationAttemptId attempt;
  Digest payload;
  DiversityProofId proof;
  friend bool operator==(const MutationAttemptRecord&, const MutationAttemptRecord&) = default;
};

// The complete durable content of a runtime. Recovery is conservative: a store
// that cannot be fully validated is refused and the caller keeps whatever it
// had.
struct PATH_DIVERSITY_API StoreContents {
  CoordinatorEpoch epoch;
  std::vector<DiversityPolicy> policies;
  std::vector<DiversityProof> proofs;
  // Persisted as provenance only. A restarted coordinator restores no live
  // publisher authority: a publisher must register again with a fresh boot.
  std::vector<PublisherSession> sessions;
  // Fences are permanent and are restored.
  std::vector<WorkerBootId> fenced_boots;
  std::vector<MutationAttemptRecord> attempts;
  // Retained proof history, oldest first, keyed by proof identity.
  std::vector<std::pair<DiversityProofId, std::vector<DiversityProof>>> history;
  // Latest immutable snapshot per proof identity, in the same order as proofs.
  std::vector<ProofSnapshot> snapshots;
  friend bool operator==(const StoreContents&, const StoreContents&) = default;
};

// --- Per record codecs (shared by the durable store and the wire codec) ----
PATH_DIVERSITY_API void encode_policy(ByteWriter& writer, const DiversityPolicy& policy);
PATH_DIVERSITY_API DecodeStatus decode_policy(ByteReader& reader, const Limits& limits,
                                              DiversityPolicy& out,
                                              DecodeFailure* failure = nullptr);
PATH_DIVERSITY_API void encode_proof(ByteWriter& writer, const DiversityProof& proof);
PATH_DIVERSITY_API DecodeStatus decode_proof(ByteReader& reader, const Limits& limits,
                                             DiversityProof& out,
                                             DecodeFailure* failure = nullptr);
PATH_DIVERSITY_API void encode_snapshot(ByteWriter& writer, const ProofSnapshot& snapshot);
PATH_DIVERSITY_API DecodeStatus decode_snapshot(ByteReader& reader, const Limits& limits,
                                                ProofSnapshot& out,
                                                DecodeFailure* failure = nullptr);
// --- Whole store ----------------------------------------------------------
PATH_DIVERSITY_API std::vector<std::uint8_t> encode_store(const StoreContents& contents,
                                                          const Limits& limits);
// Fully validates the encoded store. The detail string names the exact record
// and field that failed. A failed decode leaves the output unspecified and it
// must not be used.
PATH_DIVERSITY_API PersistenceStatus decode_store(const std::uint8_t* data, std::size_t size,
                                                  const Limits& limits, StoreContents& out,
                                                  std::string& detail);

// Atomic replacement: the new content is written to a temporary sibling, flushed
// and then renamed over the destination. A crash never leaves a half-written
// store in place of a valid one.
PATH_DIVERSITY_API PersistenceStatus write_store_atomic(const std::string& path,
                                                        const std::vector<std::uint8_t>& bytes);
PATH_DIVERSITY_API PersistenceStatus read_store_bytes(const std::string& path,
                                                      const Limits& limits,
                                                      std::vector<std::uint8_t>& out);

}  // namespace path_diversity
