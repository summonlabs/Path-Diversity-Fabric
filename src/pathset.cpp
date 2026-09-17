// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include "path_diversity/path.hpp"

#include <algorithm>
#include <string>

#include "path_diversity/proof.hpp"
#include "path_diversity/version.hpp"

namespace path_diversity {

// ---------------------------------------------------------------------------
// Path references
// ---------------------------------------------------------------------------
std::strong_ordering operator<=>(const PathRef& lhs, const PathRef& rhs) {
  if (lhs.path != rhs.path) {
    return lhs.path < rhs.path ? std::strong_ordering::less : std::strong_ordering::greater;
  }
  if (lhs.authority_generation != rhs.authority_generation) {
    return lhs.authority_generation < rhs.authority_generation ? std::strong_ordering::less
                                                              : std::strong_ordering::greater;
  }
  return std::strong_ordering::equal;
}

std::string PathRef::render() const {
  std::string out = path.str();
  out += "@pa";
  out += std::to_string(authority_generation.value());
  return out;
}

PathAuthorityView::~PathAuthorityView() = default;
PathStructureView::~PathStructureView() = default;
FailureDomainView::~FailureDomainView() = default;

void canonical_path_order(std::vector<PathRef>& paths) {
  std::sort(paths.begin(), paths.end());
}

bool has_duplicate_paths(const std::vector<PathRef>& paths) noexcept {
  for (std::size_t i = 0; i < paths.size(); ++i) {
    for (std::size_t j = i + 1; j < paths.size(); ++j) {
      if (paths[i].path == paths[j].path) {
        return true;
      }
    }
  }
  return false;
}

Digest path_set_digest(const std::vector<PathRef>& canonical_paths) {
  ByteWriter writer;
  writer.u32(kDiversityRuleSetVersion);
  writer.u32(kCanonicalEncodingVersion);
  writer.varint(canonical_paths.size());
  for (const PathRef& reference : canonical_paths) {
    writer.text(reference.path.view());
    writer.u64(reference.authority_generation.value());
  }
  return Digest::of(writer.data().data(), writer.size());
}

PathSetId path_set_id(const std::vector<PathRef>& canonical_paths) {
  return derived_path_set_id(path_set_digest(canonical_paths));
}

// ---------------------------------------------------------------------------
// Proof requests
// ---------------------------------------------------------------------------
bool ProofRequest::canonicalize() {
  canonical_path_order(paths);
  return !has_duplicate_paths(paths);
}

Digest ProofRequest::digest() const {
  ByteWriter writer;
  writer.u32(kDiversityRuleSetVersion);
  writer.u32(kCanonicalEncodingVersion);
  writer.text(policy.view());
  writer.u64(policy_generation.value());
  writer.u64(static_cast<std::uint64_t>(paths.size()));
  for (const PathRef& reference : paths) {
    writer.text(reference.path.view());
    writer.u64(reference.authority_generation.value());
  }
  return Digest::of(writer.data().data(), writer.size());
}

PathSetId ProofRequest::path_set() const { return path_set_id(paths); }

// ---------------------------------------------------------------------------
// Proof content digest.
//
// Included: the exact canonical path set, the policy identity and generation,
// every bound dependency generation, the outcome, every class result with its
// evidence-completeness fact and its complete ordered conflict list, every
// conflict, the witness subset and the pairwise matrix.
//
// Excluded by construction: timestamps, thread ids, sockets, memory addresses,
// arrival order, free-text detail strings, lifecycle, currentness, provenance
// and diagnostic counters. None of them is an input to this function, so two
// permutations of the same request produce one digest.
// ---------------------------------------------------------------------------
namespace {

void digest_conflict(Digest& digest, const SharedResource& conflict) {
  digest.update_u8(static_cast<std::uint8_t>(conflict.kind));
  digest.update_u8(static_cast<std::uint8_t>(conflict.relation));
  digest.update_text(conflict.id);
  digest.update_varint(conflict.paths.size());
  for (std::uint32_t index : conflict.paths) {
    digest.update_varint(index);
  }
}

void digest_class_result(Digest& digest, const ClassResult& result) {
  digest.update_u8(static_cast<std::uint8_t>(result.klass));
  digest.update_u8(static_cast<std::uint8_t>(result.outcome));
  digest.update_u8(result.evidence_complete ? 1U : 0U);
  digest.update_varint(result.shared.size());
  for (const SharedResource& conflict : result.shared) {
    digest_conflict(digest, conflict);
  }
}

}  // namespace

Digest proof_semantic_digest(const DiversityProof& proof) {
  Digest digest;
  digest.update_u32(kDiversityRuleSetVersion);
  digest.update_u32(kCanonicalEncodingVersion);
  digest.update_u32(kDigestSchemeVersion);

  digest.update_text(proof.request.policy.view());
  digest.update_u64(proof.request.policy_generation.value());
  digest.update_u64(static_cast<std::uint64_t>(proof.request.paths.size()));
  for (const PathRef& reference : proof.request.paths) {
    digest.update_text(reference.path.view());
    digest.update_u64(reference.authority_generation.value());
  }

  digest.update_u8(static_cast<std::uint8_t>(proof.outcome));
  if (proof.limit.has_value()) {
    digest.update_u8(1U);
    digest.update_u8(static_cast<std::uint8_t>(proof.limit->bound));
    digest.update_u64(proof.limit->observed);
    digest.update_u64(proof.limit->allowed);
  } else {
    digest.update_u8(0U);
  }

  digest.update_varint(proof.classes.size());
  for (const ClassResult& result : proof.classes) {
    digest_class_result(digest, result);
  }
  digest.update_varint(proof.advisories.size());
  for (const ClassResult& result : proof.advisories) {
    digest_class_result(digest, result);
  }

  digest.update_varint(proof.conflicts.size());
  for (const SharedResource& conflict : proof.conflicts) {
    digest_conflict(digest, conflict);
  }

  digest.update_u8(proof.witness.present ? 1U : 0U);
  digest.update_u64(proof.witness.requested_k);
  digest.update_u64(proof.witness.achieved);
  digest.update_u8(proof.witness.maximum_exact ? 1U : 0U);
  digest.update_varint(proof.witness.indices.size());
  for (std::uint32_t index : proof.witness.indices) {
    digest.update_varint(index);
  }

  digest.update_varint(proof.matrix.cells.size());
  for (const PairwiseCell& cell : proof.matrix.cells) {
    digest.update_u8(cell.independent ? 1U : 0U);
    digest.update_u8(cell.evidence_complete ? 1U : 0U);
    digest.update_varint(cell.classes.size());
    for (const ClassResult& result : cell.classes) {
      digest_class_result(digest, result);
    }
  }

  digest.update_u64(proof.dependencies.policy_generation.value());
  digest.update_u64(proof.dependencies.topology_generation.value());
  digest.update_u64(proof.dependencies.failure_domain_generation.value());
  digest.update_u64(proof.dependencies.epoch.value());
  digest.update_u8(static_cast<std::uint8_t>(proof.dependencies.endpoint_exemption));
  digest.update_varint(proof.dependencies.paths.size());
  for (const PathAuthorityBinding& binding : proof.dependencies.paths) {
    digest.update_text(binding.path.view());
    digest.update_u64(binding.generation.value());
  }
  digest.update_varint(proof.dependencies.topology_entities.size());
  for (const EntityRef& entity : proof.dependencies.topology_entities) {
    digest.update_u8(static_cast<std::uint8_t>(entity.kind));
    digest.update_text(entity.id);
  }
  return digest;
}

DiversityProofId proof_identity(const ProofRequest& canonical_request) {
  return derived_proof_id(canonical_request.digest());
}

}  // namespace path_diversity
