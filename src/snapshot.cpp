// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include "path_diversity/snapshot.hpp"

#include <algorithm>
#include <string>

#include "path_diversity/version.hpp"

namespace path_diversity {

namespace {

void digest_classes(Digest& digest, const std::vector<ClassResult>& classes) {
  digest.update_varint(classes.size());
  for (const ClassResult& result : classes) {
    digest.update_u8(static_cast<std::uint8_t>(result.klass));
    digest.update_u8(static_cast<std::uint8_t>(result.outcome));
    digest.update_u8(result.evidence_complete ? 1U : 0U);
    digest.update_varint(result.shared.size());
    for (const SharedResource& conflict : result.shared) {
      digest.update_u8(static_cast<std::uint8_t>(conflict.kind));
      digest.update_u8(static_cast<std::uint8_t>(conflict.relation));
      digest.update_text(conflict.id);
      digest.update_varint(conflict.paths.size());
      for (std::uint32_t index : conflict.paths) {
        digest.update_varint(index);
      }
    }
  }
}

}  // namespace

std::string ProofSnapshot::render() const {
  std::string out = "snapshot ";
  out += id.str();
  out += " proof=";
  out += proof.str();
  out += "@g";
  out += std::to_string(generation.value());
  out += " policy=";
  out += policy.str();
  out += "@g";
  out += std::to_string(policy_generation.value());
  out += " outcome=";
  out += std::string(to_string(outcome));
  out += " lifecycle=";
  out += std::string(to_string(lifecycle));
  out += " currentness=";
  out += std::string(to_string(currentness));
  out += " paths=[";
  for (std::size_t i = 0; i < paths.size(); ++i) {
    if (i != 0) {
      out += ",";
    }
    out += paths[i].render();
  }
  out += "]";
  return out;
}

Digest snapshot_digest(const ProofSnapshot& snapshot) {
  Digest digest;
  digest.update_u32(kDiversityRuleSetVersion);
  digest.update_u32(kCanonicalEncodingVersion);

  digest.update_text(snapshot.proof.view());
  digest.update_u64(snapshot.generation.value());
  digest.update_text(snapshot.policy.view());
  digest.update_u64(snapshot.policy_generation.value());

  digest.update_varint(snapshot.paths.size());
  for (const PathRef& reference : snapshot.paths) {
    digest.update_text(reference.path.view());
    digest.update_u64(reference.authority_generation.value());
  }

  digest.update_u8(static_cast<std::uint8_t>(snapshot.outcome));
  digest_classes(digest, snapshot.classes);

  digest.update_varint(snapshot.conflicts.size());
  for (const SharedResource& conflict : snapshot.conflicts) {
    digest.update_u8(static_cast<std::uint8_t>(conflict.kind));
    digest.update_u8(static_cast<std::uint8_t>(conflict.relation));
    digest.update_text(conflict.id);
    digest.update_varint(conflict.paths.size());
    for (std::uint32_t index : conflict.paths) {
      digest.update_varint(index);
    }
  }

  digest.update_u8(snapshot.witness.present ? 1U : 0U);
  digest.update_u64(snapshot.witness.requested_k);
  digest.update_u64(snapshot.witness.achieved);
  digest.update_u8(snapshot.witness.maximum_exact ? 1U : 0U);
  digest.update_varint(snapshot.witness.indices.size());
  for (std::uint32_t index : snapshot.witness.indices) {
    digest.update_varint(index);
  }

  digest.update_u64(snapshot.dependencies.policy_generation.value());
  digest.update_u64(snapshot.dependencies.topology_generation.value());
  digest.update_u64(snapshot.dependencies.failure_domain_generation.value());
  digest.update_u64(snapshot.dependencies.epoch.value());
  digest.update_u8(static_cast<std::uint8_t>(snapshot.dependencies.endpoint_exemption));
  digest.update_varint(snapshot.dependencies.paths.size());
  for (const PathAuthorityBinding& binding : snapshot.dependencies.paths) {
    digest.update_text(binding.path.view());
    digest.update_u64(binding.generation.value());
  }

  digest.update_u8(static_cast<std::uint8_t>(snapshot.lifecycle));
  digest.update_u8(static_cast<std::uint8_t>(snapshot.currentness));
  digest.update_u64(snapshot.provenance.epoch.value());
  digest.update_text(snapshot.provenance.publisher.view());
  digest.update_text(snapshot.provenance.boot.view());
  digest.update_text(snapshot.provenance.attempt.view());
  return digest;
}

void finalize_snapshot(ProofSnapshot& snapshot) {
  snapshot.digest = snapshot_digest(snapshot);
  snapshot.id = derived_snapshot_id(snapshot.digest);
}

ProofSnapshot capture_snapshot(const DiversityProof& proof) {
  ProofSnapshot snapshot;
  snapshot.proof = proof.id;
  snapshot.generation = proof.generation;
  snapshot.policy = proof.request.policy;
  snapshot.policy_generation = proof.request.policy_generation;
  snapshot.paths = proof.request.paths;
  snapshot.outcome = proof.outcome;
  snapshot.classes = proof.classes;
  snapshot.conflicts = proof.conflicts;
  snapshot.witness = proof.witness;
  snapshot.dependencies = proof.dependencies;
  snapshot.lifecycle = proof.lifecycle;
  snapshot.currentness = proof.currentness;
  snapshot.provenance = proof.provenance;
  finalize_snapshot(snapshot);
  return snapshot;
}

std::string_view to_string(DiffKind value) noexcept {
  switch (value) {
    case DiffKind::PATH_ADDED:
      return "PATH_ADDED";
    case DiffKind::PATH_REMOVED:
      return "PATH_REMOVED";
    case DiffKind::POLICY_CHANGED:
      return "POLICY_CHANGED";
    case DiffKind::CONFLICT_APPEARED:
      return "CONFLICT_APPEARED";
    case DiffKind::CONFLICT_DISAPPEARED:
      return "CONFLICT_DISAPPEARED";
    case DiffKind::EVIDENCE_COMPLETENESS_CHANGED:
      return "EVIDENCE_COMPLETENESS_CHANGED";
    case DiffKind::TOPOLOGY_GENERATION_CHANGED:
      return "TOPOLOGY_GENERATION_CHANGED";
    case DiffKind::FAILURE_DOMAIN_GENERATION_CHANGED:
      return "FAILURE_DOMAIN_GENERATION_CHANGED";
    case DiffKind::PATH_AUTHORITY_GENERATION_CHANGED:
      return "PATH_AUTHORITY_GENERATION_CHANGED";
    case DiffKind::POLICY_GENERATION_CHANGED:
      return "POLICY_GENERATION_CHANGED";
    case DiffKind::EPOCH_CHANGED:
      return "EPOCH_CHANGED";
    case DiffKind::PROOF_RESULT_CHANGED:
      return "PROOF_RESULT_CHANGED";
    case DiffKind::CURRENTNESS_CHANGED:
      return "CURRENTNESS_CHANGED";
    case DiffKind::LIFECYCLE_CHANGED:
      return "LIFECYCLE_CHANGED";
    case DiffKind::WITNESS_CHANGED:
      return "WITNESS_CHANGED";
    case DiffKind::CLASS_RESULT_CHANGED:
      return "CLASS_RESULT_CHANGED";
    case DiffKind::PROOF_GENERATION_CHANGED:
      return "PROOF_GENERATION_CHANGED";
    case DiffKind::PROVENANCE_CHANGED:
      return "PROVENANCE_CHANGED";
  }
  return "UNKNOWN";
}

bool is_defined_diff_kind(std::uint8_t raw) noexcept {
  return raw >= static_cast<std::uint8_t>(DiffKind::PATH_ADDED) &&
         raw <= static_cast<std::uint8_t>(DiffKind::PROVENANCE_CHANGED);
}

std::string DiffEntry::render() const {
  std::string out(to_string(kind));
  out += " ";
  out += subject;
  out += ": ";
  out += before;
  out += " -> ";
  out += after;
  return out;
}

std::string ProofDiff::render() const {
  std::string out = "diff ";
  out += left.str();
  out += " -> ";
  out += right.str();
  out += truncated ? " (truncated)" : "";
  out += "\n";
  for (const DiffEntry& entry : entries) {
    out += "  ";
    out += entry.render();
    out += "\n";
  }
  if (entries.empty()) {
    out += "  (no differences)\n";
  }
  return out;
}

namespace {

void push_entry(ProofDiff& diff, const Limits& limits, DiffKind kind, std::string subject,
                std::string before, std::string after) {
  ++diff.entries_total;
  if (diff.entries.size() >= limits.max_diff_entries) {
    diff.truncated = true;
    return;
  }
  DiffEntry entry;
  entry.kind = kind;
  entry.subject = std::move(subject);
  entry.before = std::move(before);
  entry.after = std::move(after);
  diff.entries.push_back(std::move(entry));
}

std::string generation_text(std::uint64_t value) { return std::to_string(value); }

}  // namespace

ProofDiff diff_snapshots(const ProofSnapshot& left, const ProofSnapshot& right,
                         const Limits& limits) {
  ProofDiff diff;
  diff.left = left.id;
  diff.right = right.id;

  if (left.proof != right.proof) {
    push_entry(diff, limits, DiffKind::PROVENANCE_CHANGED, "proof-identity", left.proof.str(),
               right.proof.str());
  }
  if (left.generation != right.generation) {
    push_entry(diff, limits, DiffKind::PROOF_GENERATION_CHANGED, "generation",
               generation_text(left.generation.value()),
               generation_text(right.generation.value()));
  }
  if (left.policy != right.policy) {
    push_entry(diff, limits, DiffKind::POLICY_CHANGED, "policy", left.policy.str(),
               right.policy.str());
  }
  if (left.policy_generation != right.policy_generation) {
    push_entry(diff, limits, DiffKind::POLICY_GENERATION_CHANGED, "policy-generation",
               generation_text(left.policy_generation.value()),
               generation_text(right.policy_generation.value()));
  }

  // Path set membership, matched by path identity so a reordering alone is not
  // reported as a change.
  for (const PathRef& reference : right.paths) {
    bool found = false;
    for (const PathRef& candidate : left.paths) {
      if (candidate.path == reference.path) {
        found = true;
        if (candidate.authority_generation != reference.authority_generation) {
          push_entry(diff, limits, DiffKind::PATH_AUTHORITY_GENERATION_CHANGED,
                     reference.path.str(), generation_text(candidate.authority_generation.value()),
                     generation_text(reference.authority_generation.value()));
        }
        break;
      }
    }
    if (!found) {
      push_entry(diff, limits, DiffKind::PATH_ADDED, reference.path.str(), "-",
                 reference.render());
    }
  }
  for (const PathRef& reference : left.paths) {
    bool found = false;
    for (const PathRef& candidate : right.paths) {
      if (candidate.path == reference.path) {
        found = true;
        break;
      }
    }
    if (!found) {
      push_entry(diff, limits, DiffKind::PATH_REMOVED, reference.path.str(), reference.render(),
                 "-");
    }
  }

  if (left.dependencies.topology_generation != right.dependencies.topology_generation) {
    push_entry(diff, limits, DiffKind::TOPOLOGY_GENERATION_CHANGED, "topology-generation",
               generation_text(left.dependencies.topology_generation.value()),
               generation_text(right.dependencies.topology_generation.value()));
  }
  if (left.dependencies.failure_domain_generation !=
      right.dependencies.failure_domain_generation) {
    push_entry(diff, limits, DiffKind::FAILURE_DOMAIN_GENERATION_CHANGED, "failure-domain-generation",
               generation_text(left.dependencies.failure_domain_generation.value()),
               generation_text(right.dependencies.failure_domain_generation.value()));
  }
  if (left.dependencies.epoch != right.dependencies.epoch) {
    push_entry(diff, limits, DiffKind::EPOCH_CHANGED, "epoch",
               generation_text(left.dependencies.epoch.value()),
               generation_text(right.dependencies.epoch.value()));
  }
  if (left.outcome != right.outcome) {
    push_entry(diff, limits, DiffKind::PROOF_RESULT_CHANGED, "outcome",
               std::string(to_string(left.outcome)), std::string(to_string(right.outcome)));
  }
  if (left.currentness != right.currentness) {
    push_entry(diff, limits, DiffKind::CURRENTNESS_CHANGED, "currentness",
               std::string(to_string(left.currentness)), std::string(to_string(right.currentness)));
  }
  if (left.lifecycle != right.lifecycle) {
    push_entry(diff, limits, DiffKind::LIFECYCLE_CHANGED, "lifecycle",
               std::string(to_string(left.lifecycle)), std::string(to_string(right.lifecycle)));
  }

  // Per-class evidence completeness and verdict.
  for (const ClassResult& before : left.classes) {
    for (const ClassResult& after : right.classes) {
      if (before.klass != after.klass) {
        continue;
      }
      const std::string subject(to_string(before.klass));
      if (before.evidence_complete != after.evidence_complete) {
        push_entry(diff, limits, DiffKind::EVIDENCE_COMPLETENESS_CHANGED, subject,
                   before.evidence_complete ? "COMPLETE" : "INCOMPLETE",
                   after.evidence_complete ? "COMPLETE" : "INCOMPLETE");
      }
      if (before.outcome != after.outcome) {
        push_entry(diff, limits, DiffKind::CLASS_RESULT_CHANGED, subject,
                   std::string(to_string(before.outcome)),
                   std::string(to_string(after.outcome)));
      }
      break;
    }
  }

  // Conflicts, matched by kind + identity so that ordering alone is not a change.
  for (const SharedResource& conflict : right.conflicts) {
    bool found = false;
    for (const SharedResource& candidate : left.conflicts) {
      if (candidate.kind == conflict.kind && candidate.id == conflict.id) {
        found = true;
        break;
      }
    }
    if (!found) {
      push_entry(diff, limits, DiffKind::CONFLICT_APPEARED,
                 std::string(to_string(conflict.kind)) + " " + conflict.id, "-",
                 conflict.render());
    }
  }
  for (const SharedResource& conflict : left.conflicts) {
    bool found = false;
    for (const SharedResource& candidate : right.conflicts) {
      if (candidate.kind == conflict.kind && candidate.id == conflict.id) {
        found = true;
        break;
      }
    }
    if (!found) {
      push_entry(diff, limits, DiffKind::CONFLICT_DISAPPEARED,
                 std::string(to_string(conflict.kind)) + " " + conflict.id, conflict.render(), "-");
    }
  }

  if (!(left.witness == right.witness)) {
    push_entry(diff, limits, DiffKind::WITNESS_CHANGED, "witness", left.witness.render(),
               right.witness.render());
  }
  if (!(left.provenance == right.provenance)) {
    push_entry(diff, limits, DiffKind::PROVENANCE_CHANGED, "provenance", left.provenance.publisher.str(),
               right.provenance.publisher.str());
  }
  return diff;
}

}  // namespace path_diversity
