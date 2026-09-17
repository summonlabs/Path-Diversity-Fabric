// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include <algorithm>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "path_diversity/runtime.hpp"
#include "path_diversity/version.hpp"

#include "runtime_internal.hpp"

namespace path_diversity {

std::optional<ProofSnapshot> DiversityRuntime::snapshot(const DiversityProofId& id) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const auto found = impl_->proofs.find(id);
  if (found == impl_->proofs.end() || found->second.snapshots.empty()) {
    return std::nullopt;
  }
  return found->second.snapshots.back();
}

std::vector<SnapshotId> DiversityRuntime::snapshot_ids(const DiversityProofId& id) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  std::vector<SnapshotId> out;
  const auto found = impl_->proofs.find(id);
  if (found == impl_->proofs.end()) {
    return out;
  }
  out.reserve(found->second.snapshots.size());
  for (const ProofSnapshot& snapshot : found->second.snapshots) {
    out.push_back(snapshot.id);
  }
  // Snapshots are immutable and content-addressed, so an unchanged revision
  // appears once even if it was captured repeatedly.
  out.erase(std::unique(out.begin(), out.end()), out.end());
  return out;
}

std::optional<ProofDiff> DiversityRuntime::diff(const DiversityProofId& id, const SnapshotId& left,
                                                const SnapshotId& right) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const auto found = impl_->proofs.find(id);
  if (found == impl_->proofs.end()) {
    return std::nullopt;
  }
  const ProofSnapshot* left_snapshot = nullptr;
  const ProofSnapshot* right_snapshot = nullptr;
  for (const ProofSnapshot& snapshot : found->second.snapshots) {
    if (snapshot.id == left) {
      left_snapshot = &snapshot;
    }
    if (snapshot.id == right) {
      right_snapshot = &snapshot;
    }
  }
  if (left_snapshot == nullptr || right_snapshot == nullptr) {
    return std::nullopt;
  }
  return diff_snapshots(*left_snapshot, *right_snapshot, impl_->limits);
}

std::optional<Explanation> DiversityRuntime::explain(const DiversityProofId& id) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const auto found = impl_->proofs.find(id);
  if (found == impl_->proofs.end()) {
    return std::nullopt;
  }
  return explain_proof(found->second.current, impl_->limits);
}

std::optional<Explanation> DiversityRuntime::explain_pair(const DiversityProofId& id,
                                                          std::uint32_t left,
                                                          std::uint32_t right) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const auto found = impl_->proofs.find(id);
  if (found == impl_->proofs.end()) {
    return std::nullopt;
  }
  return path_diversity::explain_pair(found->second.current, left, right, impl_->limits);
}

std::optional<ConflictGraph> DiversityRuntime::conflict_graph(const DiversityProofId& id) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const auto found = impl_->proofs.find(id);
  if (found == impl_->proofs.end()) {
    return std::nullopt;
  }
  return build_conflict_graph(found->second.current.matrix);
}

RuntimeStats DiversityRuntime::stats() const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->stats;
}

std::string DiversityRuntime::render() const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  std::string out = "runtime ";
  out += std::string(version_string());
  out += " policies=" + std::to_string(impl_->policies.size());
  out += " proofs=" + std::to_string(impl_->proofs.size());
  out += "\n  indexes: path=" + std::to_string(impl_->by_path.size()) +
         " domain=" + std::to_string(impl_->by_domain.size()) +
         " risk-group=" + std::to_string(impl_->by_risk_group.size()) +
         " entity=" + std::to_string(impl_->by_entity.size()) +
         " policy=" + std::to_string(impl_->by_policy.size()) +
         " boot=" + std::to_string(impl_->by_boot.size()) +
         " topology-generation=" + std::to_string(impl_->by_topology_generation.size()) +
         " failure-domain-generation=" +
         std::to_string(impl_->by_failure_domain_generation.size());
  out += "\n  stats: evaluations=" + std::to_string(impl_->stats.evaluations) +
         " commits=" + std::to_string(impl_->stats.commits) +
         " unchanged=" + std::to_string(impl_->stats.unchanged_revalidations) +
         " idempotent=" + std::to_string(impl_->stats.idempotent_replays) +
         " rejected=" + std::to_string(impl_->stats.rejected_mutations) +
         " watermark-rejections=" + std::to_string(impl_->stats.watermark_rejections) +
         " invalidations=" + std::to_string(impl_->stats.invalidations) +
         " demotions=" + std::to_string(impl_->stats.demotions);
  out += "\n";
  for (const auto& entry : impl_->policies) {
    out += "  ";
    out += entry.second.render();
    out += "\n";
  }
  for (const auto& entry : impl_->proofs) {
    out += "  proof ";
    out += entry.first.str();
    out += "@g";
    out += std::to_string(entry.second.current.generation.value());
    out += " outcome=";
    out += std::string(to_string(entry.second.current.outcome));
    out += " lifecycle=";
    out += std::string(to_string(entry.second.current.lifecycle));
    out += " currentness=";
    out += std::string(to_string(entry.second.current.currentness));
    out += " history=" + std::to_string(entry.second.history.size());
    out += "\n";
  }
  return out;
}

}  // namespace path_diversity
