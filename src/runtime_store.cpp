// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "path_diversity/persistence.hpp"
#include "path_diversity/runtime.hpp"

#include "runtime_internal.hpp"

namespace path_diversity {

PersistenceStatus DiversityRuntime::save(const std::string& path) const {
  StoreContents contents;
  {
    std::lock_guard<std::mutex> guard(impl_->mutex);
    contents.epoch = impl_->publication->current_epoch();
    for (const auto& entry : impl_->policies) {
      contents.policies.push_back(entry.second);
    }
    for (const auto& entry : impl_->proofs) {
      contents.proofs.push_back(entry.second.current);
      if (!entry.second.history.empty()) {
        contents.history.emplace_back(entry.first, entry.second.history);
      }
      if (!entry.second.snapshots.empty()) {
        contents.snapshots.push_back(entry.second.snapshots.back());
      }
    }
    for (const auto& entry : impl_->publication->fenced_boots()) {
      contents.fenced_boots.push_back(entry);
    }
  }
  const std::vector<std::uint8_t> bytes = encode_store(contents, impl_->limits);
  return write_store_atomic(path, bytes);
}

PersistenceStatus DiversityRuntime::load(const std::string& path) {
  std::vector<std::uint8_t> bytes;
  PersistenceStatus status = read_store_bytes(path, impl_->limits, bytes);
  if (status != PersistenceStatus::OK) {
    return status;
  }
  StoreContents contents;
  std::string detail;
  status = decode_store(bytes.data(), bytes.size(), impl_->limits, contents, detail);
  if (status != PersistenceStatus::OK) {
    // Conservative recovery: the runtime keeps exactly the state it had.
    return status;
  }

  std::lock_guard<std::mutex> guard(impl_->mutex);
  if (contents.epoch.is_set()) {
    impl_->publication->restore_epoch(contents.epoch);
  }
  for (const DiversityPolicy& policy : contents.policies) {
    impl_->policies[policy.id] = policy;
  }
  for (const DiversityProof& proof : contents.proofs) {
    ProofRecord record;
    record.current = proof;
    record.snapshots.push_back(capture_snapshot(proof));
    impl_->proofs[proof.id] = std::move(record);
  }
  for (const auto& entry : contents.history) {
    const auto found = impl_->proofs.find(entry.first);
    if (found == impl_->proofs.end()) {
      continue;
    }
    found->second.history = entry.second;
  }
  for (const auto& entry : impl_->proofs) {
    const DiversityProof& proof = entry.second.current;
    for (const PathRef& reference : proof.request.paths) {
      impl_->by_path[reference.path].insert(entry.first);
    }
    for (const ClassResult& result : proof.classes) {
      for (const SharedResource& conflict : result.shared) {
        if (conflict.kind == ConflictClass::SHARED_RISK_GROUP) {
          SharedRiskGroupId group;
          if (group.try_parse(conflict.id).has_value()) {
            impl_->by_risk_group[*group.try_parse(conflict.id)].insert(entry.first);
          }
        } else if (relation_for_conflict_class(conflict.kind).has_value()) {
          FailureDomainId domain;
          if (domain.try_parse(conflict.id).has_value()) {
            impl_->by_domain[*domain.try_parse(conflict.id)].insert(entry.first);
          }
        }
      }
    }
    for (const EntityRef& entity : proof.dependencies.topology_entities) {
      impl_->by_entity[entity].insert(entry.first);
    }
    impl_->by_policy[proof.request.policy].insert(entry.first);
    impl_->by_boot[proof.provenance.boot].insert(entry.first);
    impl_->by_topology_generation[proof.dependencies.topology_generation].insert(entry.first);
    impl_->by_failure_domain_generation[proof.dependencies.failure_domain_generation].insert(
        entry.first);
  }
  // Live publisher authority is never restored: a restarted coordinator has no
  // live publisher until one registers again. Fences, in contrast, are
  // permanent and are restored.
  for (const WorkerBootId& boot : contents.fenced_boots) {
    impl_->publication->fence_boot(boot);
  }
  return PersistenceStatus::OK;
}

}  // namespace path_diversity
