// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include "path_diversity/evidence.hpp"

#include <algorithm>
#include <map>
#include <mutex>
#include <string>
#include <utility>

#include "path_diversity/canonical.hpp"

namespace path_diversity {

namespace {

struct PathRecord {
  PathComposition composition;
  PathAuthorityGeneration current;
  bool authorized = false;
};

std::vector<EntityRef> entities_of(const PathComposition& composition) {
  std::vector<EntityRef> entities;
  for (const LinkId& link : composition.links) {
    entities.push_back(EntityRef{EntityKind::LINK, link.str()});
  }
  for (const NodeId& node : composition.transit_nodes) {
    entities.push_back(EntityRef{EntityKind::NODE, node.str()});
  }
  for (const NodeId& node : composition.sources) {
    entities.push_back(EntityRef{EntityKind::ENDPOINT, node.str()});
  }
  for (const NodeId& node : composition.destinations) {
    entities.push_back(EntityRef{EntityKind::ENDPOINT, node.str()});
  }
  for (const DeviceId& device : composition.devices) {
    entities.push_back(EntityRef{EntityKind::DEVICE, device.str()});
  }
  return entities;
}

}  // namespace

struct InMemoryEvidence::Impl {
  mutable std::mutex mutex;
  TopologyGeneration topology = TopologyGeneration::from_value(1);
  FailureDomainGeneration failure_domains = FailureDomainGeneration::from_value(1);
  std::map<PathId, PathRecord> paths;
  std::map<std::pair<EntityRef, DomainRelation>, DomainEvidence> memberships;
  std::map<EntityRef, SrlgEvidence> srlg_memberships;
};

InMemoryEvidence::InMemoryEvidence() : impl_(new Impl()) {}

InMemoryEvidence::~InMemoryEvidence() = default;

std::optional<PathAuthorityGeneration> InMemoryEvidence::current_generation(
    const PathId& path) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const auto found = impl_->paths.find(path);
  if (found == impl_->paths.end() || !found->second.authorized) {
    return std::nullopt;
  }
  return found->second.current;
}

bool InMemoryEvidence::is_authorized(const PathId& path,
                                     PathAuthorityGeneration generation) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const auto found = impl_->paths.find(path);
  if (found == impl_->paths.end() || !found->second.authorized) {
    return false;
  }
  return found->second.current == generation;
}

TopologyGeneration InMemoryEvidence::topology_generation() const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->topology;
}

std::optional<PathComposition> InMemoryEvidence::composition(const PathId& path) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const auto found = impl_->paths.find(path);
  if (found == impl_->paths.end()) {
    return std::nullopt;
  }
  return found->second.composition;
}

FailureDomainGeneration InMemoryEvidence::generation() const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->failure_domains;
}

DomainEvidence InMemoryEvidence::domain_membership(const EntityRef& entity,
                                                   DomainRelation relation) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const auto found = impl_->memberships.find(std::make_pair(entity, relation));
  if (found == impl_->memberships.end()) {
    // Absent means the authority holds no classification for this entity under
    // this relation. It never means the entity belongs to no domain.
    DomainEvidence absent;
    absent.coverage = EvidenceCoverage::ABSENT;
    absent.generation = impl_->failure_domains;
    return absent;
  }
  return found->second;
}

SrlgEvidence InMemoryEvidence::srlg_membership(const EntityRef& entity) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const auto found = impl_->srlg_memberships.find(entity);
  if (found == impl_->srlg_memberships.end()) {
    SrlgEvidence absent;
    absent.coverage = EvidenceCoverage::ABSENT;
    absent.generation = impl_->failure_domains;
    return absent;
  }
  return found->second;
}

void InMemoryEvidence::set_topology_generation(TopologyGeneration generation) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  impl_->topology = generation;
}

void InMemoryEvidence::advance_topology_generation() {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  if (TopologyGeneration::can_advance(impl_->topology.value())) {
    impl_->topology = impl_->topology.next();
  }
}

void InMemoryEvidence::set_failure_domain_generation(FailureDomainGeneration generation) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  impl_->failure_domains = generation;
}

void InMemoryEvidence::advance_failure_domain_generation() {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  if (FailureDomainGeneration::can_advance(impl_->failure_domains.value())) {
    impl_->failure_domains = impl_->failure_domains.next();
  }
}

void InMemoryEvidence::set_path(PathComposition composition) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  PathRecord record;
  record.current = composition.authority_generation;
  record.authorized = true;
  composition.canonicalize();
  record.composition = std::move(composition);
  impl_->paths[record.composition.path] = std::move(record);
}

void InMemoryEvidence::set_path_authority(const PathId& path,
                                          PathAuthorityGeneration generation, bool authorized) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  auto found = impl_->paths.find(path);
  if (found == impl_->paths.end()) {
    return;
  }
  found->second.current = generation;
  found->second.authorized = authorized;
  found->second.composition.authority_generation = generation;
}

void InMemoryEvidence::revoke_path(const PathId& path) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const auto found = impl_->paths.find(path);
  if (found != impl_->paths.end()) {
    found->second.authorized = false;
  }
}

bool InMemoryEvidence::has_path(const PathId& path) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->paths.find(path) != impl_->paths.end();
}

void InMemoryEvidence::set_domain_membership(const EntityRef& entity, DomainRelation relation,
                                             EvidenceCoverage coverage,
                                             std::vector<FailureDomainId> domains) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  DomainEvidence evidence;
  evidence.coverage = coverage;
  evidence.generation = impl_->failure_domains;
  evidence.domains = std::move(domains);
  evidence.canonicalize();
  impl_->memberships[std::make_pair(entity, relation)] = std::move(evidence);
}

void InMemoryEvidence::set_srlg_membership(const EntityRef& entity, EvidenceCoverage coverage,
                                           std::vector<SharedRiskGroupId> groups) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  SrlgEvidence evidence;
  evidence.coverage = coverage;
  evidence.generation = impl_->failure_domains;
  evidence.groups = std::move(groups);
  evidence.canonicalize();
  impl_->srlg_memberships[entity] = std::move(evidence);
}

void InMemoryEvidence::clear_entity(const EntityRef& entity) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  impl_->srlg_memberships.erase(entity);
  for (auto entry = impl_->memberships.begin(); entry != impl_->memberships.end();) {
    if (entry->first.first == entity) {
      entry = impl_->memberships.erase(entry);
    } else {
      ++entry;
    }
  }
}

void InMemoryEvidence::assign_path_entities(const PathId& path, DomainRelation relation,
                                            EvidenceCoverage coverage,
                                            std::vector<FailureDomainId> domains) {
  std::vector<EntityRef> entities;
  {
    std::lock_guard<std::mutex> guard(impl_->mutex);
    const auto found = impl_->paths.find(path);
    if (found == impl_->paths.end()) {
      return;
    }
    entities = entities_of(found->second.composition);
  }
  for (const EntityRef& entity : entities) {
    set_domain_membership(entity, relation, coverage, domains);
  }
}

void InMemoryEvidence::assign_path_entities_srlg(const PathId& path, EvidenceCoverage coverage,
                                                 std::vector<SharedRiskGroupId> groups) {
  std::vector<EntityRef> entities;
  {
    std::lock_guard<std::mutex> guard(impl_->mutex);
    const auto found = impl_->paths.find(path);
    if (found == impl_->paths.end()) {
      return;
    }
    entities = entities_of(found->second.composition);
  }
  for (const EntityRef& entity : entities) {
    set_srlg_membership(entity, coverage, groups);
  }
}

std::size_t InMemoryEvidence::path_count() const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->paths.size();
}

std::size_t InMemoryEvidence::membership_count() const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->memberships.size() + impl_->srlg_memberships.size();
}

std::string InMemoryEvidence::render() const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  std::string out = "evidence topology=g";
  out += std::to_string(impl_->topology.value());
  out += " failure-domains=g";
  out += std::to_string(impl_->failure_domains.value());
  out += " paths=" + std::to_string(impl_->paths.size());
  out += " memberships=" + std::to_string(impl_->memberships.size());
  out += " srlg=" + std::to_string(impl_->srlg_memberships.size());
  out += "\n";
  for (const auto& entry : impl_->paths) {
    out += "  ";
    out += entry.first.str();
    out += " pa=g";
    out += std::to_string(entry.second.current.value());
    out += entry.second.authorized ? " authorized" : " unauthorized";
    out += " links=" + std::to_string(entry.second.composition.links.size());
    out += " nodes=" + std::to_string(entry.second.composition.transit_nodes.size());
    out += " devices=" + std::to_string(entry.second.composition.devices.size());
    out += "\n";
  }
  return out;
}

}  // namespace path_diversity
