// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include <algorithm>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "path_diversity/evaluate.hpp"

namespace path_diversity {

namespace {

using DomainMap = std::map<FailureDomainId, std::uint32_t>;
using SrlgMap = std::map<SharedRiskGroupId, std::uint32_t>;

std::string join_ids(const std::vector<std::string>& values) {
  std::string out;
  for (std::size_t i = 0; i < values.size(); ++i) {
    if (i != 0) {
      out += ", ";
    }
    out += values[i];
  }
  return out;
}

template <class Id>
std::vector<Id> intersect_sorted(const std::vector<Id>& left, const std::vector<Id>& right) {
  std::vector<Id> out;
  std::size_t i = 0;
  std::size_t j = 0;
  while (i < left.size() && j < right.size()) {
    if (left[i] == right[j]) {
      if (out.empty() || !(out.back() == left[i])) {
        out.push_back(left[i]);
      }
      ++i;
      ++j;
    } else if (left[i] < right[j]) {
      ++i;
    } else {
      ++j;
    }
  }
  return out;
}

// Every structural entity a path exposes to a correlated-failure query.
std::vector<EntityRef> path_entities(const PathComposition& composition) {
  std::vector<EntityRef> entities;
  entities.reserve(composition.links.size() + composition.transit_nodes.size() +
                   composition.sources.size() + composition.destinations.size() +
                   composition.devices.size());
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

// Endpoint nodes exempted from node sharing, exactly as the policy declares.
std::vector<NodeId> exempt_endpoints(const PathComposition& left, const PathComposition& right,
                                     EndpointExemption exemption) {
  switch (exemption) {
    case EndpointExemption::NONE:
      return {};
    case EndpointExemption::SHARED_SOURCE_AND_DESTINATION: {
      std::vector<NodeId> shared = intersect_sorted(left.sources, right.sources);
      const std::vector<NodeId> shared_destinations =
          intersect_sorted(left.destinations, right.destinations);
      shared.insert(shared.end(), shared_destinations.begin(), shared_destinations.end());
      canonical_sort_unique(shared);
      return shared;
    }
    case EndpointExemption::SHARED_SOURCE_ONLY:
      return intersect_sorted(left.sources, right.sources);
    case EndpointExemption::SHARED_DESTINATION_ONLY:
      return intersect_sorted(left.destinations, right.destinations);
    case EndpointExemption::ANY_ENDPOINT: {
      std::vector<NodeId> left_endpoints = left.sources;
      left_endpoints.insert(left_endpoints.end(), left.destinations.begin(),
                            left.destinations.end());
      std::vector<NodeId> right_endpoints = right.sources;
      right_endpoints.insert(right_endpoints.end(), right.destinations.begin(),
                             right.destinations.end());
      canonical_sort_unique(left_endpoints);
      canonical_sort_unique(right_endpoints);
      return intersect_sorted(left_endpoints, right_endpoints);
    }
  }
  return {};
}

std::vector<NodeId> all_nodes(const PathComposition& composition) {
  std::vector<NodeId> nodes = composition.transit_nodes;
  nodes.insert(nodes.end(), composition.sources.begin(), composition.sources.end());
  nodes.insert(nodes.end(), composition.destinations.begin(), composition.destinations.end());
  canonical_sort_unique(nodes);
  return nodes;
}

SharedResource make_conflict(ConflictClass kind, DomainRelation relation, std::string id,
                             std::uint32_t max_paths) {
  SharedResource conflict;
  conflict.kind = kind;
  conflict.relation = relation;
  conflict.id = std::move(id);
  conflict.paths.push_back(0);
  if (max_paths >= 2) {
    conflict.paths.push_back(1);
  }
  return conflict;
}

void note_incomplete(ClassResult& result, const std::string& detail) {
  result.evidence_complete = false;
  if (result.detail.empty()) {
    result.detail = detail;
  }
}

// The conflict list is bounded, but the total is always reported in full: a
// bounded list never silently pretends to be complete.
void add_shared(ClassResult& result, SharedResource conflict, std::uint32_t max_shared) {
  ++result.shared_total;
  if (result.shared.size() < max_shared) {
    result.shared.push_back(std::move(conflict));
    canonical_conflict_order(result.shared);
  }
}

// ---------------------------------------------------------------------------
// Structural classes
// ---------------------------------------------------------------------------
ClassResult evaluate_link_class(const PathComposition& left, const PathComposition& right,
                                std::uint32_t max_shared) {
  ClassResult result;
  result.klass = DiversityClass::LINK_DISJOINT;
  result.evidence_complete =
      left.link_coverage == EvidenceCoverage::COMPLETE &&
      right.link_coverage == EvidenceCoverage::COMPLETE;
  const std::vector<LinkId> shared = intersect_sorted(left.links, right.links);
  for (const LinkId& link : shared) {
    add_shared(result, make_conflict(ConflictClass::SHARED_LINK, DomainRelation::FAILURE_DOMAIN,
                                     link.str(), 2),
               max_shared);
  }
  if (!shared.empty()) {
    result.outcome = ProofOutcome::NOT_DIVERSE;
    std::vector<std::string> ids;
    for (const LinkId& link : shared) {
      ids.push_back(link.str());
    }
    result.detail = "shared links: " + join_ids(ids);
    return result;
  }
  if (!result.evidence_complete) {
    result.outcome = ProofOutcome::UNKNOWN_INCOMPLETE_EVIDENCE;
    note_incomplete(result,
                    "link coverage is not complete for both paths: absence of an observed shared "
                    "link is not evidence of link disjointness");
    return result;
  }
  result.outcome = ProofOutcome::PROVEN_DIVERSE;
  return result;
}

ClassResult evaluate_transit_node_class(const PathComposition& left, const PathComposition& right,
                                        const DiversityPolicy& policy,
                                        std::uint32_t max_shared) {
  ClassResult result;
  result.klass = DiversityClass::TRANSIT_NODE_DISJOINT;
  result.evidence_complete =
      left.node_coverage == EvidenceCoverage::COMPLETE &&
      right.node_coverage == EvidenceCoverage::COMPLETE &&
      left.endpoint_coverage == EvidenceCoverage::COMPLETE &&
      right.endpoint_coverage == EvidenceCoverage::COMPLETE;

  const std::vector<NodeId> exempt =
      exempt_endpoints(left, right, policy.endpoint_exemption);
  const std::vector<NodeId> shared_all =
      intersect_sorted(all_nodes(left), all_nodes(right));

  std::vector<NodeId> relevant;
  for (const NodeId& node : shared_all) {
    bool is_exempt = false;
    for (const NodeId& candidate : exempt) {
      if (candidate == node) {
        is_exempt = true;
        break;
      }
    }
    if (!is_exempt) {
      relevant.push_back(node);
    }
  }

  for (const NodeId& node : relevant) {
    add_shared(result,
               make_conflict(ConflictClass::SHARED_TRANSIT_NODE, DomainRelation::FAILURE_DOMAIN,
                             node.str(), 2),
               max_shared);
  }
  if (!relevant.empty()) {
    result.outcome = ProofOutcome::NOT_DIVERSE;
    std::vector<std::string> ids;
    for (const NodeId& node : relevant) {
      ids.push_back(node.str());
    }
    result.detail = "shared nodes after endpoint exemption " +
                    std::string(to_string(policy.endpoint_exemption)) + ": " + join_ids(ids);
    return result;
  }
  if (!result.evidence_complete) {
    result.outcome = ProofOutcome::UNKNOWN_INCOMPLETE_EVIDENCE;
    note_incomplete(result,
                    "node or endpoint coverage is not complete for both paths");
    return result;
  }
  result.outcome = ProofOutcome::PROVEN_DIVERSE;
  return result;
}

ClassResult evaluate_device_class(const PathComposition& left, const PathComposition& right,
                                  std::uint32_t max_shared) {
  ClassResult result;
  result.klass = DiversityClass::DEVICE_DISJOINT;
  result.evidence_complete =
      left.device_coverage == EvidenceCoverage::COMPLETE &&
      right.device_coverage == EvidenceCoverage::COMPLETE;
  const std::vector<DeviceId> shared = intersect_sorted(left.devices, right.devices);
  for (const DeviceId& device : shared) {
    add_shared(result,
               make_conflict(ConflictClass::SHARED_DEVICE, DomainRelation::FAILURE_DOMAIN,
                             device.str(), 2),
               max_shared);
  }
  if (!shared.empty()) {
    result.outcome = ProofOutcome::NOT_DIVERSE;
    std::vector<std::string> ids;
    for (const DeviceId& device : shared) {
      ids.push_back(device.str());
    }
    result.detail = "shared devices: " + join_ids(ids);
    return result;
  }
  if (!result.evidence_complete) {
    result.outcome = ProofOutcome::UNKNOWN_INCOMPLETE_EVIDENCE;
    note_incomplete(result, "device coverage is not complete for both paths");
    return result;
  }
  result.outcome = ProofOutcome::PROVEN_DIVERSE;
  return result;
}

// ---------------------------------------------------------------------------
// Domain-backed classes
// ---------------------------------------------------------------------------
void collect_domain_membership(const FailureDomainView& view, const PathComposition& composition,
                               DomainRelation relation, DomainMap& into, bool& complete,
                               std::string& missing) {
  for (const EntityRef& entity : path_entities(composition)) {
    const DomainEvidence evidence = view.domain_membership(entity, relation);
    if (evidence.coverage != EvidenceCoverage::COMPLETE) {
      complete = false;
      if (missing.empty()) {
        missing = entity.render() + " under " + std::string(to_string(relation)) + " is " +
                  std::string(to_string(evidence.coverage));
      }
    }
    for (const FailureDomainId& domain : evidence.domains) {
      ++into[domain];
    }
  }
}

void collect_srlg_membership(const FailureDomainView& view, const PathComposition& composition,
                             SrlgMap& into, bool& complete, std::string& missing) {
  for (const EntityRef& entity : path_entities(composition)) {
    const SrlgEvidence evidence = view.srlg_membership(entity);
    if (evidence.coverage != EvidenceCoverage::COMPLETE) {
      complete = false;
      if (missing.empty()) {
        missing = entity.render() + " has " + std::string(to_string(evidence.coverage)) +
                  " shared-risk-group coverage";
      }
    }
    for (const SharedRiskGroupId& group : evidence.groups) {
      ++into[group];
    }
  }
}

ClassResult evaluate_domain_relation(const PathComposition& left, const PathComposition& right,
                                     DiversityClass klass, DomainRelation relation,
                                     const FailureDomainView& view, std::uint32_t max_shared,
                                     std::vector<FailureDomainId>* consulted) {
  ClassResult result;
  result.klass = klass;
  DomainMap left_domains;
  DomainMap right_domains;
  bool complete = true;
  std::string missing;
  collect_domain_membership(view, left, relation, left_domains, complete, missing);
  collect_domain_membership(view, right, relation, right_domains, complete, missing);
  result.evidence_complete = complete;
  if (consulted != nullptr) {
    for (const auto& entry : left_domains) {
      consulted->push_back(entry.first);
    }
    for (const auto& entry : right_domains) {
      consulted->push_back(entry.first);
    }
  }

  std::vector<std::string> shared_ids;
  for (const auto& entry : left_domains) {
    if (right_domains.find(entry.first) != right_domains.end()) {
      shared_ids.push_back(entry.first.str());
      add_shared(result,
                 make_conflict(conflict_class_for_relation(relation), relation,
                               entry.first.str(), 2),
                 max_shared);
    }
  }
  if (!shared_ids.empty()) {
    result.outcome = ProofOutcome::NOT_DIVERSE;
    result.detail = "shared " + std::string(to_string(relation)) + " domains: " +
                    join_ids(shared_ids);
    return result;
  }
  if (!complete) {
    result.outcome = ProofOutcome::UNKNOWN_INCOMPLETE_EVIDENCE;
    note_incomplete(result, missing);
    return result;
  }
  result.outcome = ProofOutcome::PROVEN_DIVERSE;
  return result;
}

ClassResult evaluate_srlg_class(const PathComposition& left, const PathComposition& right,
                                const FailureDomainView& view, std::uint32_t max_shared,
                                std::vector<SharedRiskGroupId>* consulted) {
  ClassResult result;
  result.klass = DiversityClass::SHARED_RISK_GROUP_DISJOINT;
  SrlgMap left_groups;
  SrlgMap right_groups;
  bool complete = true;
  std::string missing;
  collect_srlg_membership(view, left, left_groups, complete, missing);
  collect_srlg_membership(view, right, right_groups, complete, missing);
  result.evidence_complete = complete;
  if (consulted != nullptr) {
    for (const auto& entry : left_groups) {
      consulted->push_back(entry.first);
    }
    for (const auto& entry : right_groups) {
      consulted->push_back(entry.first);
    }
  }

  std::vector<std::string> shared_ids;
  for (const auto& entry : left_groups) {
    if (right_groups.find(entry.first) != right_groups.end()) {
      shared_ids.push_back(entry.first.str());
      add_shared(result,
                 make_conflict(ConflictClass::SHARED_RISK_GROUP, DomainRelation::FAILURE_DOMAIN,
                               entry.first.str(), 2),
                 max_shared);
    }
  }
  if (!shared_ids.empty()) {
    result.outcome = ProofOutcome::NOT_DIVERSE;
    result.detail = "shared risk groups: " + join_ids(shared_ids);
    return result;
  }
  if (!complete) {
    result.outcome = ProofOutcome::UNKNOWN_INCOMPLETE_EVIDENCE;
    note_incomplete(result, missing);
    return result;
  }
  result.outcome = ProofOutcome::PROVEN_DIVERSE;
  return result;
}

ClassResult evaluate_single_class(DiversityClass klass, const PathComposition& left,
                                  const PathComposition& right, const DiversityPolicy& policy,
                                  const EvaluationInputs& inputs, std::uint32_t max_shared,
                                  std::vector<FailureDomainId>* consulted_domains,
                                  std::vector<SharedRiskGroupId>* consulted_risk_groups) {
  switch (klass) {
    case DiversityClass::LINK_DISJOINT:
      return evaluate_link_class(left, right, max_shared);
    case DiversityClass::TRANSIT_NODE_DISJOINT:
      return evaluate_transit_node_class(left, right, policy, max_shared);
    case DiversityClass::DEVICE_DISJOINT:
      return evaluate_device_class(left, right, max_shared);
    case DiversityClass::SHARED_RISK_GROUP_DISJOINT:
      return evaluate_srlg_class(left, right, *inputs.domains, max_shared, consulted_risk_groups);
    case DiversityClass::RACK_DISJOINT:
      return evaluate_domain_relation(left, right, klass, DomainRelation::RACK, *inputs.domains,
                                      max_shared, consulted_domains);
    case DiversityClass::POD_DISJOINT:
      return evaluate_domain_relation(left, right, klass, DomainRelation::POD, *inputs.domains,
                                      max_shared, consulted_domains);
    case DiversityClass::SITE_DISJOINT:
      return evaluate_domain_relation(left, right, klass, DomainRelation::SITE, *inputs.domains,
                                      max_shared, consulted_domains);
    case DiversityClass::FAILURE_DOMAIN_DISJOINT: {
      // One class, several declared relations. The class is proven only when
      // every declared relation is proven; a conflict in any relation is a
      // conflict for the class.
      ClassResult merged;
      merged.klass = klass;
      if (policy.allowed_failure_domain_relations.empty()) {
        // With no declared relation set there is nothing to be disjoint about:
        // claiming a proof here would be exactly the "absence of evidence is
        // evidence of absence" error this runtime exists to prevent.
        merged.evidence_complete = false;
        merged.outcome = ProofOutcome::UNKNOWN_INCOMPLETE_EVIDENCE;
        merged.detail =
            "FAILURE_DOMAIN_DISJOINT has no declared failure-domain relation set in the policy";
        return merged;
      }
      merged.evidence_complete = true;
      merged.outcome = ProofOutcome::PROVEN_DIVERSE;
      for (DomainRelation relation : policy.allowed_failure_domain_relations) {
        ClassResult partial = evaluate_domain_relation(left, right, klass, relation,
                                                       *inputs.domains, max_shared,
                                                       consulted_domains);
        if (!partial.evidence_complete) {
          merged.evidence_complete = false;
          if (merged.detail.empty()) {
            merged.detail = partial.detail;
          }
        }
        for (const SharedResource& conflict : partial.shared) {
          add_shared(merged, conflict, max_shared);
        }
        if (partial.outcome == ProofOutcome::NOT_DIVERSE) {
          merged.outcome = ProofOutcome::NOT_DIVERSE;
          if (partial.detail.empty() == false && merged.detail.empty()) {
            merged.detail = partial.detail;
          }
        } else if (partial.outcome == ProofOutcome::UNKNOWN_INCOMPLETE_EVIDENCE &&
                   merged.outcome != ProofOutcome::NOT_DIVERSE) {
          merged.outcome = ProofOutcome::UNKNOWN_INCOMPLETE_EVIDENCE;
        }
      }
      canonical_conflict_order(merged.shared);
      return merged;
    }
  }
  ClassResult unknown;
  unknown.klass = klass;
  unknown.outcome = ProofOutcome::MALFORMED;
  unknown.detail = "class encoding is not defined";
  return unknown;
}

}  // namespace

std::vector<ClassResult> classify_pair(const PathComposition& left, const PathComposition& right,
                                       const DiversityPolicy& policy,
                                       const EvaluationInputs& inputs,
                                       std::uint32_t max_shared_per_class,
                                       std::vector<FailureDomainId>* consulted_domains,
                                       std::vector<SharedRiskGroupId>* consulted_risk_groups) {
  std::vector<ClassResult> results;
  if (inputs.domains == nullptr) {
    return results;
  }
  const std::uint32_t bound = max_shared_per_class == 0 ? 1U : max_shared_per_class;

  // Required classes first, in the policy canonical order, then every remaining
  // defined class as an advisory. Advisory results are reported and never used
  // to assert the overall outcome.
  DiversityPolicy canonical = policy;
  canonical.canonicalize();
  for (DiversityClass klass : canonical.required_classes) {
    results.push_back(evaluate_single_class(klass, left, right, canonical, inputs, bound,
                                            consulted_domains, consulted_risk_groups));
  }
  for (std::uint8_t raw = static_cast<std::uint8_t>(DiversityClass::LINK_DISJOINT);
       raw <= static_cast<std::uint8_t>(DiversityClass::SHARED_RISK_GROUP_DISJOINT); ++raw) {
    const DiversityClass klass = static_cast<DiversityClass>(raw);
    bool already = false;
    for (DiversityClass required : canonical.required_classes) {
      if (required == klass) {
        already = true;
        break;
      }
    }
    if (already) {
      continue;
    }
    // A class whose declared relation set the policy does not name cannot add
    // information, so it is not evaluated.
    results.push_back(evaluate_single_class(klass, left, right, canonical, inputs, bound,
                                            consulted_domains, consulted_risk_groups));
  }
  return results;
}

}  // namespace path_diversity
