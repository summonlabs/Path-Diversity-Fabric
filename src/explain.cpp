// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include "path_diversity/explain.hpp"

#include <string>
#include <utility>
#include <vector>

#include "path_diversity/evaluate.hpp"

namespace path_diversity {

std::string_view to_string(ExplanationKind value) noexcept {
  switch (value) {
    case ExplanationKind::POLICY:
      return "POLICY";
    case ExplanationKind::REQUIRED_CLASS:
      return "REQUIRED_CLASS";
    case ExplanationKind::ENDPOINT_SEMANTICS:
      return "ENDPOINT_SEMANTICS";
    case ExplanationKind::SHARED_LINK:
      return "SHARED_LINK";
    case ExplanationKind::SHARED_TRANSIT_NODE:
      return "SHARED_TRANSIT_NODE";
    case ExplanationKind::SHARED_DEVICE:
      return "SHARED_DEVICE";
    case ExplanationKind::SHARED_DOMAIN:
      return "SHARED_DOMAIN";
    case ExplanationKind::SHARED_RISK_GROUP:
      return "SHARED_RISK_GROUP";
    case ExplanationKind::MISSING_EVIDENCE:
      return "MISSING_EVIDENCE";
    case ExplanationKind::STALE_GENERATION:
      return "STALE_GENERATION";
    case ExplanationKind::PROOF_RESULT:
      return "PROOF_RESULT";
    case ExplanationKind::WITNESS:
      return "WITNESS";
    case ExplanationKind::CONFLICT_GRAPH:
      return "CONFLICT_GRAPH";
    case ExplanationKind::PAIR_RESULT:
      return "PAIR_RESULT";
    case ExplanationKind::RESOURCE_LIMIT:
      return "RESOURCE_LIMIT";
    case ExplanationKind::DEPENDENCY:
      return "DEPENDENCY";
  }
  return "UNKNOWN";
}

bool is_defined_explanation_kind(std::uint8_t raw) noexcept {
  return raw >= static_cast<std::uint8_t>(ExplanationKind::POLICY) &&
         raw <= static_cast<std::uint8_t>(ExplanationKind::DEPENDENCY);
}

namespace {

ExplanationKind kind_for_conflict(ConflictClass klass) {
  switch (klass) {
    case ConflictClass::SHARED_LINK:
      return ExplanationKind::SHARED_LINK;
    case ConflictClass::SHARED_TRANSIT_NODE:
    case ConflictClass::SHARED_ENDPOINT:
      return ExplanationKind::SHARED_TRANSIT_NODE;
    case ConflictClass::SHARED_DEVICE:
      return ExplanationKind::SHARED_DEVICE;
    case ConflictClass::SHARED_RISK_GROUP:
      return ExplanationKind::SHARED_RISK_GROUP;
    default:
      return ExplanationKind::SHARED_DOMAIN;
  }
}

struct Builder {
  Explanation explanation;
  const Limits* limits = nullptr;

  void push(ExplanationEntry entry) {
    ++explanation.entries_total;
    if (explanation.entries.size() >= limits->max_explanation_entries) {
      explanation.truncated = true;
      return;
    }
    explanation.entries.push_back(std::move(entry));
  }
};

// The endpoint exemption is policy content. It is carried on the proof through
// the policy identity, so the explanation states the mode the proof was
// evaluated under. A proof evaluated under a policy whose exemption allowed
// shared endpoints records no endpoint conflict; a proof evaluated without the
// exemption records one as a shared node.
void add_policy_entries(Builder& builder, const DiversityProof& proof) {
  {
    ExplanationEntry entry;
    entry.kind = ExplanationKind::POLICY;
    entry.outcome = proof.outcome;
    entry.subject = proof.request.policy.str() + "@g" +
                    std::to_string(proof.request.policy_generation.value());
    entry.detail = "required classes are listed individually below; the policy content digest "
                   "is bound into the proof semantic digest";
    builder.push(std::move(entry));
  }
  for (const ClassResult& result : proof.classes) {
    ExplanationEntry entry;
    entry.kind = ExplanationKind::REQUIRED_CLASS;
    entry.klass = result.klass;
    entry.outcome = result.outcome;
    entry.subject = std::string(to_string(result.klass));
    entry.detail = std::string("evidence ") +
                   (result.evidence_complete ? "COMPLETE" : "INCOMPLETE") +
                   "; shared resources " + std::to_string(result.shared_total);
    if (!result.detail.empty()) {
      entry.detail += "; " + result.detail;
    }
    builder.push(std::move(entry));
  }
  {
    ExplanationEntry entry;
    entry.kind = ExplanationKind::ENDPOINT_SEMANTICS;
    entry.subject = "endpoint-exemption";
    entry.outcome = proof.outcome;
    switch (proof.dependencies.endpoint_exemption) {
      case EndpointExemption::NONE:
        entry.detail =
            "source and destination nodes are ordinary nodes: sharing either fails "
            "transit-node disjointness";
        break;
      case EndpointExemption::SHARED_SOURCE_AND_DESTINATION:
        entry.detail = "a node shared as the source of every path, or as the destination of every "
                       "path, is exempt; a node shared as transit is not";
        break;
      case EndpointExemption::SHARED_SOURCE_ONLY:
        entry.detail = "only source sharing is exempt";
        break;
      case EndpointExemption::SHARED_DESTINATION_ONLY:
        entry.detail = "only destination sharing is exempt";
        break;
      case EndpointExemption::ANY_ENDPOINT:
        entry.detail = "any endpoint sharing is exempt";
        break;
    }
    builder.push(std::move(entry));
  }
}

void add_conflict_entries(Builder& builder, const DiversityProof& proof) {
  for (const SharedResource& conflict : proof.conflicts) {
    ExplanationEntry entry;
    entry.kind = kind_for_conflict(conflict.kind);
    entry.subject = conflict.id;
    entry.outcome = ProofOutcome::NOT_DIVERSE;
    entry.paths = conflict.paths;
    entry.detail = std::string(to_string(conflict.kind)) + " shared by " +
                   std::to_string(conflict.paths.size()) + " paths";
    builder.push(std::move(entry));
  }
  if (proof.conflicts.size() < proof.conflicts_total) {
    ExplanationEntry entry;
    entry.kind = ExplanationKind::PROOF_RESULT;
    entry.subject = "conflict-list";
    entry.outcome = proof.outcome;
    entry.detail = "conflict list is bounded: " + std::to_string(proof.conflicts.size()) +
                   " of " + std::to_string(proof.conflicts_total) + " entries retained";
    builder.push(std::move(entry));
  }
}

void add_dependency_entries(Builder& builder, const DiversityProof& proof) {
  {
    ExplanationEntry entry;
    entry.kind = ExplanationKind::DEPENDENCY;
    entry.subject = "generations";
    entry.outcome = proof.outcome;
    entry.detail = "policy=g" + std::to_string(proof.dependencies.policy_generation.value()) +
                   " topology=g" + std::to_string(proof.dependencies.topology_generation.value()) +
                   " failure-domains=g" +
                   std::to_string(proof.dependencies.failure_domain_generation.value()) +
                   " epoch=g" + std::to_string(proof.dependencies.epoch.value());
    builder.push(std::move(entry));
  }
  for (const PathAuthorityBinding& binding : proof.dependencies.paths) {
    ExplanationEntry entry;
    entry.kind = ExplanationKind::DEPENDENCY;
    entry.subject = binding.path.str();
    entry.outcome = proof.outcome;
    entry.detail = "Path Authority generation g" + std::to_string(binding.generation.value());
    builder.push(std::move(entry));
  }
}

void add_unknown_entries(Builder& builder, const DiversityProof& proof) {
  if (proof.outcome != ProofOutcome::UNKNOWN_INCOMPLETE_EVIDENCE &&
      proof.outcome != ProofOutcome::REVALIDATION_REQUIRED) {
    return;
  }
  for (const ClassResult& result : proof.classes) {
    if (result.evidence_complete) {
      continue;
    }
    ExplanationEntry entry;
    entry.kind = ExplanationKind::MISSING_EVIDENCE;
    entry.klass = result.klass;
    entry.outcome = result.outcome;
    entry.subject = std::string(to_string(result.klass));
    entry.detail = result.detail.empty()
                       ? "required failure-domain or structural evidence is incomplete"
                       : result.detail;
    builder.push(std::move(entry));
  }
}

void add_stale_entries(Builder& builder, const DiversityProof& proof) {
  switch (proof.outcome) {
    case ProofOutcome::STALE_PATH_AUTHORITY:
    case ProofOutcome::STALE_TOPOLOGY:
    case ProofOutcome::STALE_FAILURE_DOMAIN:
    case ProofOutcome::STALE_POLICY:
    case ProofOutcome::UNAUTHORIZED: {
      ExplanationEntry entry;
      entry.kind = ExplanationKind::STALE_GENERATION;
      entry.subject = std::string(to_string(proof.outcome));
      entry.outcome = proof.outcome;
      entry.detail = proof.detail;
      builder.push(std::move(entry));
      break;
    }
    default:
      break;
  }
}

void add_result_entries(Builder& builder, const DiversityProof& proof) {
  {
    ExplanationEntry entry;
    entry.kind = ExplanationKind::PROOF_RESULT;
    entry.subject = proof.id.str() + "@g" + std::to_string(proof.generation.value());
    entry.outcome = proof.outcome;
    entry.detail = proof.detail;
    builder.push(std::move(entry));
  }
  {
    ExplanationEntry entry;
    entry.kind = ExplanationKind::CONFLICT_GRAPH;
    entry.subject = "conflict-graph";
    entry.outcome = proof.outcome;
    const ConflictGraph graph = build_conflict_graph(proof.matrix);
    entry.detail = std::to_string(graph.path_count) + " vertices, " +
                   std::to_string(graph.edge_count()) +
                   " conflict edges; K mutually independent paths are exactly an independent "
                   "set of size K in this graph";
    builder.push(std::move(entry));
  }
  if (proof.witness.present) {
    ExplanationEntry entry;
    entry.kind = ExplanationKind::WITNESS;
    entry.subject = proof.witness.render();
    entry.outcome = proof.outcome;
    entry.detail = "requested K=" + std::to_string(proof.witness.requested_k) +
                   " achieved=" + std::to_string(proof.witness.achieved) +
                   (proof.witness.maximum_exact ? " (exact maximum)" : " (not proven exact)");
    builder.push(std::move(entry));
  }
  if (proof.limit.has_value()) {
    ExplanationEntry entry;
    entry.kind = ExplanationKind::RESOURCE_LIMIT;
    entry.subject = std::string(to_string(proof.limit->bound));
    entry.outcome = proof.outcome;
    entry.detail = proof.limit->render();
    builder.push(std::move(entry));
  }
}

}  // namespace

Explanation explain_proof(const DiversityProof& proof, const Limits& limits) {
  Builder builder;
  builder.limits = &limits;
  builder.explanation.proof = proof.id;
  builder.explanation.generation = proof.generation;
  builder.explanation.outcome = proof.outcome;

  add_policy_entries(builder, proof);
  add_dependency_entries(builder, proof);
  add_conflict_entries(builder, proof);
  add_unknown_entries(builder, proof);
  add_stale_entries(builder, proof);
  add_result_entries(builder, proof);
  return builder.explanation;
}

Explanation explain_pair(const DiversityProof& proof, std::uint32_t left, std::uint32_t right,
                         const Limits& limits) {
  Builder builder;
  builder.limits = &limits;
  builder.explanation.proof = proof.id;
  builder.explanation.generation = proof.generation;
  builder.explanation.outcome = proof.outcome;

  const PairwiseCell* cell = proof.matrix.at(left, right);
  if (cell == nullptr) {
    ExplanationEntry entry;
    entry.kind = ExplanationKind::PAIR_RESULT;
    entry.subject = "pair " + std::to_string(left) + "," + std::to_string(right);
    entry.outcome = ProofOutcome::MALFORMED;
    entry.detail = "the requested pair is not a distinct pair of the canonical path set";
    builder.push(std::move(entry));
    return builder.explanation;
  }
  {
    ExplanationEntry entry;
    entry.kind = ExplanationKind::PAIR_RESULT;
    entry.subject = "pair " + std::to_string(cell->left) + "," + std::to_string(cell->right);
    entry.outcome = cell->independent ? ProofOutcome::PROVEN_DIVERSE : ProofOutcome::NOT_DIVERSE;
    entry.paths.push_back(cell->left);
    entry.paths.push_back(cell->right);
    entry.detail = cell->independent
                       ? "the pair satisfies every required diversity class"
                       : "the pair does not satisfy every required diversity class";
    builder.push(std::move(entry));
  }
  for (const ClassResult& result : cell->classes) {
    ExplanationEntry entry;
    entry.kind = ExplanationKind::REQUIRED_CLASS;
    entry.klass = result.klass;
    entry.outcome = result.outcome;
    entry.subject = std::string(to_string(result.klass));
    entry.detail = std::string("evidence ") +
                   (result.evidence_complete ? "COMPLETE" : "INCOMPLETE");
    if (!result.detail.empty()) {
      entry.detail += "; " + result.detail;
    }
    builder.push(std::move(entry));
    if (result.evidence_complete &&
        result.outcome == ProofOutcome::UNKNOWN_INCOMPLETE_EVIDENCE) {
      ExplanationEntry missing;
      missing.kind = ExplanationKind::MISSING_EVIDENCE;
      missing.klass = result.klass;
      missing.outcome = result.outcome;
      missing.subject = std::string(to_string(result.klass));
      missing.detail = result.detail;
      builder.push(std::move(missing));
    }
    for (const SharedResource& conflict : result.shared) {
      ExplanationEntry shared;
      shared.kind = kind_for_conflict(conflict.kind);
      shared.klass = result.klass;
      shared.outcome = result.outcome;
      shared.subject = conflict.id;
      shared.paths = conflict.paths;
      shared.detail = conflict.render();
      builder.push(std::move(shared));
    }
  }
  return builder.explanation;
}

std::string ExplanationEntry::render() const {
  std::string out = "[";
  out += std::string(to_string(kind));
  if (kind == ExplanationKind::REQUIRED_CLASS || kind == ExplanationKind::MISSING_EVIDENCE ||
      kind == ExplanationKind::SHARED_LINK || kind == ExplanationKind::SHARED_TRANSIT_NODE ||
      kind == ExplanationKind::SHARED_DEVICE || kind == ExplanationKind::SHARED_DOMAIN ||
      kind == ExplanationKind::SHARED_RISK_GROUP) {
    out += " ";
    out += std::string(to_string(klass));
  }
  out += "] ";
  out += subject;
  out += " outcome=";
  out += std::string(to_string(outcome));
  if (!paths.empty()) {
    out += " paths=[";
    for (std::size_t i = 0; i < paths.size(); ++i) {
      if (i != 0) {
        out += ",";
      }
      out += std::to_string(paths[i]);
    }
    out += "]";
  }
  if (!detail.empty()) {
    out += " :: ";
    out += detail;
  }
  return out;
}

std::string Explanation::render() const {
  std::string out = "explanation ";
  out += proof.str();
  out += "@g";
  out += std::to_string(generation.value());
  out += " outcome=";
  out += std::string(to_string(outcome));
  out += truncated ? " (truncated)" : "";
  out += "\n";
  for (const ExplanationEntry& entry : entries) {
    out += "  ";
    out += entry.render();
    out += "\n";
  }
  return out;
}

std::string render_explanation(const Explanation& explanation) { return explanation.render(); }

}  // namespace path_diversity
