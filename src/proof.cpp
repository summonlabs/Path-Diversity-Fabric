// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include "path_diversity/proof.hpp"

#include <algorithm>
#include <string>

#include "path_diversity/version.hpp"

namespace path_diversity {

// ---------------------------------------------------------------------------
// Outcomes
// ---------------------------------------------------------------------------
std::string_view to_string(ProofOutcome value) noexcept {
  switch (value) {
    case ProofOutcome::PROVEN_DIVERSE:
      return "PROVEN_DIVERSE";
    case ProofOutcome::NOT_DIVERSE:
      return "NOT_DIVERSE";
    case ProofOutcome::UNKNOWN_INCOMPLETE_EVIDENCE:
      return "UNKNOWN_INCOMPLETE_EVIDENCE";
    case ProofOutcome::STALE_PATH_AUTHORITY:
      return "STALE_PATH_AUTHORITY";
    case ProofOutcome::STALE_TOPOLOGY:
      return "STALE_TOPOLOGY";
    case ProofOutcome::STALE_FAILURE_DOMAIN:
      return "STALE_FAILURE_DOMAIN";
    case ProofOutcome::STALE_POLICY:
      return "STALE_POLICY";
    case ProofOutcome::REVALIDATION_REQUIRED:
      return "REVALIDATION_REQUIRED";
    case ProofOutcome::UNAUTHORIZED:
      return "UNAUTHORIZED";
    case ProofOutcome::RESOURCE_LIMIT:
      return "RESOURCE_LIMIT";
    case ProofOutcome::MALFORMED:
      return "MALFORMED";
  }
  return "UNKNOWN";
}

bool is_defined_proof_outcome(std::uint8_t raw) noexcept {
  return raw >= static_cast<std::uint8_t>(ProofOutcome::PROVEN_DIVERSE) &&
         raw <= static_cast<std::uint8_t>(ProofOutcome::MALFORMED);
}

std::optional<ProofOutcome> proof_outcome_from_string(std::string_view text) noexcept {
  for (std::uint8_t raw = static_cast<std::uint8_t>(ProofOutcome::PROVEN_DIVERSE);
       raw <= static_cast<std::uint8_t>(ProofOutcome::MALFORMED); ++raw) {
    const ProofOutcome candidate = static_cast<ProofOutcome>(raw);
    if (to_string(candidate) == text) {
      return candidate;
    }
  }
  return std::nullopt;
}

bool outcome_asserts_independence(ProofOutcome value) noexcept {
  return value == ProofOutcome::PROVEN_DIVERSE;
}

bool outcome_asserts_conflict(ProofOutcome value) noexcept { return value == ProofOutcome::NOT_DIVERSE; }

bool outcome_is_decisive(ProofOutcome value) noexcept {
  return outcome_asserts_independence(value) || outcome_asserts_conflict(value);
}

// ---------------------------------------------------------------------------
// Conflicts
// ---------------------------------------------------------------------------
std::string_view to_string(ConflictClass value) noexcept {
  switch (value) {
    case ConflictClass::SHARED_FAILURE_DOMAIN:
      return "SHARED_FAILURE_DOMAIN";
    case ConflictClass::SHARED_RISK_GROUP:
      return "SHARED_RISK_GROUP";
    case ConflictClass::SHARED_SITE:
      return "SHARED_SITE";
    case ConflictClass::SHARED_POD:
      return "SHARED_POD";
    case ConflictClass::SHARED_RACK:
      return "SHARED_RACK";
    case ConflictClass::SHARED_POWER_DOMAIN:
      return "SHARED_POWER_DOMAIN";
    case ConflictClass::SHARED_CONDUIT:
      return "SHARED_CONDUIT";
    case ConflictClass::SHARED_COOLING:
      return "SHARED_COOLING";
    case ConflictClass::SHARED_DEVICE:
      return "SHARED_DEVICE";
    case ConflictClass::SHARED_TRANSIT_NODE:
      return "SHARED_TRANSIT_NODE";
    case ConflictClass::SHARED_LINK:
      return "SHARED_LINK";
    case ConflictClass::SHARED_ENDPOINT:
      return "SHARED_ENDPOINT";
    case ConflictClass::INCOMPLETE_EVIDENCE:
      return "INCOMPLETE_EVIDENCE";
    case ConflictClass::STALE_DEPENDENCY:
      return "STALE_DEPENDENCY";
  }
  return "UNKNOWN";
}

bool is_defined_conflict_class(std::uint8_t raw) noexcept {
  return raw >= static_cast<std::uint8_t>(ConflictClass::SHARED_FAILURE_DOMAIN) &&
         raw <= static_cast<std::uint8_t>(ConflictClass::STALE_DEPENDENCY);
}

ConflictClass conflict_class_for_relation(DomainRelation relation) noexcept {
  switch (relation) {
    case DomainRelation::FAILURE_DOMAIN:
      return ConflictClass::SHARED_FAILURE_DOMAIN;
    case DomainRelation::RACK:
      return ConflictClass::SHARED_RACK;
    case DomainRelation::POD:
      return ConflictClass::SHARED_POD;
    case DomainRelation::SITE:
      return ConflictClass::SHARED_SITE;
    case DomainRelation::POWER_DOMAIN:
      return ConflictClass::SHARED_POWER_DOMAIN;
    case DomainRelation::CONDUIT:
      return ConflictClass::SHARED_CONDUIT;
    case DomainRelation::COOLING:
      return ConflictClass::SHARED_COOLING;
  }
  return ConflictClass::SHARED_FAILURE_DOMAIN;
}

std::optional<DomainRelation> relation_for_conflict_class(ConflictClass value) noexcept {
  switch (value) {
    case ConflictClass::SHARED_FAILURE_DOMAIN:
      return DomainRelation::FAILURE_DOMAIN;
    case ConflictClass::SHARED_RACK:
      return DomainRelation::RACK;
    case ConflictClass::SHARED_POD:
      return DomainRelation::POD;
    case ConflictClass::SHARED_SITE:
      return DomainRelation::SITE;
    case ConflictClass::SHARED_POWER_DOMAIN:
      return DomainRelation::POWER_DOMAIN;
    case ConflictClass::SHARED_CONDUIT:
      return DomainRelation::CONDUIT;
    case ConflictClass::SHARED_COOLING:
      return DomainRelation::COOLING;
    default:
      return std::nullopt;
  }
}

std::string SharedResource::render() const {
  std::string out(to_string(kind));
  if (relation_for_conflict_class(kind).has_value()) {
    out += "(";
    out += std::string(to_string(relation));
    out += ")";
  }
  out += " ";
  out += id;
  out += " shared-by=[";
  for (std::size_t i = 0; i < paths.size(); ++i) {
    if (i != 0) {
      out += ",";
    }
    out += std::to_string(paths[i]);
  }
  out += "]";
  return out;
}

void SharedResource::encode(ByteWriter& writer) const {
  writer.u8(static_cast<std::uint8_t>(kind));
  writer.u8(static_cast<std::uint8_t>(relation));
  writer.text(id);
  writer.varint(paths.size());
  for (std::uint32_t index : paths) {
    writer.varint(index);
  }
}

bool conflict_less(const SharedResource& lhs, const SharedResource& rhs) {
  if (lhs.kind != rhs.kind) {
    return static_cast<std::uint8_t>(lhs.kind) < static_cast<std::uint8_t>(rhs.kind);
  }
  if (lhs.id != rhs.id) {
    return lhs.id < rhs.id;
  }
  if (lhs.relation != rhs.relation) {
    return static_cast<std::uint8_t>(lhs.relation) < static_cast<std::uint8_t>(rhs.relation);
  }
  return lhs.paths < rhs.paths;
}

void canonical_conflict_order(std::vector<SharedResource>& conflicts) {
  std::sort(conflicts.begin(), conflicts.end(), conflict_less);
}

// ---------------------------------------------------------------------------
// Pairwise matrix and witness
// ---------------------------------------------------------------------------
std::size_t PairwiseMatrix::cell_index(std::size_t path_count, std::uint32_t i,
                                          std::uint32_t j) noexcept {
  if (i > j) {
    const std::uint32_t temporary = i;
    i = j;
    j = temporary;
  }
  // Row-major upper triangle: the row offset is the number of cells in the rows
  // strictly above row i, which is sum over r < i of (path_count - 1 - r).
  const std::uint64_t n = path_count;
  const std::uint64_t low = i;
  const std::uint64_t offset = (low * (2ULL * n - low - 1ULL)) / 2ULL;
  return static_cast<std::size_t>(offset + (static_cast<std::uint64_t>(j) - low - 1ULL));
}

std::size_t PairwiseMatrix::cell_count(std::size_t path_count) noexcept {
  return (path_count * (path_count - 1)) / 2;
}

const PairwiseCell* PairwiseMatrix::at(std::uint32_t i, std::uint32_t j) const noexcept {
  if (i == j || i >= order.size() || j >= order.size()) {
    return nullptr;
  }
  const std::uint32_t low = i < j ? i : j;
  const std::uint32_t high = i < j ? j : i;
  const std::size_t index = cell_index(order.size(), low, high);
  if (index >= cells.size()) {
    return nullptr;
  }
  return &cells[index];
}

std::string WitnessSubset::render() const {
  if (!present) {
    return "witness=none";
  }
  std::string out = "witness k=" + std::to_string(requested_k);
  out += " achieved=" + std::to_string(achieved);
  out += maximum_exact ? " exact" : " inexact";
  out += " indices=[";
  for (std::size_t i = 0; i < indices.size(); ++i) {
    if (i != 0) {
      out += ",";
    }
    out += std::to_string(indices[i]);
  }
  out += "]";
  return out;
}

}  // namespace path_diversity
