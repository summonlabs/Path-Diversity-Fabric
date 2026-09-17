// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include "path_diversity/policy.hpp"

#include <algorithm>
#include <string>

#include "path_diversity/version.hpp"

namespace path_diversity {

namespace {

template <class T>
std::optional<T> enum_from_string(std::string_view text, T first, T last,
                                  std::string_view (*render)(T) noexcept) {
  for (std::uint8_t raw = static_cast<std::uint8_t>(first);
       raw <= static_cast<std::uint8_t>(last); ++raw) {
    const T candidate = static_cast<T>(raw);
    if (render(candidate) == text) {
      return candidate;
    }
  }
  return std::nullopt;
}

}  // namespace

std::string_view to_string(EndpointExemption value) noexcept {
  switch (value) {
    case EndpointExemption::NONE:
      return "NONE";
    case EndpointExemption::SHARED_SOURCE_AND_DESTINATION:
      return "SHARED_SOURCE_AND_DESTINATION";
    case EndpointExemption::SHARED_SOURCE_ONLY:
      return "SHARED_SOURCE_ONLY";
    case EndpointExemption::SHARED_DESTINATION_ONLY:
      return "SHARED_DESTINATION_ONLY";
    case EndpointExemption::ANY_ENDPOINT:
      return "ANY_ENDPOINT";
  }
  return "UNKNOWN";
}

bool is_defined_endpoint_exemption(std::uint8_t raw) noexcept {
  return raw >= static_cast<std::uint8_t>(EndpointExemption::NONE) &&
         raw <= static_cast<std::uint8_t>(EndpointExemption::ANY_ENDPOINT);
}

std::optional<EndpointExemption> endpoint_exemption_from_string(std::string_view text) noexcept {
  return enum_from_string(text, EndpointExemption::NONE, EndpointExemption::ANY_ENDPOINT,
                          &to_string);
}

std::string_view to_string(SetSemantics value) noexcept {
  switch (value) {
    case SetSemantics::ALL_PAIRS:
      return "ALL_PAIRS";
    case SetSemantics::AT_LEAST_K_INDEPENDENT:
      return "AT_LEAST_K_INDEPENDENT";
  }
  return "UNKNOWN";
}

bool is_defined_set_semantics(std::uint8_t raw) noexcept {
  return raw >= static_cast<std::uint8_t>(SetSemantics::ALL_PAIRS) &&
         raw <= static_cast<std::uint8_t>(SetSemantics::AT_LEAST_K_INDEPENDENT);
}

std::optional<SetSemantics> set_semantics_from_string(std::string_view text) noexcept {
  return enum_from_string(text, SetSemantics::ALL_PAIRS, SetSemantics::AT_LEAST_K_INDEPENDENT,
                          &to_string);
}

std::string_view to_string(CompletenessRequirement value) noexcept {
  switch (value) {
    case CompletenessRequirement::REQUIRE_COMPLETE_EVIDENCE:
      return "REQUIRE_COMPLETE_EVIDENCE";
    case CompletenessRequirement::PROVEN_CONFLICT_DECISIVE:
      return "PROVEN_CONFLICT_DECISIVE";
  }
  return "UNKNOWN";
}

bool is_defined_completeness_requirement(std::uint8_t raw) noexcept {
  return raw >= static_cast<std::uint8_t>(CompletenessRequirement::REQUIRE_COMPLETE_EVIDENCE) &&
         raw <= static_cast<std::uint8_t>(CompletenessRequirement::PROVEN_CONFLICT_DECISIVE);
}

std::optional<CompletenessRequirement> completeness_requirement_from_string(
    std::string_view text) noexcept {
  return enum_from_string(text, CompletenessRequirement::REQUIRE_COMPLETE_EVIDENCE,
                          CompletenessRequirement::PROVEN_CONFLICT_DECISIVE, &to_string);
}

std::string_view to_string(UnknownBehavior value) noexcept {
  switch (value) {
    case UnknownBehavior::REJECT_PROOF:
      return "REJECT_PROOF";
    case UnknownBehavior::DEMOTE_TO_REVALIDATION:
      return "DEMOTE_TO_REVALIDATION";
  }
  return "UNKNOWN";
}

bool is_defined_unknown_behavior(std::uint8_t raw) noexcept {
  return raw >= static_cast<std::uint8_t>(UnknownBehavior::REJECT_PROOF) &&
         raw <= static_cast<std::uint8_t>(UnknownBehavior::DEMOTE_TO_REVALIDATION);
}

std::optional<UnknownBehavior> unknown_behavior_from_string(std::string_view text) noexcept {
  return enum_from_string(text, UnknownBehavior::REJECT_PROOF,
                          UnknownBehavior::DEMOTE_TO_REVALIDATION, &to_string);
}

void DiversityPolicy::canonicalize() {
  std::sort(required_classes.begin(), required_classes.end());
  std::sort(allowed_failure_domain_relations.begin(), allowed_failure_domain_relations.end());
}

Digest DiversityPolicy::semantic_digest() const {
  DiversityPolicy canonical = *this;
  canonical.canonicalize();
  ByteWriter writer;
  // The declared id and the generation are excluded: the id is an identity of
  // this content, and the generation is the version of that identity. Both are
  // bound explicitly elsewhere (policy registry and dependency binding).
  writer.u32(kDiversityRuleSetVersion);
  writer.text(canonical.scope.view());
  writer.varint(canonical.required_classes.size());
  for (DiversityClass klass : canonical.required_classes) {
    writer.u8(static_cast<std::uint8_t>(klass));
  }
  writer.u8(static_cast<std::uint8_t>(canonical.endpoint_exemption));
  writer.varint(canonical.minimum_independent_paths);
  writer.u8(static_cast<std::uint8_t>(canonical.semantics));
  writer.u8(static_cast<std::uint8_t>(canonical.completeness));
  writer.u8(static_cast<std::uint8_t>(canonical.unknown_behavior));
  writer.varint(canonical.allowed_failure_domain_relations.size());
  for (DomainRelation relation : canonical.allowed_failure_domain_relations) {
    writer.u8(static_cast<std::uint8_t>(relation));
  }
  writer.boolean(canonical.require_path_authority_current);
  writer.text(canonical.description);
  return Digest::of(writer.data().data(), writer.size());
}

std::string DiversityPolicy::render() const {
  DiversityPolicy canonical = *this;
  canonical.canonicalize();
  std::string out = "policy ";
  out += canonical.id.str();
  out += "@g";
  out += std::to_string(canonical.generation.value());
  out += " scope=";
  out += canonical.scope.str();
  out += " classes=[";
  for (std::size_t i = 0; i < canonical.required_classes.size(); ++i) {
    if (i != 0) {
      out += ",";
    }
    out += std::string(to_string(canonical.required_classes[i]));
  }
  out += "] endpoints=";
  out += std::string(to_string(canonical.endpoint_exemption));
  out += " k=" + std::to_string(canonical.minimum_independent_paths);
  out += " semantics=";
  out += std::string(to_string(canonical.semantics));
  out += " completeness=";
  out += std::string(to_string(canonical.completeness));
  out += " unknown=";
  out += std::string(to_string(canonical.unknown_behavior));
  out += " relations=[";
  for (std::size_t i = 0; i < canonical.allowed_failure_domain_relations.size(); ++i) {
    if (i != 0) {
      out += ",";
    }
    out += std::string(to_string(canonical.allowed_failure_domain_relations[i]));
  }
  out += "]";
  return out;
}

std::string_view to_string(PolicyStatus status) noexcept {
  switch (status) {
    case PolicyStatus::VALID:
      return "VALID";
    case PolicyStatus::INVALID_IDENTITY:
      return "INVALID_IDENTITY";
    case PolicyStatus::UNSET_GENERATION:
      return "UNSET_GENERATION";
    case PolicyStatus::NO_REQUIRED_CLASSES:
      return "NO_REQUIRED_CLASSES";
    case PolicyStatus::TOO_MANY_REQUIRED_CLASSES:
      return "TOO_MANY_REQUIRED_CLASSES";
    case PolicyStatus::DUPLICATE_REQUIRED_CLASS:
      return "DUPLICATE_REQUIRED_CLASS";
    case PolicyStatus::UNKNOWN_REQUIRED_CLASS:
      return "UNKNOWN_REQUIRED_CLASS";
    case PolicyStatus::INVALID_MINIMUM_INDEPENDENT_PATHS:
      return "INVALID_MINIMUM_INDEPENDENT_PATHS";
    case PolicyStatus::MINIMUM_EXCEEDS_PATH_BOUND:
      return "MINIMUM_EXCEEDS_PATH_BOUND";
    case PolicyStatus::UNKNOWN_DOMAIN_RELATION:
      return "UNKNOWN_DOMAIN_RELATION";
    case PolicyStatus::DUPLICATE_DOMAIN_RELATION:
      return "DUPLICATE_DOMAIN_RELATION";
    case PolicyStatus::MISSING_DOMAIN_RELATIONS:
      return "MISSING_DOMAIN_RELATIONS";
    case PolicyStatus::DESCRIPTION_TOO_LONG:
      return "DESCRIPTION_TOO_LONG";
    case PolicyStatus::INVALID_SCOPE:
      return "INVALID_SCOPE";
  }
  return "UNKNOWN";
}

namespace {

bool contains_required_class(const std::vector<DiversityClass>& classes, DiversityClass value) {
  for (DiversityClass candidate : classes) {
    if (candidate == value) {
      return true;
    }
  }
  return false;
}

}  // namespace

PolicyValidation validate_policy(const DiversityPolicy& policy, const Limits& limits) {
  PolicyValidation result;
  if (!policy.id.valid()) {
    result.status = PolicyStatus::INVALID_IDENTITY;
    result.detail = "policy id is not a valid DiversityPolicyId encoding";
    return result;
  }
  if (!policy.generation.is_set()) {
    result.status = PolicyStatus::UNSET_GENERATION;
    result.detail = "policy generation 0 is not a legal required generation";
    return result;
  }
  if (!policy.scope.valid()) {
    result.status = PolicyStatus::INVALID_SCOPE;
    result.detail = "policy scope is not a valid ScopeId encoding";
    return result;
  }
  if (policy.required_classes.empty()) {
    result.status = PolicyStatus::NO_REQUIRED_CLASSES;
    result.detail = "a policy that requires no diversity class proves nothing";
    return result;
  }
  if (policy.required_classes.size() > limits.max_required_classes) {
    result.status = PolicyStatus::TOO_MANY_REQUIRED_CLASSES;
    result.detail = "required class count " + std::to_string(policy.required_classes.size()) +
                    " exceeds max_required_classes " +
                    std::to_string(limits.max_required_classes);
    return result;
  }
  for (DiversityClass klass : policy.required_classes) {
    if (!is_defined_diversity_class(static_cast<std::uint8_t>(klass))) {
      result.status = PolicyStatus::UNKNOWN_REQUIRED_CLASS;
      result.detail = "required class encoding is not defined";
      return result;
    }
  }
  {
    std::vector<DiversityClass> sorted = policy.required_classes;
    std::sort(sorted.begin(), sorted.end());
    for (std::size_t i = 1; i < sorted.size(); ++i) {
      if (sorted[i] == sorted[i - 1]) {
        result.status = PolicyStatus::DUPLICATE_REQUIRED_CLASS;
        result.detail = std::string("required class ") + std::string(to_string(sorted[i])) +
                        " is declared more than once";
        return result;
      }
    }
  }
  if (policy.minimum_independent_paths < 2) {
    result.status = PolicyStatus::INVALID_MINIMUM_INDEPENDENT_PATHS;
    result.detail = "minimum independent path count must be at least 2";
    return result;
  }
  if (policy.minimum_independent_paths > limits.max_paths_per_proof) {
    result.status = PolicyStatus::MINIMUM_EXCEEDS_PATH_BOUND;
    result.detail = "minimum independent path count " +
                    std::to_string(policy.minimum_independent_paths) +
                    " exceeds max_paths_per_proof " +
                    std::to_string(limits.max_paths_per_proof);
    return result;
  }
  for (DomainRelation relation : policy.allowed_failure_domain_relations) {
    if (!is_defined_domain_relation(static_cast<std::uint8_t>(relation))) {
      result.status = PolicyStatus::UNKNOWN_DOMAIN_RELATION;
      result.detail = "allowed failure-domain relation encoding is not defined";
      return result;
    }
  }
  {
    std::vector<DomainRelation> sorted = policy.allowed_failure_domain_relations;
    std::sort(sorted.begin(), sorted.end());
    for (std::size_t i = 1; i < sorted.size(); ++i) {
      if (sorted[i] == sorted[i - 1]) {
        result.status = PolicyStatus::DUPLICATE_DOMAIN_RELATION;
        result.detail = std::string("allowed relation ") + std::string(to_string(sorted[i])) +
                        " is declared more than once";
        return result;
      }
    }
  }
  if (contains_required_class(policy.required_classes, DiversityClass::FAILURE_DOMAIN_DISJOINT) &&
      policy.allowed_failure_domain_relations.empty()) {
    result.status = PolicyStatus::MISSING_DOMAIN_RELATIONS;
    result.detail =
        "FAILURE_DOMAIN_DISJOINT requires an explicit allowed_failure_domain_relations set: "
        "absence of an observed shared domain is only meaningful against a declared relation set";
    return result;
  }
  if (policy.description.size() > limits.max_persistence_record_bytes) {
    result.status = PolicyStatus::DESCRIPTION_TOO_LONG;
    result.detail = "policy description does not fit inside one persistence record";
    return result;
  }
  return result;
}

DiversityPolicyId derived_policy_id(const Digest& digest) {
  return DiversityPolicyId::parse(mint_prefixed("dpol-", digest));
}

}  // namespace path_diversity
