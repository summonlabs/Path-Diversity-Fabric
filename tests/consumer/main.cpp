// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.

// Independent consumer of the installed package. It uses only the public API
// and only config-mode discovery, and it returns non-zero as soon as one of the
// claims it makes about the library does not hold.
//
// The scenario walks one path set through every decision the library can reach:
// proven link and node independence, a shared failure domain, missing required
// evidence, and a return to a proven result under complete evidence.

#include <cstdint>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include "path_diversity/path_diversity.hpp"

namespace {

using namespace path_diversity;

int checks = 0;
int failures = 0;

void check(bool condition, const std::string& claim) {
  ++checks;
  if (!condition) {
    ++failures;
  }
  std::cout << (condition ? "ok   " : "FAIL ") << claim << "\n";
}

template <class T, class U>
void check_equal(const T& actual, const U& expected, const std::string& claim) {
  ++checks;
  const bool equal = (actual == expected);
  if (!equal) {
    ++failures;
  }
  std::cout << (equal ? "ok   " : "FAIL ") << claim;
  if (!equal) {
    std::cout << " [observed " << actual << ", expected " << expected << "]";
  }
  std::cout << "\n";
}

template <class Enum>
void check_name(const Enum& actual, const char* expected, const std::string& claim) {
  check_equal(std::string(to_string(actual)), std::string(expected), claim);
}

PathComposition make_path(const char* id, const char* source, const char* destination,
                          const std::vector<std::string>& transit,
                          const std::vector<std::string>& links) {
  PathComposition composition;
  composition.path = PathId::parse(id);
  composition.authority_generation = PathAuthorityGeneration::from_value(1);
  composition.topology_generation = TopologyGeneration::from_value(1);
  composition.sources.push_back(NodeId::parse(source));
  composition.destinations.push_back(NodeId::parse(destination));
  for (const std::string& node : transit) {
    composition.transit_nodes.push_back(NodeId::parse(node));
  }
  for (const std::string& link : links) {
    composition.links.push_back(LinkId::parse(link));
  }
  composition.canonicalize();
  return composition;
}

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
  return entities;
}

void classify(InMemoryEvidence& evidence, const PathComposition& composition,
              const std::string& domain) {
  const std::vector<FailureDomainId> domains{FailureDomainId::parse(domain)};
  for (const EntityRef& entity : entities_of(composition)) {
    evidence.set_domain_membership(entity, DomainRelation::FAILURE_DOMAIN,
                                   EvidenceCoverage::COMPLETE, domains);
  }
}

ActingAuthority make_authority(const PublisherId& publisher, const WorkerBootId& boot,
                               CoordinatorEpoch epoch, const char* attempt) {
  ActingAuthority acting;
  acting.epoch = epoch;
  acting.publisher = publisher;
  acting.boot = boot;
  acting.scope = default_scope();
  acting.attempt = MutationAttemptId::parse(attempt);
  return acting;
}

const ClassResult* class_result(const DiversityProof& proof, DiversityClass klass) {
  for (const ClassResult& candidate : proof.classes) {
    if (candidate.klass == klass) {
      return &candidate;
    }
  }
  return nullptr;
}

DiversityPolicy build_policy() {
  DiversityPolicy policy;
  policy.id = DiversityPolicyId::parse("dpol-consumer-mandatory");
  policy.generation = DiversityPolicyGeneration::from_value(1);
  policy.scope = default_scope();
  policy.required_classes = {DiversityClass::LINK_DISJOINT,
                             DiversityClass::TRANSIT_NODE_DISJOINT,
                             DiversityClass::FAILURE_DOMAIN_DISJOINT};
  policy.allowed_failure_domain_relations = {DomainRelation::FAILURE_DOMAIN};
  policy.endpoint_exemption = EndpointExemption::SHARED_SOURCE_AND_DESTINATION;
  policy.minimum_independent_paths = 2;
  policy.semantics = SetSemantics::ALL_PAIRS;
  policy.completeness = CompletenessRequirement::REQUIRE_COMPLETE_EVIDENCE;
  policy.unknown_behavior = UnknownBehavior::REJECT_PROOF;
  policy.description = "independent consumer policy";
  policy.canonicalize();
  return policy;
}

}  // namespace

int main() {
  std::cout << "consumer of " << library_name() << " " << version_string() << "\n";

  // Two paths with distinct endpoints: two paths that share an endpoint share
  // that endpoint's failure domain, so the endpoints stay distinct here and the
  // shared-resource scenarios below are unambiguous.
  const PathComposition first =
      make_path("cons-path-a", "node-a1", "node-d1", {"node-b"}, {"link-a1b", "link-bd1"});
  const PathComposition second =
      make_path("cons-path-b", "node-a2", "node-d2", {"node-c"}, {"link-a2c", "link-cd2"});

  InMemoryEvidence evidence;
  evidence.set_path(first);
  evidence.set_path(second);
  classify(evidence, first, "fd-alpha");
  classify(evidence, second, "fd-beta");

  PublicationAuthority publication;
  DiversityRuntime runtime(evidence, evidence, evidence, publication);

  const PublisherId publisher = mint_publisher_id("consumer");
  const WorkerBootId boot = mint_worker_boot_id();
  const CoordinatorEpoch epoch = publication.current_epoch();
  PublisherSession session;
  session.publisher = publisher;
  session.boot = boot;
  session.epoch = epoch;
  session.scope = default_scope();
  check_name(publication.register_publisher(session), "ACCEPTED",
             "the consumer publisher registered with the publication authority");

  const MutationResult published = runtime.publish_policy(
      build_policy(), make_authority(publisher, boot, epoch, "attempt-cons-policy"));
  check_name(published.status, "APPLIED", "the mandatory policy was published");
  if (!published.has_policy) {
    std::cout << "consumer checks=" << checks << " failures=" << (failures + 1) << "\n";
    return 1;
  }

  ProofRequest request;
  request.policy = published.policy.id;
  request.policy_generation = published.policy.generation;
  request.paths.push_back(PathRef{first.path, first.authority_generation});
  request.paths.push_back(PathRef{second.path, second.authority_generation});
  check(request.canonicalize(), "the proof request canonicalized without duplicate paths");

  // --- 1. Link and node independence -------------------------------------
  const MutationResult proven =
      runtime.evaluate(request, make_authority(publisher, boot, epoch, "attempt-cons-step1"));
  check_name(proven.status, "APPLIED", "the first evaluation committed");
  if (!proven.has_proof) {
    std::cout << "consumer checks=" << checks << " failures=" << (failures + 1) << "\n";
    return 1;
  }
  const DiversityProofId identity = proven.proof.id;
  check_name(proven.proof.outcome, "PROVEN_DIVERSE",
             "two link-disjoint and node-disjoint paths are proven diverse");
  const ClassResult* links = class_result(proven.proof, DiversityClass::LINK_DISJOINT);
  const ClassResult* nodes = class_result(proven.proof, DiversityClass::TRANSIT_NODE_DISJOINT);
  const ClassResult* domains = class_result(proven.proof, DiversityClass::FAILURE_DOMAIN_DISJOINT);
  check(links != nullptr && nodes != nullptr && domains != nullptr,
        "all three required classes were evaluated");
  if (links == nullptr || nodes == nullptr || domains == nullptr) {
    std::cout << "consumer checks=" << checks << " failures=" << (failures + 1) << "\n";
    return 1;
  }
  check_name(links->outcome, "PROVEN_DIVERSE", "LINK_DISJOINT is proven");
  check_name(nodes->outcome, "PROVEN_DIVERSE", "TRANSIT_NODE_DISJOINT is proven");
  check_name(domains->outcome, "PROVEN_DIVERSE", "FAILURE_DOMAIN_DISJOINT is proven");
  check_equal(proven.proof.conflicts_total, std::uint64_t{0}, "no shared resource was observed");
  check(proven.proof.current(), "the committed proof is current");

  // --- 2. An injected shared failure domain -------------------------------
  const std::vector<FailureDomainId> shared{FailureDomainId::parse("fd-shared")};
  evidence.set_domain_membership(EntityRef{EntityKind::LINK, "link-bd1"},
                                 DomainRelation::FAILURE_DOMAIN, EvidenceCoverage::COMPLETE,
                                 shared);
  evidence.set_domain_membership(EntityRef{EntityKind::LINK, "link-cd2"},
                                 DomainRelation::FAILURE_DOMAIN, EvidenceCoverage::COMPLETE,
                                 shared);
  const MutationResult conflicted = runtime.revalidate(
      identity, make_authority(publisher, boot, epoch, "attempt-cons-step2"));
  check_name(conflicted.status, "APPLIED", "revalidation committed after the evidence change");
  check_name(conflicted.proof.outcome, "NOT_DIVERSE",
             "a shared failure domain makes the whole proof NOT_DIVERSE");
  const ClassResult* conflicted_domains =
      class_result(conflicted.proof, DiversityClass::FAILURE_DOMAIN_DISJOINT);
  check(conflicted_domains != nullptr &&
            conflicted_domains->outcome == ProofOutcome::NOT_DIVERSE,
        "FAILURE_DOMAIN_DISJOINT reports the conflict");
  check(!conflicted.proof.conflicts.empty(), "the shared resource is named");
  if (!conflicted.proof.conflicts.empty()) {
    check_equal(conflicted.proof.conflicts.front().id, std::string("fd-shared"),
                "the conflict names the exact shared failure domain");
  }

  // --- 3. Required evidence removed ---------------------------------------
  evidence.set_domain_membership(EntityRef{EntityKind::LINK, "link-bd1"},
                                 DomainRelation::FAILURE_DOMAIN, EvidenceCoverage::COMPLETE,
                                 std::vector<FailureDomainId>{FailureDomainId::parse("fd-alpha")});
  evidence.set_domain_membership(EntityRef{EntityKind::LINK, "link-cd2"},
                                 DomainRelation::FAILURE_DOMAIN, EvidenceCoverage::COMPLETE,
                                 std::vector<FailureDomainId>{FailureDomainId::parse("fd-beta")});
  evidence.clear_entity(EntityRef{EntityKind::NODE, "node-c"});
  const MutationResult unknown = runtime.revalidate(
      identity, make_authority(publisher, boot, epoch, "attempt-cons-step3"));
  check_name(unknown.status, "APPLIED", "revalidation committed after evidence was removed");
  check_name(unknown.proof.outcome, "UNKNOWN_INCOMPLETE_EVIDENCE",
             "missing classification yields UNKNOWN_INCOMPLETE_EVIDENCE");
  const ClassResult* unknown_domains =
      class_result(unknown.proof, DiversityClass::FAILURE_DOMAIN_DISJOINT);
  check(unknown_domains != nullptr &&
            unknown_domains->outcome == ProofOutcome::UNKNOWN_INCOMPLETE_EVIDENCE,
        "FAILURE_DOMAIN_DISJOINT cannot be decided from absent evidence");
  check(unknown_domains != nullptr && !unknown_domains->evidence_complete,
        "the class records its evidence as incomplete");
  check(!unknown.proof.current(), "an incomplete result is never current");

  // --- 4. Complete independent evidence restored --------------------------
  evidence.set_domain_membership(EntityRef{EntityKind::NODE, "node-c"},
                                 DomainRelation::FAILURE_DOMAIN, EvidenceCoverage::COMPLETE,
                                 std::vector<FailureDomainId>{FailureDomainId::parse("fd-beta")});
  const MutationResult restored = runtime.revalidate(
      identity, make_authority(publisher, boot, epoch, "attempt-cons-step4"));
  check_name(restored.status, "APPLIED", "revalidation committed after evidence was restored");
  check_name(restored.proof.outcome, "PROVEN_DIVERSE",
             "complete independent evidence proves the set again");
  check(restored.proof.current(), "the restored proof is current");
  check_equal(restored.proof.conflicts_total, std::uint64_t{0},
              "no conflict remains after restoring the evidence");
  const ClassResult* restored_domains =
      class_result(restored.proof, DiversityClass::FAILURE_DOMAIN_DISJOINT);
  check(restored_domains != nullptr && restored_domains->evidence_complete &&
            restored_domains->outcome == ProofOutcome::PROVEN_DIVERSE,
        "FAILURE_DOMAIN_DISJOINT is proven under complete evidence");
  check_equal(restored.proof.id, identity, "the proof identity is stable across revalidations");
  check_equal(restored.proof.generation.value(), std::uint64_t{4},
              "every semantic change advanced the proof revision");

  const std::optional<DiversityProof> stored = runtime.proof(identity);
  check(stored.has_value() && stored->current(), "the runtime publishes the restored proof");
  check_equal(runtime.current_proofs().total, std::uint64_t{1},
              "exactly one proof is current");

  std::cout << "consumer checks=" << checks << " failures=" << failures << "\n";
  return failures == 0 ? 0 : 1;
}
