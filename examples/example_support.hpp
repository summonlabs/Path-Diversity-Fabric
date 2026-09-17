// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

// Shared helpers for the example programs. Every helper builds SYNTHETIC
// evidence through the public InMemoryEvidence reference implementation: none
// of them stands in for an authority that an embedding product must supply.

#include <cstdint>
#include <filesystem>
#include <iostream>
#include <sstream>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include "path_diversity/path_diversity.hpp"

namespace example {

using namespace path_diversity;

// Prints one deterministic line per established fact and counts the claims that
// did not hold, so a transcript and an exit status can never disagree.
class Reporter {
 public:
  explicit Reporter(std::string title) : title_(std::move(title)) {
    std::cout << "== " << title_ << " ==\n";
  }
  void note(const std::string& text) { std::cout << "   " << text << "\n"; }
  template <class T>
  void field(const std::string& label, const T& value) {
    std::ostringstream stream;
    stream << value;
    std::cout << "   " << label << " = " << stream.str() << "\n";
  }
  void check(bool condition, const std::string& claim) {
    ++checks_;
    failures_ += condition ? 0 : 1;
    std::cout << (condition ? "   ok   " : "   FAIL ") << claim << "\n";
  }
  template <class T, class U>
  void check_equal(const T& actual, const U& expected, const std::string& claim) {
    std::ostringstream stream;
    stream << claim << " [observed " << actual << ", expected " << expected << "]";
    check(actual == expected, stream.str());
  }
  // Enum comparison through the library's own canonical spelling.
  template <class Enum>
  void check_name(const Enum& actual, const std::string& expected, const std::string& claim) {
    check_equal(std::string(to_string(actual)), expected, claim);
  }
  int finish() {
    std::cout << "== " << title_ << " checks=" << checks_ << " failures=" << failures_ << "\n";
    return failures_ == 0 ? 0 : 1;
  }

 private:
  std::string title_;
  int checks_ = 0;
  int failures_ = 0;
};

// One path composition; structural elements repeat only to state a conflict.
inline PathComposition make_path(const std::string& id, const std::string& source,
                                 const std::string& destination,
                                 const std::vector<std::string>& transit,
                                 const std::vector<std::string>& links,
                                 std::uint64_t topology_generation = 1,
                                 std::uint64_t authority_generation = 1) {
  PathComposition composition;
  composition.path = PathId::parse(id);
  composition.authority_generation = PathAuthorityGeneration::from_value(authority_generation);
  composition.topology_generation = TopologyGeneration::from_value(topology_generation);
  composition.sources.push_back(NodeId::parse(source));
  composition.destinations.push_back(NodeId::parse(destination));
  for (const std::string& node : transit) composition.transit_nodes.push_back(NodeId::parse(node));
  for (const std::string& link : links) composition.links.push_back(LinkId::parse(link));
  composition.canonicalize();
  return composition;
}

// Publishes one authoritative classification for every entity of one path.
inline void classify_path(InMemoryEvidence& evidence, const PathComposition& composition,
                          DomainRelation relation, EvidenceCoverage coverage,
                          const std::vector<std::string>& text_domains) {
  std::vector<FailureDomainId> parsed;
  for (const std::string& text : text_domains) parsed.push_back(FailureDomainId::parse(text));
  const auto assign = [&](EntityKind kind, const std::string& id) {
    evidence.set_domain_membership(EntityRef{kind, id}, relation, coverage, parsed);
  };
  for (const LinkId& link : composition.links) assign(EntityKind::LINK, link.str());
  for (const NodeId& node : composition.transit_nodes) assign(EntityKind::NODE, node.str());
  for (const NodeId& node : composition.sources) assign(EntityKind::ENDPOINT, node.str());
  for (const NodeId& node : composition.destinations) assign(EntityKind::ENDPOINT, node.str());
  for (const DeviceId& device : composition.devices) assign(EntityKind::DEVICE, device.str());
}

inline std::vector<FailureDomainId> parse_domains(const std::string& text) {
  return std::vector<FailureDomainId>{FailureDomainId::parse(text)};
}

struct PolicySpec {
  std::string id;
  std::vector<DiversityClass> classes;
  EndpointExemption exemption = EndpointExemption::SHARED_SOURCE_AND_DESTINATION;
  std::uint32_t minimum_paths = 2;
  SetSemantics semantics = SetSemantics::ALL_PAIRS;
  CompletenessRequirement completeness = CompletenessRequirement::REQUIRE_COMPLETE_EVIDENCE;
  // Declared relation set of FAILURE_DOMAIN_DISJOINT: never assumed by policy.
  std::vector<DomainRelation> relations;
};

inline DiversityPolicy build_policy(const PolicySpec& spec) {
  DiversityPolicy policy;
  policy.id = DiversityPolicyId::parse(spec.id);
  policy.generation = DiversityPolicyGeneration::from_value(1);
  policy.scope = default_scope();
  policy.required_classes = spec.classes;
  policy.endpoint_exemption = spec.exemption;
  policy.minimum_independent_paths = spec.minimum_paths;
  policy.semantics = spec.semantics;
  policy.completeness = spec.completeness;
  policy.unknown_behavior = UnknownBehavior::REJECT_PROOF;
  policy.allowed_failure_domain_relations = spec.relations;
  policy.description = "example policy " + spec.id;
  policy.canonicalize();
  return policy;
}
inline PublisherSession publisher_session(const PublisherId& publisher, const WorkerBootId& boot,
                                          CoordinatorEpoch epoch) {
  PublisherSession session;
  session.publisher = publisher;
  session.boot = boot;
  session.epoch = epoch;
  session.scope = default_scope();
  return session;
}
// Evidence views, publication authority, runtime and one registered publisher.
class Harness {
 public:
  explicit Harness(Limits limits = Limits())
      : evidence(),
        publication(limits),
        runtime(evidence, evidence, evidence, publication, limits) {
    publisher = mint_publisher_id("example");
    boot = mint_worker_boot_id();
    publication.register_publisher(
        publisher_session(publisher, boot, publication.current_epoch()));
  }
  // A fresh MutationAttemptId per mutation: reusing one attempt identity with a
  // different payload is an attempt conflict by design.
  ActingAuthority authority(const std::string& label) {
    ActingAuthority acting;
    acting.epoch = publication.current_epoch();
    acting.publisher = publisher;
    acting.boot = boot;
    acting.scope = default_scope();
    acting.attempt = MutationAttemptId::parse("attempt-" + label + "-" + std::to_string(++serial_));
    return acting;
  }
  MutationResult publish(const PolicySpec& spec, const std::string& label) {
    return runtime.publish_policy(build_policy(spec), authority(label));
  }
  ProofRequest request(const DiversityPolicyId& policy,
                       const std::vector<PathComposition>& compositions) {
    ProofRequest out;
    out.policy = policy;
    out.policy_generation = runtime.policy_generation(policy);
    for (const PathComposition& composition : compositions) {
      out.paths.push_back(PathRef{composition.path, composition.authority_generation});
    }
    (void)out.canonicalize();
    return out;
  }
  InMemoryEvidence evidence;
  PublicationAuthority publication;
  DiversityRuntime runtime;
  PublisherId publisher;
  WorkerBootId boot;
 private:
  std::uint64_t serial_ = 0;
};

// A writable scratch file name; it is never printed, so no claim depends on it.
inline std::string scratch_path(const std::string& name) {
#if defined(PATH_DIVERSITY_TEST_TEMP_ROOT)
  const std::filesystem::path root(PATH_DIVERSITY_TEST_TEMP_ROOT);
#else
  const std::filesystem::path root = std::filesystem::temp_directory_path();
#endif
  std::error_code error;
  std::filesystem::create_directories(root, error);
  return (root / name).string();
}
}  // namespace example
