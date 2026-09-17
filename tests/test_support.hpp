// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

// Minimal, dependency-free harness shared by every suite. There are no
// framework timeouts: a hanging test is a defect and must be diagnosed rather
// than masked. The only bounded waits are the explicit cross-process ones, and
// crossing their bound is a failed assertion, never a silent pass.

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <iostream>
#include <memory>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "path_diversity/path_diversity.hpp"

#if defined(_WIN32)
#if !defined(WIN32_LEAN_AND_MEAN)
#define WIN32_LEAN_AND_MEAN
#endif
#include <process.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace pd_test {

struct Registry {
  struct Case {
    std::string name;
    std::function<void()> body;
  };
  std::vector<Case> cases;
  int failures = 0;
  int assertions = 0;
  std::string current;
};

inline Registry& registry() {
  static Registry instance;
  return instance;
}

struct CaseRegistrar {
  CaseRegistrar(std::string name, std::function<void()> body) {
    registry().cases.push_back(Registry::Case{std::move(name), std::move(body)});
  }
};

inline void fail(const std::string& file, int line, const std::string& message) {
  ++registry().failures;
  std::cout << "FAIL " << registry().current << " " << file << ":" << line << ": " << message
            << "\n";
  std::cout.flush();
}

inline void check(bool condition, const std::string& text, const std::string& file, int line) {
  ++registry().assertions;
  if (!condition) {
    fail(file, line, text);
  }
}

template <class T, class U>
inline void check_eq(const T& actual, const U& expected, const std::string& text,
                     const std::string& file, int line) {
  ++registry().assertions;
  if (!(actual == expected)) {
    std::ostringstream stream;
    stream << text;
    fail(file, line, stream.str());
  }
}

// Bounded wait with an explicit failure. Used only for cross-process proofs.
template <class Predicate>
inline bool wait_for(Predicate predicate, std::chrono::milliseconds bound,
                     const std::string& description, const std::string& file, int line) {
  const auto deadline = std::chrono::steady_clock::now() + bound;
  while (std::chrono::steady_clock::now() < deadline) {
    if (predicate()) {
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  if (predicate()) {
    return true;
  }
  fail(file, line, "timed out waiting for " + description);
  return false;
}

inline int run_all() {
  Registry& instance = registry();
  for (auto& test_case : instance.cases) {
    instance.current = test_case.name;
    const int before = instance.failures;
    test_case.body();
    std::cout << (instance.failures == before ? "PASS " : "FAIL ") << test_case.name << "\n";
    std::cout.flush();
  }
  std::cout << "cases=" << instance.cases.size() << " assertions=" << instance.assertions
            << " failures=" << instance.failures << "\n";
  return instance.failures == 0 ? 0 : 1;
}

// Per-process, per-call unique path under the test temp root. Reusing a name
// across runs would silently reuse a stale durable store.
inline std::filesystem::path unique_test_path(const std::string& name) {
  static std::mt19937_64 engine([]() {
    std::random_device device;
    return (static_cast<std::uint64_t>(device()) << 32) ^ static_cast<std::uint64_t>(device());
  }());
#if defined(_WIN32)
  const auto process = static_cast<std::uint64_t>(_getpid());
#else
  const auto process = static_cast<std::uint64_t>(getpid());
#endif
  static std::atomic<std::uint64_t> counter{0};
  const std::uint64_t serial = counter.fetch_add(1) + 1;
  const std::filesystem::path root(PATH_DIVERSITY_TEST_TEMP_ROOT);
  std::error_code error;
  std::filesystem::create_directories(root, error);
  return root / (name + "-" + std::to_string(process) + "-" + std::to_string(serial) + "-" +
                 std::to_string(engine() % 1000000));
}

// ---------------------------------------------------------------------------
// Scenario helpers. These build SYNTHETIC evidence only: they exist so a test
// can state a scenario in a few lines, never to stand in for an authority.
// ---------------------------------------------------------------------------
using namespace path_diversity;

inline PathComposition make_path(const std::string& id, int authority_generation,
                                 const std::vector<std::string>& transit,
                                 const std::vector<std::string>& links,
                                 const std::vector<std::string>& devices,
                                 const std::string& source, const std::string& destination) {
  PathComposition composition;
  composition.path = PathId::parse(id);
  composition.authority_generation =
      PathAuthorityGeneration::from_value(static_cast<std::uint64_t>(authority_generation));
  composition.topology_generation = TopologyGeneration::from_value(1);
  composition.sources.push_back(NodeId::parse(source));
  composition.destinations.push_back(NodeId::parse(destination));
  for (const std::string& node : transit) {
    composition.transit_nodes.push_back(NodeId::parse(node));
  }
  for (const std::string& link : links) {
    composition.links.push_back(LinkId::parse(link));
  }
  for (const std::string& device : devices) {
    composition.devices.push_back(DeviceId::parse(device));
  }
  composition.canonicalize();
  return composition;
}

inline std::vector<EntityRef> entities_of(const PathComposition& composition) {
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

inline void classify_path(InMemoryEvidence& evidence, const PathComposition& composition,
                          DomainRelation relation, EvidenceCoverage coverage,
                          const std::vector<std::string>& domains) {
  std::vector<FailureDomainId> parsed;
  for (const std::string& text : domains) {
    parsed.push_back(FailureDomainId::parse(text));
  }
  for (const EntityRef& entity : entities_of(composition)) {
    evidence.set_domain_membership(entity, relation, coverage, parsed);
  }
}

inline void classify_path_srlg(InMemoryEvidence& evidence, const PathComposition& composition,
                               EvidenceCoverage coverage,
                               const std::vector<std::string>& groups) {
  std::vector<SharedRiskGroupId> parsed;
  for (const std::string& text : groups) {
    parsed.push_back(SharedRiskGroupId::parse(text));
  }
  for (const EntityRef& entity : entities_of(composition)) {
    evidence.set_srlg_membership(entity, coverage, parsed);
  }
}

inline DiversityPolicy make_policy(const std::string& id,
                                   const std::vector<DiversityClass>& classes,
                                   EndpointExemption exemption,
                                   std::uint32_t minimum_paths,
                                   SetSemantics semantics = SetSemantics::ALL_PAIRS,
                                   CompletenessRequirement completeness =
                                       CompletenessRequirement::REQUIRE_COMPLETE_EVIDENCE) {
  DiversityPolicy policy;
  policy.id = DiversityPolicyId::parse(id);
  policy.generation = DiversityPolicyGeneration::from_value(1);
  policy.scope = default_scope();
  policy.required_classes = classes;
  policy.endpoint_exemption = exemption;
  policy.minimum_independent_paths = minimum_paths;
  policy.semantics = semantics;
  policy.completeness = completeness;
  policy.unknown_behavior = UnknownBehavior::REJECT_PROOF;
  for (DiversityClass klass : classes) {
    if (klass == DiversityClass::FAILURE_DOMAIN_DISJOINT) {
      policy.allowed_failure_domain_relations = {DomainRelation::FAILURE_DOMAIN,
                                                 DomainRelation::RACK};
    }
    if (klass == DiversityClass::RACK_DISJOINT) {
      policy.allowed_failure_domain_relations.push_back(DomainRelation::RACK);
    }
    if (klass == DiversityClass::POD_DISJOINT) {
      policy.allowed_failure_domain_relations.push_back(DomainRelation::POD);
    }
    if (klass == DiversityClass::SITE_DISJOINT) {
      policy.allowed_failure_domain_relations.push_back(DomainRelation::SITE);
    }
  }
  if (!policy.allowed_failure_domain_relations.empty()) {
    canonical_sort_unique(policy.allowed_failure_domain_relations);
  }
  policy.description = "test policy " + id;
  policy.canonicalize();
  return policy;
}

// A complete local scenario: evidence, publication authority, runtime and one
// registered publisher acting under one epoch.
struct Fixture {
  explicit Fixture(Limits limits = Limits())
      : evidence(), publication(limits), runtime(evidence, evidence, evidence, publication, limits),
        limits(limits) {
    publisher = mint_publisher_id("test");
    boot = mint_worker_boot_id();
    PublisherSession session;
    session.publisher = publisher;
    session.boot = boot;
    session.epoch = publication.current_epoch();
    session.scope = default_scope();
    const AuthorityStatus registered = publication.register_publisher(session);
    (void)registered;
  }

  ActingAuthority actor(const std::string& label) {
    ActingAuthority authority;
    authority.epoch = publication.current_epoch();
    authority.publisher = publisher;
    authority.boot = boot;
    authority.scope = default_scope();
    authority.attempt = MutationAttemptId::parse("attempt-" + label);
    return authority;
  }

  InMemoryEvidence evidence;
  PublicationAuthority publication;
  DiversityRuntime runtime;
  Limits limits;
  PublisherId publisher;
  WorkerBootId boot;
};

// Independent raw-set oracles. These deliberately share no helper with the
// production evaluation path: they recompute intersections from the raw path
// composition values.
namespace oracle {

inline std::vector<std::string> intersection(const std::vector<std::string>& left,
                                             const std::vector<std::string>& right) {
  std::vector<std::string> out;
  for (const std::string& value : left) {
    for (const std::string& candidate : right) {
      if (value == candidate) {
        bool seen = false;
        for (const std::string& existing : out) {
          if (existing == value) {
            seen = true;
            break;
          }
        }
        if (!seen) {
          out.push_back(value);
        }
        break;
      }
    }
  }
  for (std::size_t i = 0; i + 1 < out.size(); ++i) {
    for (std::size_t j = i + 1; j < out.size(); ++j) {
      if (out[j] < out[i]) {
        const std::string temporary = out[i];
        out[i] = out[j];
        out[j] = temporary;
      }
    }
  }
  return out;
}

inline std::vector<std::string> texts(const std::vector<LinkId>& values) {
  std::vector<std::string> out;
  for (const LinkId& value : values) {
    out.push_back(value.str());
  }
  return out;
}

inline std::vector<std::string> texts(const std::vector<NodeId>& values) {
  std::vector<std::string> out;
  for (const NodeId& value : values) {
    out.push_back(value.str());
  }
  return out;
}

inline std::vector<std::string> texts(const std::vector<DeviceId>& values) {
  std::vector<std::string> out;
  for (const DeviceId& value : values) {
    out.push_back(value.str());
  }
  return out;
}

inline std::vector<std::string> all_nodes(const PathComposition& composition) {
  std::vector<std::string> out = texts(composition.transit_nodes);
  for (const NodeId& node : composition.sources) {
    out.push_back(node.str());
  }
  for (const NodeId& node : composition.destinations) {
    out.push_back(node.str());
  }
  return out;
}

inline std::vector<std::string> exempt(const PathComposition& left, const PathComposition& right,
                                       EndpointExemption exemption) {
  const std::vector<std::string> left_sources = texts(left.sources);
  const std::vector<std::string> right_sources = texts(right.sources);
  const std::vector<std::string> left_destinations = texts(left.destinations);
  const std::vector<std::string> right_destinations = texts(right.destinations);
  switch (exemption) {
    case EndpointExemption::NONE:
      return {};
    case EndpointExemption::SHARED_SOURCE_ONLY:
      return intersection(left_sources, right_sources);
    case EndpointExemption::SHARED_DESTINATION_ONLY:
      return intersection(left_destinations, right_destinations);
    case EndpointExemption::SHARED_SOURCE_AND_DESTINATION: {
      std::vector<std::string> out = intersection(left_sources, right_sources);
      const std::vector<std::string> more = intersection(left_destinations, right_destinations);
      out.insert(out.end(), more.begin(), more.end());
      return out;
    }
    case EndpointExemption::ANY_ENDPOINT: {
      std::vector<std::string> left_all = texts(left.sources);
      const std::vector<std::string> more_left = texts(left.destinations);
      left_all.insert(left_all.end(), more_left.begin(), more_left.end());
      std::vector<std::string> right_all = texts(right.sources);
      const std::vector<std::string> more_right = texts(right.destinations);
      right_all.insert(right_all.end(), more_right.begin(), more_right.end());
      return intersection(left_all, right_all);
    }
  }
  return {};
}

// True when the pair is link-disjoint under the raw link sets.
inline bool link_disjoint(const PathComposition& left, const PathComposition& right) {
  return intersection(texts(left.links), texts(right.links)).empty();
}

// True when the pair is node-disjoint after applying the endpoint exemption.
inline bool node_disjoint(const PathComposition& left, const PathComposition& right,
                          EndpointExemption exemption) {
  const std::vector<std::string> shared = intersection(all_nodes(left), all_nodes(right));
  const std::vector<std::string> allowed = exempt(left, right, exemption);
  for (const std::string& node : shared) {
    bool is_allowed = false;
    for (const std::string& candidate : allowed) {
      if (candidate == node) {
        is_allowed = true;
        break;
      }
    }
    if (!is_allowed) {
      return false;
    }
  }
  return true;
}

inline bool device_disjoint(const PathComposition& left, const PathComposition& right) {
  return intersection(texts(left.devices), texts(right.devices)).empty();
}

}  // namespace oracle

}  // namespace pd_test

#define PD_TEST(name)                                                                 \
  static void pd_test_case_##name();                                                  \
  static const pd_test::CaseRegistrar pd_test_registrar_##name(#name,                 \
                                                               pd_test_case_##name);  \
  static void pd_test_case_##name()

#define PD_CHECK(condition) pd_test::check((condition), #condition, __FILE__, __LINE__)

#define PD_CHECK_EQ(actual, expected)                                            \
  pd_test::check_eq((actual), (expected),                                        \
                    std::string(#actual) + " == " + std::string(#expected), __FILE__, __LINE__)

// The condition is evaluated exactly once. Evaluating it twice would silently
// re-run any call inside it, which for this product means re-issuing a mutation
// and observing the idempotent replay instead of the original result.
#define PD_REQUIRE(condition)                                 \
  do {                                                        \
    const bool pd_require_value = static_cast<bool>(condition); \
    PD_CHECK(pd_require_value);                               \
    if (!pd_require_value) {                                  \
      return;                                                 \
    }                                                         \
  } while (false)

#define PD_WAIT_FOR(predicate, bound, description) \
  pd_test::wait_for([&]() { return (predicate); }, (bound), (description), __FILE__, __LINE__)

#define PD_TEST_MAIN()        \
  int main() {                \
    return pd_test::run_all(); \
  }
