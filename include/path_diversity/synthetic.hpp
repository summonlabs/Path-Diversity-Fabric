// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "path_diversity/evidence.hpp"
#include "path_diversity/export.hpp"
#include "path_diversity/ids.hpp"
#include "path_diversity/limits.hpp"
#include "path_diversity/path.hpp"
#include "path_diversity/policy.hpp"

namespace path_diversity {

// Synthetic fabric population generator.
//
// Everything it produces is SYNTHETIC: fabricated topology, fabricated
// placement and fabricated failure-domain classification. It exists so that
// scale behaviour and invalidation fan-out can be measured on this host. It is
// never evidence about a physical fabric and never a redundancy proof.
struct PATH_DIVERSITY_API SyntheticFabricOptions {
  std::uint32_t spine_count = 4;
  std::uint32_t leaf_count = 8;
  std::uint32_t racks = 4;
  std::uint32_t pods = 2;
  std::uint32_t sites = 1;
  std::uint32_t paths_per_pair = 2;
  // When true every entity is classified COMPLETE. When false a deterministic
  // fraction of entities is left ABSENT so incomplete-evidence behaviour can be
  // exercised at scale.
  bool complete_domain_coverage = true;
  // Deterministic seed: the generator is a pure function of the seed and the
  // options, so the same seed always produces the same fabric.
  std::uint64_t seed = 20260101ULL;
};

struct PATH_DIVERSITY_API SyntheticPath {
  PathId path;
  PathAuthorityGeneration authority_generation;
  std::string label;
  friend bool operator==(const SyntheticPath&, const SyntheticPath&) = default;
};

struct PATH_DIVERSITY_API SyntheticFabric {
  SyntheticFabricOptions options;
  TopologyGeneration topology_generation = TopologyGeneration::from_value(1);
  FailureDomainGeneration failure_domain_generation = FailureDomainGeneration::from_value(1);
  std::vector<SyntheticPath> paths;
  // Deterministic description of the generated shape, for benchmark reports.
  std::string render() const;
};

// Populates the evidence with the generated fabric and returns the path
// catalogue. The evidence keeps ownership of everything described.
PATH_DIVERSITY_API SyntheticFabric populate_synthetic_fabric(InMemoryEvidence& evidence,
                                                             const SyntheticFabricOptions& options);

// Deterministic pseudo-random stream used by the generator and by property
// tests. Exposed so that a failing property run can replay the exact sequence.
class PATH_DIVERSITY_API DeterministicRng {
 public:
  explicit DeterministicRng(std::uint64_t seed) noexcept;
  std::uint64_t next_u64() noexcept;
  std::uint32_t next_below(std::uint32_t bound) noexcept;
  bool next_bool() noexcept;
  void reseed(std::uint64_t seed) noexcept;
  std::uint64_t seed() const noexcept;

 private:
  std::uint64_t state_;
};

// A policy suitable for synthetic workloads: link, transit-node, device and
// failure-domain independence over an explicit relation set.
PATH_DIVERSITY_API DiversityPolicy synthetic_policy(const std::string& id, ScopeId scope,
                                                    SetSemantics semantics,
                                                    std::uint32_t minimum_paths);

}  // namespace path_diversity
